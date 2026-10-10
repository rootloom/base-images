"""Historical binary-image tooling. Legacy releases are disabled; use source_release.py."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

IMAGES = ('debian-slim', 'ubi-minimal', 'alpine', 'ubuntu', 'rocky-minimal')
ARCHES = ('amd64', 'arm64')
SMOKE = ('set -eu; test "$(id -u)" = 65532; test "$(id -g)" = 65532; '
         'test "$PWD" = /app; test -w /app; test -w /home/rootloom; '
         '(test -s /etc/ssl/certs/ca-certificates.crt || '
         'test -s /etc/pki/tls/certs/ca-bundle.crt); '
         'touch /app/.smoke; rm /app/.smoke')


def now():
    return datetime.now(timezone.utc).isoformat()


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


def digest(value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('Invalid digest')
    return value


def base_default(text):
    before, _, after = text.partition('FROM ')
    match = re.search(r'^ARG BASE_IMAGE=([^\s]+)\s*$', before, re.M)
    if not match or not after.startswith('${BASE_IMAGE}'):
        raise ValueError('Expected ARG BASE_IMAGE default and FROM ${BASE_IMAGE}')
    return match[1]


def platforms(index):
    result = {}
    for item in index['manifests']:
        platform = item.get('platform', {})
        arch = platform.get('architecture')
        if platform.get('os') == 'linux' and arch in ARCHES:
            if arch in result:
                raise ValueError('Duplicate platform')
            result[arch] = digest(item['digest'])
    if set(result) != set(ARCHES):
        raise ValueError('Both platforms are required')
    return result


def policy(report, expected):
    # Missing inventory, wrong bytes, or unsupported OS must not mean zero CVEs.
    if report.get('SchemaVersion') != 2 or report.get('ArtifactType') != 'container_image':
        raise ValueError('Unsupported scan schema')
    metadata = report['Metadata']
    if expected not in metadata.get('RepoDigests', []):
        raise ValueError('Scan digest mismatch')
    family = metadata.get('OS', {}).get('Family')
    supported = ('alpine', 'debian', 'ubuntu', 'redhat', 'rocky')
    if family not in supported or metadata['OS'].get('EOSL'):
        raise ValueError('Unsupported or end-of-life OS')
    results = report['Results']
    if not isinstance(results, list) or not any(r.get('Class') == 'os-pkgs' and r.get('Type') == family and isinstance(r.get('Packages'), list) and r['Packages'] for r in results):
        raise ValueError('Missing OS package inventory')
    blocked = []
    for result in results:
        vulnerabilities = result.get('Vulnerabilities')
        if vulnerabilities is not None and not isinstance(vulnerabilities, list):
            raise ValueError('Malformed vulnerability list')
        for finding in vulnerabilities or []:
            if finding['Severity'] in ('HIGH', 'CRITICAL') and finding.get('FixedVersion'):
                blocked.append(finding['VulnerabilityID'])
    return sorted(set(blocked))


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def registry_retry(operation, published=False):
    for attempt in range(5):
        try:
            return operation()
        except (HTTPError, URLError, TimeoutError, ConnectionError, subprocess.CalledProcessError) as error:
            if isinstance(error, HTTPError):
                recoverable = error.code in (408, 429, 500, 502, 503, 504) or (published and error.code == 404)
            elif isinstance(error, URLError):
                recoverable = isinstance(error.reason, (TimeoutError, ConnectionError))
            elif isinstance(error, subprocess.CalledProcessError):
                text = ((error.stderr or '') + (error.output or '')).lower()
                denied = any(word in text for word in ('unauthorized', 'forbidden', 'denied', '401', '403'))
                recoverable = not denied and (any(word in text for word in (
                    'too many requests', '429', '500 internal server error', '502 bad gateway',
                    '503 service unavailable', '504 gateway timeout', 'connection reset',
                    'connection refused', 'i/o timeout', 'tls handshake timeout')) or
                    (published and any(word in text for word in ('not found', 'manifest unknown'))))
            else:
                recoverable = True
            if not recoverable or attempt == 4:
                raise
            time.sleep(5 * (attempt + 1))


def inspect(ref, published=False):
    summary = registry_retry(lambda: run('docker', 'buildx', 'imagetools', 'inspect', ref,
                                         stderr=subprocess.PIPE), published)
    match = re.search(r'^Digest:\s+(sha256:[0-9a-f]{64})\s*$', summary, re.M)
    if not match:
        raise ValueError('Registry index digest is missing')
    value = digest(match[1])
    raw = registry_retry(lambda: run('docker', 'buildx', 'imagetools', 'inspect',
                                     ref.split('@')[0] + '@' + value, '--raw', stderr=subprocess.PIPE), published)
    return value, json.loads(raw)


def public_bytes(repo, tag, name):
    with urlopen(f'https://github.com/{repo}/releases/download/{tag}/{name}', timeout=60) as response:
        return response.read()


def verify_public(repo, tag, path):
    for attempt in range(5):
        try:
            if hashlib.sha256(public_bytes(repo, tag, path.name)).hexdigest() != sha(path):
                raise ValueError('Public asset checksum mismatch')
            return
        except Exception:
            if attempt == 4:
                raise
            time.sleep(5)


def promoted_evidence(repo, image):
    pages = json.loads(run('gh', 'api', '--paginate', '--slurp', f'repos/{repo}/releases?per_page=100'))
    for item in (item for page in pages for item in page):
        tag = item['tag_name']
        if item['draft'] or item['prerelease'] or not re.fullmatch(r'standard-' + re.escape(image) + r'-[0-9]+-[0-9]+', tag):
            continue
        if not any(asset['name'] == 'promotion.json' for asset in item['assets']):
            continue
        promotion = json.loads(public_bytes(repo, tag, 'promotion.json'))
        raw = public_bytes(repo, tag, 'manifest.json')
        if hashlib.sha256(raw).hexdigest() != promotion['manifest_sha256']:
            raise ValueError('Promoted manifest checksum mismatch')
        manifest = json.loads(raw)
        if manifest['variant'] != 'standard' or manifest['source_repository'] != repo:
            raise ValueError('Wrong promoted evidence source')
        refresh_reason(manifest['refresh_inputs'], manifest, promotion)
        return manifest, promotion
    return None


def refresh_reason(inputs, manifest=None, promotion=None, checked_at=None):
    if manifest is None:
        return 'no_known_promotion'
    if not isinstance(manifest, dict) or not isinstance(promotion, dict):
        raise ValueError('Malformed promoted evidence')
    if manifest['schema_version'] != 1 or promotion['schema_version'] != 1:
        raise ValueError('Unsupported promotion schema')
    if manifest['status'] != 'passed' or promotion['status'] != 'promoted':
        raise ValueError('Evidence did not pass promotion')
    for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag'):
        if not isinstance(manifest[key], str) or manifest[key] != promotion[key]:
            raise ValueError('Promotion does not match evidence')
    digest(manifest['index_digest'])
    if not re.fullmatch(r'standard-[0-9]+-[0-9]+', manifest['version_tag']) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', manifest['supported_version_tag']):
        raise ValueError('Invalid promoted tags')
    if set(manifest['platforms']) != set(ARCHES):
        raise ValueError('Incomplete promoted platforms')
    for record in manifest['platforms'].values():
        digest(record['digest'])
        if record['scan_status'] != 'complete' or record['quality'] != 'passed' or record['policy'] != 'passed':
            raise ValueError('Incomplete promoted qualification')
    previous = manifest['refresh_inputs']
    required = {'build_sha256', 'upstream_reference', 'upstream_digest', 'scanner_version', 'database_sha256', 'database_repository'}
    if not isinstance(previous, dict) or set(previous) != required or set(inputs) != required:
        raise ValueError('Malformed refresh inputs')
    for key, value in previous.items():
        if not isinstance(value, str) or not value:
            raise ValueError('Malformed refresh input')
        if key.endswith('_sha256') and not re.fullmatch(r'[0-9a-f]{64}', value):
            raise ValueError('Malformed refresh checksum')
    digest(previous['upstream_digest'])
    started = datetime.fromisoformat(manifest['started_at'].replace('Z', '+00:00'))
    promoted = datetime.fromisoformat(promotion['promoted_at'].replace('Z', '+00:00'))
    current = checked_at or datetime.now(timezone.utc)
    if not started.tzinfo or not promoted.tzinfo or not started <= promoted <= current:
        raise ValueError('Invalid promotion times')
    if previous != inputs:
        return 'inputs_changed'
    if (current - started).total_seconds() >= 24 * 3600:
        return 'daily_package_refresh'
    return None


def anonymous_registry_access(manifest):
    repository = manifest['image'].removeprefix('ghcr.io/')
    if not re.fullmatch(r'rootloom/(?:' + '|'.join(IMAGES) + ')', repository):
        raise ValueError('Unexpected public registry repository')
    # Direct HTTP checks do not use Docker credentials or cached image data.
    with registry_retry(lambda: urlopen(f'https://ghcr.io/token?service=ghcr.io&scope=repository:{repository}:pull', timeout=60)) as response:
        token = json.loads(response.read())['token']
    for value in {manifest['index_digest'], *[record['digest'] for record in manifest['platforms'].values()]}:
        request = Request(f'https://ghcr.io/v2/{repository}/manifests/{digest(value)}',
                          headers={'Authorization': 'Bearer ' + token,
                                   'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json'})
        with registry_retry(lambda: urlopen(request, timeout=60), published=True) as response:
            if 'sha256:' + hashlib.sha256(response.read()).hexdigest() != value:
                raise ValueError('Anonymous registry manifest mismatch')


def reject_legacy_release():
    raise ValueError('Legacy binary-image release disabled: pinned-source compilation into an empty final rootfs is required; use scripts/source_release.py')


def promote(manifest, out, repo, tag):
    reject_legacy_release()
    registry = manifest['image']
    ref = registry + '@' + manifest['index_digest']
    anonymous_registry_access(manifest)
    # New GHCR packages can be private. Require anonymous pulls before promotion.
    with tempfile.TemporaryDirectory() as config:
        env = dict(os.environ, DOCKER_CONFIG=config)
        for arch, record in manifest['platforms'].items():
            run('docker', 'pull', '--platform', 'linux/' + arch, registry + '@' + record['digest'], env=env)
    run('cosign', 'sign', '--yes', ref)
    for record in manifest['platforms'].values():
        run('cosign', 'sign', '--yes', registry + '@' + record['digest'])
    identity = 'https://github.com/rootloom/base-images/.github/workflows/release.yml@refs/heads/main'
    issuer = 'https://token.actions.githubusercontent.com'
    signed = sorted({manifest['index_digest'], *[record['digest'] for record in manifest['platforms'].values()]})
    for value in signed:
        run('cosign', 'verify', '--certificate-identity', identity,
            '--certificate-oidc-issuer', issuer, registry + '@' + digest(value))
    version = manifest['version_tag']
    supported = manifest['supported_version_tag']
    run('docker', 'buildx', 'imagetools', 'create', '-t', registry + ':' + version,
        '-t', registry + ':' + supported, '-t', registry + ':latest', ref)
    for stable in (version, supported, 'latest'):
        promoted, _ = inspect(registry + ':' + stable, published=True)
        if promoted != manifest['index_digest']:
            raise ValueError('Promoted index differs from qualified index')
    promotion = {key: manifest[key] for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag')}
    promotion.update(schema_version=1, status='promoted', promoted_at=now(), manifest_sha256=sha(out / 'manifest.json'))
    promotion['signature_verification'] = {'status': 'passed', 'identity': identity, 'issuer': issuer, 'digests': signed}
    path = out / 'promotion.json'
    write_json(path, promotion)
    # Do not overwrite evidence. A workflow retry uses a new run attempt and tag.
    run('gh', 'release', 'upload', tag, str(path), '--repo', repo)
    verify_public(repo, tag, path)


def main(mode, image):
    if mode != 'pr':
        reject_legacy_release()
    dockerfile = Path('images') / image / 'Dockerfile'
    if mode == 'pr':
        upstream = base_default(dockerfile.read_text())
        upstream_digest, upstream_index = inspect(upstream)
        platforms(upstream_index)
        pinned = upstream + '@' + upstream_digest
        for arch in ARCHES:
            tag = 'rootloom-test:' + arch
            run('docker', 'buildx', 'build', '--pull', '--no-cache', '--platform', 'linux/' + arch,
                '--build-arg', 'BASE_IMAGE=' + pinned, '--load', '-t', tag, str(dockerfile.parent))
            run('docker', 'run', '--rm', '--platform', 'linux/' + arch, '--network', 'none', tag, '/bin/sh', '-c', SMOKE)
        return
    if os.environ.get('GITHUB_REPOSITORY') != 'rootloom/base-images' or os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('Publishing requires the trusted repository main branch')
    repo = os.environ['GITHUB_REPOSITORY']
    source = os.environ['GITHUB_SHA']
    build = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    tag = 'standard-' + image + '-' + build
    registry = 'ghcr.io/rootloom/' + image
    candidate = registry + ':candidate-' + build
    out = Path('evidence')
    out.mkdir(exist_ok=True)
    manifest = {'schema_version': 1, 'variant': 'standard', 'image': registry,
                'source_commit': source, 'source_repository': repo,
                'run_url': f'https://github.com/{repo}/actions/runs/{os.environ["GITHUB_RUN_ID"]}',
                'started_at': now(), 'version_tag': 'standard-' + build,
                'platforms': {arch: {'scan_status': 'not_run', 'quality': 'not_run'} for arch in ARCHES},
                'policy': 'block fixable HIGH/CRITICAL; fail closed',
                'status': 'failed', 'scanner': {'name': 'Trivy', 'version': '0.75.0'}}
    manifest['coverage'] = 'Trivy known vulnerabilities; no guarantee of CVE-free images. Vendor feeds can exclude third-party packages.'
    try:
        upstream = base_default(dockerfile.read_text())
        manifest['upstream'] = {'reference': upstream}
        os_version = upstream.rsplit(':', 1)[-1].removesuffix('-slim').removesuffix('-minimal')
        if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', os_version):
            raise ValueError('Unsupported OS version tag')
        manifest['supported_version_tag'] = os_version
        upstream_digest, upstream_index = inspect(upstream)
        manifest['upstream'].update(digest=upstream_digest, platforms=platforms(upstream_index))
        pinned = upstream + '@' + upstream_digest
        run('trivy', 'image', '--cache-dir', str(out / '.trivy'), '--download-db-only')
        db = json.loads((out / '.trivy/db/metadata.json').read_text())
        manifest['scanner']['database'] = db
        updated = datetime.fromisoformat(db['UpdatedAt'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - updated).total_seconds()
        if not 0 <= age <= 48 * 3600:
            raise ValueError('Vulnerability database is stale or future-dated')
        manifest['scanner']['database_sha256'] = sha(out / '.trivy/db/trivy.db')
        manifest['scanner']['database_repository'] = 'mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2'
        manifest['scanner']['actual_version'] = run('trivy', '--version')
        fingerprint = hashlib.sha256()
        for path in (dockerfile, Path('scripts/release.py'), Path('.github/workflows/release.yml')):
            fingerprint.update(str(path).encode() + b'\0' + path.read_bytes() + b'\0')
        inputs = {'build_sha256': fingerprint.hexdigest(), 'upstream_reference': upstream,
                  'upstream_digest': upstream_digest, 'scanner_version': manifest['scanner']['version'],
                  'database_sha256': manifest['scanner']['database_sha256'],
                  'database_repository': manifest['scanner']['database_repository']}
        manifest['refresh_inputs'] = inputs
        manifest['refresh_reason'] = 'forced_' + os.environ.get('GITHUB_EVENT_NAME', 'manual')
        if os.environ.get('GITHUB_EVENT_NAME') == 'schedule':
            previous = promoted_evidence(repo, image)
            if previous and previous[0]['image'] != registry:
                raise ValueError('Wrong promoted image')
            reason = refresh_reason(inputs, *previous) if previous else 'no_known_promotion'
            if previous:
                live, _ = inspect(registry + ':latest')
                if live != previous[0]['index_digest']:
                    reason = 'latest_digest_changed'
            if reason is None:
                print('Refresh skipped: promoted inputs unchanged and package rebuild is not due')
                return
            manifest['refresh_reason'] = reason
        subprocess.run(['docker', 'login', 'ghcr.io', '-u', os.environ['GITHUB_ACTOR'], '--password-stdin'],
                       input=os.environ['GH_TOKEN'], text=True, check=True, stdout=subprocess.DEVNULL)
        run('docker', 'buildx', 'build', '--pull', '--no-cache', '--platform', 'linux/amd64,linux/arm64',
            '--build-arg', 'BASE_IMAGE=' + pinned, '--provenance=mode=max', '--push',
            '--label', 'org.opencontainers.image.source=https://github.com/' + repo,
            '--label', 'org.opencontainers.image.revision=' + source,
            '-t', candidate, str(dockerfile.parent))
        index_digest, index = inspect(candidate, published=True)
        manifest['index_digest'] = index_digest
        write_json(out / 'index.json', index)
        children = platforms(index)
        for arch, child in children.items():
            manifest['platforms'][arch]['digest'] = child
        scanner_config = out / '.scanner.yaml'
        scanner_config.write_text('{}\n')
        for arch, child in children.items():
            ref = registry + '@' + child
            record = manifest['platforms'][arch]
            record.update(quality='failed', started_at=now())
            try:
                run('docker', 'pull', '--platform', 'linux/' + arch, ref)
                record['size_bytes'] = int(run('docker', 'image', 'inspect', '--format', '{{.Size}}', ref))
                run('docker', 'run', '--rm', '--platform', 'linux/' + arch, '--network', 'none', ref, '/bin/sh', '-c', SMOKE)
                record['quality'] = 'passed'
                record['scan_status'] = 'failed'
                report_path = out / (arch + '.cve.json')
                run('trivy', '--config', str(scanner_config), 'image', '--image-src', 'remote', '--platform', 'linux/' + arch,
                    '--cache-dir', str(out / '.trivy'), '--skip-db-update', '--scanners', 'vuln',
                    '--ignorefile', '/dev/null', '--list-all-pkgs', '--format', 'json', '--output', str(report_path), ref)
                report = json.loads(report_path.read_text())
                blocked = policy(report, ref)
                record['os'] = report['Metadata']['OS']
                findings = [finding for result in report['Results'] for finding in result.get('Vulnerabilities') or []]
                record['severity_counts'] = {severity: sum(finding['Severity'] == severity for finding in findings)
                                             for severity in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
                if sum(record['severity_counts'].values()) != len(findings):
                    raise ValueError('Unsupported vulnerability severity')
                record['package_count'] = sum(len(result.get('Packages') or []) for result in report['Results'])
                sbom_path = out / (arch + '.spdx.json')
                run('trivy', '--config', str(scanner_config), 'image', '--image-src', 'remote', '--platform', 'linux/' + arch,
                    '--cache-dir', str(out / '.trivy'), '--skip-db-update', '--format', 'spdx-json',
                    '--output', str(sbom_path), ref)
                sbom = json.loads(sbom_path.read_text())
                if not sbom.get('spdxVersion', '').startswith('SPDX-') or not sbom.get('packages'):
                    raise ValueError('Invalid SBOM')
                record.update(scan_status='complete', blocked_cves=blocked,
                              vulnerability_count=len(findings),
                              policy='blocked' if blocked else 'passed')
            except Exception as error:
                record['error'] = str(error)
            record['finished_at'] = now()
        manifest['status'] = 'passed' if all(r.get('policy') == 'passed' and r['quality'] == 'passed'
                                             for r in manifest['platforms'].values()) else 'blocked'
    except Exception as error:
        manifest['error'] = str(error)
    manifest['finished_at'] = now()
    assets = [p for p in out.iterdir() if p.is_file() and not p.name.startswith('.')
              and p.name not in ('manifest.json', 'SHA256SUMS', 'promotion.json')]
    manifest['assets'] = {p.name: {'sha256': sha(p), 'url': f'https://github.com/{repo}/releases/download/{tag}/{p.name}'} for p in assets}
    write_json(out / 'manifest.json', manifest)
    assets.append(out / 'manifest.json')
    (out / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(assets)))
    assets.append(out / 'SHA256SUMS')
    run('gh', 'release', 'create', tag, '--repo', repo, '--target', source, '--title', tag,
        '--notes', 'Standard image evidence. Policy status: ' + manifest['status'], '--latest=false',
        *[str(p) for p in assets])
    # Anonymous retrieval verifies public evidence, not authenticated API access.
    for path in assets:
        verify_public(repo, tag, path)
    if manifest['status'] != 'passed':
        raise RuntimeError('Evidence published; promotion blocked')
    promote(manifest, out, repo, tag)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pr', 'release'))
    parser.add_argument('image', choices=IMAGES)
    args = parser.parse_args()
    main(args.mode, args.image)
