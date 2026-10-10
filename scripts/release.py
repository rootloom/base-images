"""Standard-only builds. Public evidence must pass before mutable tags change."""

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
from urllib.request import urlopen

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


def inspect(ref):
    summary = run('docker', 'buildx', 'imagetools', 'inspect', ref)
    match = re.search(r'^Digest:\s+(sha256:[0-9a-f]{64})\s*$', summary, re.M)
    if not match:
        raise ValueError('Registry index digest is missing')
    value = digest(match[1])
    raw = run('docker', 'buildx', 'imagetools', 'inspect', ref.split('@')[0] + '@' + value, '--raw')
    return value, json.loads(raw)


def main(mode, image):
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
        subprocess.run(['docker', 'login', 'ghcr.io', '-u', os.environ['GITHUB_ACTOR'], '--password-stdin'],
                       input=os.environ['GH_TOKEN'], text=True, check=True, stdout=subprocess.DEVNULL)
        run('docker', 'buildx', 'build', '--pull', '--no-cache', '--platform', 'linux/amd64,linux/arm64',
            '--build-arg', 'BASE_IMAGE=' + pinned, '--provenance=mode=max', '--push',
            '--label', 'org.opencontainers.image.source=https://github.com/' + repo,
            '--label', 'org.opencontainers.image.revision=' + source,
            '-t', candidate, str(dockerfile.parent))
        index_digest, index = inspect(candidate)
        manifest['index_digest'] = index_digest
        write_json(out / 'index.json', index)
        children = platforms(index)
        for arch, child in children.items():
            manifest['platforms'][arch]['digest'] = child
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
        scanner_config = out / '.scanner.yaml'
        scanner_config.write_text('{}\n')
        for arch, child in children.items():
            ref = registry + '@' + child
            record = manifest['platforms'][arch]
            record.update(quality='failed', started_at=now())
            try:
                run('docker', 'pull', '--platform', 'linux/' + arch, ref)
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
                sbom_path = out / (arch + '.spdx.json')
                run('trivy', '--config', str(scanner_config), 'image', '--image-src', 'remote', '--platform', 'linux/' + arch,
                    '--cache-dir', str(out / '.trivy'), '--skip-db-update', '--format', 'spdx-json',
                    '--output', str(sbom_path), ref)
                sbom = json.loads(sbom_path.read_text())
                if not sbom.get('spdxVersion', '').startswith('SPDX-') or not sbom.get('packages'):
                    raise ValueError('Invalid SBOM')
                record.update(scan_status='complete', blocked_cves=blocked,
                              vulnerability_count=sum(len(r.get('Vulnerabilities') or []) for r in report['Results']),
                              policy='blocked' if blocked else 'passed')
            except Exception as error:
                record['error'] = str(error)
            record['finished_at'] = now()
        manifest['status'] = 'passed' if all(r.get('policy') == 'passed' and r['quality'] == 'passed'
                                             for r in manifest['platforms'].values()) else 'blocked'
    except Exception as error:
        manifest['error'] = str(error)
    manifest['finished_at'] = now()
    assets = [p for p in out.iterdir() if p.is_file() and not p.name.startswith('.')]
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
        url = f'https://github.com/{repo}/releases/download/{tag}/{path.name}'
        for attempt in range(5):
            try:
                with urlopen(url, timeout=60) as response:
                    if hashlib.sha256(response.read()).hexdigest() != sha(path):
                        raise ValueError('Public asset checksum mismatch')
                break
            except Exception:
                if attempt == 4:
                    raise
                time.sleep(5)
    if manifest['status'] != 'passed':
        raise RuntimeError('Evidence published; promotion blocked')
    ref = registry + '@' + manifest['index_digest']
    # New GHCR packages can be private. Refuse promotion until anonymous pulls work.
    with tempfile.TemporaryDirectory() as config:
        env = dict(os.environ, DOCKER_CONFIG=config)
        for arch, record in manifest['platforms'].items():
            run('docker', 'pull', '--platform', 'linux/' + arch, registry + '@' + record['digest'], env=env)
    run('cosign', 'sign', '--yes', ref)
    for record in manifest['platforms'].values():
        run('cosign', 'sign', '--yes', registry + '@' + record['digest'])
    version = 'standard-' + build
    run('docker', 'buildx', 'imagetools', 'create', '-t', registry + ':' + version,
        '-t', registry + ':' + os_version, '-t', registry + ':latest', ref)
    for stable in (version, os_version, 'latest'):
        promoted, _ = inspect(registry + ':' + stable)
        if promoted != manifest['index_digest']:
            raise ValueError('Promoted index differs from qualified index')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('pr', 'release'))
    parser.add_argument('image', choices=IMAGES)
    args = parser.parse_args()
    main(args.mode, args.image)
