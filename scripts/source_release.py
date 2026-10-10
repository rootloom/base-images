"""Source-only qualification. Limited NVD CPE coverage is not a CVE-free claim."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import Request, urlopen

from release import ARCHES, digest, inspect, now, platforms, public_bytes, run, sha, verify_public, write_json

ROOT = Path('images/source-minimal')
OUT = Path('source-evidence')
IMAGE = 'ghcr.io/rootloom/source-minimal'
SCANNER = '0.120.1'
SCANNER_SHA = {
    'amd64': '0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d',
    'arm64': '29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514',
}
CONTROLS = {
    'musl': ('cpe:2.3:a:musl-libc:musl:1.2.1:*:*:*:*:*:*:*', 'CVE-2020-28928'),
    'busybox': ('cpe:2.3:a:busybox:busybox:1.34.1:*:*:*:*:*:*:*', 'CVE-2022-48174'),
}
COVERAGE = ('NVD CPE matching for musl and BusyBox only. CPE records can be missing or incorrect. '
            'No distribution advisory coverage, compiler trust bootstrap, CA trust audit, or CVE-free guarantee. '
            'Patches do not automatically suppress findings. No FIPS claim.')


def checksum(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError('Invalid SHA-256')
    return value


def lockfile():
    lock = json.loads((ROOT / 'sources.lock.json').read_text())
    if lock['schema_version'] != 1 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', lock['image_version']):
        raise ValueError('Invalid source lock schema or version')
    digest(lock['builder']['digest'])
    if set(lock['builder']['platform_digests']) != set(ARCHES):
        raise ValueError('Both bootstrap platforms are required')
    for value in lock['builder']['platform_digests'].values():
        digest(value)
    names = set()
    for source in [*lock['sources'], *lock.get('patches', []), *lock.get('verification_inputs', [])]:
        checksum(source['sha256'])
        if not source['url'].startswith('https://') or Path(source['filename']).name != source['filename']:
            raise ValueError('Unsafe source URL or filename')
        if source['filename'] in names:
            raise ValueError('Duplicate source filename')
        names.add(source['filename'])
    components(lock, require_coverage=False)
    return lock


def components(lock, require_coverage=True):
    records = {s['name']: s for s in lock['sources'] if s['name'] in CONTROLS}
    if set(records) != set(CONTROLS):
        raise ValueError('Missing source component inventory')
    if len([s for s in lock['sources'] if s['name'] in CONTROLS]) != 2:
        raise ValueError('Duplicate source component')
    for name, item in records.items():
        prefix = CONTROLS[name][0].split(':')[:5]
        if item['cpe'].split(':') != [*prefix, item['version'], '*', '*', '*', '*', '*', '*', '*']:
            raise ValueError('Source CPE identity mismatch')
        if item['purl'] != 'pkg:generic/' + name + '@' + item['version'] or not item['license']:
            raise ValueError('Missing source purl or license')
    # Data inputs must not be silently treated as executable packages.
    if require_coverage and coverage_gaps(lock):
        raise ValueError('Unsupported source component coverage')
    return records


def coverage_gaps(lock):
    return [s['name'] for s in lock['sources'] if s['name'] not in CONTROLS and (s['name'] != 'mozilla-ca-bundle' or s.get('kind') != 'trust-data')]


def cpe_policy(report, cpe):
    if report.get('source') != {'type': 'cpe', 'target': cpe}:
        raise ValueError('Scanner CPE inventory mismatch')
    if report.get('descriptor', {}).get('name') != 'grype' or report['descriptor'].get('version') != SCANNER:
        raise ValueError('Unexpected scanner version')
    db = report.get('descriptor', {}).get('db')
    status = db.get('status', {}) if isinstance(db, dict) else {}
    nvd = db.get('providers', {}).get('nvd', {}) if isinstance(db, dict) else {}
    if status.get('valid') is not True or status.get('error') or not status.get('schemaVersion') or not status.get('built') or not status.get('from') or not nvd.get('captured') or not nvd.get('input'):
        raise ValueError('Missing scanner database evidence')
    for value in (status['built'], nvd['captured']):
        if not datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo:
            raise ValueError('Invalid scanner database time')
    if not status['from'].startswith('https://grype.anchore.io/databases/'):
        raise ValueError('Unexpected scanner database source')
    if not isinstance(report.get('matches'), list) or report.get('ignoredMatches') or report.get('alertsByPackage'):
        raise ValueError('Missing findings or filtered/unsupported coverage')
    blocked = []
    for finding in report['matches']:
        artifact = finding['artifact']
        if artifact['version'] != cpe.split(':')[5] or cpe not in artifact['cpes']:
            raise ValueError('Finding belongs to another source component')
        vulnerability = finding['vulnerability']
        severity = vulnerability['severity'].upper()
        if severity not in ('UNKNOWN', 'NEGLIGIBLE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
            raise ValueError('Unsupported vulnerability severity')
        if not any(d.get('matcher') == 'stock-matcher' and d.get('type') == 'cpe-match' for d in finding['matchDetails']):
            raise ValueError('Missing NVD CPE match evidence')
        if severity in ('HIGH', 'CRITICAL'):
            blocked.append(vulnerability['id'])
    return sorted(set(blocked))


def source_policy(report, lock, expected_ref):
    """Validate saved source scan evidence without shell or network access."""
    digest(expected_ref.rsplit('@', 1)[1])
    if report.get('schema_version') != 1 or report.get('subject') != expected_ref:
        raise ValueError('Source scan digest mismatch')
    checksum(report['database_sha256'])
    expected = components(lock, require_coverage=False)
    if not isinstance(report.get('components'), list) or len(report['components']) != len(expected):
        raise ValueError('Missing source scan inventory')
    if set(report.get('controls', {})) != set(CONTROLS):
        raise ValueError('Missing source coverage controls')
    databases = []
    for name, (cpe, cve) in CONTROLS.items():
        control = report['controls'][name]
        cpe_policy(control, cpe)
        if not any(f['vulnerability']['id'] == cve for f in control['matches']):
            raise ValueError('Source coverage positive control failed: ' + name)
        databases.append(control['descriptor']['db'])
    seen = set()
    blocked = []
    for record in report['components']:
        name = record['name']
        if name in seen or name not in expected:
            raise ValueError('Unexpected source scan component')
        seen.add(name)
        if any(record[key] != expected[name][key] for key in ('version', 'cpe')):
            raise ValueError('Source version mismatch')
        blocked.extend(cpe_policy(record['report'], record['cpe']))
        databases.append(record['report']['descriptor']['db'])
    if any(db != databases[0] for db in databases):
        raise ValueError('Source scan databases differ')
    if coverage_gaps(lock) or report.get('unscanned_components'):
        raise ValueError('Unsupported source component coverage')
    return sorted(set(blocked))


def rootfs_inventory(path, docker_export=False, expected=None):
    result = {}
    with tarfile.open(path) as archive:
        for item in archive:
            name = item.name.removeprefix('./').rstrip('/')
            if not name or name == '.':
                continue
            if name.startswith('/') or '..' in Path(name).parts or name in result:
                raise ValueError('Unsafe or duplicate rootfs path')
            if docker_export and name in ('.dockerenv', 'etc/hosts', 'etc/hostname', 'etc/resolv.conf'):
                continue
            content = ''
            if item.isfile() or item.islnk():
                stream = archive.extractfile(item)
                hasher = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    hasher.update(chunk)
                content = hasher.hexdigest()
            elif not item.isdir() and not item.issym():
                raise ValueError('Unsupported rootfs file type')
            result[name] = (item.mode, item.uid, item.gid, 'file' if item.isfile() or item.islnk() else 'dir' if item.isdir() else 'link',
                            item.linkname if item.issym() else '', content)
    if docker_export and expected is not None:
        # Docker can add these exact entries. Never discard paths supplied by the image.
        injected = {'dev/console': (0o755, 0, 0, 'file', '', hashlib.sha256(b'').hexdigest()),
                    'dev/pts': (0o755, 0, 0, 'dir', '', ''), 'dev/shm': (0o755, 0, 0, 'dir', '', ''),
                    'etc/mtab': (0o777, 0, 0, 'link', '/proc/mounts', '')}
        for name, value in injected.items():
            if name not in expected and result.get(name) == value:
                result.pop(name)
    return result


def scanner_env():
    return dict(os.environ, GRYPE_DB_CACHE_DIR=str(OUT.resolve() / '.grype'), GRYPE_DB_AUTO_UPDATE='false',
                GRYPE_CHECK_FOR_APP_UPDATE='false', GRYPE_MATCH_STOCK_USING_CPES='true')


def scan(cpe):
    return json.loads(run('grype', '--config', str(OUT / '.grype.yaml'), cpe, '-o', 'json', env=scanner_env()))


def install():
    # Only disposable hosted Linux runners can use this temporary tool installer.
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise ValueError('Scanner installer requires a disposable Actions Linux runner')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    target = Path(os.environ['RUNNER_TEMP'])
    archive = target / 'grype.tar.gz'
    with urlopen(f'https://github.com/anchore/grype/releases/download/v{SCANNER}/grype_{SCANNER}_linux_{arch}.tar.gz', timeout=60) as response:
        archive.write_bytes(response.read())
    if sha(archive) != SCANNER_SHA[arch]:
        raise ValueError('Scanner archive checksum mismatch')
    with tarfile.open(archive) as bundle:
        member = bundle.getmember('grype')
        if not member.isfile():
            raise ValueError('Invalid scanner archive')
        binary = target / 'grype'
        binary.write_bytes(bundle.extractfile(member).read())
        binary.chmod(0o700)
    with Path(os.environ['GITHUB_PATH']).open('a') as output:
        output.write(str(target) + '\n')


def new_manifest():
    return {'schema_version': 1, 'variant': 'source', 'image': IMAGE,
            'source_commit': os.environ.get('GITHUB_SHA', 'local'), 'source_repository': 'rootloom/base-images',
            'run_url': 'https://github.com/rootloom/base-images/actions/runs/' + os.environ.get('GITHUB_RUN_ID', '0'),
            'started_at': now(), 'status': 'blocked', 'coverage': COVERAGE,
            'scanner': {'name': 'Grype', 'version': SCANNER},
            'version_tag': 'source-' + os.environ.get('GITHUB_RUN_ID', '0') + '-' + os.environ.get('GITHUB_RUN_ATTEMPT', '0'),
            'platforms': {arch: {'scan_status': 'not_run', 'quality': 'not_run', 'reproducibility': 'not_run', 'policy': 'unknown'} for arch in ARCHES},
            'policy': 'Block all HIGH/CRITICAL, including unknown fix status; fail closed on missing coverage. No automatic exceptions.'}


def refresh_reason(inputs, previous=None, promotion=None, checked_at=None):
    if previous is None:
        return 'no_known_promotion'
    if previous['schema_version'] != 1 or previous['source_repository'] != 'rootloom/base-images' or previous['variant'] != 'source' or previous['status'] not in ('passed', 'blocked') or previous['image'] != IMAGE:
        raise ValueError('Invalid previous source evidence')
    passed = previous['status'] == 'passed'
    if passed:
        if promotion is None or promotion['status'] != 'promoted' or promotion['manifest_sha256'] != hashlib.sha256(json.dumps(previous, indent=2, sort_keys=True).encode() + b'\n').hexdigest():
            raise ValueError('Missing or mismatched promotion evidence')
        for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag'):
            if previous[key] != promotion[key]:
                raise ValueError('Promotion identity mismatch')
        digest(previous['index_digest'])
    elif promotion is not None:
        raise ValueError('Blocked attempt cannot be promoted')
    if set(previous['platforms']) != set(ARCHES):
        raise ValueError('Missing promoted architecture')
    for record in previous['platforms'].values():
        digest(record['digest'])
        if record['quality'] != 'passed' or record['reproducibility'] != 'passed':
            raise ValueError('Incomplete source qualification')
        if passed and (record['policy'] != 'passed' or record['scan_status'] != 'complete'):
            raise ValueError('Incomplete source scan')
        if not passed and (record['policy'] not in ('blocked', 'unknown', 'passed') or record['scan_status'] not in ('complete', 'partial')):
            raise ValueError('Incomplete blocked source scan')
    old = previous['refresh_inputs']
    if set(old) != {'lock_sha256', 'build_sha256', 'database_sha256', 'scanner_version'} or set(inputs) != set(old):
        raise ValueError('Malformed source refresh inputs')
    for key in ('lock_sha256', 'build_sha256', 'database_sha256'):
        checksum(old[key])
        checksum(inputs[key])
    started = datetime.fromisoformat(previous['started_at'])
    promoted = datetime.fromisoformat(promotion['promoted_at'] if passed else previous['finished_at'])
    current = checked_at or datetime.now(timezone.utc)
    if not started.tzinfo or not promoted.tzinfo or not started <= promoted <= current:
        raise ValueError('Invalid source promotion time')
    if old != inputs:
        return 'inputs_changed'
    return 'daily_rebuild' if (current - started).total_seconds() >= 86400 else None


def check():
    OUT.mkdir(exist_ok=True)
    manifest = new_manifest()
    try:
        lock = lockfile()
        write_json(OUT / 'sources.lock.json', lock)
        manifest.update(supported_version_tag=lock['image_version'], bootstrap_builder=lock['builder'], source_inventory=lock['sources'], patches=lock.get('patches', []))
        manifest['coverage_gaps'] = coverage_gaps(lock)
        builder = lock['builder']
        pinned = builder['image'] + '@' + builder['digest']
        if not (ROOT / 'Dockerfile').read_text().startswith('FROM ' + pinned + ' AS fetch\n'):
            raise ValueError('Bootstrap builder does not match source lock')
        resolved, index = inspect(pinned)
        if resolved != builder['digest'] or platforms(index) != builder['platform_digests']:
            raise ValueError('Bootstrap builder platform digest mismatch')
        (OUT / '.grype.yaml').write_text('match:\n  stock:\n    using-cpes: true\nignore: []\n')
        run('grype', '--config', str(OUT / '.grype.yaml'), 'db', 'update', env=scanner_env())
        status = json.loads(run('grype', '--config', str(OUT / '.grype.yaml'), 'db', 'status', '-o', 'json', env=scanner_env()))
        built = datetime.fromisoformat(status['built'].replace('Z', '+00:00'))
        age = (datetime.now(timezone.utc) - built).total_seconds()
        if status.get('valid') is not True or status.get('error') or not 0 <= age <= 48 * 3600:
            raise ValueError('Invalid or stale vulnerability database')
        dbfiles = list((OUT / '.grype').rglob('vulnerability.db'))
        if len(dbfiles) != 1:
            raise ValueError('Missing scanner database bytes')
        manifest['scanner'].update(database=status, database_sha256=sha(dbfiles[0]))
        controls = {name: scan(cpe) for name, (cpe, _) in CONTROLS.items()}
        write_json(OUT / 'coverage-controls.json', controls)
        for name, (cpe, cve) in CONTROLS.items():
            cpe_policy(controls[name], cpe)
            if not any(f['vulnerability']['id'] == cve for f in controls[name]['matches']):
                raise ValueError('Source coverage positive control failed: ' + name)
        fingerprint = hashlib.sha256()
        paths = [*ROOT.rglob('*'), Path('scripts/source_release.py'), Path('scripts/release.py'), Path('.github/workflows/source-release.yml')]
        for path in sorted(p for p in paths if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'):
            fingerprint.update(str(path).encode() + b'\0' + path.read_bytes() + b'\0')
        inputs = {'lock_sha256': sha(ROOT / 'sources.lock.json'), 'build_sha256': fingerprint.hexdigest(),
                  'database_sha256': manifest['scanner']['database_sha256'], 'scanner_version': SCANNER}
        manifest['refresh_inputs'] = inputs
        manifest['refresh_reason'] = 'forced_' + os.environ.get('GITHUB_EVENT_NAME', 'manual')
        if os.environ.get('GITHUB_EVENT_NAME') == 'schedule':
            pages = json.loads(run('gh', 'api', '--paginate', '--slurp', 'repos/rootloom/base-images/releases?per_page=100'))
            for item in (item for page in pages for item in page):
                if item['draft'] or item['prerelease'] or not re.fullmatch(r'source-source-minimal-[0-9]+-[0-9]+', item['tag_name']):
                    continue
                previous = json.loads(public_bytes('rootloom/base-images', item['tag_name'], 'manifest.json'))
                promotion = json.loads(public_bytes('rootloom/base-images', item['tag_name'], 'promotion.json')) if any(a['name'] == 'promotion.json' for a in item['assets']) else None
                # A completed blocked attempt can avoid repeated source builds, not establish publication.
                if previous['status'] == 'blocked' and any(r.get('quality') != 'passed' or r.get('reproducibility') != 'passed' or r.get('scan_status') not in ('complete', 'partial') for r in previous['platforms'].values()):
                    continue
                reason = refresh_reason(inputs, previous, promotion)
                if reason is None and previous['status'] == 'blocked':
                    for arch, record in previous['platforms'].items():
                        name = arch + '.cve.json'
                        raw = public_bytes('rootloom/base-images', item['tag_name'], name)
                        if hashlib.sha256(raw).hexdigest() != previous['assets'][name]['sha256']:
                            raise ValueError('Blocked source report checksum mismatch')
                        saved = json.loads(raw)
                        if saved['database_sha256'] != inputs['database_sha256']:
                            raise ValueError('Blocked source database mismatch')
                        try:
                            blocked = source_policy(saved, lock, IMAGE + '@' + record['digest'])
                        except ValueError as error:
                            if str(error) != 'Unsupported source component coverage' or not coverage_gaps(lock) or record['scan_status'] != 'partial':
                                raise
                        else:
                            if not blocked:
                                raise ValueError('Blocked source evidence has no policy blocker')
                if previous['status'] == 'passed':
                    live, _ = inspect(IMAGE + ':latest')
                    reason = reason if live == previous['index_digest'] else 'latest_digest_changed'
                manifest['refresh_reason'] = reason
                break
            if manifest['refresh_reason'] is None:
                manifest['status'] = 'skipped'
        if manifest['status'] != 'skipped':
            manifest['status'] = 'ready'
    except Exception as error:
        manifest['error'] = str(error)
    write_json(OUT / 'attempt.json', manifest)
    if os.environ.get('GITHUB_OUTPUT'):
        with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
            output.write('build=' + str(manifest['status'] == 'ready').lower() + '\n')
            output.write('skip=' + str(manifest['status'] == 'skipped').lower() + '\n')
    if manifest['status'] == 'blocked':
        raise RuntimeError(manifest['error'])


def sbom(lock, ref):
    return {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
            'metadata': {'component': {'type': 'container', 'name': IMAGE, 'version': ref.rsplit('@', 1)[1], 'bom-ref': ref}},
            'components': [{'type': 'data' if s.get('kind') == 'trust-data' else 'library', 'name': s['name'], 'version': s['version'],
                            'bom-ref': s['purl'], 'purl': s['purl'], **({'cpe': s['cpe']} if s.get('cpe') else {}),
                            'hashes': [{'alg': 'SHA-256', 'content': s['sha256']}], 'licenses': [{'license': {'id': s['license']}}],
                            'externalReferences': [{'type': 'distribution', 'url': s['url']}]} for s in lock['sources']]}


def handoff_tag():
    run_id, attempt = os.environ['GITHUB_RUN_ID'], os.environ['GITHUB_RUN_ATTEMPT']
    if not run_id.isdecimal() or not attempt.isdecimal():
        raise ValueError('Invalid source handoff run identity')
    return 'source-source-minimal-' + run_id + '-' + attempt


def handoff(restore=False, arch=None):
    """Use draft Release assets, not metered Actions artifacts, for job transfer."""
    tag = handoff_tag()
    repo = 'rootloom/base-images'
    name = arch or 'state'
    descriptor = name + '.handoff.json'
    if restore or arch is not None:
        release = json.loads(run('gh', 'release', 'view', tag, '--repo', repo, '--json', 'isDraft,targetCommitish,tagName'))
        if release != {'isDraft': True, 'targetCommitish': os.environ['GITHUB_SHA'], 'tagName': tag}:
            raise ValueError('Source handoff Release identity mismatch')
    if not restore:
        attempt = json.loads((OUT / 'attempt.json').read_text()) if arch is None else None
        if attempt and attempt['status'] == 'skipped':
            return
        if arch is None:
            paths = [OUT / n for n in ('attempt.json', 'sources.lock.json', 'coverage-controls.json') if (OUT / n).is_file()]
            if (OUT / '.grype').exists():
                snapshot = OUT / 'scanner-state.tar.gz'
                with tarfile.open(snapshot, 'w:gz') as bundle:
                    bundle.add(OUT / '.grype', arcname='.grype')
                    bundle.add(OUT / '.grype.yaml', arcname='.grype.yaml')
                paths.append(snapshot)
                attempt['scanner']['handoff_snapshot_bytes'] = snapshot.stat().st_size
                write_json(OUT / 'attempt.json', attempt)
        else:
            paths = sorted(OUT.glob(arch + '.*'))
            paths = [p for p in paths if p.is_file() and not p.name.endswith('.handoff.json')]
        if not paths:
            raise ValueError('Missing source handoff evidence')
        write_json(OUT / descriptor, {'schema_version': 1, 'tag': tag, 'source_commit': os.environ['GITHUB_SHA'],
                                    'actions_artifact_bytes': 0, 'size_bytes': sum(p.stat().st_size for p in paths),
                                    'assets': {p.name: sha(p) for p in paths}})
        print((OUT / descriptor).read_text())
        if arch is None:
            run('gh', 'release', 'create', tag, '--repo', repo, '--target', os.environ['GITHUB_SHA'],
                '--draft', '--title', tag, '--notes', 'Incomplete source qualification. No promotion.',
                *[str(p) for p in [*paths, OUT / descriptor]])
        else:
            run('gh', 'release', 'upload', tag, '--repo', repo, *[str(p) for p in [*paths, OUT / descriptor]])
        return
    with tempfile.TemporaryDirectory() as tmp:
        downloaded = Path(tmp)
        run('gh', 'release', 'download', tag, '--repo', repo, '--pattern', descriptor, '--dir', tmp)
        record = json.loads((downloaded / descriptor).read_text())
        if record.get('schema_version') != 1 or record.get('tag') != tag or record.get('source_commit') != os.environ['GITHUB_SHA'] or not record.get('assets'):
            raise ValueError('Source handoff snapshot identity mismatch')
        if arch is not None and arch + '.qualification.json' not in record['assets']:
            raise ValueError('Missing native source qualification evidence')
        for filename, value in record['assets'].items():
            allowed = filename in ('attempt.json', 'sources.lock.json', 'coverage-controls.json', 'scanner-state.tar.gz') if arch is None else filename.startswith(arch + '.') and filename.endswith(('.json', '.sources.tar.gz'))
            if not allowed or Path(filename).name != filename:
                raise ValueError('Unsafe source handoff asset')
            checksum(value)
            run('gh', 'release', 'download', tag, '--repo', repo, '--pattern', filename, '--dir', tmp)
            if sha(downloaded / filename) != value:
                raise ValueError('Source handoff asset checksum mismatch')
        if arch is None:
            attempt = json.loads((downloaded / 'attempt.json').read_text())
            expected_version = 'source-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
            if attempt['source_commit'] != os.environ['GITHUB_SHA'] or attempt['version_tag'] != expected_version:
                raise ValueError('Source handoff attempt identity mismatch')
            snapshot = downloaded / 'scanner-state.tar.gz'
            if snapshot.exists():
                with tarfile.open(snapshot) as bundle:
                    for item in bundle:
                        if item.name != '.grype.yaml' and not item.name.startswith('.grype/') and item.name != '.grype':
                            raise ValueError('Unsafe scanner snapshot path')
                        if '..' in Path(item.name).parts or not (item.isfile() or item.isdir()):
                            raise ValueError('Unsafe scanner snapshot member')
                        target = downloaded / item.name
                        if item.isdir():
                            target.mkdir(parents=True, exist_ok=True)
                        else:
                            target.parent.mkdir(parents=True, exist_ok=True)
                            with bundle.extractfile(item) as stream, target.open('wb') as output:
                                shutil.copyfileobj(stream, output)
                databases = list((downloaded / '.grype').rglob('vulnerability.db'))
                if len(databases) != 1 or sha(databases[0]) != attempt['scanner']['database_sha256']:
                    raise ValueError('Source handoff database checksum mismatch')
            elif attempt['status'] == 'ready':
                raise ValueError('Missing source handoff database')
        OUT.mkdir(exist_ok=True)
        for path in downloaded.iterdir():
            if path.is_dir():
                shutil.copytree(path, OUT / path.name, dirs_exist_ok=True)
            elif path.name != descriptor:
                shutil.copyfile(path, OUT / path.name)


def build(arch, publish=True):
    native = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}[platform.machine()]
    if native != arch:
        raise ValueError('Native architecture required; no host emulation')
    OUT.mkdir(exist_ok=True)
    lock = lockfile()
    attempt = json.loads((OUT / 'attempt.json').read_text()) if publish else new_manifest()
    record = attempt['platforms'][arch]
    record.update(architecture=arch, quality='failed', reproducibility='failed', started_at=now())
    try:
        with tempfile.TemporaryDirectory() as tmp:
            exports = []
            for number in (1, 2):
                export = Path(tmp) / str(number)
                run('docker', 'buildx', 'build', '--pull', '--no-cache-filter=compile', '--platform', 'linux/' + arch,
                    '-f', str(ROOT / 'Dockerfile'), '--target', 'evidence', '--build-arg', 'BUILD_NONCE=' + str(number),
                    '--output', 'type=local,dest=' + str(export), '.')
                exports.append(export)
            first, second = exports
            if sha(first / 'rootfs.tar') != sha(second / 'rootfs.tar'):
                raise ValueError('Repeat rootfs checksum differs')
            record.update(reproducibility='passed', rootfs_sha256=sha(second / 'rootfs.tar'), repeat_rootfs_sha256=sha(first / 'rootfs.tar'))
            if (second / 'sources.lock.json').read_bytes() != (ROOT / 'sources.lock.json').read_bytes():
                raise ValueError('Build source lock mismatch')
            evidence = json.loads((second / 'build-evidence.json').read_text())
            if evidence.get('compile_network') != 'none' or evidence.get('architecture') != arch or evidence.get('lock_sha256') != sha(ROOT / 'sources.lock.json') or evidence.get('builder') != lock['builder']:
                raise ValueError('Missing network-isolated compile evidence')
            write_json(OUT / (arch + '.build.json'), evidence)
            sources = second / 'sources'
            for source in [*lock['sources'], *lock.get('patches', []), *lock.get('verification_inputs', [])]:
                if sha(sources / source['filename']) != source['sha256']:
                    raise ValueError('Corresponding source archive mismatch')
            if not (sources / 'busybox.effective.config').is_file():
                raise ValueError('Missing effective BusyBox configuration')
            with tarfile.open(OUT / (arch + '.sources.tar.gz'), 'w:gz') as bundle:
                bundle.add(sources, arcname='sources')
            record['corresponding_source_sha256'] = sha(OUT / (arch + '.sources.tar.gz'))
            tag = IMAGE + ':candidate-' + attempt['version_tag'] + '-' + arch if publish else 'rootloom-source-test:' + arch
            run('docker', 'buildx', 'build', '--platform', 'linux/' + arch, '-f', str(ROOT / 'Dockerfile'),
                '--target', 'runtime', '--build-arg', 'BUILD_NONCE=2', '--provenance=mode=max',
                '--push' if publish else '--load', '-t', tag, '.')
            if publish:
                candidate_digest, index = inspect(tag)
                record['candidate_index_digest'] = candidate_digest
                write_json(OUT / (arch + '.index.json'), index)
                matches = [m['digest'] for m in index['manifests'] if m.get('platform') == {'architecture': arch, 'os': 'linux'}]
                if len(matches) != 1:
                    raise ValueError('Missing exact native platform digest')
                record['digest'] = digest(matches[0])
                ref = IMAGE + '@' + record['digest']
                run('docker', 'pull', '--platform', 'linux/' + arch, ref)
            else:
                ref = tag
            container = run('docker', 'create', ref)
            try:
                exported = Path(tmp) / 'runtime.tar'
                with exported.open('wb') as output:
                    subprocess.run(['docker', 'export', container], stdout=output, check=True)
                expected = rootfs_inventory(second / 'rootfs.tar')
                actual = rootfs_inventory(exported, docker_export=True, expected=expected)
                with tarfile.open(exported) as archive:
                    embedded = archive.extractfile('usr/share/rootloom/rootfs.sha256').read().decode().split()[0]
                if embedded != record['rootfs_sha256']:
                    raise ValueError('Embedded runtime rootfs checksum mismatch')
                actual.pop('usr/share/rootloom/rootfs.sha256', None)
                # Docker supplies these three files at container creation.
                for name in ('etc/hosts', 'etc/hostname', 'etc/resolv.conf'):
                    expected.pop(name, None)
                if expected != actual:
                    raise ValueError('Exact-digest runtime differs from repeat rootfs')
            finally:
                run('docker', 'rm', container)
            run('docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--tmpfs', '/app:uid=65532,gid=65532',
                '--tmpfs', '/home/rootloom:uid=65532,gid=65532', '--tmpfs', '/tmp:mode=1777',
                ref, '/bin/sh', '-c', (ROOT / 'smoke.sh').read_text())
            record.update(quality='passed', size_bytes=int(run('docker', 'image', 'inspect', '--format', '{{.Size}}', ref)))
            evidence.update(subject=ref, source_commit=attempt['source_commit'], source_repository=attempt['source_repository'],
                            rootfs_sha256=record['rootfs_sha256'], repeat_rootfs_sha256=record['repeat_rootfs_sha256'],
                            reproducibility='passed', quality='passed')
            write_json(OUT / (arch + '.build.json'), evidence)
            if publish:
                dbfiles = list((OUT / '.grype').rglob('vulnerability.db'))
                if len(dbfiles) != 1 or sha(dbfiles[0]) != attempt['scanner']['database_sha256']:
                    raise ValueError('Native scanner database differs from preflight')
                report = {'schema_version': 1, 'subject': ref, 'database_sha256': attempt['scanner']['database_sha256'],
                          'controls': json.loads((OUT / 'coverage-controls.json').read_text()),
                          'unscanned_components': coverage_gaps(lock),
                          'components': [dict(name=name, version=s['version'], cpe=s['cpe'], report=scan(s['cpe'])) for name, s in components(lock, require_coverage=False).items()]}
                write_json(OUT / (arch + '.cve.json'), report)
                write_json(OUT / (arch + '.cdx.json'), sbom(lock, ref))
                record['scan_status'] = 'partial' if coverage_gaps(lock) else 'failed'
                blocked = source_policy(report, lock, ref)
                findings = [f['vulnerability'] for s in report['components'] for f in s['report']['matches']]
                counts = {s: sum(v['severity'].upper() == s for v in findings) for s in ('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')}
                counts['LOW'] += sum(v['severity'].upper() == 'NEGLIGIBLE' for v in findings)
                record.update(scan_status='complete', policy='blocked' if blocked else 'passed', blocked_cves=blocked,
                              severity_counts=counts, vulnerability_count=len(findings), package_count=len(lock['sources']))
    except Exception as error:
        record['error'] = str(error)
    record['finished_at'] = now()
    write_json(OUT / (arch + '.qualification.json'), record)
    print(json.dumps(record, sort_keys=True))
    if record['quality'] != 'passed' or (publish and record['policy'] != 'passed'):
        raise RuntimeError(record.get('error', 'Source vulnerability policy blocks promotion'))


def anonymous(manifest):
    if manifest['image'] != IMAGE:
        raise ValueError('Unexpected source registry')
    repository = 'rootloom/source-minimal'
    with urlopen('https://ghcr.io/token?service=ghcr.io&scope=repository:' + repository + ':pull', timeout=60) as response:
        token = json.loads(response.read())['token']
    for value in [manifest['index_digest'], *[r['digest'] for r in manifest['platforms'].values()]]:
        request = Request('https://ghcr.io/v2/' + repository + '/manifests/' + digest(value), headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json'})
        with urlopen(request, timeout=60) as response:
            if 'sha256:' + hashlib.sha256(response.read()).hexdigest() != value:
                raise ValueError('Anonymous source digest mismatch')


def publish():
    OUT.mkdir(exist_ok=True)
    manifest = json.loads((OUT / 'attempt.json').read_text()) if (OUT / 'attempt.json').is_file() else new_manifest()
    repo = manifest['source_repository']
    tag = 'source-source-minimal-' + manifest['version_tag'].removeprefix('source-')
    try:
        lock = lockfile()
        if manifest['status'] != 'ready':
            raise ValueError('Source preflight did not pass')
        if json.loads((OUT / 'sources.lock.json').read_text()) != lock:
            raise ValueError('Public source lock inventory mismatch')
        for arch in ARCHES:
            path = OUT / (arch + '.qualification.json')
            if path.is_file():
                manifest['platforms'][arch] = json.loads(path.read_text())
        for arch, record in manifest['platforms'].items():
            if record['architecture'] != arch or any(record[k] != v for k, v in (('quality', 'passed'), ('reproducibility', 'passed'), ('scan_status', 'complete'), ('policy', 'passed'))):
                raise ValueError('Missing source qualification gate: ' + arch)
            if checksum(record['rootfs_sha256']) != checksum(record['repeat_rootfs_sha256']):
                raise ValueError('Missing actual repeat checksum')
            report = json.loads((OUT / (arch + '.cve.json')).read_text())
            if report['database_sha256'] != manifest['scanner']['database_sha256'] or source_policy(report, lock, IMAGE + '@' + digest(record['digest'])):
                raise ValueError('Source scan policy failed')
            for component in report['components']:
                status = component['report']['descriptor']['db']['status']
                if any(status[k] != manifest['scanner']['database'][k] for k in ('built', 'from', 'schemaVersion')):
                    raise ValueError('Report database metadata does not match preflight')
            archive = OUT / (arch + '.sources.tar.gz')
            if not archive.is_file() or archive.stat().st_size == 0 or sha(archive) != record['corresponding_source_sha256']:
                raise ValueError('Corresponding source publication gate failed')
            ref = IMAGE + '@' + record['digest']
            if json.loads((OUT / (arch + '.cdx.json')).read_text()) != sbom(lock, ref):
                raise ValueError('Source SBOM inventory mismatch')
            provenance = json.loads((OUT / (arch + '.build.json')).read_text())
            if provenance['subject'] != ref or provenance['lock_sha256'] != manifest['refresh_inputs']['lock_sha256'] or provenance['rootfs_sha256'] != record['rootfs_sha256']:
                raise ValueError('Source provenance identity mismatch')
        run('docker', 'buildx', 'imagetools', 'create', '-t', IMAGE + ':candidate-' + manifest['version_tag'],
            *[IMAGE + '@' + digest(r['candidate_index_digest']) for r in manifest['platforms'].values()])
        index_digest, index = inspect(IMAGE + ':candidate-' + manifest['version_tag'])
        if platforms(index) != {a: r['digest'] for a, r in manifest['platforms'].items()}:
            raise ValueError('Index differs from qualified platforms')
        manifest.update(index_digest=index_digest, status='passed')
        write_json(OUT / 'index.json', index)
    except Exception as error:
        manifest.update(status='blocked', error=str(error))
    manifest['finished_at'] = now()
    assets = [p for p in OUT.iterdir() if p.is_file() and not p.name.startswith('.') and not p.name.endswith('.handoff.json') and p.name not in ('scanner-state.tar.gz', 'attempt.json', 'manifest.json', 'SHA256SUMS', 'promotion.json')]
    oversized = [p for p in assets if p.stat().st_size >= 2 * 1024 ** 3]
    if oversized:
        manifest.update(status='blocked', error='Release assets exceed GitHub size limit', unpublished_assets=[p.name for p in oversized])
        assets = [p for p in assets if p not in oversized]
    manifest['assets'] = {p.name: {'sha256': sha(p), 'size_bytes': p.stat().st_size, 'url': f'https://github.com/{repo}/releases/download/{tag}/{p.name}'} for p in assets}
    write_json(OUT / 'manifest.json', manifest)
    assets.append(OUT / 'manifest.json')
    (OUT / 'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(assets)))
    assets.append(OUT / 'SHA256SUMS')
    notes = 'Source runtime evidence. Status: ' + manifest['status'] + '. ' + COVERAGE
    if os.environ.get('SOURCE_HANDOFF') == 'release':
        if tag != handoff_tag():
            raise ValueError('Source publication handoff identity mismatch')
        identity = json.loads(run('gh', 'release', 'view', tag, '--repo', repo, '--json', 'isDraft,targetCommitish,tagName'))
        if identity != {'isDraft': True, 'targetCommitish': os.environ['GITHUB_SHA'], 'tagName': tag}:
            raise ValueError('Source publication draft identity mismatch')
        run('gh', 'release', 'upload', tag, '--repo', repo, '--clobber', *[str(p) for p in assets])
        remote = json.loads(run('gh', 'release', 'view', tag, '--repo', repo, '--json', 'assets'))
        for asset in remote['assets']:
            if asset['name'] not in {p.name for p in assets}:
                run('gh', 'release', 'delete-asset', tag, asset['name'], '--repo', repo, '--yes')
        run('gh', 'release', 'edit', tag, '--repo', repo, '--draft=false', '--latest=false', '--notes', notes)
    else:
        run('gh', 'release', 'create', tag, '--repo', repo, '--target', manifest['source_commit'], '--title', tag,
            '--notes', notes, '--latest=false', *[str(p) for p in assets])
    for path in assets:
        verify_public(repo, tag, path)
    if manifest['status'] != 'passed':
        raise RuntimeError('Blocked source evidence published; no promotion')
    try:
        promote_source(manifest, repo, tag)
    except Exception as error:
        failure = OUT / 'promotion-attempt.json'
        write_json(failure, {'schema_version': 1, 'status': 'blocked', 'image': IMAGE, 'index_digest': manifest['index_digest'],
                             'failed_at': now(), 'error': str(error), 'manifest_sha256': sha(OUT / 'manifest.json')})
        run('gh', 'release', 'upload', tag, str(failure), '--repo', repo)
        verify_public(repo, tag, failure)
        raise


def promote_source(manifest, repo, tag):
    anonymous(manifest)
    with tempfile.TemporaryDirectory() as config:
        for arch, record in manifest['platforms'].items():
            run('docker', 'pull', '--platform', 'linux/' + arch, IMAGE + '@' + record['digest'], env=dict(os.environ, DOCKER_CONFIG=config))
    for arch, record in manifest['platforms'].items():
        ref = IMAGE + '@' + record['digest']
        run('cosign', 'sign', '--yes', ref)
        run('cosign', 'attest', '--yes', '--type', 'cyclonedx', '--predicate', str(OUT / (arch + '.cdx.json')), ref)
        run('cosign', 'attest', '--yes', '--type', 'https://rootloom.org/source-build/v1', '--predicate', str(OUT / (arch + '.build.json')), ref)
    ref = IMAGE + '@' + manifest['index_digest']
    run('cosign', 'sign', '--yes', ref)
    identity = 'https://github.com/rootloom/base-images/.github/workflows/source-release.yml@refs/heads/main'
    options = ('--certificate-identity', identity, '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
               '--certificate-github-workflow-sha', manifest['source_commit'])
    verification = {}
    with tempfile.TemporaryDirectory() as config:
        env = dict(os.environ, DOCKER_CONFIG=config)
        subjects = [(None, manifest['index_digest']), *[(arch, record['digest']) for arch, record in manifest['platforms'].items()]]
        for arch, value in subjects:
            subject = IMAGE + '@' + value
            signatures = json.loads(run('cosign', 'verify', '--output', 'json', *options, subject, env=env))
            if not isinstance(signatures, list) or not signatures or any(s['critical']['image']['docker-manifest-digest'] != value for s in signatures):
                raise ValueError('Anonymous signature digest verification failed')
            verification[value] = {'signature': 'verified', 'identity': identity, 'issuer': 'https://token.actions.githubusercontent.com', 'predicates': {}}
            if arch is None:
                continue
            for kind, suffix in (('cyclonedx', '.cdx.json'), ('https://rootloom.org/source-build/v1', '.build.json')):
                path = OUT / (arch + suffix)
                expected = json.loads(path.read_text())
                output = run('cosign', 'verify-attestation', '--type', kind, *options, subject, env=env)
                statements = [json.loads(base64.b64decode(json.loads(line)['payload'], validate=True)) for line in output.splitlines() if line.strip()]
                if not statements or not any(s.get('subject') == [{'name': IMAGE, 'digest': {'sha256': value.removeprefix('sha256:')}}] and s.get('predicate') == expected for s in statements):
                    raise ValueError('Anonymous attestation subject or predicate mismatch')
                verification[value]['predicates'][kind] = {'status': 'verified', 'sha256': sha(path)}
    run('docker', 'buildx', 'imagetools', 'create', '-t', IMAGE + ':' + manifest['version_tag'],
        '-t', IMAGE + ':' + manifest['supported_version_tag'], '-t', IMAGE + ':latest', ref)
    for stable in (manifest['version_tag'], manifest['supported_version_tag'], 'latest'):
        if inspect(IMAGE + ':' + stable)[0] != manifest['index_digest']:
            raise ValueError('Promoted source tag digest mismatch')
    promotion = {key: manifest[key] for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag')}
    promotion.update(schema_version=1, status='promoted', promoted_at=now(), manifest_sha256=sha(OUT / 'manifest.json'), verification=verification)
    write_json(OUT / 'promotion.json', promotion)
    run('gh', 'release', 'upload', tag, str(OUT / 'promotion.json'), '--repo', repo)
    verify_public(repo, tag, OUT / 'promotion.json')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('install-scanner', 'check', 'build', 'pr', 'publish', 'stage', 'restore'))
    parser.add_argument('--arch', choices=ARCHES)
    args = parser.parse_args()
    if args.mode in ('check', 'build', 'publish', 'stage', 'restore') and (os.environ.get('GITHUB_REPOSITORY') != 'rootloom/base-images' or os.environ.get('GITHUB_REF') != 'refs/heads/main'):
        raise ValueError('Source release requires trusted repository main')
    if args.mode == 'install-scanner':
        install()
    elif args.mode == 'check':
        check()
    elif args.mode == 'publish':
        publish()
    elif args.mode in ('stage', 'restore'):
        handoff(restore=args.mode == 'restore', arch=args.arch)
    else:
        if not args.arch:
            parser.error('--arch is required')
        build(args.arch, publish=args.mode == 'build')
