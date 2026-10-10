import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
import io
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release', Path(__file__).parents[1] / 'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
DIGEST = 'sha256:' + 'a' * 64
REF = 'ghcr.io/rootloom/alpine@' + DIGEST


class ReleaseTests(unittest.TestCase):
    def evidence(self):
        inputs = {'build_sha256': 'a' * 64, 'upstream_reference': 'alpine:3.24',
                  'upstream_digest': DIGEST, 'scanner_version': '0.75.0',
                  'database_sha256': 'b' * 64, 'database_repository': 'scanner-db:2'}
        manifest = {'schema_version': 1, 'variant': 'standard', 'source_repository': 'rootloom/base-images',
                    'image': 'ghcr.io/rootloom/alpine', 'index_digest': DIGEST,
                    'version_tag': 'standard-1-1', 'supported_version_tag': '3.24',
                    'status': 'passed', 'started_at': '2026-10-10T00:00:00+00:00',
                    'refresh_inputs': inputs,
                    'platforms': {arch: {'digest': DIGEST, 'quality': 'passed',
                                         'scan_status': 'complete', 'policy': 'passed'} for arch in release.ARCHES}}
        promotion = {key: manifest[key] for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag')}
        promotion.update(schema_version=1, status='promoted', promoted_at='2026-10-10T00:10:00+00:00')
        return inputs, manifest, promotion

    def test_refresh_skip_and_daily_boundary(self):
        inputs, manifest, promotion = self.evidence()
        start = datetime.fromisoformat(manifest['started_at'])
        self.assertIsNone(release.refresh_reason(inputs, manifest, promotion, start + timedelta(hours=23, minutes=59)))
        self.assertEqual(release.refresh_reason(inputs, manifest, promotion, start + timedelta(hours=24)), 'daily_package_refresh')
        self.assertEqual(release.refresh_reason(inputs), 'no_known_promotion')

    def test_refresh_changed_inputs(self):
        inputs, manifest, promotion = self.evidence()
        for key in inputs:
            changed = dict(inputs, **{key: 'c' * 64 if key.endswith('_sha256') else 'changed'})
            self.assertEqual(release.refresh_reason(changed, manifest, promotion,
                                                   datetime(2026, 10, 10, 1, tzinfo=timezone.utc)), 'inputs_changed')

    def test_refresh_fail_closed(self):
        for mutate in (lambda m, p: m.update(status='failed'),
                       lambda m, p: p.update(status='failed'),
                       lambda m, p: p.update(schema_version=2),
                       lambda m, p: m.update(version_tag='latest'),
                       lambda m, p: p.update(index_digest='sha256:' + 'b' * 64),
                       lambda m, p: m.update(platforms={}),
                       lambda m, p: m['platforms']['amd64'].update(scan_status='not_run'),
                       lambda m, p: m.update(started_at='invalid'),
                       lambda m, p: p.update(promoted_at='2026-10-11T00:00:00Z'),
                       lambda m, p: m['refresh_inputs'].update(database_sha256='invalid'),
                       lambda m, p: m.update(refresh_inputs={})):
            inputs, manifest, promotion = self.evidence()
            inputs = dict(inputs)
            mutate(manifest, promotion)
            with self.assertRaises((ValueError, KeyError)):
                release.refresh_reason(inputs, manifest, promotion, datetime(2026, 10, 10, 1, tzinfo=timezone.utc))

    def test_promoted_lookup_absence_and_checksum(self):
        inputs, manifest, promotion = self.evidence()
        raw = release.json.dumps(manifest).encode()
        promotion['manifest_sha256'] = release.hashlib.sha256(raw).hexdigest()
        page = [[{'tag_name': 'standard-alpine-1-1', 'draft': False, 'prerelease': False,
                  'assets': [{'name': 'promotion.json'}]}]]
        with patch.object(release, 'run', return_value='[[]]'):
            self.assertIsNone(release.promoted_evidence('rootloom/base-images', 'alpine'))
        with patch.object(release, 'run', return_value=release.json.dumps(page)), \
             patch.object(release, 'public_bytes', side_effect=[release.json.dumps(promotion).encode(), raw]), \
             patch.object(release, 'refresh_reason', return_value=None):
            self.assertEqual(release.promoted_evidence('rootloom/base-images', 'alpine'), (manifest, promotion))
        promotion['manifest_sha256'] = '0' * 64
        with patch.object(release, 'run', return_value=release.json.dumps(page)), \
             patch.object(release, 'public_bytes', side_effect=[release.json.dumps(promotion).encode(), raw]):
            with self.assertRaisesRegex(ValueError, 'checksum'):
                release.promoted_evidence('rootloom/base-images', 'alpine')

    def test_promotion_record_only_after_all_gates(self):
        _, manifest, _ = self.evidence()
        for failure in ('anonymous', 'signature', 'tag', None):
            calls = []
            def command(*args, **kwargs):
                calls.append(args)
                if failure == 'signature' and args[0] == 'cosign':
                    raise RuntimeError('signature failed')
                return ''
            with tempfile.TemporaryDirectory() as directory:
                out = Path(directory)
                release.write_json(out / 'manifest.json', manifest)
                with patch.object(release, 'run', side_effect=command), \
                     patch.object(release, 'anonymous_registry_access', side_effect=RuntimeError('anonymous denied') if failure == 'anonymous' else None), \
                     patch.object(release, 'inspect', return_value=('sha256:' + ('b' if failure == 'tag' else 'a') * 64, {})) as inspected, \
                     patch.object(release, 'verify_public') as verified:
                    if failure:
                        with self.assertRaises((RuntimeError, ValueError)):
                            release.promote(manifest, out, 'rootloom/base-images', 'standard-alpine-1-1')
                        self.assertFalse((out / 'promotion.json').exists())
                        self.assertFalse(any(call[:3] == ('gh', 'release', 'upload') for call in calls))
                        if failure == 'anonymous':
                            self.assertEqual(calls, [])
                    else:
                        release.promote(manifest, out, 'rootloom/base-images', 'standard-alpine-1-1')
                        self.assertEqual(inspected.call_count, 3)
                        record = release.json.loads((out / 'promotion.json').read_text())
                        self.assertEqual(record['status'], 'promoted')
                        self.assertEqual(record['manifest_sha256'], release.sha(out / 'manifest.json'))
                        self.assertEqual(record['version_tag'], 'standard-1-1')
                        self.assertEqual(calls[-1][:3], ('gh', 'release', 'upload'))
                        self.assertNotIn('--clobber', calls[-1])
                        verified.assert_called_once()

    def test_scheduled_skip_and_forced_refresh(self):
        root = Path(__file__).resolve().parents[1]
        texts = {path: (root / path).read_text() for path in ('scripts/release.py', '.github/workflows/release.yml')}
        index = {'manifests': [{'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': arch}} for arch in release.ARCHES]}
        env = {'GITHUB_REPOSITORY': 'rootloom/base-images', 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_SHA': 'd' * 40, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '2',
               'GITHUB_ACTOR': 'test', 'GH_TOKEN': 'test'}
        for event in ('schedule', 'push', 'workflow_dispatch'):
            calls = []
            def command(*args, **kwargs):
                calls.append(args)
                if '--download-db-only' in args:
                    db = Path('evidence/.trivy/db')
                    db.mkdir(parents=True)
                    release.write_json(db / 'metadata.json', {'UpdatedAt': release.now()})
                    (db / 'trivy.db').write_bytes(b'database')
                elif args[:3] == ('docker', 'image', 'inspect'):
                    return '12345'
                elif args[0] == 'trivy' and '--output' in args:
                    output = Path(args[args.index('--output') + 1])
                    release.write_json(output, self.report() if '--list-all-pkgs' in args else
                                       {'spdxVersion': 'SPDX-2.3', 'packages': [{'name': 'musl'}]})
                return ''
            cwd = os.getcwd()
            with tempfile.TemporaryDirectory() as directory:
                try:
                    os.chdir(directory)
                    Path('images/alpine').mkdir(parents=True)
                    Path('images/alpine/Dockerfile').write_text('ARG BASE_IMAGE=alpine:3.24\nFROM ${BASE_IMAGE}\n')
                    for path, text in texts.items():
                        Path(path).parent.mkdir(parents=True, exist_ok=True)
                        Path(path).write_text(text)
                    fingerprint = release.hashlib.sha256()
                    for path in (Path('images/alpine/Dockerfile'), Path('scripts/release.py'), Path('.github/workflows/release.yml')):
                        fingerprint.update(str(path).encode() + b'\0' + path.read_bytes() + b'\0')
                    inputs, previous, promotion = self.evidence()
                    inputs.update(build_sha256=fingerprint.hexdigest(), database_sha256=release.hashlib.sha256(b'database').hexdigest(),
                                  database_repository='mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2')
                    previous.update(source_commit='c' * 40, started_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
                    promotion['promoted_at'] = release.now()
                    Path('README.md').write_text('Documentation changed after the prior promotion.\n')
                    with patch.dict(os.environ, dict(env, GITHUB_EVENT_NAME=event)), \
                         patch.object(release, 'run', side_effect=command), patch.object(release.subprocess, 'run'), \
                         patch.object(release, 'inspect', return_value=(DIGEST, index)), \
                         patch.object(release, 'promoted_evidence', return_value=(previous, promotion)) as lookup, \
                         patch.object(release, 'verify_public'), patch.object(release, 'anonymous_registry_access'):
                        release.main('release', 'alpine')
                    if event == 'schedule':
                        lookup.assert_called_once()
                        self.assertFalse(Path('evidence/manifest.json').exists())
                        self.assertFalse(any(call[:3] == ('gh', 'release', 'create') or
                                             call[:3] == ('docker', 'buildx', 'build') for call in calls))
                    else:
                        lookup.assert_not_called()
                        manifest = release.json.loads(Path('evidence/manifest.json').read_text())
                        self.assertEqual(manifest['refresh_inputs'], inputs)
                        self.assertEqual(manifest['refresh_reason'], 'forced_' + event)
                        self.assertEqual(manifest['version_tag'], 'standard-1-2')
                        self.assertEqual(manifest['status'], 'passed')
                        self.assertTrue(Path('evidence/promotion.json').exists())
                        for record in manifest['platforms'].values():
                            self.assertEqual(record['size_bytes'], 12345)
                            self.assertEqual(record['package_count'], 1)
                            self.assertEqual(record['severity_counts'], dict.fromkeys(('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), 0))
                finally:
                    os.chdir(cwd)

    def report(self):
        return {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                'Metadata': {'RepoDigests': [REF], 'OS': {'Family': 'alpine'}},
                'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Packages': [{'Name': 'musl'}], 'Vulnerabilities': []}]}

    def test_base(self):
        self.assertEqual(release.base_default('ARG BASE_IMAGE=alpine:3.22\nFROM ${BASE_IMAGE}\n'), 'alpine:3.22')
        with self.assertRaises(ValueError):
            release.base_default('FROM alpine:latest')

    def test_anonymous_registry_requires_exact_public_bytes(self):
        _, manifest, _ = self.evidence()
        data = b'{"schemaVersion": 2}'
        value = 'sha256:' + release.hashlib.sha256(data).hexdigest()
        manifest['index_digest'] = value
        for record in manifest['platforms'].values():
            record['digest'] = value
        with patch.object(release, 'urlopen', side_effect=[io.BytesIO(b'{"token":"anonymous"}'), io.BytesIO(data)]) as opened:
            release.anonymous_registry_access(manifest)
            self.assertNotIn('Authorization', opened.call_args_list[0].args[0])
            self.assertEqual(opened.call_args_list[1].args[0].get_header('Authorization'), 'Bearer anonymous')
        with patch.object(release, 'urlopen', side_effect=[io.BytesIO(b'{"token":"anonymous"}'), io.BytesIO(b'wrong')]):
            with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
                release.anonymous_registry_access(manifest)

    def test_platforms(self):
        index = {'manifests': [{'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': arch}} for arch in release.ARCHES]}
        self.assertEqual(set(release.platforms(index)), set(release.ARCHES))
        index['manifests'].pop()
        with self.assertRaises(ValueError):
            release.platforms(index)

    def test_complete_empty(self):
        self.assertEqual(release.policy(self.report(), REF), [])

    def test_fixable_policy(self):
        report = self.report()
        report['Results'][0]['Vulnerabilities'] = [
            {'VulnerabilityID': 'CVE-1', 'Severity': 'HIGH', 'FixedVersion': '2'},
            {'VulnerabilityID': 'CVE-2', 'Severity': 'CRITICAL'},
            {'VulnerabilityID': 'CVE-3', 'Severity': 'LOW', 'FixedVersion': '2'}]
        self.assertEqual(release.policy(report, REF), ['CVE-1'])

    def test_fail_closed(self):
        for mutate in (lambda r: r.update(Results=[]),
                       lambda r: r['Metadata'].update(RepoDigests=[]),
                       lambda r: r['Metadata']['OS'].update(EOSL=True),
                       lambda r: r['Metadata']['OS'].update(Family='unsupported'),
                       lambda r: r['Results'][0].update(Vulnerabilities={}),
                       lambda r: r['Results'][0].update(Type='ubuntu'),
                       lambda r: r['Results'][0].update(Type='unsupported'),
                       lambda r: r.update(SchemaVersion=1)):
            report = copy.deepcopy(self.report())
            mutate(report)
            with self.assertRaises(ValueError):
                release.policy(report, REF)

    def test_digest(self):
        self.assertEqual(release.digest(DIGEST), DIGEST)
        with self.assertRaises(ValueError):
            release.digest('latest')

    def test_inspect_registry_digest(self):
        index = {'manifests': []}
        summary = 'Name: alpine:3.24\nDigest: ' + DIGEST + '\n'
        with patch.object(release, 'run', side_effect=[summary, release.json.dumps(index)]) as command:
            self.assertEqual(release.inspect('alpine:3.24'), (DIGEST, index))
            self.assertEqual(command.call_args.args[-2:], ('alpine:3.24@' + DIGEST, '--raw'))
        with patch.object(release, 'run', return_value='Digest: <no value>'):
            with self.assertRaises(ValueError):
                release.inspect('alpine:3.24')

    def test_duplicate_platform(self):
        entry = {'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': 'amd64'}}
        with self.assertRaises(ValueError):
            release.platforms({'manifests': [entry, entry]})

    def test_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_bytes(b'abc')
            self.assertEqual(release.sha(path), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_scanner_failure_publishes_failed_evidence_without_promotion(self):
        self.failed_evidence(False)

    def test_upstream_failure_publishes_failed_evidence_without_promotion(self):
        self.failed_evidence(True)

    def failed_evidence(self, upstream_failure):
        index = {'manifests': [{'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': arch}} for arch in release.ARCHES]}
        calls = []

        def command(*args, **kwargs):
            calls.append(args)
            if args[:2] == ('trivy', 'image'):
                raise RuntimeError('scanner database unavailable')
            return ''

        env = {'GITHUB_REPOSITORY': 'rootloom/base-images', 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
               'GITHUB_ACTOR': 'test', 'GH_TOKEN': 'test'}
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                Path('images/alpine').mkdir(parents=True)
                Path('images/alpine/Dockerfile').write_text('ARG BASE_IMAGE=alpine:3.24\nFROM ${BASE_IMAGE}\n')
                with patch.dict(os.environ, env), patch.object(release, 'inspect', return_value=(DIGEST, index),
                     side_effect=RuntimeError('upstream unavailable') if upstream_failure else None), \
                     patch.object(release, 'run', side_effect=command), patch.object(release.subprocess, 'run'), \
                     patch.object(release, 'urlopen', side_effect=lambda url, **kw: io.BytesIO(Path('evidence', url.rsplit('/', 1)[-1]).read_bytes())):
                    with self.assertRaisesRegex(RuntimeError, 'promotion blocked'):
                        release.main('release', 'alpine')
                manifest = release.json.loads(Path('evidence/manifest.json').read_text())
                self.assertEqual(manifest['status'], 'failed')
                self.assertEqual(set(manifest['platforms']), set(release.ARCHES))
                for record in manifest['platforms'].values():
                    self.assertEqual(record['scan_status'], 'not_run')
                    self.assertNotIn('digest', record)
                self.assertIn('upstream unavailable' if upstream_failure else 'scanner database unavailable', manifest['error'])
                self.assertTrue(any(call[:3] == ('gh', 'release', 'create') for call in calls))
                self.assertFalse(any(call[0] == 'cosign' or call[:4] == ('docker', 'buildx', 'imagetools', 'create') for call in calls))
            finally:
                os.chdir(cwd)


if __name__ == '__main__':
    unittest.main()
