import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
import io
import os
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('release', Path(__file__).parents[1] / 'scripts/release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
DIGEST = 'sha256:' + 'a' * 64
REF = 'ghcr.io/rootloom/alpine@' + DIGEST


class ReleaseTests(unittest.TestCase):
    def report(self):
        return {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                'Metadata': {'RepoDigests': [REF], 'OS': {'Family': 'alpine'}},
                'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Packages': [{'Name': 'musl'}], 'Vulnerabilities': []}]}

    def test_base(self):
        self.assertEqual(release.base_default('ARG BASE_IMAGE=alpine:3.22\nFROM ${BASE_IMAGE}\n'), 'alpine:3.22')
        with self.assertRaises(ValueError):
            release.base_default('FROM alpine:latest')

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
                    if not upstream_failure:
                        self.assertEqual(record['digest'], DIGEST)
                self.assertIn('upstream unavailable' if upstream_failure else 'scanner database unavailable', manifest['error'])
                self.assertTrue(any(call[:3] == ('gh', 'release', 'create') for call in calls))
                self.assertFalse(any(call[0] == 'cosign' or call[:4] == ('docker', 'buildx', 'imagetools', 'create') for call in calls))
            finally:
                os.chdir(cwd)


if __name__ == '__main__':
    unittest.main()
