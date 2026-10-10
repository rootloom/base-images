import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
spec = importlib.util.spec_from_file_location('image_status', Path(__file__).parents[1] / 'scripts/status.py')
status = importlib.util.module_from_spec(spec)
spec.loader.exec_module(status)
DIGEST = 'sha256:' + 'a' * 64
REGISTRY = 'ghcr.io/rootloom/alpine'


class StatusTests(unittest.TestCase):
    def evidence(self):
        report = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
                  'Metadata': {'RepoDigests': [REGISTRY + '@' + DIGEST], 'OS': {'Family': 'alpine'}},
                  'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Packages': [{'Name': 'musl'}],
                               'Vulnerabilities': [{'VulnerabilityID': 'CVE-1', 'Severity': 'LOW'}]}]}
        data = json.dumps(report).encode()
        value = {'schema_version': 1, 'image': REGISTRY, 'index_digest': DIGEST,
                 'status': 'passed', 'source_repository': 'rootloom/base-images', 'source_commit': 'a' * 40,
                 'finished_at': status.datetime.now(status.timezone.utc).isoformat(),
                 'version_tag': 'standard-1-1', 'supported_version_tag': '3.24',
                 'upstream': {'reference': 'alpine:3.24', 'digest': DIGEST}, 'scanner': {'version': '0.75.0'},
                 'platforms': {arch: {'digest': DIGEST, 'scan_status': 'complete', 'quality': 'passed',
                                      'policy': 'passed', 'size_bytes': 1234} for arch in status.ARCHES},
                 'assets': {arch + '.cve.json': {'sha256': hashlib.sha256(data).hexdigest()}
                            for arch in status.ARCHES}}
        index = {'manifests': [{'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': arch}}
                               for arch in status.ARCHES]}
        entry = {'tag_name': 'standard-alpine-1-1'}
        return entry, value, data, index

    def collect(self, value, data, index, entry):
        with patch.object(status, 'IMAGES', ('alpine',)), patch.object(status, 'manifest', return_value=value), \
                patch.object(status, 'asset', return_value=data), \
                patch.object(status, 'inspect', return_value=(DIGEST, index)):
            return status.collect('rootloom/base-images', [entry])

    def test_counts_match_live_digest(self):
        entry, value, data, index = self.evidence()
        result = self.collect(value, data, index, entry)['images'][0]
        self.assertEqual(result['state'], 'registry-verified')
        self.assertEqual(result['platforms']['amd64']['severity_counts']['LOW'], 1)
        self.assertEqual(result['platforms']['arm64']['severity_counts']['CRITICAL'], 0)
        self.assertEqual(result['platforms']['amd64']['size_bytes'], 1234)
        self.assertFalse(result['promotion_confirmed'])

    def test_promotion_record_confirms_tags(self):
        entry, value, data, index = self.evidence()
        entry['assets'] = [{'name': 'promotion.json'}]
        raw = json.dumps(value).encode()
        promotion = {key: value[key] for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag')}
        promotion.update(status='promoted', manifest_sha256=hashlib.sha256(raw).hexdigest())

        def public(repo, tag, name):
            return json.dumps(promotion).encode() if name == 'promotion.json' else raw if name == 'manifest.json' else data

        with patch.object(status, 'IMAGES', ('alpine',)), patch.object(status, 'manifest', return_value=value), \
                patch.object(status, 'asset', side_effect=public), \
                patch.object(status, 'inspect', return_value=(DIGEST, index)):
            result = status.collect('rootloom/base-images', [entry])['images'][0]
            self.assertEqual(result['state'], 'promotion-confirmed')
            promotion['index_digest'] = 'sha256:' + 'b' * 64
            self.assertEqual(status.collect('rootloom/base-images', [entry])['images'][0]['state'], 'unverified')

    def test_legacy_evidence_does_not_advertise_version_tags(self):
        entry, value, data, index = self.evidence()
        snapshot = self.collect(value, data, index, entry)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text(status.START + '\n' + status.END)
            status.render(snapshot, root)
            text = (root / 'latest.md').read_text()
            self.assertNotIn('Confirmed version tags:', text)
            self.assertIn('local image size: 1234 bytes', text)

    def test_mismatch_or_incomplete_means_unknown(self):
        for field, bad in [('index_digest', 'sha256:' + 'b' * 64), ('status', 'blocked')]:
            entry, value, data, index = self.evidence()
            value[field] = bad
            result = self.collect(value, data, index, entry)['images'][0]
            self.assertEqual(result['state'], 'unverified')
            self.assertEqual(result['platforms'], {})
        entry, value, data, index = self.evidence()
        value['platforms']['arm64']['scan_status'] = 'failed'
        self.assertEqual(self.collect(value, data, index, entry)['images'][0]['platforms'], {})

    def test_checksum_failure_means_unknown(self):
        entry, value, data, index = self.evidence()
        result = self.collect(value, data + b' ', index, entry)['images'][0]
        self.assertEqual(result['platforms'], {})

    def test_missing_latest_retains_failed_attempt(self):
        entry, value, _, _ = self.evidence()
        value['status'] = 'failed'
        with patch.object(status, 'IMAGES', ('alpine',)), patch.object(status, 'manifest', return_value=value), \
                patch.object(status, 'inspect', side_effect=RuntimeError('not found')):
            result = status.collect('rootloom/base-images', [entry])['images'][0]
        self.assertEqual(result['last_attempt']['status'], 'failed')
        self.assertEqual(result['platforms'], {})

    def test_manifest_checksum(self):
        entry, value, _, _ = self.evidence()
        data = json.dumps(value).encode()
        checksums = (hashlib.sha256(data).hexdigest() + '  manifest.json\n').encode()
        with patch.object(status, 'asset', side_effect=[data, checksums]):
            self.assertEqual(status.manifest('rootloom/base-images', entry), value)
        with patch.object(status, 'asset', side_effect=[data, b'incorrect']):
            with self.assertRaises(ValueError):
                status.manifest('rootloom/base-images', entry)

    def test_render_is_stable_and_unknown_is_not_zero(self):
        record = {'image': 'alpine', 'state': 'unverified', 'platforms': {}}
        snapshot = {'schema_version': 1, 'images': [record]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('Before\n' + status.START + '\nold\n' + status.END + '\nAfter\n')
            status.render(snapshot, root)
            first = (root / 'README.md').read_text()
            status.render(snapshot, root)
            self.assertEqual((root / 'README.md').read_text(), first)
            self.assertIn('| ? | ? | ? | ? | ? |', first)
            self.assertTrue(first.startswith('Before\n'))
            self.assertTrue(first.endswith('\nAfter\n'))


if __name__ == '__main__':
    unittest.main()
