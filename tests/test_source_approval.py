"""Contract regressions with a mocked verifier, not real signed approval."""

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import source_approval as approval


class SourceApprovalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.blob = Path(self.directory.name) / 'approval.json'
        self.bundle = Path(self.directory.name) / 'bundle.json'
        self.bundle.write_bytes(b'mocked bundle, not a signature')
        self.now = datetime(2026, 10, 11, 12, tzinfo=timezone.utc)
        self.trust = {'identity': 'https://github.com/rootloom/base-images/.github/workflows/quality.yml@refs/heads/main',
                      'workflow_sha': 'b' * 40, 'run_id': '200', 'run_attempt': '1'}
        self.expected = {'repository': 'rootloom/base-images', 'source_commit': 'a' * 40,
                         'producer': {'identity': 'https://github.com/rootloom/base-images/.github/workflows/source-release.yml@refs/heads/main',
                                      'workflow_sha': 'a' * 40, 'run_id': '100', 'run_attempt': '2'},
                         'image': 'ghcr.io/rootloom/source-minimal', 'index_digest': 'sha256:' + 'c' * 64,
                         'platforms': {'amd64': 'sha256:' + 'd' * 64, 'arm64': 'sha256:' + 'e' * 64},
                         'evidence': {name: 'f' * 64 for name in approval.REQUIRED_EVIDENCE}, 'variant': 'standard'}
        for arch in ('amd64', 'arm64'):
            self.expected['evidence'].update({arch + suffix: 'f' * 64 for suffix in approval.PLATFORM_EVIDENCE})
        self.record = {'schema_version': 1, 'candidate': copy.deepcopy(self.expected),
                       'approver': copy.deepcopy(self.trust), 'issued_at': '2026-10-11T11:00:00Z',
                       'expires_at': '2026-10-11T13:00:00Z',
                       'results': {arch: {check: 'passed' for check in approval.REQUIRED_CHECKS} for arch in ('amd64', 'arm64')}}
        self.runner = Mock(return_value='')

    def validate(self):
        self.blob.write_text(json.dumps(self.record))
        return approval.validate_approval(self.blob, self.bundle, self.expected, self.trust,
                                          runner=self.runner, now=self.now)

    def test_valid_mocked_contract_and_exact_verifier_arguments(self):
        def verify(*args):
            self.assertEqual(args[:2], ('cosign', 'verify-blob'))
            self.assertIn('--new-bundle-format', args)
            self.assertEqual(Path(args[-1]).read_bytes(), self.blob.read_bytes())
            self.assertEqual(Path(args[args.index('--bundle') + 1]).read_bytes(), self.bundle.read_bytes())
            for option, value in (('--certificate-identity', self.trust['identity']),
                                  ('--certificate-oidc-issuer', approval.ISSUER),
                                  ('--certificate-github-workflow-sha', self.trust['workflow_sha'])):
                self.assertEqual(args[args.index(option) + 1], value)
            self.assertFalse(any('insecure' in arg or 'ignore' in arg for arg in args))
        self.runner.side_effect = verify
        self.assertEqual(self.validate(), self.record)
        self.runner.assert_called_once()

    def test_unsigned_bundle_rejected_without_verifier(self):
        self.bundle.write_bytes(b'')
        with self.assertRaises(ValueError):
            self.validate()
        self.runner.assert_not_called()

    def test_missing_bundle_rejected(self):
        self.bundle.unlink()
        with self.assertRaises(FileNotFoundError):
            self.validate()
        self.runner.assert_not_called()

    def test_tampered_or_untrusted_signature_failure_propagates(self):
        self.runner.side_effect = subprocess.CalledProcessError(1, 'cosign')
        with self.assertRaises(subprocess.CalledProcessError):
            self.validate()

    def test_candidate_binding_mismatches(self):
        mutations = [('repository', 'other/repo'), ('source_commit', '0' * 40),
                     ('image', 'ghcr.io/rootloom/other'), ('index_digest', 'sha256:' + '0' * 64),
                     ('variant', 'fips')]
        for field, value in mutations:
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                self.record['candidate'][field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.record = record

    def test_producer_sha_run_attempt_and_workflow_mismatches(self):
        for field, value in [('workflow_sha', '0' * 40), ('run_id', '101'), ('run_attempt', '3'), ('identity', self.trust['identity'])]:
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                self.record['candidate']['producer'][field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.record = record

    def test_approver_binding_mismatches(self):
        for field in self.trust:
            with self.subTest(field=field):
                record = copy.deepcopy(self.record)
                self.record['approver'][field] += '1'
                with self.assertRaises(ValueError):
                    self.validate()
                self.record = record

    def test_self_approval_workflow_or_run_rejected_before_verification(self):
        for field in ('identity', 'run_id'):
            with self.subTest(field=field):
                trust = copy.deepcopy(self.trust)
                self.trust[field] = self.expected['producer'][field]
                with self.assertRaises(ValueError):
                    self.validate()
                self.runner.assert_not_called()
                self.trust = trust

    def test_untrusted_identity_and_malformed_run_rejected(self):
        for field, value in [('identity', 'https://github.com/attacker/repo/.github/workflows/quality.yml@refs/heads/main'),
                             ('workflow_sha', 'main'), ('run_id', ''), ('run_attempt', 1)]:
            with self.subTest(field=field):
                trust = copy.deepcopy(self.trust)
                self.trust[field] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.runner.assert_not_called()
                self.trust = trust

    def test_expired_future_and_excessive_lifetime_rejected(self):
        for issued, expires in [('2026-10-11T10:00:00Z', '2026-10-11T12:00:00Z'),
                                ('2026-10-11T12:01:00Z', '2026-10-11T13:00:00Z'),
                                ('2026-10-10T11:00:00Z', '2026-10-12T13:00:00Z')]:
            with self.subTest(issued=issued, expires=expires):
                self.record.update(issued_at=issued, expires_at=expires)
                with self.assertRaises(ValueError):
                    self.validate()

    def test_missing_platform_or_wrong_digest_rejected(self):
        for mutate in (lambda platforms: platforms.pop('arm64'),
                       lambda platforms: platforms.update(arm64='sha256:' + '0' * 64)):
            record = copy.deepcopy(self.record)
            mutate(self.record['candidate']['platforms'])
            with self.assertRaises(ValueError):
                self.validate()
            self.record = record

    def test_missing_or_changed_evidence_rejected(self):
        for mutate in (lambda evidence: evidence.pop('arm64.cve.json'),
                       lambda evidence: evidence.update({'manifest.json': '0' * 64})):
            record = copy.deepcopy(self.record)
            mutate(self.record['candidate']['evidence'])
            with self.assertRaises(ValueError):
                self.validate()
            self.record = record

    def test_missing_failed_and_skipped_results_rejected(self):
        for value in ('failed', 'skipped', True, None):
            with self.subTest(value=value):
                self.record['results']['arm64']['security'] = value
                with self.assertRaises(ValueError):
                    self.validate()
        self.record['results']['arm64'].pop('security')
        with self.assertRaises(ValueError):
            self.validate()

    def test_missing_platform_results_rejected(self):
        self.record['results'].pop('arm64')
        with self.assertRaises(ValueError):
            self.validate()

    def test_fips_cannot_be_authorized_by_standard_approval(self):
        self.expected['variant'] = self.record['candidate']['variant'] = 'fips'
        with self.assertRaisesRegex(ValueError, 'FIPS'):
            self.validate()
        self.runner.assert_not_called()

    def test_duplicate_json_keys_rejected(self):
        self.blob.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            approval.validate_approval(self.blob, self.bundle, self.expected, self.trust,
                                       runner=self.runner, now=self.now)

    def test_mutation_during_verification_does_not_change_validated_bytes(self):
        self.runner.side_effect = lambda *args: self.blob.write_text('{}')
        self.assertEqual(self.validate(), self.record)

    def test_missing_expected_platform_evidence_rejected_before_verification(self):
        self.expected['evidence'].pop('amd64.build.json')
        with self.assertRaises(ValueError):
            self.validate()
        self.runner.assert_not_called()


if __name__ == '__main__':
    unittest.main()
