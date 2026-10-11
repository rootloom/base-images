import copy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('source_release', SCRIPTS / 'source_release.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
HASH = 'a' * 64
DIGEST = 'sha256:' + HASH
REF = source.IMAGE + '@' + DIGEST


def raw(cpe, cve=None, severity='Low'):
    return {'source': {'type': 'cpe', 'target': cpe}, 'descriptor': {'name': 'grype', 'version': source.SCANNER,
            'db': {'status': {'valid': True, 'schemaVersion': 'v6.1.10', 'built': '2026-10-10T00:00:00Z', 'from': 'https://grype.anchore.io/databases/test'},
                   'providers': {'nvd': {'captured': '2026-10-10T00:00:00Z', 'input': 'xxh64:test'}}}},
            'matches': [] if cve is None else [{'artifact': {'version': cpe.split(':')[5], 'cpes': [cpe]},
                                              'vulnerability': {'id': cve, 'severity': severity, 'fix': {'versions': [], 'state': 'unknown'}},
                                              'matchDetails': [{'matcher': 'stock-matcher', 'type': 'cpe-match'}]}]}


class SourceReleaseTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, SOURCE_HANDOFF='')
        environment.start()
        self.addCleanup(environment.stop)

    def test_draft_snapshot_restore_checks_identity_assets_and_database(self):
        env = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA=HASH)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env), patch.object(source, 'run') as run:
            staged, restored = Path(tmp) / 'staged', Path(tmp) / 'restored'
            database = staged / '.grype' / '6' / 'vulnerability.db'
            database.parent.mkdir(parents=True)
            database.write_bytes(b'scanner fixture')
            (staged / '.grype.yaml').write_text('ignore: []\n')
            manifest = source.new_manifest()
            manifest.update(status='ready', scanner={'database_sha256': source.sha(database)})
            source.write_json(staged / 'attempt.json', manifest)
            source.write_json(staged / 'sources.lock.json', {})
            source.write_json(staged / 'coverage-controls.json', {})
            with patch.object(source, 'OUT', staged):
                source.handoff()
            self.assertIn('--draft', run.call_args.args)
            self.assertIn('--verify-tag', run.call_args.args)
            commands = [call.args for call in run.call_args_list]
            self.assertEqual(commands[-2], ('git', '-c', 'credential.helper=', '-c',
                'credential.helper=!gh auth git-credential', 'push',
                'https://github.com/rootloom/base-images.git', HASH + ':refs/tags/' + source.handoff_tag()))
            self.assertEqual(commands[-1][:3], ('gh', 'release', 'create'))
            assets = {p.name: p.read_bytes() for p in staged.iterdir() if p.is_file()}
            def command(*args, **kwargs):
                if args[:3] == ('gh', 'release', 'view'):
                    return json.dumps({'isDraft': True, 'targetCommitish': HASH, 'tagName': source.handoff_tag()})
                if args[:3] == ('gh', 'release', 'download'):
                    name = args[args.index('--pattern') + 1]
                    (Path(args[args.index('--dir') + 1]) / name).write_bytes(assets[name])
                return ''
            run.side_effect = command
            with patch.object(source, 'OUT', restored):
                source.handoff(restore=True)
            self.assertEqual((restored / '.grype/6/vulnerability.db').read_bytes(), b'scanner fixture')
            for mutation, error in (('asset', 'asset checksum'), ('database', 'database checksum'), ('commit', 'snapshot identity')):
                broken = dict(assets)
                descriptor = json.loads(broken['state.handoff.json'])
                if mutation == 'asset':
                    broken['attempt.json'] += b' '
                elif mutation == 'database':
                    attempt = json.loads(broken['attempt.json'])
                    attempt['scanner']['database_sha256'] = 'b' * 64
                    broken['attempt.json'] = json.dumps(attempt).encode()
                    descriptor['assets']['attempt.json'] = hashlib.sha256(broken['attempt.json']).hexdigest()
                else:
                    descriptor['source_commit'] = 'b' * 64
                broken['state.handoff.json'] = json.dumps(descriptor).encode()
                original, assets = assets, broken
                destination = Path(tmp) / mutation
                with patch.object(source, 'OUT', destination), self.assertRaisesRegex(ValueError, error):
                    source.handoff(restore=True)
                self.assertFalse(destination.exists())
                assets = original

    def test_failed_source_tag_push_blocks_draft_creation(self):
        env = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA=HASH)
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env), patch.object(source, 'OUT', Path(tmp)):
            source.write_json(Path(tmp) / 'attempt.json', {'status': 'blocked'})
            with patch.object(source, 'run', side_effect=source.subprocess.CalledProcessError(1, 'git push')) as run:
                with self.assertRaises(source.subprocess.CalledProcessError):
                    source.handoff()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], 'git')
            self.assertNotIn('--force', run.call_args.args)

    def test_skipped_check_does_not_create_handoff(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp)), patch.dict(os.environ, {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}), patch.object(source, 'run') as run:
            source.write_json(Path(tmp) / 'attempt.json', {'status': 'skipped'})
            source.handoff()
            run.assert_not_called()

    def test_missing_native_publish_is_blocked_and_removes_private_snapshot(self):
        lock, _ = self.evidence()
        env = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA=HASH, SOURCE_HANDOFF='release')
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env), patch.object(source, 'OUT', Path(tmp)), patch.object(source, 'lockfile', return_value=lock), patch.object(source, 'run') as run, patch.object(source, 'verify_public'):
            attempt = source.new_manifest()
            attempt['status'] = 'ready'
            source.write_json(Path(tmp) / 'attempt.json', attempt)
            source.write_json(Path(tmp) / 'sources.lock.json', lock)
            (Path(tmp) / 'scanner-state.tar.gz').write_bytes(b'private snapshot')
            source.write_json(Path(tmp) / 'state.handoff.json', {})
            def command(*args, **kwargs):
                if args[:3] == ('gh', 'release', 'view'):
                    if args[-1] == 'assets':
                        return json.dumps({'assets': [{'name': name} for name in ('scanner-state.tar.gz', 'state.handoff.json', 'attempt.json')]})
                    return json.dumps({'isDraft': True, 'targetCommitish': HASH, 'tagName': source.handoff_tag()})
                return ''
            run.side_effect = command
            with self.assertRaisesRegex(RuntimeError, 'no promotion'):
                source.publish()
            manifest = json.loads((Path(tmp) / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'blocked')
            self.assertNotIn('scanner-state.tar.gz', manifest['assets'])
            calls = [c.args for c in run.call_args_list]
            finalization = next(i for i, c in enumerate(calls) if c[:3] == ('gh', 'release', 'edit'))
            deleted = {c[4] for c in calls[:finalization] if c[:3] == ('gh', 'release', 'delete-asset')}
            self.assertEqual(deleted, {'scanner-state.tar.gz', 'state.handoff.json', 'attempt.json'})
            self.assertFalse(any(c[0] in ('docker', 'cosign') for c in calls))

    def test_missing_native_handoff_and_wrong_release_fail_closed(self):
        env = dict(GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA=HASH)
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp) / 'out'), patch.dict(os.environ, env), patch.object(source, 'run') as run:
            def command(*args, **kwargs):
                if args[:3] == ('gh', 'release', 'view'):
                    return json.dumps({'isDraft': True, 'targetCommitish': HASH, 'tagName': source.handoff_tag()})
                source.write_json(Path(args[args.index('--dir') + 1]) / 'arm64.handoff.json',
                                  {'schema_version': 1, 'tag': source.handoff_tag(), 'source_commit': HASH,
                                   'assets': {'arm64.build.json': HASH}})
                return ''
            run.side_effect = command
            with self.assertRaisesRegex(ValueError, 'Missing native'):
                source.handoff(restore=True, arch='arm64')
            self.assertFalse(source.OUT.exists())
            run.side_effect = None
            run.return_value = json.dumps({'isDraft': False, 'targetCommitish': HASH, 'tagName': source.handoff_tag()})
            with self.assertRaisesRegex(ValueError, 'Release identity'):
                source.handoff(restore=True)

    def test_workflows_use_no_metered_artifacts_or_pr_write_permissions(self):
        root = Path(__file__).parents[1]
        for name in ('source-release.yml', 'source-pr.yml'):
            workflow = (root / '.github/workflows' / name).read_text()
            self.assertNotIn('actions/upload-artifact', workflow)
            self.assertNotIn('actions/download-artifact', workflow)
        self.assertNotIn(': write', (root / '.github/workflows/source-pr.yml').read_text())
        script = (SCRIPTS / 'source_release.py').read_text()
        self.assertIn("'--no-cache-filter=compile'", script)
        self.assertNotIn("'--no-cache'", script)
        self.assertIn('for number in (1, 2):', script)
        self.assertNotIn("bundle.add(ROOT, arcname='build-scripts')", script)

    def evidence(self):
        lock = json.loads((Path(__file__).parents[1] / 'images/source-minimal/sources.lock.json').read_text())
        # These policy fixtures cover the verified components, not future coverage additions.
        lock['sources'] = [s for s in lock['sources'] if s['name'] in (*source.CONTROLS, 'mozilla-ca-bundle')]
        report = {'schema_version': 1, 'subject': REF, 'database_sha256': HASH,
                  'controls': {n: raw(c, v) for n, (c, v) in source.CONTROLS.items()},
                  'components': [dict(name=n, version=s['version'], cpe=s['cpe'], report=raw(s['cpe'])) for n, s in source.components(lock).items()]}
        return lock, report

    def test_source_workflows_trigger_for_shared_release_helpers(self):
        root = Path(__file__).parents[1]
        for name in ('source-pr.yml', 'source-release.yml'):
            workflow = (root / '.github/workflows' / name).read_text()
            paths = workflow.split('    paths:\n', 1)[1].split('\npermissions:', 1)[0]
            self.assertIn('      - scripts/release.py\n', paths)

    def test_explicit_empty_findings_with_controls(self):
        lock, report = self.evidence()
        self.assertEqual(source.source_policy(report, lock, REF), [])

    def primary(self, lock):
        # Minimal fixture for the published CNA range, not complete advisory coverage.
        data = {'dataType': 'CVE_RECORD', 'cveMetadata': {'cveId': 'CVE-2026-40200', 'state': 'PUBLISHED'},
                'containers': {'cna': {'providerMetadata': {'shortName': 'mitre'},
                    'references': [{'url': 'https://www.openwall.com/lists/oss-security/2026/04/10/13'}],
                    'affected': [{'vendor': 'musl-libc', 'product': 'musl', 'defaultStatus': 'unknown',
                        'versions': [{'version': '0.7.10', 'lessThanOrEqual': '1.2.6', 'versionType': 'semver', 'status': 'affected'}]}],
                    'metrics': [{'cvssV3_1': {'baseSeverity': 'HIGH'}}]}}}
        payload = json.dumps(data).encode()
        snapshot = {'url': source.MUSL_ADVISORY, 'sha256': hashlib.sha256(payload).hexdigest(),
                    'bytes_base64': base64.b64encode(payload).decode()}
        musl = next(s for s in lock['sources'] if s['name'] == 'musl')
        return {'musl': {'version': musl['version'], 'source_sha256': musl['sha256'], 'snapshot': snapshot,
            'controls': {v: ['CVE-2026-40200'] for v in ('0.7.10', '1.2.6')}, 'blocked': ['CVE-2026-40200']}}

    def test_primary_musl_blocks_even_when_nvd_has_no_match(self):
        lock, report = self.evidence()
        report.update(schema_version=2, primary_advisories=self.primary(lock))
        self.assertEqual(source.source_policy(report, lock, REF), ['CVE-2026-40200'])
        # Lock patches never suppress primary or NVD findings.
        lock['patches'] = [{'component': 'musl', 'cve': 'CVE-2026-40200'}]
        self.assertEqual(source.source_policy(report, lock, REF), ['CVE-2026-40200'])

    def test_primary_unknown_versions_and_tampering_fail_closed(self):
        lock, _ = self.evidence()
        evidence = self.primary(lock)
        snapshot = evidence['musl']['snapshot']
        for version in ('0.7.9', '1.2.7', '1.2.6-patched', 'unknown'):
            with self.assertRaisesRegex(ValueError, 'Unknown primary musl'):
                source.musl_advisory_policy(snapshot, version)
        for mutate in (lambda e: e['musl'].update(version='1.2.5'),
                       lambda e: e['musl'].update(source_sha256='b' * 64),
                       lambda e: e['musl'].update(controls={}),
                       lambda e: e['musl'].update(blocked=[]),
                       lambda e: e['musl']['snapshot'].update(sha256='b' * 64),
                       lambda e: e['musl']['snapshot'].update(url='https://example.invalid')):
            broken = copy.deepcopy(evidence)
            mutate(broken)
            with self.assertRaises(ValueError):
                source.primary_policy(broken, lock)

    def test_changed_primary_range_and_missing_new_evidence_block(self):
        lock, report = self.evidence()
        report['schema_version'] = 2
        with self.assertRaises(KeyError):
            source.source_policy(report, lock, REF)
        primary = self.primary(lock)
        snapshot = primary['musl']['snapshot']
        data = source.advisory_data(snapshot, source.MUSL_ADVISORY)
        data['containers']['cna']['affected'][0]['versions'][0]['lessThanOrEqual'] = '1.2.5'
        payload = json.dumps(data).encode()
        snapshot.update(sha256=hashlib.sha256(payload).hexdigest(), bytes_base64=base64.b64encode(payload).decode())
        with self.assertRaisesRegex(ValueError, 'range changed'):
            source.primary_policy(primary, lock)

    def test_empty_llvm_feed_does_not_close_builtins_coverage(self):
        lock, report = self.evidence()
        actual = json.loads((Path(__file__).parents[1] / 'images/source-minimal/sources.lock.json').read_text())
        primary = self.primary(lock)
        primary['compiler-rt-builtins'] = {'coverage_status': 'unknown', 'snapshot': {
            'url': source.LLVM_ADVISORIES, 'sha256': hashlib.sha256(b'[]').hexdigest(),
            'bytes_base64': base64.b64encode(b'[]').decode()}}
        report.update(schema_version=2, primary_advisories=primary)
        with self.assertRaisesRegex(ValueError, 'Unsupported source component coverage'):
            source.source_policy(report, actual, REF)
        primary['compiler-rt-builtins']['coverage_status'] = 'complete'
        with self.assertRaisesRegex(ValueError, 'Unsupported compiler-rt'):
            source.primary_policy(primary, actual)

    def test_primary_fetch_failure_or_pagination_is_not_empty_coverage(self):
        with patch.object(source, 'urlopen', side_effect=OSError('network failed')):
            with self.assertRaises(OSError):
                source.advisory_snapshot(source.LLVM_ADVISORIES)
        with patch.object(source, 'urlopen') as opened:
            response = opened.return_value.__enter__.return_value
            response.read.return_value = b'[]'
            response.headers = {'Link': '<https://example.invalid>; rel="next"'}
            with self.assertRaisesRegex(ValueError, 'Incomplete'):
                source.advisory_snapshot(source.LLVM_ADVISORIES)

    def test_missing_fix_still_blocks_high_and_critical(self):
        lock, report = self.evidence()
        for severity in ('High', 'Critical'):
            item = report['components'][0]
            item['report'] = raw(item['cpe'], 'CVE-TEST', severity)
            self.assertEqual(source.source_policy(report, lock, REF), ['CVE-TEST'])

    def test_controls_fail_closed_for_each_component(self):
        lock, report = self.evidence()
        for name in source.CONTROLS:
            broken = copy.deepcopy(report)
            broken['controls'][name]['matches'] = []
            with self.assertRaisesRegex(ValueError, 'positive control'):
                source.source_policy(broken, lock, REF)

    def test_digest_inventory_and_database_fail_closed(self):
        lock, report = self.evidence()
        mutations = [lambda r: r.update(subject=source.IMAGE + '@sha256:' + 'b' * 64),
                     lambda r: r['components'].pop(),
                     lambda r: r['components'].append(copy.deepcopy(r['components'][0])),
                     lambda r: r['components'][0].update(version='0'),
                     lambda r: r['components'][0]['report']['source'].update(target='unsupported'),
                     lambda r: r['components'][0]['report']['descriptor']['db']['status'].update(built='other'),
                     lambda r: r['components'][0]['report']['descriptor'].update(db={}),
                     lambda r: r['components'][0]['report'].update(matches=None),
                     lambda r: r['components'][0]['report'].update(ignoredMatches=[{}]),
                     lambda r: r['components'][0]['report']['descriptor'].update(version='wrong')]
        for mutate in mutations:
            broken = copy.deepcopy(report)
            mutate(broken)
            with self.assertRaises(ValueError):
                source.source_policy(broken, lock, REF)

    def test_unsupported_extra_source_is_not_zero(self):
        lock, report = self.evidence()
        lock['sources'].append({'name': 'openssl', 'kind': 'runtime-source'})
        with self.assertRaisesRegex(ValueError, 'Unsupported source'):
            source.source_policy(report, lock, REF)
        self.assertEqual(source.coverage_gaps(lock), ['openssl'])
        self.assertEqual(set(source.components(lock, require_coverage=False)), set(source.CONTROLS))

    def test_real_compiler_runtime_inventory_blocks_unverified_coverage(self):
        lock, report = self.evidence()
        actual = json.loads((Path(__file__).parents[1] / 'images/source-minimal/sources.lock.json').read_text())
        self.assertIn('compiler-rt-builtins', source.coverage_gaps(actual))
        with self.assertRaisesRegex(ValueError, 'Unsupported source component coverage'):
            source.source_policy(report, actual, REF)

    def test_wrong_cpe_and_malformed_match(self):
        lock, report = self.evidence()
        item = report['components'][0]
        item['report'] = raw(item['cpe'], 'CVE-TEST')
        item['report']['matches'][0]['artifact']['cpes'] = []
        with self.assertRaisesRegex(ValueError, 'another source'):
            source.source_policy(report, lock, REF)
        item['report'] = raw(item['cpe'], 'CVE-TEST', 'invented')
        with self.assertRaisesRegex(ValueError, 'severity'):
            source.source_policy(report, lock, REF)

    def refresh(self):
        inputs = dict(lock_sha256=HASH, build_sha256=HASH, database_sha256=HASH, scanner_version=source.SCANNER)
        manifest = source.new_manifest()
        manifest.update(status='passed', index_digest=DIGEST, supported_version_tag='musl-1.2.6-busybox-1.36.1-r1',
                        started_at='2026-10-10T00:00:00+00:00', refresh_inputs=inputs)
        manifest['platforms'] = {a: dict(digest=DIGEST, quality='passed', policy='passed', scan_status='complete', reproducibility='passed') for a in source.ARCHES}
        promotion = {k: manifest[k] for k in ('image', 'index_digest', 'version_tag', 'supported_version_tag')}
        promotion.update(status='promoted', promoted_at='2026-10-10T00:10:00+00:00', manifest_sha256=hashlib.sha256((json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()).hexdigest())
        return inputs, manifest, promotion

    def test_refresh_daily_changed_inputs_and_absent_release(self):
        inputs, manifest, promotion = self.refresh()
        current = datetime(2026, 10, 10, 1, tzinfo=timezone.utc)
        self.assertIsNone(source.refresh_reason(inputs, manifest, promotion, current))
        self.assertEqual(source.refresh_reason(inputs, manifest, promotion, current + timedelta(days=1)), 'daily_rebuild')
        self.assertEqual(source.refresh_reason(dict(inputs, database_sha256='b' * 64), manifest, promotion, current), 'inputs_changed')
        self.assertEqual(source.refresh_reason(inputs), 'no_known_promotion')

    def test_refresh_requires_actual_promotion(self):
        inputs, manifest, promotion = self.refresh()
        with self.assertRaises(ValueError):
            source.refresh_reason(inputs, manifest, None)
        promotion['manifest_sha256'] = 'b' * 64
        with self.assertRaises(ValueError):
            source.refresh_reason(inputs, manifest, promotion)

    def test_completed_blocked_refresh_has_daily_bound(self):
        inputs, manifest, _ = self.refresh()
        manifest.update(status='blocked', finished_at='2026-10-10T00:10:00+00:00')
        for record in manifest['platforms'].values():
            record.update(scan_status='partial', policy='unknown')
        current = datetime(2026, 10, 10, 1, tzinfo=timezone.utc)
        self.assertIsNone(source.refresh_reason(inputs, manifest, None, current))
        self.assertEqual(source.refresh_reason(inputs, manifest, None, current + timedelta(days=1)), 'daily_rebuild')
        manifest['platforms']['amd64']['quality'] = 'failed'
        with self.assertRaises(ValueError):
            source.refresh_reason(inputs, manifest, None, current)

    def test_initial_platforms_are_unknown_not_zero(self):
        manifest = source.new_manifest()
        for record in manifest['platforms'].values():
            self.assertEqual(record['scan_status'], 'not_run')
            self.assertEqual(record['policy'], 'unknown')
            self.assertNotIn('severity_counts', record)

    def test_rootfs_contents_ownership_modes_and_links(self):
        def archive(path, mode=0o755, payload=b'hello', uid=65532):
            with tarfile.open(path, 'w') as out:
                member = tarfile.TarInfo('bin/runtime')
                member.mode, member.uid, member.size = mode, uid, len(payload)
                out.addfile(member, io.BytesIO(payload))
                link = tarfile.TarInfo('bin/sh')
                link.type, link.linkname = tarfile.SYMTYPE, 'runtime'
                out.addfile(link)
        with tempfile.TemporaryDirectory() as tmp:
            first, second = Path(tmp) / 'a.tar', Path(tmp) / 'b.tar'
            archive(first)
            archive(second)
            self.assertEqual(source.rootfs_inventory(first), source.rootfs_inventory(second))
            for kwargs in ({'mode': 0o4755}, {'payload': b'evil'}, {'uid': 0}):
                archive(second, **kwargs)
                self.assertNotEqual(source.rootfs_inventory(first), source.rootfs_inventory(second))

    def test_exact_docker_injected_entries_preserve_image_paths_and_mismatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / 'export.tar'
            with tarfile.open(archive, 'w') as bundle:
                for name in ('dev/console', 'dev/pts', 'dev/shm', 'etc/mtab', 'dev/unexpected'):
                    item = tarfile.TarInfo(name)
                    item.mode = 0o777 if name == 'etc/mtab' else 0o755
                    if name in ('dev/pts', 'dev/shm'):
                        item.type = tarfile.DIRTYPE
                    elif name == 'etc/mtab':
                        item.type, item.linkname = tarfile.SYMTYPE, '/proc/mounts'
                    bundle.addfile(item)
            original = source.rootfs_inventory(archive)
            normalized = source.rootfs_inventory(archive, docker_export=True, expected={})
            self.assertEqual(set(normalized), {'dev/unexpected'})
            normalized = source.rootfs_inventory(archive, docker_export=True, expected={'etc/mtab': original['etc/mtab']})
            self.assertEqual(set(normalized), {'dev/unexpected', 'etc/mtab'})
            with tarfile.open(archive, 'w') as bundle:
                item = tarfile.TarInfo('dev/console')
                item.mode, item.size = 0o755, 4
                bundle.addfile(item, io.BytesIO(b'evil'))
            self.assertIn('dev/console', source.rootfs_inventory(archive, docker_export=True, expected={}))

    def test_blocked_attempt_publishes_without_sign_or_latest(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp)), patch.object(source, 'lockfile', side_effect=ValueError('no lock')), patch.object(source, 'run') as run, patch.object(source, 'verify_public'):
            with self.assertRaisesRegex(RuntimeError, 'no promotion'):
                source.publish()
            manifest = json.loads((Path(tmp) / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'blocked')
            calls = [c.args for c in run.call_args_list]
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[0][0], 'git')
            self.assertIn('push', calls[0])
            self.assertEqual(calls[0][-1], manifest['source_commit'] + ':refs/tags/' + calls[1][3])
            self.assertEqual(calls[1][:3], ('gh', 'release', 'create'))
            self.assertIn('--verify-tag', calls[1])
            self.assertIn('--draft', calls[1])
            self.assertEqual(calls[2][:3], ('gh', 'release', 'edit'))
            self.assertIn('--draft=false', calls[2])
            self.assertFalse((Path(tmp) / 'promotion.json').exists())

    def test_failed_fallback_tag_push_blocks_release_creation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp)), \
                patch.object(source, 'lockfile', side_effect=ValueError('no lock')), \
                patch.object(source, 'run', side_effect=RuntimeError('tag push failed')) as run, \
                patch.object(source, 'verify_public') as verify, patch.object(source, 'promote_source') as promote:
            with self.assertRaisesRegex(RuntimeError, 'tag push failed'):
                source.publish()
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], 'git')
            self.assertIn('push', run.call_args.args)
            verify.assert_not_called()
            promote.assert_not_called()

    def test_sbom_retains_identifiers_and_licenses(self):
        lock, _ = self.evidence()
        result = source.sbom(lock, REF)
        self.assertEqual(result['metadata']['component']['bom-ref'], REF)
        self.assertEqual(len(result['components']), len(lock['sources']))
        for record, expected in zip(result['components'], lock['sources']):
            self.assertEqual(record['purl'], expected['purl'])
            self.assertEqual(record['licenses'][0]['license']['id'], expected['license'])

    def test_signatures_and_anonymous_access_precede_mutable_tags(self):
        _, manifest, _ = self.refresh()
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp)), patch.object(source, 'anonymous') as anonymous, patch.object(source, 'run') as run, patch.object(source, 'inspect', return_value=(DIGEST, {})), patch.object(source, 'verify_public'):
            source.write_json(Path(tmp) / 'manifest.json', manifest)
            for arch in source.ARCHES:
                for suffix in ('.build.json', '.cdx.json'):
                    source.write_json(Path(tmp) / (arch + suffix), {'fixture': arch + suffix})
            def command(*args, **kwargs):
                if args[:2] == ('cosign', 'verify'):
                    return json.dumps([{'critical': {'image': {'docker-manifest-digest': DIGEST}}}])
                if args[:2] == ('cosign', 'verify-attestation'):
                    suffix = '.cdx.json' if args[3] == 'cyclonedx' else '.build.json'
                    statement = {'subject': [{'name': source.IMAGE, 'digest': {'sha256': HASH}}],
                                 'predicate': json.loads((Path(tmp) / ('amd64' + suffix)).read_text())}
                    return json.dumps({'payload': base64.b64encode(json.dumps(statement).encode()).decode()})
                return ''
            # Both fixture platform digests are equal; predicates must also be equal.
            for suffix in ('.build.json', '.cdx.json'):
                source.write_json(Path(tmp) / ('arm64' + suffix), json.loads((Path(tmp) / ('amd64' + suffix)).read_text()))
            run.side_effect = command
            source.promote_source(manifest, 'rootloom/base-images', 'source-source-minimal-1-1')
            anonymous.assert_called_once_with(manifest)
            calls = [c.args for c in run.call_args_list]
            mutation = next(i for i, c in enumerate(calls) if c[:4] == ('docker', 'buildx', 'imagetools', 'create'))
            self.assertEqual(sum(c[:2] == ('cosign', 'sign') for c in calls[:mutation]), 3)
            self.assertEqual(sum(c[:2] == ('cosign', 'attest') for c in calls[:mutation]), 4)
            self.assertEqual(sum(c[:2] == ('cosign', 'verify') for c in calls[:mutation]), 3)
            self.assertEqual(sum(c[:2] == ('cosign', 'verify-attestation') for c in calls[:mutation]), 4)
            for call in run.call_args_list:
                if call.args[:2] in (('cosign', 'verify'), ('cosign', 'verify-attestation')):
                    self.assertIn('--certificate-identity', call.args)
                    self.assertIn('--certificate-oidc-issuer', call.args)
                    self.assertIn('DOCKER_CONFIG', call.kwargs['env'])
            promotion = json.loads((Path(tmp) / 'promotion.json').read_text())
            self.assertEqual(promotion['status'], 'promoted')
            run.reset_mock()
            run.side_effect = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('verify failed')) if args[:2] == ('cosign', 'verify') else ''
            with self.assertRaisesRegex(RuntimeError, 'verify failed'):
                source.promote_source(manifest, 'rootloom/base-images', 'source-source-minimal-2-1')
            self.assertFalse(any(c.args[:4] == ('docker', 'buildx', 'imagetools', 'create') for c in run.call_args_list))
            for field in ('predicate', 'subject'):
                def wrong_attestation(*args, **kwargs):
                    output = command(*args, **kwargs)
                    if args[:2] == ('cosign', 'verify-attestation'):
                        envelope = json.loads(output)
                        statement = json.loads(base64.b64decode(envelope['payload']))
                        statement[field] = {} if field == 'predicate' else []
                        envelope['payload'] = base64.b64encode(json.dumps(statement).encode()).decode()
                        return json.dumps(envelope)
                    return output
                run.reset_mock()
                run.side_effect = wrong_attestation
                with self.assertRaisesRegex(ValueError, 'predicate mismatch'):
                    source.promote_source(manifest, 'rootloom/base-images', 'source-source-minimal-3-1')
                self.assertFalse(any(c.args[:4] == ('docker', 'buildx', 'imagetools', 'create') for c in run.call_args_list))

    def test_failed_public_access_has_explicit_blocked_promotion_evidence(self):
        lock, report = self.evidence()
        inputs, manifest, _ = self.refresh()
        manifest.update(status='ready', scanner={'database_sha256': HASH, 'database': report['components'][0]['report']['descriptor']['db']['status']})
        record = dict(architecture='amd64', digest=DIGEST, candidate_index_digest=DIGEST, quality='passed', policy='passed',
                      scan_status='complete', reproducibility='passed', rootfs_sha256=HASH, repeat_rootfs_sha256=HASH)
        index = {'manifests': [{'digest': DIGEST, 'platform': {'os': 'linux', 'architecture': a}} for a in source.ARCHES]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(source, 'OUT', Path(tmp)), patch.object(source, 'lockfile', return_value=lock), patch.object(source, 'inspect', return_value=(DIGEST, index)), patch.object(source, 'run') as run, patch.object(source, 'verify_public'), patch.object(source, 'promote_source', side_effect=ValueError('private registry')):
            out = Path(tmp)
            source.write_json(out / 'attempt.json', manifest)
            source.write_json(out / 'sources.lock.json', lock)
            for arch in source.ARCHES:
                archive = out / (arch + '.sources.tar.gz')
                archive.write_bytes(b'fixture')
                source.write_json(out / (arch + '.qualification.json'), dict(record, architecture=arch, corresponding_source_sha256=source.sha(archive)))
                source.write_json(out / (arch + '.cve.json'), report)
                source.write_json(out / (arch + '.cdx.json'), source.sbom(lock, REF))
                source.write_json(out / (arch + '.build.json'), dict(subject=REF, lock_sha256=HASH, rootfs_sha256=HASH))
            with self.assertRaisesRegex(ValueError, 'private registry'):
                source.publish()
            failure = json.loads((out / 'promotion-attempt.json').read_text())
            self.assertEqual(failure['status'], 'blocked')
            self.assertFalse((out / 'promotion.json').exists())
            self.assertTrue(any(c.args[:3] == ('gh', 'release', 'upload') for c in run.call_args_list))
            manifest['primary_advisories'] = self.primary(lock)
            source.write_json(out / 'attempt.json', manifest)
            with self.assertRaisesRegex(RuntimeError, 'no promotion'):
                source.publish()
            saved = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(saved['status'], 'blocked')
            self.assertEqual(saved['error'], 'Primary advisory preflight binding mismatch')


if __name__ == '__main__':
    unittest.main()
