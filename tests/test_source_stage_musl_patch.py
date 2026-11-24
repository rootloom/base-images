import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / 'scripts/stage_musl_patch.py'
RECIPE = Path('images/source-minimal')
COMMIT = 'abcd' * 10
# Synthetic identities and documentation-only bytes. Never fetch this URL.
PATCH = (f'From {COMMIT} Mon Sep 17 00:00:00 2001\n'
         'Subject: [PATCH] Update fixture note\n\n'
         'diff --git a/note b/note\n--- a/note\n+++ b/note\n'
         '@@ -1 +1 @@\n-old note\n+new note\n').encode()
REVIEW = {'name': 'musl-fixture-note', 'upstream_commit': COMMIT,
          'url': 'https://www.openwall.com/lists/musl/2000/01/01/1/1',
          'sha256': hashlib.sha256(PATCH).hexdigest()}


class MuslPatchStaging(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / 'repo'
        subprocess.run(['git', 'clone', '-q', '--local', '--no-hardlinks', str(REPO), str(self.root)], check=True)

    def stage(self, review=REVIEW, patch=PATCH):
        (self.root / 'review.json').write_text(json.dumps(review))
        (self.root / 'input.patch').write_bytes(patch)
        return subprocess.run([sys.executable, '-B', str(SCRIPT), 'review.json', 'input.patch'],
                              cwd=self.root, capture_output=True)

    def test_proposal(self):
        first = self.stage()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, self.stage(dict(reversed(list(REVIEW.items())))).stdout)
        base = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root).strip()
        self.assertTrue(first.stdout.startswith(b'Rootloom source base: ' + base + b'\n'))
        subprocess.run(['git', 'diff', '--quiet'], cwd=self.root, check=True)
        for flags in (['--check'], []):
            subprocess.run(['git', 'apply', *flags, '-'], cwd=self.root, input=first.stdout, check=True)
        files = subprocess.check_output(['git', 'diff', '--name-only'], cwd=self.root, text=True).splitlines()
        self.assertEqual(files, [str(RECIPE / name) for name in ('build.sh', 'sources.lock.json')])
        validate = f'import sys; sys.path.insert(0, {str(REPO / "scripts")!r}); from source_release import lockfile; print(lockfile()["image_version"])'
        version = subprocess.check_output([sys.executable, '-B', '-c', validate], cwd=self.root, text=True).strip()
        original = json.loads(subprocess.check_output(['git', 'show', f'HEAD:{RECIPE}/sources.lock.json'], cwd=self.root))
        prefix, revision = original['image_version'].rsplit('-r', 1)
        self.assertEqual(version, f'{prefix}-r{int(revision) + 1}')
        lock = json.loads((self.root / RECIPE / 'sources.lock.json').read_text())
        self.assertEqual(lock['patches'][-1], dict(REVIEW, component='musl', filename='musl-fixture-note.patch', license='MIT'))
        build = (self.root / RECIPE / 'build.sh').read_text()
        self.assertIn('patch --batch --fuzz=0 -p1 < /downloads/musl-fixture-note.patch\n    cd /build\nfi', build)
        repeat = self.stage()
        self.assertNotEqual(repeat.returncode, 0)
        self.assertIn(b'already exists', repeat.stderr)
        self.assertEqual(repeat.stdout, b'')

    def test_invalid_inputs(self):
        for review, patch in [(dict(REVIEW, sha256='0' * 64), PATCH),
                              (dict(REVIEW, upstream_commit='0' * 40), PATCH),
                              (dict(REVIEW, url='https://example.invalid/fixture'), PATCH),
                              ({k: v for k, v in REVIEW.items() if k != 'upstream_commit'}, PATCH),
                              (dict(REVIEW, sha256=hashlib.sha256(PATCH * 2).hexdigest()), PATCH * 2)]:
            with self.subTest(review=review):
                result = self.stage(review, patch)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')

    def test_changed_base(self):
        with (self.root / RECIPE / 'build.sh').open('a') as stream:
            stream.write('# local edit\n')
        result = self.stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'differs from recorded base', result.stderr)
        self.assertEqual(result.stdout, b'')
