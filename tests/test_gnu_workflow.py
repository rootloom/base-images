from pathlib import Path
import unittest


class GnuWorkflowTests(unittest.TestCase):
    def test_manual_targets_keep_native_offline_construction_boundary(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / '.github/workflows/gnu-source-bootstrap.yml').read_text()
        self.assertIn('default: runtime-trace-evidence', workflow)
        self.assertIn('runtime-trace-evidence|libgcc-evidence) ;;', workflow)
        self.assertIn('Unsupported construction target', workflow)
        self.assertIn('--target "$TARGET"', workflow)
        self.assertEqual(workflow.count('docker buildx build '), 1)
        self.assertIn("if: ${{ inputs.target == 'libgcc-evidence' }}", workflow)
        self.assertIn('GNU_LIBGCC_EVIDENCE: evidence/result', workflow)
        self.assertIn('-p test_gnu_libgcc.py -v', workflow)
        self.assertIn('runner: ubuntu-24.04-arm', workflow)
        self.assertIn('test "$(uname -m)" = "$EXPECTED_MACHINE"', workflow)
        self.assertIn('contents: read', workflow)
        self.assertNotIn(': write', workflow)
        dockerfile = (root / 'images/debian-slim/Bootstrap.Dockerfile').read_text()
        self.assertIn('RUN --network=none python3 /recipe/libgcc.py', dockerfile)
        self.assertIn('FROM scratch AS libgcc-evidence', dockerfile)


if __name__ == '__main__':
    unittest.main()
