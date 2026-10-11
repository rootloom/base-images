"""Check real GNU bootstrap inputs and native build evidence when supplied."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gnu_bootstrap", ROOT / "images/debian-slim/bootstrap.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


class GnuBootstrapTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_locked_archives_and_descriptor_bindings(self):
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        for name, _, _, _, materials in BOOTSTRAP.SOURCES:
            descriptor = (inputs / materials[0][0]).read_text()
            for filename, expected in materials:
                with self.subTest(component=name, filename=filename):
                    data = (inputs / filename).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
                    if filename.endswith(".tar.xz"):
                        self.assertRegex(descriptor, re.compile(
                            rf"^ {expected} {len(data)} {re.escape(filename)}$", re.MULTILINE))

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_EVIDENCE"), "Native GNU build evidence is required")
    def test_native_build_stays_unqualified(self):
        evidence = Path(os.environ["GNU_BOOTSTRAP_EVIDENCE"])
        record = json.loads((evidence / "bootstrap.json").read_bytes())
        self.assertIs(record["release_qualified"], False)
        self.assertEqual(record["scope"], "temporary-bootstrap")
        self.assertEqual([item["name"] for item in record["sources"]],
                         [item[0] for item in BOOTSTRAP.SOURCES])
        for item, expected in zip(record["sources"], BOOTSTRAP.SOURCES):
            with self.subTest(component=item["name"]):
                self.assertIs(item["completed"], True)
                self.assertEqual(item["materials"], dict(expected[4]))
                self.assertEqual(item["signing_fingerprint"], expected[3])
                self.assertTrue(item["patches"])
                self.assertGreater((evidence / (item["name"] + ".build.log")).stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
