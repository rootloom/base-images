"""Check real GNU bootstrap inputs and native build evidence when supplied."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("gnu_bootstrap", ROOT / "images/debian-slim/bootstrap.py")
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)
GCC_SPEC = importlib.util.spec_from_file_location("gcc_bootstrap", ROOT / "images/debian-slim/gcc_bootstrap.py")
GCC = importlib.util.module_from_spec(GCC_SPEC)
with patch.dict(sys.modules, {"bootstrap": BOOTSTRAP}):
    GCC_SPEC.loader.exec_module(GCC)


class GnuBootstrapTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_locked_archives_and_descriptor_bindings(self):
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        sources = (*BOOTSTRAP.SOURCES, ("gcc", "14.2.0-19", "", GCC.SIGNER, GCC.MATERIALS))
        for name, _, _, _, materials in sources:
            descriptor = (inputs / materials[0][0]).read_text()
            for filename, expected in materials:
                with self.subTest(component=name, filename=filename):
                    data = (inputs / filename).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
                    if ".tar." in filename:
                        self.assertRegex(descriptor, re.compile(
                            rf"^ {expected} {len(data)} {re.escape(filename)}$", re.MULTILINE))

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_real_descriptor_signatures(self):
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"]).resolve()
        sources = (*BOOTSTRAP.SOURCES, ("gcc", "14.2.0-19", "", GCC.SIGNER, GCC.MATERIALS))
        for name, _, _, signer, materials in sources:
            with self.subTest(component=name), tempfile.TemporaryDirectory() as directory:
                primary = BOOTSTRAP.verify_source(inputs, Path(directory), signer, materials)
                self.assertRegex(primary, r"^[A-F0-9]{40}$")

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_compiler_prerequisites_bind_to_verified_source(self):
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        archive_path = inputs / GCC.MATERIALS[1][0]
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), GCC.MATERIALS[1][1])
        with tarfile.open(archive_path) as outer:
            with outer.extractfile("gcc-14-14.2.0/gcc-14.2.0-dfsg.tar.xz") as stream:
                with tarfile.open(fileobj=stream, mode="r:xz") as inner:
                    manifest = inner.extractfile("gcc-14.2.0/contrib/prerequisites.sha512").read().decode()
        expected = {filename: checksum for checksum, filename in
                    (line.split() for line in manifest.splitlines())}
        for filename in GCC.PREREQUISITES:
            with self.subTest(filename=filename):
                self.assertEqual(hashlib.sha512((inputs / filename).read_bytes()).hexdigest(), expected[filename])

    @unittest.skipUnless(os.environ.get("GNU_COMPILER_EVIDENCE"), "Native GNU compiler evidence is required")
    def test_native_compiler_stays_unqualified(self):
        evidence = Path(os.environ["GNU_COMPILER_EVIDENCE"])
        record = json.loads((evidence / "gcc-bootstrap.json").read_bytes())
        self.assertIs(record["release_qualified"], False)
        self.assertEqual(record["scope"], "temporary-bootstrap")
        self.assertIs(record["completed"], True)
        self.assertEqual(record["materials"], dict(GCC.MATERIALS))
        self.assertEqual(record["signing_fingerprint"], GCC.SIGNER)
        self.assertTrue(record["patches"])
        self.assertRegex(record["distro_defaults_sha256"], r"^[a-f0-9]{64}$")
        self.assertGreater((evidence / "gcc-bootstrap.build.log").stat().st_size, 0)

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
