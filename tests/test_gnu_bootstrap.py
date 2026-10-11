"""Check real GNU bootstrap inputs and native build evidence when supplied."""

import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import importlib.util
import json
import lzma
import os
from pathlib import Path
import re
import sys
import subprocess
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

    @unittest.skipUnless(os.environ.get("DEBIAN_INDEX_EVIDENCE") and os.environ.get("GNU_BOOTSTRAP_INPUTS"),
                         "Signed Debian indexes and real GNU inputs are required")
    def test_signed_distribution_index_membership(self):
        evidence = Path(os.environ["DEBIAN_INDEX_EVIDENCE"]).resolve()
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        roles = {
            "trixie-current": {"B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8",
                               "04B54C3CDCA79751B16BC6B5225629DF75B188BD",
                               "41587F7DB8C774BCCF131416762F67A0B2C39DE4"},
            "trixie-security-current": {"05AB90340C0C5E797F44A8C8254CF3B5AEC0A8F0",
                                        "5E04A1E3223A19A20706E20F9904613D4CCE68C6"},
        }
        records = []
        for prefix, expected_signers in roles.items():
            with tempfile.TemporaryDirectory() as temporary:
                plaintext = Path(temporary) / "Release"
                result = subprocess.run([
                    "gpg", "--no-options", "--batch", "--homedir", temporary, "--no-default-keyring",
                    "--keyring", str(evidence / "debian-index-verification.gpg"), "--status-fd", "1",
                    "--output", str(plaintext), "--decrypt", str(evidence / (prefix + "-InRelease"))],
                    check=True, capture_output=True, text=True)
                signers = {line.split()[-1] for line in result.stdout.splitlines()
                           if line.startswith("[GNUPG:] VALIDSIG ")}
                self.assertEqual(signers, expected_signers)
                index = (evidence / (prefix + "-Sources.xz")).read_bytes()
                release = plaintext.read_text()
                expiry = re.search(r"^Valid-Until: (.+)$", release, re.MULTILINE)
                if prefix == "trixie-security-current":
                    self.assertIsNotNone(expiry, "Security index must declare its expiry")
                if expiry:
                    self.assertGreater(parsedate_to_datetime(expiry.group(1)), datetime.now(timezone.utc))
                self.assertRegex(release, re.compile(
                    rf"^ {hashlib.sha256(index).hexdigest()} +{len(index)} main/source/Sources\.xz$", re.MULTILINE))
                records.extend(lzma.decompress(index).decode().split("\n\n"))
        sources = (*BOOTSTRAP.SOURCES, ("gcc", "14.2.0-19", "", GCC.SIGNER, GCC.MATERIALS))
        for name, version, _, _, materials in sources:
            with self.subTest(component=name):
                descriptor = (inputs / materials[0][0]).read_text()
                package = re.search(r"^Source: (.+)$", descriptor, re.MULTILINE).group(1)
                publisher_version = re.search(r"^Version: (.+)$", descriptor, re.MULTILINE).group(1)
                self.assertEqual(publisher_version.split(":", 1)[-1], version)
                candidates = [record for record in records
                              if re.search(rf"^Package: {re.escape(package)}$", record, re.MULTILINE)
                              and re.search(rf"^Version: {re.escape(publisher_version)}$", record, re.MULTILINE)]
                self.assertTrue(candidates, "Source version is absent from signed indexes")
                self.assertTrue(any(all(re.search(rf"^ {digest} +\d+ {re.escape(filename)}$", record, re.MULTILINE)
                                            for filename, digest in materials[:3]) for record in candidates),
                                "Signed index does not bind all locked source archives")

    @unittest.skipUnless(os.environ.get("GNU_COMPILER_EVIDENCE"), "Native GNU compiler evidence is required")
    def test_native_compiler_stays_unqualified(self):
        evidence = Path(os.environ["GNU_COMPILER_EVIDENCE"])
        record = json.loads((evidence / "gcc-bootstrap.json").read_bytes())
        self.assertIs(record["release_qualified"], False)
        self.assertEqual(record["scope"], "temporary-bootstrap")
        self.assertIs(record["completed"], True)
        self.assertEqual(record["materials"], dict(GCC.MATERIALS))
        self.assertEqual(record["signing_fingerprint"], GCC.SIGNER)
        self.assertIn("--enable-link-mutex", record["commands"][2])
        self.assertTrue(record["patches"])
        self.assertRegex(record["distro_defaults_sha256"], r"^[a-f0-9]{64}$")
        snapshot = evidence / "gcc.source-files.json"
        self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), record["source_snapshot_sha256"])
        index = json.loads(snapshot.read_text())
        self.assertTrue(index)
        self.assertEqual({item["component"] for item in index.values()}, {"gcc"})
        self.assertEqual(index["/build/gcc/gcc-14-14.2.0/src/gcc/distro-defaults.h"]["sha256"],
                         record["distro_defaults_sha256"])
        self.assertGreater((evidence / "gcc-bootstrap.build.log").stat().st_size, 0)

    @unittest.skipUnless(os.environ.get("GNU_HEADER_EVIDENCE"), "Native GNU header evidence is required")
    def test_native_header_audit_stays_unqualified(self):
        evidence = Path(os.environ["GNU_HEADER_EVIDENCE"])
        record = json.loads((evidence / "gnu-headers.json").read_text())
        self.assertIs(record["release_qualified"], False)
        self.assertEqual(record["scope"], "source-header-audit")
        self.assertIs(record["completed"], True)
        self.assertTrue(record["headers"])
        self.assertEqual(record["headers_verified"], all(item["verified"] for item in record["headers"]))
        source_files = {}
        for name in ("gcc", "glibc", "linux"):
            source_files.update(json.loads((evidence / (name + ".source-files.json")).read_text()))
        for header in record["headers"]:
            with self.subTest(header=header["path"]):
                self.assertRegex(header["sha256"], r"^[a-f0-9]{64}$")
                retained = evidence / "header-inputs" / header["sha256"]
                self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), header["sha256"])
                self.assertEqual(header["verified"], bool(header["sources"] or header.get("producer")))
                if header.get("producer"):
                    producer = header["producer"]
                    self.assertEqual(producer["sha256"], header["sha256"])
                    self.assertTrue(producer["inputs"])
                    self.assertTrue(producer["command"])
                    for source in producer["inputs"]:
                        self.assertEqual(source_files[source["path"]],
                                         {"sha256": source["sha256"], "component": source["component"]})
                        retained = evidence / "header-inputs" / source["sha256"]
                        self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), source["sha256"])
                for source in header["sources"]:
                    self.assertEqual(source_files[source["path"]]["sha256"], header["sha256"])
                    self.assertEqual(source_files[source["path"]]["component"], source["component"])

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
                if item["name"] in ("linux", "glibc"):
                    snapshot = evidence / (item["name"] + ".source-files.json")
                    self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(), item["source_snapshot_sha256"])
                    index = json.loads(snapshot.read_text())
                    self.assertTrue(index)
                    self.assertEqual({entry["component"] for entry in index.values()}, {item["name"]})


if __name__ == "__main__":
    unittest.main()
