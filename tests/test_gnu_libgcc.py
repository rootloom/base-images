"""Test GNU runtime admission with synthetic records, not native compilation."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "images/source-minimal"))
sys.path.insert(0, str(ROOT / "images/debian-slim"))
SPEC = importlib.util.spec_from_file_location("gnu_libgcc", ROOT / "images/debian-slim/libgcc.py")
LIBGCC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIBGCC)


class LibgccTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "fresh"
        self.work.mkdir()
        self.records = self.root / "records"
        self.records.mkdir()
        self.retained = self.root / "retained"
        source = self.root / "source.c"
        source.write_text("int source;\n")
        self.index = {str(source): {"component": "gcc", "sha256": LIBGCC.sha256(source)}}
        self.source = source
        for name in ("member.o", *LIBGCC.STARTUP):
            obj = self.work / name
            obj.write_bytes(("fresh " + name).encode())
            record = {"object": str(obj), "object_sha256": LIBGCC.sha256(obj),
                      "inputs": [{"path": str(source), "sha256": LIBGCC.sha256(source)}]}
            for kind in ("preprocessed", "dependencies", "assembly"):
                path = self.records / (name + "." + kind)
                path.write_text("verified compiler evidence\n")
                record[kind] = path.name
                record[kind + "_sha256"] = LIBGCC.sha256(path)
            (self.records / (name + ".json")).write_text(json.dumps(record))
        for name in ("libgcc.a", "libgcc_eh.a"):
            (self.work / name).write_bytes(b"!<arch>\nsynthetic archive")

    def archive(self, command, **kwargs):
        if command[1] == "t":
            return "member.o\n"
        return (self.work / "member.o").read_bytes()

    def inspect(self):
        with patch.object(LIBGCC.subprocess, "check_output", side_effect=self.archive):
            return LIBGCC.inspect_runtime(self.work, self.records, self.index, self.retained)

    def test_retains_archive_members_startup_inputs_and_records(self):
        artifacts = self.inspect()
        self.assertEqual(len(artifacts), 7)
        member = artifacts[0]["members"][0]
        self.assertEqual(member["name"], "member.o")
        self.assertEqual(member["components"], ["gcc"])
        self.assertEqual(member["inputs"][0]["path"], str(self.source))
        self.assertEqual(LIBGCC.sha256(member["retained"]), member["sha256"])
        self.assertEqual(LIBGCC.sha256(member["record"]), member["record_sha256"])
        self.assertEqual(LIBGCC.sha256(member["retained_record"]), member["record_sha256"])
        self.assertEqual((self.records / "inputs" / LIBGCC.sha256(self.source)).read_bytes(), self.source.read_bytes())
        self.assertTrue(all(Path(item["retained"]).is_file() for item in artifacts))

    def test_missing_runtime_artifact(self):
        (self.work / "libgcc.a").unlink()
        with self.assertRaisesRegex(ValueError, "Missing or prebuilt"):
            self.inspect()

    def test_unknown_runtime_header(self):
        self.index.clear()
        with self.assertRaisesRegex(ValueError, "Unknown runtime input"):
            self.inspect()

    def test_missing_compiler_inputs(self):
        path = self.records / "member.o.json"
        record = json.loads(path.read_text())
        record["inputs"] = []
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "Missing compiler inputs"):
            self.inspect()

    def test_prebuilt_archive_member(self):
        (self.records / "member.o.json").unlink()
        with self.assertRaisesRegex(ValueError, "Prebuilt or unrecorded"):
            self.inspect()

    def test_prebuilt_startup_symlink(self):
        outside = self.root / "bootstrap.o"
        outside.write_bytes((self.work / "crtbegin.o").read_bytes())
        (self.work / "crtbegin.o").unlink()
        (self.work / "crtbegin.o").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "Missing or prebuilt"):
            self.inspect()

    def test_changed_archive_member(self):
        with patch.object(LIBGCC.subprocess, "check_output", side_effect=["member.o\n", b"bootstrap"]):
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                LIBGCC.inspect_runtime(self.work, self.records, self.index, self.retained)

    def test_duplicate_archive_members(self):
        with patch.object(LIBGCC.subprocess, "check_output", return_value="member.o\nmember.o\n"):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                LIBGCC.inspect_runtime(self.work, self.records, self.index, self.retained)

    def test_thin_archive_rejected(self):
        (self.work / "libgcc.a").write_bytes(b"!<thin>\n")
        with self.assertRaisesRegex(ValueError, "thin or prebuilt"):
            self.inspect()

    def test_changed_source_header(self):
        self.source.write_text("changed source\n")
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            self.inspect()

    def test_header_source_references_and_retained_bytes(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        sources = []
        for name in ("gcc", "glibc", "linux"):
            snapshot = evidence / (name + ".source-files.json")
            source = self.root / (name + ".h")
            source.write_text("/* " + name + " */\n")
            snapshot.write_text(json.dumps({str(source): {"component": name, "sha256": LIBGCC.sha256(source)}}))
            sources.append({"name": name, "completed": True, "source_snapshot_sha256": LIBGCC.sha256(snapshot)})
        gcc = {**sources[0], "materials": dict(LIBGCC.MATERIALS), "signing_fingerprint": LIBGCC.SIGNER}
        (evidence / "gcc-bootstrap.json").write_text(json.dumps(gcc))
        (evidence / "bootstrap.json").write_text(json.dumps({"sources": sources[1:]}))
        header = self.root / "installed.h"
        header.write_bytes((self.root / "gcc.h").read_bytes())
        retained = evidence / "header-inputs"
        retained.mkdir()
        (retained / LIBGCC.sha256(header)).write_bytes(header.read_bytes())
        report = {"scope": "source-header-audit", "headers_verified": True, "headers": [
            {"path": str(header), "sha256": LIBGCC.sha256(header), "verified": True,
             "sources": [{"path": str(self.root / "gcc.h"), "component": "gcc"}], "producer": None}]}
        (evidence / "gnu-headers.json").write_text(json.dumps(report))
        index, _ = LIBGCC.source_inputs(evidence)
        self.assertEqual(index[str(header)]["component"], "gcc")
        (retained / LIBGCC.sha256(header)).write_bytes(b"bootstrap header")
        with self.assertRaisesRegex(ValueError, "Retained installed header changed"):
            LIBGCC.source_inputs(evidence)


if __name__ == "__main__":
    unittest.main()
