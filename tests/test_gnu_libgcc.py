"""Test fail-closed construction receipts; native checks require real evidence."""

import importlib.util
import json
import os
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
                      "command": ["gcc", "-c", str(source), "-o", str(obj)],
                      "inputs": [{"path": str(source), "sha256": LIBGCC.sha256(source)}]}
            for kind in ("preprocessed", "dependencies", "assembly"):
                path = self.records / (name + "." + kind)
                path.write_text("verified compiler evidence\n")
                if kind == "dependencies":
                    path.write_text("object: " + str(source) + "\n")
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

    def generated_fixture(self):
        source = self.root / "libgcc"
        source.mkdir()
        for name in ("configure", "config.host", "config.in", "Makefile.in"):
            (source / name).write_text("pinned source\n")
        (source / "mkheader.sh").write_text('printf "%s\\n" "$DEFINES" "$HEADERS"\n')
        for path in source.iterdir():
            self.index[str(path)] = {"component": "gcc", "sha256": LIBGCC.sha256(path)}
        (self.work / "Makefile").write_text("libgcc_tm_defines = HAVE_TEST=1\nlibgcc_tm_file = test.h\n")
        (self.work / "config.status").write_text('printf "configured header\\n" > auto-target.h\n')
        (self.work / "libgcc_tm.h").write_text("HAVE_TEST=1\ntest.h\n")
        (self.work / "auto-target.h").write_text("configured header\n")
        return source

    def replay(self, source):
        return LIBGCC.replay_generated_headers(self.work, source, self.index, self.retained, {})

    def test_generated_replay_retains_bytes_without_admission(self):
        source = self.generated_fixture()
        before = dict(self.index)
        proofs = self.replay(source)
        self.assertEqual(len(proofs), 2)
        self.assertEqual(self.index, before)
        for proof in proofs:
            self.assertTrue(proof["replay_verified"])
            self.assertFalse(proof["admitted"])
            self.assertEqual(LIBGCC.sha256(proof["retained"]), proof["sha256"])
            self.assertEqual(len(proof["inputs"]), 7)
            for item in proof["inputs"]:
                self.assertEqual(LIBGCC.sha256(item["retained"]), item["sha256"])

    def test_generated_replay_rejects_unknown_producer(self):
        source = self.generated_fixture()
        del self.index[str(source / "mkheader.sh")]
        with self.assertRaisesRegex(ValueError, "Unknown generated-header producer"):
            self.replay(source)

    def test_generated_replay_does_not_authorize_runtime_dependency(self):
        source = self.generated_fixture()
        self.replay(source)
        path = self.records / "member.o.json"
        record = json.loads(path.read_text())
        header = self.work / "auto-target.h"
        record["inputs"].append({"path": str(header), "sha256": LIBGCC.sha256(header)})
        path.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "Unknown runtime input"):
            self.inspect()

    def test_generated_replay_rejects_changed_input_during_replay(self):
        source = self.generated_fixture()

        def change_producer(*args, **kwargs):
            (source / "config.host").write_text("changed while replaying\n")
            return (self.work / "libgcc_tm.h").read_bytes()

        with patch.object(LIBGCC.subprocess, "check_output", side_effect=change_producer):
            with self.assertRaisesRegex(ValueError, "producer changed during replay"):
                self.replay(source)

    def test_generated_replay_rejects_changed_producer(self):
        source = self.generated_fixture()
        (source / "mkheader.sh").write_text("exit 0\n")
        with self.assertRaisesRegex(ValueError, "Unknown generated-header producer"):
            self.replay(source)

    def test_generated_replay_rejects_make_expansion(self):
        source = self.generated_fixture()
        (self.work / "Makefile").write_text("libgcc_tm_defines = $(UNKNOWN)\nlibgcc_tm_file = test.h\n")
        with self.assertRaisesRegex(ValueError, "Unknown generated-header parameter"):
            self.replay(source)

    def test_generated_replay_rejects_mismatched_target_header(self):
        source = self.generated_fixture()
        (self.work / "auto-target.h").write_text("bootstrap header\n")
        with self.assertRaisesRegex(ValueError, "differs from replay: auto-target.h"):
            self.replay(source)

    def test_generated_replay_rejects_mismatched_tm_header(self):
        source = self.generated_fixture()
        (self.work / "libgcc_tm.h").write_text("bootstrap header\n")
        with self.assertRaisesRegex(ValueError, "differs from replay: libgcc_tm.h"):
            self.replay(source)

    def test_generated_replay_rejects_bootstrap_config_status_symlink(self):
        source = self.generated_fixture()
        original = self.root / "bootstrap-config.status"
        (self.work / "config.status").rename(original)
        (self.work / "config.status").symlink_to(original)
        with self.assertRaisesRegex(ValueError, "Missing fresh configure output"):
            self.replay(source)

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

    def receipt_fixture(self):
        source = self.generated_fixture()
        evidence = self.root / "evidence"
        (evidence / "sources").mkdir(parents=True)
        directory = evidence / "sources/compilation"
        self.records.rename(directory)
        self.records = directory
        self.retained = evidence / "sources/libgcc"
        artifacts = self.inspect()
        proofs = LIBGCC.replay_generated_headers(
            self.work, source, self.index, evidence / "sources/libgcc-producers", {})
        snapshots = {}
        sources = []
        for name in ("gcc", "glibc", "linux"):
            index = self.index
            if name != "gcc":
                path = self.root / (name + ".c")
                path.write_text("source\n")
                index = {str(path): {"component": name, "sha256": LIBGCC.sha256(path)}}
            path = evidence / (name + ".source-files.json")
            path.write_text(json.dumps(index))
            snapshots[name] = LIBGCC.sha256(path)
            sources.append({"name": name, "completed": True, "source_snapshot_sha256": snapshots[name]})
        gcc = {**sources[0], "materials": dict(LIBGCC.MATERIALS), "signing_fingerprint": LIBGCC.SIGNER}
        (evidence / "gcc-bootstrap.json").write_text(json.dumps(gcc))
        (evidence / "bootstrap.json").write_text(json.dumps({"sources": sources[1:]}))
        digest = LIBGCC.sha256(self.source)
        (evidence / "header-inputs").mkdir()
        (evidence / "header-inputs" / digest).write_bytes(self.source.read_bytes())
        headers = [{"path": str(self.source), "sha256": digest, "verified": True,
                    "sources": [{"path": str(self.source), "component": "gcc"}], "producer": None}]
        (evidence / "gnu-headers.json").write_text(json.dumps(
            {"scope": "source-header-audit", "headers_verified": True, "headers": headers}))
        receipt = {"schema_version": 1, "scope": "gnu-libgcc-construction", "release_qualified": False,
                   "completed": True, "runtime_verified": True, "machine": "x86_64",
                   "headers": headers, "source_snapshots": snapshots, "artifacts": artifacts,
                   "generated_headers": proofs,
                   "bootstrap_config_status_sha256": LIBGCC.sha256(self.work / "config.status"),
                   "gcc_preparation_sha256": LIBGCC.sha256(evidence / "gcc-bootstrap.json"),
                   "header_audit_sha256": LIBGCC.sha256(evidence / "gnu-headers.json")}
        (evidence / "gnu-libgcc.json").write_text(json.dumps(receipt))
        return evidence, receipt

    def verify_fixture(self, evidence, receipt):
        (evidence / "gnu-libgcc.json").write_text(json.dumps(receipt))
        with patch.object(LIBGCC.subprocess, "check_output", side_effect=self.archive):
            return LIBGCC.verify_retained_runtime(evidence)

    def test_offline_fixture_is_construction_only_not_native_pass(self):
        evidence, receipt = self.receipt_fixture()
        self.source.unlink()
        self.assertIs(self.verify_fixture(evidence, receipt)["release_qualified"], False)

    def test_receipt_rejects_incomplete_or_release_scope(self):
        evidence, receipt = self.receipt_fixture()
        for field, value in (("scope", "release"), ("completed", False),
                             ("runtime_verified", False), ("release_qualified", True)):
            with self.subTest(field=field):
                changed = {**receipt, field: value}
                with self.assertRaisesRegex(ValueError, "construction receipt"):
                    self.verify_fixture(evidence, changed)

    def test_receipt_rejects_missing_or_tampered_retained_bytes(self):
        evidence, receipt = self.receipt_fixture()
        paths = [evidence / "sources/libgcc" / receipt["artifacts"][0]["sha256"],
                 evidence / "sources/libgcc" / (receipt["artifacts"][0]["members"][0]["record_sha256"] + ".json"),
                 evidence / "sources/compilation/inputs" / LIBGCC.sha256(self.source),
                 evidence / "sources/libgcc-producers" / receipt["generated_headers"][0]["sha256"],
                 evidence / "gcc.source-files.json", evidence / "gnu-headers.json"]
        for path in paths:
            original = path.read_bytes()
            for tamper in (False, True):
                with self.subTest(path=path, tamper=tamper):
                    if tamper:
                        path.write_bytes(b"tampered")
                    else:
                        path.unlink()
                    with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                        self.verify_fixture(evidence, receipt)
                    path.write_bytes(original)

    def test_receipt_rejects_naming_only_artifacts(self):
        evidence, receipt = self.receipt_fixture()
        receipt["artifacts"][0]["members"][0]["components"] = ["trusted-by-name"]
        with self.assertRaisesRegex(ValueError, "components differ"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_unknown_dependency_even_with_matching_hashes(self):
        evidence, receipt = self.receipt_fixture()
        obj = receipt["artifacts"][0]["members"][0]
        path = evidence / "sources/libgcc" / (obj["record_sha256"] + ".json")
        record = json.loads(path.read_text())
        record["inputs"][0]["path"] = "/unreviewed/compiler-header.h"
        dependency = self.records / record["dependencies"]
        dependency.write_text("object: /unreviewed/compiler-header.h\n")
        record["dependencies_sha256"] = LIBGCC.sha256(dependency)
        path.write_text(json.dumps(record))
        obj["record_sha256"] = LIBGCC.sha256(path)
        path.rename(path.with_name(obj["record_sha256"] + ".json"))
        obj["inputs"] = record["inputs"]
        with self.assertRaisesRegex(ValueError, "Unknown runtime input"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_unlisted_dependency(self):
        evidence, receipt = self.receipt_fixture()
        obj = receipt["artifacts"][0]["members"][0]
        path = evidence / "sources/libgcc" / (obj["record_sha256"] + ".json")
        record = json.loads(path.read_text())
        dependency = self.records / record["dependencies"]
        dependency.write_text("object: " + str(self.source) + " /unknown.h\n")
        record["dependencies_sha256"] = LIBGCC.sha256(dependency)
        path.write_text(json.dumps(record))
        obj["record_sha256"] = LIBGCC.sha256(path)
        path.rename(path.with_name(obj["record_sha256"] + ".json"))
        with self.assertRaisesRegex(ValueError, "dependency list differs"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_missing_compilation_command(self):
        evidence, receipt = self.receipt_fixture()
        obj = receipt["artifacts"][0]["members"][0]
        path = evidence / "sources/libgcc" / (obj["record_sha256"] + ".json")
        record = json.loads(path.read_text())
        del record["command"]
        path.write_text(json.dumps(record))
        obj["record_sha256"] = LIBGCC.sha256(path)
        path.rename(path.with_name(obj["record_sha256"] + ".json"))
        with self.assertRaisesRegex(ValueError, "Missing runtime compilation command"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_generated_header_admission(self):
        evidence, receipt = self.receipt_fixture()
        receipt["generated_headers"][0]["admitted"] = True
        with self.assertRaisesRegex(ValueError, "Unproved generated-header admission"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_missing_generated_header_proof(self):
        evidence, receipt = self.receipt_fixture()
        receipt["generated_headers"].pop()
        with self.assertRaisesRegex(ValueError, "Missing generated-header proofs"):
            self.verify_fixture(evidence, receipt)

    def test_receipt_rejects_changed_archive_member_bytes(self):
        evidence, receipt = self.receipt_fixture()
        with patch.object(LIBGCC.subprocess, "check_output", side_effect=["member.o\n", b"tampered"]):
            with self.assertRaisesRegex(ValueError, "member checksum mismatch"):
                LIBGCC.verify_retained_runtime(evidence)

    @unittest.skipUnless(os.environ.get("GNU_LIBGCC_EVIDENCE"), "Retained native libgcc evidence is required")
    def test_native_libgcc_construction_receipt(self):
        receipt = LIBGCC.verify_retained_runtime(Path(os.environ["GNU_LIBGCC_EVIDENCE"]))
        self.assertIs(receipt["release_qualified"], False)


if __name__ == "__main__":
    unittest.main()
