"""Test retained config evidence links, not native configure qualification."""

import hashlib
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
SPEC = importlib.util.spec_from_file_location("glibc_config", ROOT / "images/debian-slim/glibc_config.py")
CONFIG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONFIG)
RUNTIME_SPEC = importlib.util.spec_from_file_location("config_capture_runtime", ROOT / "images/debian-slim/runtime.py")
RUNTIME = importlib.util.module_from_spec(RUNTIME_SPEC)
RUNTIME_SPEC.loader.exec_module(RUNTIME)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.generation = self.root / "sources/generation"
        (self.generation / "inputs").mkdir(parents=True)
        (self.root / "sources/trace-inputs").mkdir()
        self.data = b"#define PROBE_RESULT 1\n"
        self.digest = hashlib.sha256(self.data).hexdigest()
        (self.root / "sources/trace-inputs" / self.digest).write_bytes(self.data)
        (self.generation / "inputs" / self.digest).write_bytes(self.data)
        self.dependencies = b"probe.s: /build/glibc-runtime/config.h\n"
        (self.generation / "probe.d").write_bytes(self.dependencies)
        self.record = {"dependencies": "probe.d", "cwd": "/build/glibc/glibc-2.41/csu",
                       "dependencies_sha256": hashlib.sha256(self.dependencies).hexdigest(),
                       "inputs": [{"path": CONFIG.CONFIG, "sha256": self.digest}]}
        self.trace = {"scope": "gnu-runtime-trace", "release_qualified": False,
                      "unknown_inputs": {CONFIG.CONFIG: self.digest}, "verified_inputs": {},
                      "commands": [[CONFIG.SOURCE_ROOT + "configure", "--prefix=/usr"]]}
        self.save()
        self.sources = [{"path": CONFIG.SOURCE_ROOT + name, "component": "glibc", "sha256": "a" * 64}
                        for name in CONFIG.SOURCE_NAMES]
        self.mock = patch.object(CONFIG, "verify_config_sources", return_value=self.sources)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def save(self):
        data = json.dumps(self.record).encode()
        (self.generation / "probe.json").write_bytes(data)
        self.trace["generation_records"] = {"probe.json": hashlib.sha256(data).hexdigest()}
        (self.root / "gnu-libc-trace.json").write_text(json.dumps(self.trace))

    def inspect(self):
        return CONFIG.inspect_retained_config(self.root, self.root)

    def capture(self):
        retained = self.root / "sources/configure"
        retained.mkdir()
        references = []
        for source in self.sources:
            data = source["path"].encode()
            digest = hashlib.sha256(data).hexdigest()
            source["sha256"] = digest
            (retained / digest).write_bytes(data)
            references.append({**source, "role": "source"})
        (retained / self.digest).write_bytes(self.data)
        references.append({"path": CONFIG.CONFIG, "role": "output", "sha256": self.digest})
        self.capture_receipt = {"schema_version": 1, "scope": "glibc-configure-capture",
                                "admitted": False, "release_qualified": False,
                                "environment_complete": False, "sysdeps_selection_verified": False,
                                "probe_provenance_verified": False, "output_replayed": False,
                                "command": self.trace["commands"][0], "cwd": str(Path(CONFIG.CONFIG).parent),
                                "files": references,
                                "missing_outputs": ["config.status", "config.log", "confdefs.h", "config.make", "config.cache"]}
        self.save_capture()
        return retained

    def save_capture(self):
        data = json.dumps(self.capture_receipt).encode()
        (self.root / "glibc-configure-capture.json").write_bytes(data)
        self.trace["configure_capture_sha256"] = hashlib.sha256(data).hexdigest()
        self.save()

    def test_capture_does_not_admit_config(self):
        self.capture()
        report = self.inspect()
        self.assertFalse(report["admitted"])
        self.assertIn("confdefs.h", report["capture"]["missing_outputs"])
        with self.assertRaisesRegex(ValueError, "Unproved glibc"):
            CONFIG.require_config_producer(self.root, self.root)

    def test_capture_missing_file_rejected(self):
        retained = self.capture()
        (retained / self.digest).unlink()
        with self.assertRaisesRegex(ValueError, "Unlisted or missing"):
            self.inspect()

    def test_capture_unlisted_file_rejected(self):
        retained = self.capture()
        (retained / ("b" * 64)).write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "Unlisted or missing"):
            self.inspect()

    def test_capture_tamper_rejected(self):
        retained = self.capture()
        (retained / self.digest).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.inspect()

    def test_capture_source_binding_rejected(self):
        self.capture()
        self.capture_receipt["files"][0]["component"] = "gcc"
        self.save_capture()
        with self.assertRaisesRegex(ValueError, "source binding mismatch"):
            self.inspect()

    def test_capture_admission_flags_rejected(self):
        self.capture()
        for key in ("admitted", "release_qualified", "probe_provenance_verified", "output_replayed"):
            with self.subTest(key=key):
                self.capture_receipt[key] = True
                self.save_capture()
                with self.assertRaisesRegex(ValueError, "capture admission"):
                    self.inspect()
                self.capture_receipt[key] = False

    def test_capture_invocation_mismatch_rejected(self):
        self.capture()
        self.capture_receipt["cwd"] = "/wrong"
        self.save_capture()
        with self.assertRaisesRegex(ValueError, "invocation mismatch"):
            self.inspect()

    def test_capture_omitted_output_not_reported_rejected(self):
        self.capture()
        self.capture_receipt["missing_outputs"] = []
        self.save_capture()
        with self.assertRaisesRegex(ValueError, "missing output list mismatch"):
            self.inspect()

    def test_capture_output_link_mismatch_rejected(self):
        retained = self.capture()
        data = b"different config"
        digest = hashlib.sha256(data).hexdigest()
        (retained / self.digest).unlink()
        (retained / digest).write_bytes(data)
        self.capture_receipt["files"][-1]["sha256"] = digest
        self.save_capture()
        with self.assertRaisesRegex(ValueError, "capture output mismatch"):
            self.inspect()

    def test_valid_links_remain_blocked(self):
        report = self.inspect()
        self.assertFalse(report["admitted"])
        self.assertFalse(report["release_qualified"])
        self.assertFalse(report["output_replayed"])
        self.assertFalse(report["invocation_verified"])
        self.assertEqual(report["retained_consumers"], ["probe.json"])
        self.assertEqual(report["unproved_generation_inputs"], [CONFIG.CONFIG])
        self.assertEqual(len(report["blockers"]), 5)

    def test_require_always_blocks(self):
        with self.assertRaisesRegex(ValueError, "Unproved glibc config.h producer"):
            CONFIG.require_config_producer(self.root, self.root)

    def test_missing_config_bytes(self):
        (self.root / "sources/trace-inputs" / self.digest).unlink()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            self.inspect()

    def test_tampered_config_bytes(self):
        (self.root / "sources/trace-inputs" / self.digest).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.inspect()

    def test_missing_generation_input(self):
        (self.generation / "inputs" / self.digest).unlink()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            self.inspect()

    def test_tampered_generation_record(self):
        (self.generation / "probe.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.inspect()

    def test_unlisted_generation_record(self):
        (self.generation / "other.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Unlisted or missing"):
            self.inspect()

    def test_missing_generation_record(self):
        (self.generation / "probe.json").unlink()
        with self.assertRaisesRegex(ValueError, "Unlisted or missing"):
            self.inspect()

    def test_self_consistent_unlisted_dependency(self):
        data = b"probe.s: /build/glibc-runtime/config.h /unknown/header.h\n"
        (self.generation / "probe.d").write_bytes(data)
        self.record["dependencies_sha256"] = hashlib.sha256(data).hexdigest()
        self.save()
        with self.assertRaisesRegex(ValueError, "dependency list mismatch"):
            self.inspect()

    def test_duplicate_inputs(self):
        self.record["inputs"] *= 2
        self.save()
        with self.assertRaisesRegex(ValueError, "Invalid config generation inputs"):
            self.inspect()

    def test_unknown_input_remains_unproved(self):
        path = "/unknown/header.h"
        self.trace["unknown_inputs"][path] = self.digest
        self.record["inputs"].append({"path": path, "sha256": self.digest})
        data = ("probe.s: " + CONFIG.CONFIG + " " + path + "\n").encode()
        (self.generation / "probe.d").write_bytes(data)
        self.record["dependencies_sha256"] = hashlib.sha256(data).hexdigest()
        self.save()
        report = self.inspect()
        self.assertFalse(report["admitted"])
        self.assertIn(path, report["unproved_generation_inputs"])

    def test_wrong_config_digest(self):
        self.trace["unknown_inputs"][CONFIG.CONFIG] = "b" * 64
        (self.root / "sources/trace-inputs" / ("b" * 64)).write_bytes(b"wrong")
        self.save()
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.inspect()

    def test_admission_claim_rejected(self):
        self.trace["verified_inputs"][CONFIG.CONFIG] = {"sha256": self.digest, "admitted": True}
        self.save()
        with self.assertRaisesRegex(ValueError, "Unproved config.h admission"):
            self.inspect()

    def test_release_claim_rejected(self):
        self.trace["release_qualified"] = True
        self.save()
        with self.assertRaisesRegex(ValueError, "trace scope"):
            self.inspect()

    def test_path_escape_rejected(self):
        self.record["dependencies"] = "../probe.d"
        self.save()
        with self.assertRaisesRegex(ValueError, "Invalid config evidence reference"):
            self.inspect()

    def test_symlink_rejected(self):
        path = self.generation / "inputs" / self.digest
        path.unlink()
        path.symlink_to(self.root / "sources/trace-inputs" / self.digest)
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            self.inspect()

    def test_missing_invocation(self):
        self.trace["commands"] = []
        self.save()
        with self.assertRaisesRegex(ValueError, "Missing claimed configure invocation"):
            self.inspect()


    def test_retained_cwd_not_host_cwd(self):
        data = b"probe.s: ../../../../glibc-runtime/config.h\n"
        self.record["cwd"] = "/build/glibc/glibc-2.41/csu/extra"
        (self.generation / "probe.d").write_bytes(data)
        self.record["dependencies_sha256"] = hashlib.sha256(data).hexdigest()
        self.save()
        self.assertFalse(self.inspect()["admitted"])

    def test_missing_generation_cwd(self):
        del self.record["cwd"]
        self.save()
        with self.assertRaisesRegex(ValueError, "generation cwd"):
            self.inspect()

    def test_missing_pinned_source_material(self):
        self.mock.stop()
        with self.assertRaisesRegex(ValueError, "Missing or unsafe"):
            CONFIG.verify_config_sources(self.root, self.root)

    def test_tampered_pinned_source_material(self):
        self.mock.stop()
        materials = next(item[-1] for item in CONFIG.SOURCES if item[0] == "glibc")
        (self.root / materials[0][0]).write_bytes(b"not the pinned source descriptor")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            CONFIG.verify_config_sources(self.root, self.root)


class CaptureExecutionTests(unittest.TestCase):
    def test_actual_invocation_retains_outputs_before_make(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, work, evidence = (root / name for name in ("source", "work", "evidence"))
            source.mkdir()
            work.mkdir()
            evidence.mkdir()
            names = ("configure", "config.h.in", "sysdeps/generic/configure")
            sources = {}
            for name in names:
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(name)
                sources[str(path)] = {"component": "glibc", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            (work / "config.cache").write_text("pre-cache")
            environment = {"PATH": "/tools", "CC": "gcc", "ac_cv_test": "yes", "SECRET_TOKEN": "not retained"}
            command = [str(source / "configure"), "--prefix=/usr"]

            def run(argv, **kwargs):
                self.assertEqual(argv, command)
                self.assertEqual(kwargs["env"], environment)
                self.assertEqual(kwargs["cwd"], work)
                for name in ("config.h", "config.status", "config.log"):
                    (work / name).write_text("probe command/result/tool evidence " + name)
                (work / "config.make").write_text("config-sysdirs = sysdeps/generic\n")
                (work / "config.cache").write_text("post-cache")
                return subprocess_result

            subprocess_result = type("Result", (), {"returncode": 0})()
            with patch.object(RUNTIME.subprocess, "run", side_effect=run):
                RUNTIME.capture_configure(command, work, environment, sources, evidence, None)
            receipt = json.loads((evidence / "glibc-configure-capture.json").read_text())
            self.assertNotIn("SECRET_TOKEN", receipt["environment"])
            self.assertEqual(receipt["environment"]["ac_cv_test"], "yes")
            self.assertIn("confdefs.h", receipt["missing_outputs"])
            self.assertEqual(receipt["selected_sysdeps"], ["sysdeps/generic"])
            self.assertFalse(receipt["probe_provenance_verified"])
            self.assertFalse(receipt["admitted"])
            for item in receipt["files"]:
                CONFIG.checked(evidence / "sources/configure", item["sha256"], item["sha256"])
            cache = [item for item in receipt["files"] if item["path"] == str(work / "config.cache")]
            self.assertEqual({item["role"] for item in cache}, {"pre-cache", "output"})
            self.assertNotEqual(cache[0]["sha256"], cache[1]["sha256"])


class NativeConfigTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE"),
                         "Pinned source inputs and retained native evidence are required")
    def test_actual_retained_config_is_not_qualified(self):
        report = CONFIG.inspect_retained_config(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"],
                                                os.environ["GNU_BOOTSTRAP_INPUTS"])
        self.assertEqual(len(report["sources"]), 2)
        self.assertGreater(len(report["retained_consumers"]), 0)
        self.assertFalse(report["admitted"])
        self.assertFalse(report["release_qualified"])
        self.assertFalse(report["output_replayed"])
        self.assertIn(CONFIG.CONFIG, report["unproved_generation_inputs"])

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE"),
                         "Pinned source inputs and retained native evidence are required")
    def test_self_consistent_source_snapshot_tamper(self):
        evidence = Path(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bootstrap = json.loads((evidence / "bootstrap.json").read_text())
            snapshot = json.loads((evidence / "glibc.source-files.json").read_text())
            snapshot[CONFIG.SOURCE_ROOT + "configure"]["sha256"] = "a" * 64
            data = json.dumps(snapshot).encode()
            (root / "glibc.source-files.json").write_bytes(data)
            vendor = next(item for item in bootstrap["sources"] if item["name"] == "glibc")
            vendor["source_snapshot_sha256"] = hashlib.sha256(data).hexdigest()
            (root / "bootstrap.json").write_text(json.dumps(bootstrap))
            with self.assertRaisesRegex(ValueError, "Config source snapshot mismatch"):
                CONFIG.verify_config_sources(root, os.environ["GNU_BOOTSTRAP_INPUTS"])


if __name__ == "__main__":
    unittest.main()
