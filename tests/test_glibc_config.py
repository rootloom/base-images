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
