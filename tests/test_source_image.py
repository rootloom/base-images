import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "images/source-minimal"


class SourceImagePolicy(unittest.TestCase):
    def test_lock(self):
        lock = json.loads((RECIPE / "sources.lock.json").read_text())
        self.assertEqual(lock["schema_version"], 1)
        self.assertEqual(lock["supported_architectures"], ["amd64", "arm64"])
        self.assertEqual({x["name"] for x in lock["sources"]}, {"musl", "busybox", "compiler-rt-builtins", "mozilla-ca-bundle"})
        for source in lock["sources"] + lock["patches"]:
            self.assertRegex(source["sha256"], r"^[a-f0-9]{64}$")
            self.assertTrue(source["url"].startswith("https://"))
            self.assertTrue(source["license"])
        dockerfile = (RECIPE / "Dockerfile").read_text()
        self.assertIn(lock["builder"]["image"] + "@" + lock["builder"]["digest"], dockerfile)

    def test_busybox_remediation_pin(self):
        lock = json.loads((RECIPE / "sources.lock.json").read_text())
        source = next(x for x in lock["sources"] if x["name"] == "busybox")
        self.assertEqual(source["version"], "1.37.0")
        self.assertEqual(source["sha256"], "3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4")
        self.assertEqual(source["purl"], "pkg:generic/busybox@1.37.0")
        self.assertIn("CVE-2022-48174", source["verification"])
        build = (RECIPE / "build.sh").read_text()
        self.assertIn("/downloads/" + source["filename"], build)
        self.assertIn("/build/busybox-1.37.0", build)
        self.assertIn("/build/busybox-1.37.0/.config", (RECIPE / "evidence.py").read_text())

    def test_scratch_and_network_boundary(self):
        dockerfile = (RECIPE / "Dockerfile").read_text()
        runtime = dockerfile.split("FROM scratch AS runtime\n")[1]
        self.assertIn("USER 65532:65532", runtime)
        self.assertNotIn("RUN ", runtime)
        self.assertIn("RUN --network=none", dockerfile)
        build = (RECIPE / "build.sh").read_text()
        for command in ["curl ", "wget ", "apt-get ", "apk "]:
            self.assertNotIn(command, build)

    def test_minimal_applet_selection(self):
        config = (RECIPE / "busybox.config").read_text()
        for selected in ["CONFIG_ASH=y", "CONFIG_PIE=y", "CONFIG_SHA256SUM=y"]:
            self.assertIn(selected, config)
        for rejected in ["CONFIG_WGET=y", "CONFIG_SU=y", "CONFIG_LOGIN=y", "CONFIG_TAR=y", "CONFIG_FEATURE_SH_MATH=y"]:
            self.assertNotIn(rejected, config)

    def test_fetch_checksum_failure(self):
        spec = importlib.util.spec_from_file_location("source_fetch", RECIPE / "fetch.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            lock = {"schema_version": 1, "patches": [], "sources": [{"url": "https://musl.libc.org/test", "filename": "test.tar.gz", "sha256": "0" * 64}]}
            lock_path = Path(tmp) / "lock.json"
            lock_path.write_text(json.dumps(lock))
            def fake_download(args, **kwargs):
                Path(args[args.index("--output") + 1]).write_bytes(b"wrong")
            with patch.object(module.subprocess, "run", side_effect=fake_download):
                with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                    module.fetch(lock_path, Path(tmp) / "downloads")
            self.assertFalse((Path(tmp) / "downloads/test.tar.gz").exists())

    def test_fetch_rejects_traversal(self):
        spec = importlib.util.spec_from_file_location("source_fetch", RECIPE / "fetch.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock.json"
            path.write_text(json.dumps({"schema_version": 1, "patches": [], "sources": [{"url": "https://musl.libc.org/test", "filename": "../bad", "sha256": hashlib.sha256(b"").hexdigest()}]}))
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                module.fetch(path, Path(tmp) / "downloads")

    def test_fetch_rejects_wrong_signature(self):
        spec = importlib.util.spec_from_file_location("source_fetch", RECIPE / "fetch.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        fingerprint = "836489290BB6B70F99FFDA0556BCDB593020450F"
        entry = {"url": "https://musl.libc.org/test", "sha256": hashlib.sha256(b"fixture").hexdigest()}
        lock = {"schema_version": 1, "patches": [], "sources": [dict(entry, filename="musl-1.2.6.tar.gz")], "verification_inputs": [dict(entry, name="musl-release-key", filename="musl.pub", fingerprint=fingerprint), dict(entry, name="musl-release-signature", filename="musl-1.2.6.tar.gz.asc")]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock.json"
            path.write_text(json.dumps(lock))
            def fake_download(args, **kwargs):
                if args[0] == "curl":
                    Path(args[args.index("--output") + 1]).write_bytes(b"fixture")
            listing = "fpr:::::::::" + fingerprint + ":\n"
            with patch.object(module.subprocess, "run", side_effect=fake_download), patch.object(module.subprocess, "check_output", side_effect=[listing, "[GNUPG:] VALIDSIG WRONGSIGNER 0\n"]):
                with self.assertRaisesRegex(ValueError, "signature does not match"):
                    module.fetch(path, Path(tmp) / "downloads")

    def test_source_built_compiler_runtime(self):
        build = (RECIPE / "build.sh").read_text()
        self.assertIn("LIBCC=/build/compiler-builtins.a", build)
        evidence = (RECIPE / "evidence.py").read_text()
        self.assertIn('line.startswith("LOAD ")', evidence)
        self.assertIn('"libgcc.a", "libgcc_eh.a", "crtbegin", "crtend"', evidence)

    @unittest.skipUnless(os.environ.get("SOURCE_IMAGE"), "Set SOURCE_IMAGE for native Docker smoke tests")
    def test_runtime(self):
        image = os.environ["SOURCE_IMAGE"]
        for flags in [[], ["--read-only", "--tmpfs", "/app:uid=65532,gid=65532", "--tmpfs", "/home/rootloom:uid=65532,gid=65532", "--tmpfs", "/tmp:mode=1777"]]:
            with self.subTest(read_only=bool(flags)):
                result = subprocess.run(["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *flags, "-i", image, "/bin/sh", "-s"], input=(RECIPE / "smoke.sh").read_text(), text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("rootloom-source-smoke-passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
