import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "images/alpine"
spec = importlib.util.spec_from_file_location("alpine_source", RECIPE / "source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
LOCK = RECIPE / "sources.lock.json"
INPUTS = os.environ.get("ALPINE_SOURCE_INPUTS")


class AlpineSourceContract(unittest.TestCase):
    def test_distribution_versions_and_inputs(self):
        lock = source.load_lock(LOCK)
        self.assertEqual(lock["branch"], "3.24-stable")
        versions = {item["name"]: (item["version"], item["revision"]) for item in lock["packages"]}
        self.assertEqual(versions, {"alpine-baselayout": ("3.7.2", 1), "alpine-base": ("3.24.2", 0),
                                    "musl": ("1.2.6", 2), "busybox": ("1.37.0", 31)})
        for package in lock["packages"]:
            self.assertTrue(package["license"])
            self.assertTrue(any(item["path"].endswith("/APKBUILD") for item in package["recipe_files"]))
            for item in package["recipe_files"]:
                self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
            for item in package["sources"]:
                self.assertRegex(item["sha512"], r"^[0-9a-f]{128}$")

    def test_alpine_runtime_patches_and_configuration_are_locked(self):
        lock = source.load_lock(LOCK)
        packages = {item["name"]: item for item in lock["packages"]}
        musl = {item["filename"] for item in packages["musl"]["sources"]}
        self.assertIn("CVE-2026-40200.patch", musl)
        self.assertIn("CVE-2026-6042.patch", musl)
        self.assertIn("__stack_chk_fail_local.c", musl)
        busybox = {item["filename"] for item in packages["busybox"]["sources"]}
        self.assertIn("busyboxconfig", busybox)
        self.assertIn("0035-cpio-map-F-to-file-long-option.patch", busybox)
        self.assertGreater(sum(name.endswith(".patch") for name in busybox), 40)

    def test_path_traversal_is_rejected(self):
        for name in ("/etc/passwd", "../../runtime", "main/../escape"):
            with self.assertRaises(ValueError):
                source.safe_path(name)

    def test_install_adapter_modes_and_target_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "source"
            data.write_text("data\n")
            target = root / "nested/hooks"
            source.install(["-Dm755", str(data), "-t", str(target)])
            self.assertEqual((target / "source").read_bytes(), data.read_bytes())
            self.assertEqual((target / "source").stat().st_mode & 0o777, 0o755)
            source.install(["-d", "-m", "1777", str(root / "tmp")])
            self.assertEqual((root / "tmp").stat().st_mode & 0o7777, 0o1777)

    def test_archive_tamper_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "archive"
            archive.write_bytes(b"not aports")
            with self.assertRaisesRegex(ValueError, "archive checksum"):
                source.archive_files(archive)


@unittest.skipUnless(INPUTS, "Set ALPINE_SOURCE_INPUTS to fetched, verified primary inputs")
class AlpinePrimaryInputBuild(unittest.TestCase):
    def test_all_primary_inputs_verify(self):
        source.verify(LOCK, INPUTS)

    def test_lock_generation_matches_reviewed_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "lock.json"
            source.make_lock(Path(INPUTS) / "aports.tar.gz", output)
            self.assertEqual(output.read_bytes(), LOCK.read_bytes())

    def test_local_source_tamper_blocks_build(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs"
            shutil.copytree(INPUTS, inputs)
            (inputs / "main/alpine-baselayout/passwd").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "Recipe checksum mismatch"):
                source.build_layout(LOCK, inputs, Path(directory) / "output")
            self.assertFalse((Path(directory) / "output").exists())

    def test_external_source_tamper_blocks_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs"
            shutil.copytree(INPUTS, inputs)
            (inputs / "main/alpine-baselayout/protocols-6.4").write_text("tampered\n")
            with self.assertRaisesRegex(ValueError, "Source checksum mismatch"):
                source.verify(LOCK, inputs)

    def test_actual_offline_layout_recipes_repeat_and_preserve_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            source.build_layout(LOCK, INPUTS, first)
            source.build_layout(LOCK, INPUTS, second)
            self.assertEqual((first / "layout-evidence.json").read_bytes(),
                             (second / "layout-evidence.json").read_bytes())
            root = first / "rootfs"
            self.assertEqual((root / "etc/alpine-release").read_text(), "3.24.2\n")
            self.assertIn("VERSION_ID=3.24.2", (root / "etc/os-release").read_text())
            self.assertTrue((root / "etc/os-release").is_symlink())
            self.assertIn("rootloom:x:65532:65532:", (root / "etc/passwd").read_text())
            self.assertIn("root:!:", (root / "etc/shadow").read_text())
            self.assertEqual((root / "etc/passwd").stat().st_mode & 0o777, 0o444)
            evidence = json.loads((first / "layout-evidence.json").read_text())
            self.assertIn("not runnable", evidence["status"])
            records = {record["path"]: record for record in evidence["files"]}
            self.assertEqual(records["app"]["uid"], 65532)
            self.assertEqual(records["home/rootloom"]["gid"], 65532)
            self.assertNotIn("bin/busybox", records)
            for record in records.values():
                if record["type"] == "file":
                    self.assertTrue(record["source"])
                    self.assertFalse((root / record["path"]).read_bytes().startswith(b"\x7fELF"))
            with self.assertRaisesRegex(ValueError, "must be empty"):
                source.build_layout(LOCK, INPUTS, first)

    def test_alpine_runtime_patch_sets_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            source.prepare_runtime(LOCK, INPUTS, directory)
            root = Path(directory)
            musl = root / "musl-1.2.6"
            self.assertEqual((musl / "VERSION").read_text(), "1.2.6\n")
            self.assertFalse((musl / "src/string/x86_64/memcpy.s").exists())
            self.assertEqual((root / "busybox-1.37.0/.config").read_bytes(),
                             (Path(INPUTS) / "main/busybox/busyboxconfig").read_bytes())
            evidence = json.loads((root / "runtime-source-evidence.json").read_text())
            self.assertEqual(len(evidence["packages"]), 2)
            self.assertGreater(len(list(root.glob("*.patch.log"))), 40)


if __name__ == "__main__":
    unittest.main()
