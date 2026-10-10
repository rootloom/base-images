import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "images/debian-slim"
spec = importlib.util.spec_from_file_location("base_files_slice", ROOT / "scripts/base_files_slice.py")
slice_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(slice_module)


class DebianSourceSlice(unittest.TestCase):
    def fixture(self, directory, extra=None):
        archive = directory / "source.tar.xz"
        files = {"base-files/etc/" + name: b"Debian #OSNAME#\n" for name in
                 ("debian_version", "host.conf", "issue", "issue.net", "os-release")}
        files.update({"base-files/licenses/GPL-2": b"license", "base-files/origins/debian": b"Debian",
                      "base-files/debian/copyright": b"copyright", "base-files/debian/rules": b"recipe"})
        if extra:
            files.update(extra)
        with tarfile.open(archive, "w:xz") as tar:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                tar.addfile(member, io.BytesIO(data))
        data = archive.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        descriptor = directory / "source.dsc"
        descriptor.write_text(f"Checksums-Sha256:\n {sha} {len(data)} source.tar.xz\n")
        lock = json.loads((RECIPE / "source-slice.lock.json").read_text())
        lock.pop("verification_inputs", None)
        lock["authentication"]["status"] = "unverified-signature"
        lock["sources"] = [{"filename": p.name, "size": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in (descriptor, archive)]
        lock_path = directory / "lock.json"
        lock_path.write_text(json.dumps(lock))
        return lock_path

    def test_offline_build_and_origins(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock = self.fixture(directory)
            output = directory / "output"
            manifest = slice_module.build(directory, output, lock)
            self.assertFalse(manifest["release_qualified"])
            self.assertEqual((output / "rootfs/etc/os-release").read_bytes(), b"Debian GNU/Linux\n")
            self.assertEqual((output / "rootfs/etc/os-release").readlink().as_posix(), "../usr/lib/os-release")
            for item in manifest["files"]:
                if item["type"] == "file":
                    target = output / "rootfs" / item["path"]
                    self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), item["sha256"])
                    self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            self.assertTrue((output / "corresponding-source/source.tar.xz").is_file())

    def test_checksum_mismatch_blocks_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock = self.fixture(directory)
            (directory / "source.tar.xz").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                slice_module.build(directory, directory / "output", lock)
            self.assertFalse((directory / "output").exists())

    def test_fetch_rechecks_cached_materials(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock = self.fixture(directory)
            with patch.object(slice_module, "urlopen") as request:
                slice_module.fetch(directory, lock)
                request.assert_not_called()
                (directory / "source.tar.xz").write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "checksum"):
                    slice_module.fetch(directory, lock)

    def test_archive_traversal_blocks_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock = self.fixture(directory, {"base-files/../../escape": b"bad"})
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                slice_module.build(directory, directory / "output", lock)
            self.assertFalse((directory / "output").exists())

    def test_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock = self.fixture(directory)
            with self.assertRaisesRegex(ValueError, "must not exist"):
                slice_module.build(directory, directory, lock)

    def test_unverified_signature_claim_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock_path = self.fixture(directory)
            lock = json.loads(lock_path.read_text())
            lock["authentication"]["status"] = "descriptor-signature-verified"
            lock_path.write_text(json.dumps(lock))
            with self.assertRaisesRegex(ValueError, "requires a pinned key"):
                slice_module.build(directory, directory / "output", lock_path)
            self.assertFalse((directory / "output").exists())

    def test_unexpected_descriptor_signer_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            lock_path = self.fixture(directory)
            (directory / "key.asc").write_bytes(b"key")
            lock = json.loads(lock_path.read_text())
            lock["verification_inputs"] = [{"filename": "key.asc", "size": 3,
                "sha256": hashlib.sha256(b"key").hexdigest(), "fingerprint": "A" * 40}]
            lock_path.write_text(json.dumps(lock))
            with patch.object(slice_module.subprocess, "run") as run:
                run.return_value.stdout = "[GNUPG:] VALIDSIG " + "B" * 40 + "\n"
                with self.assertRaisesRegex(ValueError, "Unexpected descriptor signer"):
                    slice_module.build(directory, directory / "output", lock_path)
            self.assertFalse((directory / "output").exists())

    def test_lock_does_not_claim_complete_image(self):
        lock = json.loads((RECIPE / "source-slice.lock.json").read_text())
        self.assertFalse(lock["release_qualified"])
        self.assertEqual(lock["authentication"]["status"], "descriptor-signature-verified")
        self.assertEqual(lock["verification_inputs"][0]["fingerprint"], "D54C3BFAFFB042DE382DA5D741CE7F0B9F1B8B32")
        for source in lock["sources"]:
            self.assertRegex(source["sha256"], r"^[a-f0-9]{64}$")
            self.assertTrue(source["url"].startswith("https://deb.debian.org/"))

    def test_ubuntu_inputs_are_not_debian_inputs(self):
        debian = json.loads((RECIPE / "source-slice.lock.json").read_text())
        ubuntu = json.loads((ROOT / "images/ubuntu/source-slice.lock.json").read_text())
        self.assertEqual(ubuntu["vendor"], "ubuntu")
        self.assertEqual(ubuntu["version"], "13ubuntu10.5")
        self.assertNotEqual(ubuntu["sources"][1]["sha256"], debian["sources"][1]["sha256"])
        self.assertFalse(ubuntu["release_qualified"])


if __name__ == "__main__":
    unittest.main()
