import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / "images/alpine"
source_spec = importlib.util.spec_from_file_location("alpine_runtime_source", RECIPE / "source.py")
source = importlib.util.module_from_spec(source_spec)
source_spec.loader.exec_module(source)
runtime_spec = importlib.util.spec_from_file_location("alpine_runtime", RECIPE / "runtime.py")
runtime = importlib.util.module_from_spec(runtime_spec)
with patch.dict(sys.modules, {"source": source}):
    runtime_spec.loader.exec_module(runtime)


class AlpineRuntimeContract(unittest.TestCase):
    def test_shared_audited_builder_and_scratch_final(self):
        dockerfile = (RECIPE / "Source.Dockerfile").read_text()
        self.assertIn("RUN --network=none ALPINE_SOURCE_INPUTS=", dockerfile)
        self.assertIn("sh /recipe/build.sh", dockerfile)
        self.assertIn("FROM scratch AS runtime", dockerfile)
        self.assertIn("USER 65532:65532", dockerfile)
        self.assertNotIn("apk add", dockerfile)
        self.assertNotIn("apt-get", dockerfile)
        self.assertIn("/recipe/fetch.py /recipe/sources.lock.json /downloads", dockerfile)

    def test_privileged_and_external_dependency_applets_omitted(self):
        for name in ("SU", "LOGIN", "WGET", "TLS", "SSL_CLIENT", "FEATURE_UTMP", "FEATURE_WTMP", "MOUNT", "LINUXRC"):
            self.assertNotIn(name, runtime.APPLET_CONFIG)


@unittest.skipUnless(os.environ.get("ALPINE_SOURCE_INPUTS"), "Set ALPINE_SOURCE_INPUTS for actual Alpine source configuration")
class AlpineRuntimeInputs(unittest.TestCase):
    def test_actual_config_and_patch_delta(self):
        inputs = Path(os.environ["ALPINE_SOURCE_INPUTS"]).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            recipe = Path(tmp) / "recipe"
            shutil.copytree(ROOT / "images/source-minimal", recipe, ignore=shutil.ignore_patterns("__pycache__"))
            runtime.prepare_recipe(recipe, inputs)
            lock = json.loads((recipe / "sources.lock.json").read_bytes())
            self.assertEqual(lock["distribution"]["aports_commit"], source.COMMIT)
            self.assertFalse(lock["distribution"]["package_manager"])
            alpine = source.load_lock(RECIPE / "sources.lock.json")
            expected = sum(entry["filename"].endswith(".patch") for package in alpine["packages"][2:] for entry in package["sources"])
            self.assertEqual(len(lock["patches"]), expected)
            for entry in lock["patches"]:
                filename = entry["filename"].removeprefix(entry["component"] + "-")
                self.assertEqual(entry["sha256"], source.digest((inputs / "main" / entry["component"] / filename).read_bytes()))
            config = (recipe / "busybox.config").read_text()
            self.assertIn("CONFIG_ASH=y", config)
            self.assertIn("CONFIG_AWK=y", config)
            self.assertIn("CONFIG_PIE=y", config)
            self.assertNotIn("CONFIG_FEATURE_UTMP=y", config)
            self.assertNotIn("CONFIG_WGET=y", config)
            self.assertEqual((recipe / "alpine-original-busybox.config").read_bytes(), (inputs / "main/busybox/busyboxconfig").read_bytes())


if __name__ == "__main__":
    unittest.main()
