"""Check real GNU bootstrap inputs and native build evidence when supplied."""

import hashlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
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
    def constant_runtime(self):
        from test_source_origins import compiler, headers, origins

        spec = importlib.util.spec_from_file_location("gnu_runtime", ROOT / "images/debian-slim/runtime.py")
        runtime = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"compiler": compiler, "headers": headers, "origins": origins}):
            spec.loader.exec_module(runtime)
        return runtime

    def test_runtime_loader_does_not_require_prior_compiler_import(self):
        with patch.dict(sys.modules):
            sys.modules.pop("compiler", None)
            runtime = self.constant_runtime()
            self.assertTrue(callable(runtime.generated_inputs))

    def test_constant_replay_requires_verified_scripts_symbols_and_stdin(self):
        runtime = self.constant_runtime()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "scripts").mkdir()
            retained = root / "retained"
            retained.mkdir()
            symbol = root / "offsets.sym"
            symbol.write_bytes(b"offset\n")
            extract = root / "scripts/glibcextract.py"
            extract.write_text("import subprocess\nimport tempfile\nfrom pathlib import Path\n"
                "def compute():\n"
                "    with tempfile.TemporaryDirectory() as d:\n"
                "        c, s = Path(d) / 'test.c', Path(d) / 'test.s'\n"
                "        c.write_bytes(b'verified stdin')\n"
                "        subprocess.check_call(f'replay -S -o {s} -x c - < {c}', shell=True)\n"
                "        return s.read_text()\n")
            script = root / "scripts/gen-as-const.py"
            script.write_text("import glibcextract\nimport sys\nfrom pathlib import Path\n"
                "def main():\n"
                "    if Path(sys.argv[-1]).read_bytes() != b'offset\\n':\n"
                "        raise ValueError('unknown symbol')\n"
                "    print(glibcextract.compute(), end='')\n")
            index = {str(path): {"component": "glibc", "sha256": runtime.sha256(path)}
                     for path in (symbol, script, extract)}
            assembly = b"#define offset 7\n"
            producer = runtime.replay_constants(root, symbol, b"verified stdin", assembly, index, retained)
            self.assertEqual(producer["sha256"], hashlib.sha256(assembly).hexdigest())
            self.assertEqual(len(producer["inputs"]), 3)
            generations = root / "generation"
            (generations / "inputs").mkdir(parents=True)
            header = root / "source.h"
            header.write_bytes(b"verified dependency")
            index[str(header)] = {"component": "glibc", "sha256": runtime.sha256(header)}
            stdin_digest = hashlib.sha256(b"verified stdin").hexdigest()
            (generations / "inputs" / stdin_digest).write_bytes(b"verified stdin")
            (generations / "inputs" / runtime.sha256(header)).write_bytes(header.read_bytes())
            (generations / "probe.s").write_bytes(assembly)
            (generations / "probe.d").write_text("test.s: " + str(header) + "\n")
            record = {"cwd": str(root), "inputs": [{"path": "<stdin>", "sha256": stdin_digest},
                                  {"path": str(header), "sha256": runtime.sha256(header)}],
                      "assembly": "probe.s", "assembly_sha256": runtime.sha256(generations / "probe.s"),
                      "dependencies": "probe.d", "dependencies_sha256": runtime.sha256(generations / "probe.d")}
            (generations / "probe.json").write_text(json.dumps(record))
            producers = runtime.constant_inputs(root, index, retained, generations, {}, root)
            proof = producers[producer["sha256"]]
            self.assertEqual(proof["generation_record_sha256"], runtime.sha256(generations / "probe.json"))
            self.assertEqual(proof["generation_inputs"][0]["sha256"], runtime.sha256(header))
            evidence = root / "evidence"
            (evidence / "sources").mkdir(parents=True)
            (evidence / "sources/generation").symlink_to(generations, target_is_directory=True)
            (evidence / "runtime-inputs").symlink_to(retained, target_is_directory=True)
            traced = evidence / "sources/trace-inputs"
            traced.mkdir()
            (traced / proof["sha256"]).write_bytes(assembly)
            record.update({"command": ["gcc", "-S"], "output_sha256": record["assembly_sha256"]})
            (generations / "probe.json").write_text(json.dumps(record))
            proof["generation_record_sha256"] = runtime.sha256(generations / "probe.json")
            snapshot = dict(index)
            for source in proof["inputs"]:
                original = source["path"]
                source["path"] = "/build/glibc/glibc-2.41/" + str(Path(original).relative_to(root))
                snapshot[source["path"]] = snapshot[original]
            receipt = {"verified_inputs": {"/build/glibc-runtime/offsets.h": proof}, "unknown_inputs": {},
                       "generation_records": {"probe.json": proof["generation_record_sha256"]}}
            compilation = evidence / "sources/compilation"
            compilation.mkdir()
            (compilation / "probe.json").write_text(json.dumps({"inputs": [
                {"path": "/build/glibc-runtime/offsets.h", "sha256": proof["sha256"]}]}))
            self.assertEqual(runtime.verify_constant_proofs(evidence, receipt, snapshot), 1)
            (generations / "relative.d").write_text("test.s: ../source.h\n")
            relative = {**record, "cwd": str(root / "subdir"), "dependencies": "relative.d",
                        "dependencies_sha256": runtime.sha256(generations / "relative.d")}
            (generations / "relative.json").write_text(json.dumps(relative))
            receipt["generation_records"]["relative.json"] = runtime.sha256(generations / "relative.json")
            with patch.dict(proof, {"generation_record": "relative.json",
                                   "generation_record_sha256": receipt["generation_records"]["relative.json"]}):
                self.assertEqual(runtime.verify_constant_proofs(evidence, receipt, snapshot), 1)
            (generations / "relative.json").unlink()
            blocked = {"sha256": runtime.sha256(header), "admitted": False}
            with patch.dict(receipt["verified_inputs"], {str(header): blocked}), patch.dict(
                    proof, {"generation_inputs": [{"path": str(header),
                            "sha256": runtime.sha256(header), "producer": blocked}]}):
                with self.assertRaisesRegex(ValueError, "Unverified generated constant dependency"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            (generations / "other.d").write_text("test.s: " + str(header) + " /unlisted.h\n")
            wrong = {**record, "dependencies": "other.d",
                     "dependencies_sha256": runtime.sha256(generations / "other.d")}
            (generations / "other.json").write_text(json.dumps(wrong))
            receipt["generation_records"]["other.json"] = runtime.sha256(generations / "other.json")
            with patch.dict(proof, {"generation_record": "other.json",
                                   "generation_record_sha256": receipt["generation_records"]["other.json"]}):
                with self.assertRaisesRegex(ValueError, "dependency list differs"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            (generations / "other.json").unlink()
            with patch.dict(receipt["unknown_inputs"], {"/build/glibc-runtime/offsets.h": proof["sha256"]}):
                with self.assertRaisesRegex(ValueError, "verified compiler input"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            with patch.dict(receipt, {"verified_inputs": {"/build/glibc-runtime/not-consumed.h": proof}}):
                with self.assertRaisesRegex(ValueError, "verified compiler input"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            for field, bad in (("generation_record", "missing.json"),
                               ("generation_record_sha256", "0" * 64),
                               ("stdin_sha256", "0" * 64),
                               ("generation_inputs", []),
                               ("generation_inputs", [{"path": str(header), "sha256": "0" * 64,
                                                       "component": "glibc"}]),
                               ("sha256", "0" * 64)):
                with self.subTest(field=field, bad=bad):
                    original = proof[field]
                    proof[field] = bad
                    with self.assertRaises(ValueError):
                        runtime.verify_constant_proofs(evidence, receipt, snapshot)
                    proof[field] = original
            for path in (generations / "probe.json", generations / "probe.s", generations / "probe.d",
                         generations / "inputs" / runtime.sha256(header),
                         generations / "inputs" / stdin_digest,
                         retained / proof["inputs"][0]["sha256"], traced / proof["sha256"]):
                with self.subTest(tampered=str(path)):
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed")
                    with self.assertRaises(ValueError):
                        runtime.verify_constant_proofs(evidence, receipt, snapshot)
                    path.write_bytes(original)
                    path.unlink()
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        runtime.verify_constant_proofs(evidence, receipt, snapshot)
                    path.write_bytes(original)
            wrong = {**record, "inputs": [{"path": "<stdin>", "sha256": stdin_digest}]}
            (generations / "other.json").write_text(json.dumps(wrong))
            receipt["generation_records"]["other.json"] = runtime.sha256(generations / "other.json")
            with patch.dict(proof, {"generation_record": "other.json",
                                   "generation_record_sha256": receipt["generation_records"]["other.json"]}):
                with self.assertRaisesRegex(ValueError, "dependency list differs"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            (generations / "other.json").unlink()
            wrong = {**record, "object": "/build/bootstrap.o"}
            (generations / "other.json").write_text(json.dumps(wrong))
            receipt["generation_records"]["other.json"] = runtime.sha256(generations / "other.json")
            with patch.dict(proof, {"generation_record": "other.json",
                                   "generation_record_sha256": receipt["generation_records"]["other.json"]}):
                with self.assertRaisesRegex(ValueError, "not assembly"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            (generations / "other.json").unlink()
            (generations / "other.s").write_bytes(b"#define offset 8\n")
            wrong = {**record, "assembly": "other.s", "assembly_sha256": runtime.sha256(generations / "other.s"),
                     "output_sha256": runtime.sha256(generations / "other.s")}
            (generations / "other.json").write_text(json.dumps(wrong))
            receipt["generation_records"]["other.json"] = runtime.sha256(generations / "other.json")
            with patch.dict(proof, {"generation_record": "other.json",
                                   "generation_record_sha256": receipt["generation_records"]["other.json"]}):
                with self.assertRaisesRegex(ValueError, "replay output mismatch"):
                    runtime.verify_constant_proofs(evidence, receipt, snapshot)
            (generations / "other.json").unlink()
            unknown = dict(snapshot)
            unknown.pop(str(header))
            with self.assertRaisesRegex(ValueError, "Unverified constant dependency"):
                runtime.verify_constant_proofs(evidence, receipt, unknown)
            unknown_digest = hashlib.sha256(b"unknown producer stdin").hexdigest()
            (generations / "inputs" / unknown_digest).write_bytes(b"unknown producer stdin")
            record["inputs"][0]["sha256"] = unknown_digest
            (generations / "probe.json").write_text(json.dumps(record))
            self.assertEqual(runtime.constant_inputs(root, index, retained, generations, {}, root), {})
            (generations / "probe.s").write_bytes(b"changed assembly")
            with self.assertRaisesRegex(ValueError, "evidence changed"):
                runtime.constant_inputs(root, index, retained, generations, {}, root)
            with self.assertRaisesRegex(ValueError, "stdin mismatch"):
                runtime.replay_constants(root, symbol, b"unknown stdin", assembly, index, retained)
            for path in (symbol, script, extract):
                data = path.read_bytes()
                path.write_bytes(data + b"# changed\n")
                with self.assertRaises(ValueError):
                    runtime.replay_constants(root, symbol, b"verified stdin", assembly, index, retained)
                path.write_bytes(data)

    def test_native_constant_acceptance_requires_actual_producer(self):
        runtime = self.constant_runtime()
        for producers in ({}, {"/build/glibc-runtime/config.h": {"recipe_sha256": "a" * 64}}):
            with self.subTest(producers=producers), self.assertRaisesRegex(ValueError, "Missing actual constant producer"):
                runtime.verify_constant_proofs(Path("unused"), {"verified_inputs": producers}, {})

    def test_module_source_rule_keeps_unproved_dependency_blocked(self):
        runtime = self.constant_runtime()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            libc = root / "libc"
            (libc / "scripts").mkdir(parents=True)
            (libc / "Makeconfig").write_text("built-modules = fixture\n\n"
                "$(common-objpfx)libc-modules.h: $(common-objpfx)libc-modules.stmp; @:\n"
                "$(common-objpfx)libc-modules.stmp: $(..)scripts/gen-libc-modules.awk \\\n"
                "    $(common-objpfx)soversions.i\n"
                '\t$(AWK) -v buildlist="$(subst -,_,$(built-modules))" -f $^ > ${@:stmp=T}\n'
                "\t$(move-if-change) ${@:stmp=T} ${@:stmp=h}\n\ttouch $@\n\n")
            (libc / "scripts/gen-libc-modules.awk").write_text(
                'BEGIN { print "#define MODULE_" buildlist " 1" }\n')
            (libc / "scripts/move-if-change").write_text('mv "$1" "$2"\n')
            index = {str(path): {"component": "glibc", "sha256": runtime.sha256(path)}
                     for path in (libc / "Makeconfig", *sorted((libc / "scripts").iterdir()))}
            retained = root / "runtime-inputs"
            retained.mkdir()
            dependency = root / "soversions.i"
            dependency.write_bytes(b"DEFAULT libc 6\n")
            proof = runtime.replay_modules(libc, index, retained, dependency,
                                           b"#define MODULE_fixture 1\n")
            snapshot = {}
            for item in proof["inputs"]:
                original = item["path"]
                item["path"] = "/build/glibc/glibc-2.41/" + str(Path(original).relative_to(libc))
                snapshot[item["path"]] = index[original]
            self.assertFalse(runtime.verify_modules_proof(root, proof, snapshot))
            self.assertEqual(proof["blocked_inputs"], ["/build/glibc-runtime/soversions.i"])
            with patch.dict(proof, {"admitted": True}):
                with self.assertRaisesRegex(ValueError, "Unclosed"):
                    runtime.verify_modules_proof(root, proof, snapshot)
            with patch.dict(proof, {"inputs": proof["inputs"] + [proof["inputs"][0]]}):
                with self.assertRaisesRegex(ValueError, "dependency list differs"):
                    runtime.verify_modules_proof(root, proof, snapshot)
            with patch.dict(proof, {"generated_inputs": proof["generated_inputs"] + [
                    {"path": "/unlisted.h", "sha256": "a" * 64}]}):
                with self.assertRaisesRegex(ValueError, "dependency list differs"):
                    runtime.verify_modules_proof(root, proof, snapshot)
            with self.assertRaisesRegex(ValueError, "Unverified module"):
                runtime.verify_modules_proof(root, proof, {})
            for item in proof["inputs"] + proof["generated_inputs"] + [
                    {"sha256": proof["sha256"]}, {"sha256": proof["recipe_sha256"]}]:
                path = retained / item["sha256"]
                data = path.read_bytes()
                path.write_bytes(data + b"tampered")
                with self.assertRaisesRegex(ValueError, "evidence changed"):
                    runtime.verify_modules_proof(root, proof, snapshot)
                path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "output mismatch"):
                runtime.replay_modules(libc, index, retained, dependency, b"wrong output")
            (libc / "scripts/gen-libc-modules.awk").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "Unverified module"):
                runtime.replay_modules(libc, index, retained, dependency, b"wrong output")

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_pinned_module_source_rule_replays_fixture_dependency(self):
        runtime = self.constant_runtime()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            libc = root / "libc"
            (libc / "scripts").mkdir(parents=True)
            retained = root / "retained"
            retained.mkdir()
            index = {}
            archive_path = Path(os.environ["GNU_BOOTSTRAP_INPUTS"]) / "glibc_2.41.orig.tar.xz"
            materials = next(source[-1] for source in BOOTSTRAP.SOURCES if source[0] == "glibc")
            digest = next(digest for name, digest in materials if name == archive_path.name)
            self.assertEqual(runtime.sha256(archive_path), digest)
            with tarfile.open(archive_path) as tar:
                for name in ("Makeconfig", "scripts/gen-libc-modules.awk", "scripts/move-if-change"):
                    path = libc / name
                    path.write_bytes(tar.extractfile("glibc-2.41/" + name).read())
                    index[str(path)] = {"component": "glibc", "sha256": runtime.sha256(path)}
            text = (libc / "Makeconfig").read_text()
            modules = re.search(r"^built-modules = (.*?)(?=^\n)", text, re.M | re.S).group(1)
            modules = " ".join(modules.replace("\\\n", " ").split()).replace("-", "_")
            dependency = root / "soversions.i"
            dependency.write_bytes(b"DEFAULT libc 6\nDEFAULT ld ld.so.1\n")
            expected = subprocess.check_output(["awk", "-v", "buildlist=" + modules, "-f",
                str(libc / "scripts/gen-libc-modules.awk"), str(dependency)])
            proof = runtime.replay_modules(libc, index, retained, dependency, expected)
            self.assertEqual(proof["sha256"], hashlib.sha256(expected).hexdigest())
            self.assertFalse(proof["admitted"])
            self.assertIn(b"MODULE_libc", expected)

    def test_unknown_constant_dependency_has_no_producer_admission(self):
        runtime = self.constant_runtime()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generations = root / "generation"
            (generations / "inputs").mkdir(parents=True)
            data = b"unknown dependency"
            digest = hashlib.sha256(data).hexdigest()
            (generations / "inputs" / digest).write_bytes(data)
            for name in ("probe.s", "probe.d"):
                (generations / name).write_bytes(data)
            record = {"inputs": [{"path": "<stdin>", "sha256": digest},
                                  {"path": str(root / "unknown.h"), "sha256": digest}],
                      "assembly": "probe.s", "assembly_sha256": digest,
                      "dependencies": "probe.d", "dependencies_sha256": digest}
            (generations / "probe.json").write_text(json.dumps(record))
            with patch.object(runtime, "replay_constants") as replay:
                self.assertEqual(runtime.constant_inputs(root, {}, root, generations, {}, root), {})
                replay.assert_not_called()

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS"), "Real GNU source inputs are required")
    def test_vendor_constant_scripts_replay_exact_stdin_and_assembly(self):
        runtime = self.constant_runtime()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "scripts").mkdir()
            retained = root / "retained"
            retained.mkdir()
            paths = [root / "scripts/gen-as-const.py", root / "scripts/glibcextract.py"]
            with tarfile.open(Path(os.environ["GNU_BOOTSTRAP_INPUTS"]) / "glibc_2.41.orig.tar.xz") as archive:
                for path in paths:
                    path.write_bytes(archive.extractfile("glibc-2.41/" + str(path.relative_to(root))).read())
            symbol = root / "constants.sym"
            symbol.write_text("#define VALUE 7\nVALUE\n")
            index = {str(path): {"component": "glibc", "sha256": runtime.sha256(path)}
                     for path in [*paths, symbol]}
            stdin = (b"#define VALUE 7\nvoid\ndummy (void)\n{\n"
                     b'asm ("/* @@@name@@@VALUE@@@value@@@%0@@@end@@@ */" '
                     b': : "i" ((long int) (VALUE)));\n}\n')
            assembly = b"/* @@@name@@@VALUE@@@value@@@$7@@@end@@@ */\n"
            producer = runtime.replay_constants(root, symbol, stdin, assembly, index, retained)
            self.assertEqual(producer["sha256"], hashlib.sha256(b"#define VALUE 7\n").hexdigest())
            with self.assertRaisesRegex(ValueError, "stdin mismatch"):
                runtime.replay_constants(root, symbol, stdin + b"changed", assembly, index, retained)

    def test_temporary_stdin_generation_retains_bytes_and_vendor_dependencies(self):
        from test_source_origins import trace

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence = root / "generation"
            output = root / "test.s"
            header = root / "source.h"
            header.write_bytes(b"#define VALUE 7\n")
            vendor = root / "vendor.d"
            explicit = root / "vendor.dt"
            joined = root / "vendor-joined.dt"
            args = ["-S", "-o", str(output), "-x", "c", "-", "-pipe",
                    "-Wp,-MD," + str(vendor), "-MF", str(explicit), "-MF" + str(joined)]

            def compile_probe(command, **options):
                self.assertEqual(command.count("-MF"), 1)
                self.assertNotIn("-pipe", command)
                self.assertNotIn(str(explicit), command)
                self.assertNotIn("-MF" + str(joined), command)
                self.assertEqual(options["input"], data)
                self.assertIs(options["check"], True)
                output.write_bytes(b"/* @@@name@@@VALUE@@@value@@@7@@@end@@@ */\n")
                Path(command[-1]).write_text("test.s: " + str(header) + "\n")

            with patch.object(trace, "GENERATIONS", evidence), \
                    patch.object(trace, "GENERATION_ROOTS", (root,)), \
                    patch.object(trace.subprocess, "run", side_effect=compile_probe), \
                    patch.object(trace.compiler, "main") as objects, patch.object(trace.sys, "stdin") as stream:
                for data in (b"void dummy(void) { /* first */ }\n", b"void dummy(void) { /* second */ }\n",
                             b"void dummy(void) { /* second */ }\n"):
                    stream.buffer = io.BytesIO(data)
                    trace.main(args)
                objects.assert_not_called()
            records = list(evidence.glob("*.json"))
            self.assertEqual(len(records), 3)
            for path in records:
                record = json.loads(path.read_text())
                self.assertNotIn("object", record)
                self.assertEqual(record["output"], str(output))
                self.assertEqual(record["output_sha256"], record["assembly_sha256"])
                self.assertEqual(record["inputs"][0]["path"], "<stdin>")
                self.assertEqual(record["inputs"][1]["path"], str(header))
                for item in record["inputs"]:
                    retained = evidence / "inputs" / item["sha256"]
                    self.assertEqual(hashlib.sha256(retained.read_bytes()).hexdigest(), item["sha256"])
                for field in ("dependencies", "assembly"):
                    self.assertEqual(hashlib.sha256((evidence / record[field]).read_bytes()).hexdigest(),
                                     record[field + "_sha256"])
                for destination in (vendor, explicit, joined):
                    self.assertEqual(destination.read_bytes(), (evidence / record["dependencies"]).read_bytes())

    def test_generation_rejects_response_files_and_assembler_imports(self):
        from test_source_origins import trace

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            output = root / "test.s"
            args = ["-S", "-o", str(output), "source.c"]
            with patch.object(trace, "GENERATIONS", root / "generation"), \
                    patch.object(trace, "GENERATION_ROOTS", (root,)), \
                    patch.object(trace.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "response file"):
                    trace.main([*args, "@unreviewed"])
                run.assert_not_called()
                output.write_text('.incbin "unreviewed"\n')
                with self.assertRaisesRegex(ValueError, "Assembler file imports"):
                    trace.main(args)
                self.assertFalse(list((root / "generation").glob("*.json")))

    def test_generation_resolved_output_cannot_escape_traced_root(self):
        from test_source_origins import trace

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            allowed = root / "allowed"
            allowed.mkdir()
            (allowed / "escape").symlink_to(root, target_is_directory=True)
            args = ["-S", "-o", str(allowed / "escape/test.s"), "source.c"]
            with patch.object(trace, "GENERATION_ROOTS", (allowed,)), \
                    patch.object(trace.compiler, "main") as fallback, \
                    patch.object(trace.subprocess, "run") as run:
                trace.main(args)
                fallback.assert_called_once_with(args)
                run.assert_not_called()

    def runtime_sources(self, root, evidence, machine):
        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        materials = next(source[-1] for source in BOOTSTRAP.SOURCES if source[0] == "glibc")
        for name, digest in materials:
            self.assertEqual(hashlib.sha256((inputs / name).read_bytes()).hexdigest(), digest, name)
        snapshot = json.loads((evidence / "glibc.source-files.json").read_text())
        sysdirs = ["sysdeps/x86_64/64", "sysdeps/x86"] if machine == "x86_64" else ["sysdeps/aarch64"]
        names = ["math/Makefile", "locale/Makefile", "locale/gen-translit.py", "locale/C-translit.h.in",
                 "csu/Makefile", "abi-tags", "Makerules", "libc-abis", "scripts/gen-libc-abis",
                 "elf/Makefile", "posix/Makefile", "posix/posix-conf-vars.list", "scripts/gen-posix-conf-vars.awk",
                 "sysdeps/unix/sysv/linux/" + ("x86" if machine == "x86_64" else "aarch64") + "/Makefile",
                 "scripts/move-if-change", "Makeconfig", "scripts/gen-tunables.awk", *[
                     name + "/dl-tunables.list" for name in ["elf", "sysdeps/nptl", *sysdirs]]]
        report = json.loads((evidence / "gnu-libc-trace.json").read_text())
        for producer in report.get("verified_inputs", {}).values():
            if producer.get("replay") == "verified-stdin-retained-assembly":
                names.extend(str(Path(source["path"]).relative_to("/build/glibc/glibc-2.41"))
                             for source in producer["inputs"])
        names = list(dict.fromkeys(names))
        index = {}
        with tarfile.open(Path(os.environ["GNU_BOOTSTRAP_INPUTS"]) / "glibc_2.41.orig.tar.xz") as archive:
            for name in names:
                self.assertNotIn("..", Path(name).parts)
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive.extractfile("glibc-2.41/" + name).read())
                index[str(path)] = snapshot["/build/glibc/glibc-2.41/" + name]
        bootstrap = json.loads((evidence / "bootstrap.json").read_text())
        vendor = next(item for item in bootstrap["sources"] if item["name"] == "glibc")
        patches = {item["path"]: item["sha256"] for item in vendor["patches"]}
        with tarfile.open(Path(os.environ["GNU_BOOTSTRAP_INPUTS"]) / "glibc_2.41-12+deb13u4.debian.tar.xz") as archive:
            series = archive.extractfile("debian/patches/series").read().decode().splitlines()
            for line in series:
                fields = line.split("#", 1)[0].split()
                if not fields:
                    continue
                self.assertEqual(len(fields), 1, "Replay requires declared patch strip options")
                data = archive.extractfile("debian/patches/" + fields[0]).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(), patches[fields[0]])
                subprocess.run(["git", "apply", "-p1", *["--include=" + name for name in names]],
                               input=data, cwd=root, check=True)
        for path, source in index.items():
            self.assertEqual(hashlib.sha256(Path(path).read_bytes()).hexdigest(), source["sha256"], path)
        return index

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE"),
                         "Real GNU source and runtime inputs are required")
    def test_runtime_sources_match_vendor_patch_snapshot(self):
        evidence = Path(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"])
        machine = json.loads((evidence / "gnu-libc-trace.json").read_text())["machine"]
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(self.runtime_sources(Path(directory).resolve(), evidence, machine))

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE"),
                         "Real GNU source and runtime inputs are required")
    def test_loader_stub_source_recipe_replays(self):
        from test_source_origins import headers

        runtime = self.constant_runtime()
        evidence = Path(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"])
        report = json.loads((evidence / "gnu-libc-trace.json").read_text())
        name = "/build/glibc-runtime/elf/librtld.mapT.o.stdin.s"
        expected = report["unknown_inputs"].get(name) or report["verified_inputs"][name]["sha256"]
        constructor = tempfile.TemporaryDirectory
        with constructor() as directory:
            root = Path(directory).resolve()
            retained = root / "retained"
            retained.mkdir()
            index = self.runtime_sources(root, evidence, report["machine"])
            with patch.object(headers.tempfile, "TemporaryDirectory", side_effect=lambda **kw: constructor(dir=root)):
                producer = runtime.loader_input(root, index, retained)
                self.assertEqual(producer["sha256"], expected)
                self.assertEqual(headers.sha256(retained / producer["recipe_sha256"]), producer["recipe_sha256"])
                makefile = root / "elf/Makefile"
                makefile.write_text(makefile.read_text().replace("  calloc ", "  unverified_symbol "))
                with self.assertRaises(ValueError):
                    runtime.loader_input(root, index, retained)

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE")
                         and shutil.which("gawk"), "Real GNU source, runtime inputs, and GNU awk are required")
    def test_runtime_recipes_reproduce_consumed_inputs(self):
        from test_source_origins import headers, origins

        runtime = self.constant_runtime()
        evidence = Path(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"])
        report = json.loads((evidence / "gnu-libc-trace.json").read_text())
        machine = report["machine"]
        constructor = tempfile.TemporaryDirectory
        with constructor() as directory:
            root = Path(directory).resolve()
            retained = root / "retained"
            retained.mkdir()
            index = self.runtime_sources(root, evidence, machine)
            with patch.object(headers.tempfile, "TemporaryDirectory", side_effect=lambda **kw: constructor(dir=root)):
                generated = runtime.generated_inputs(root, index, retained, machine, shutil.which("gawk"))
            expected = {**report["unknown_inputs"], **{
                name: producer["sha256"] for name, producer in report.get("verified_inputs", {}).items()}}
            matched = 0
            for relative, producer in generated.items():
                name = "/build/glibc-runtime/" + relative
                if name not in expected:
                    continue
                matched += 1
                self.assertEqual(producer["sha256"], expected[name])
                self.assertTrue(producer["command"])
                self.assertEqual(headers.sha256(retained / producer["recipe_sha256"]), producer["recipe_sha256"])
                for source in producer["inputs"]:
                    self.assertEqual(headers.sha256(retained / source["sha256"]), source["sha256"])
            self.assertGreaterEqual(matched, 10)
            (root / "math/Makefile").write_text("gen-calls = unverifiedF\n")
            with self.assertRaises(ValueError):
                origins.input_origin(root / "math/Makefile", index)

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_RUNTIME_TRACE_EVIDENCE"),
                         "Native GNU runtime trace and upstream source inputs are required")
    def test_native_runtime_trace_stays_unqualified(self):
        evidence = Path(os.environ["GNU_RUNTIME_TRACE_EVIDENCE"])
        record = json.loads((evidence / "gnu-libc-trace.json").read_text())
        self.assertEqual(record["scope"], "gnu-runtime-trace")
        self.assertIs(record["release_qualified"], False)
        self.assertIs(record["completed"], True)
        self.assertIn(record["machine"], ("x86_64", "aarch64"))
        self.assertGreater(record["compiler_records"], 0)
        self.assertEqual(record["compiler_records"], len(list((evidence / "sources/compilation").glob("*.json"))))
        self.assertEqual(record["header_audit_sha256"], hashlib.sha256((evidence / "gnu-headers.json").read_bytes()).hexdigest())
        self.assertRegex(record["libc_sha256"], r"^[a-f0-9]{64}$")
        self.assertTrue(record["link_maps"])
        self.assertGreaterEqual(len(record["generation_records"]), 4)
        generations = evidence / "sources/generation"
        outputs = set()
        for name, digest in record["generation_records"].items():
            path = generations / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            generation = json.loads(path.read_text())
            self.assertNotIn("object", generation)
            self.assertIn("-S", generation["command"])
            outputs.add(generation["output"])
            self.assertEqual(generation["output_sha256"], generation["assembly_sha256"])
            for field in ("dependencies", "assembly"):
                self.assertEqual(hashlib.sha256((generations / generation[field]).read_bytes()).hexdigest(),
                                 generation[field + "_sha256"])
            self.assertTrue(generation["inputs"])
            for source in generation["inputs"]:
                self.assertEqual(hashlib.sha256((generations / "inputs" / source["sha256"]).read_bytes()).hexdigest(),
                                 source["sha256"])
        expected = {"/build/glibc-runtime/stdio-common/" + name for name in (
            "errlist-data-aux-shared.S", "errlist-data-aux.S", "siglist-aux-shared.S", "siglist-aux.S")}
        self.assertTrue(expected.issubset(outputs))
        for name, digest in record["link_maps"].items():
            self.assertEqual(Path(name).name, name)
            self.assertEqual(hashlib.sha256((evidence / "sources/link-maps" / name).read_bytes()).hexdigest(), digest)
        for digest in record["unknown_inputs"].values():
            self.assertEqual(hashlib.sha256((evidence / "sources/trace-inputs" / digest).read_bytes()).hexdigest(), digest)
        self.assertGreaterEqual(len(record["verified_inputs"]), 10)
        source_files = json.loads((evidence / "glibc.source-files.json").read_text())
        constant_sources = dict(source_files)
        for component in ("gcc", "linux"):
            constant_sources.update(json.loads((evidence / (component + ".source-files.json")).read_text()))
        headers = json.loads((evidence / "gnu-headers.json").read_text())
        for header in headers["headers"]:
            self.assertIs(header["verified"], True)
            references = header["sources"] or header["producer"]["inputs"]
            constant_sources[header["path"]] = {"component": references[0]["component"], "sha256": header["sha256"]}
        with tempfile.TemporaryDirectory() as directory:
            self.runtime_sources(Path(directory).resolve(), evidence, record["machine"])
        self.assertGreater(self.constant_runtime().verify_constant_proofs(evidence, record, constant_sources), 0)
        for name, producer in record["verified_inputs"].items():
            self.assertNotIn(name, record["unknown_inputs"])
            self.assertTrue(producer["command"])
            self.assertTrue(producer["inputs"])
            self.assertEqual(hashlib.sha256((evidence / "sources/trace-inputs" / producer["sha256"]).read_bytes()).hexdigest(),
                             producer["sha256"])
            retained = evidence / "runtime-inputs"
            if producer.get("replay") == "verified-stdin-retained-assembly":
                generation = evidence / "sources/generation" / producer["generation_record"]
                self.assertEqual(hashlib.sha256(generation.read_bytes()).hexdigest(),
                                 producer["generation_record_sha256"])
                self.assertTrue(producer["generation_inputs"])
            else:
                self.assertEqual(hashlib.sha256((retained / producer["recipe_sha256"]).read_bytes()).hexdigest(),
                                 producer["recipe_sha256"])
            for source in producer["inputs"]:
                self.assertEqual(source_files[source["path"]],
                                 {"component": source["component"], "sha256": source["sha256"]})
                self.assertEqual(hashlib.sha256((retained / source["sha256"]).read_bytes()).hexdigest(), source["sha256"])

    @unittest.skipUnless(os.environ.get("GNU_BOOTSTRAP_INPUTS") and os.environ.get("GNU_HEADER_EVIDENCE"),
                         "Real GNU source and header inputs are required")
    def test_source_make_recipes_reproduce_retained_headers(self):
        from test_source_origins import headers

        inputs = Path(os.environ["GNU_BOOTSTRAP_INPUTS"])
        report = json.loads((Path(os.environ["GNU_HEADER_EVIDENCE"]) / "gnu-headers.json").read_text())
        expected = {item["path"]: item["sha256"] for item in report["headers"]}
        architecture = "aarch64" if any("aarch64" in name for name in expected) else "x86"
        constructor = tempfile.TemporaryDirectory
        with constructor() as directory:
            root = Path(directory).resolve()
            retained = root / "retained"
            retained.mkdir()
            with tarfile.open(inputs / "glibc_2.41.orig.tar.xz") as archive:
                files = {}
                for name in ("Makerules", "Makeconfig", "sysdeps/unix/sysv/linux/" + architecture + "/Makefile"):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.extractfile("glibc-2.41/" + name).read())
                    files[name] = path
            wrapper = re.search(r"^\$\(common-objpfx\)gnu/lib-names.h:\n.*?(?=^endif$)",
                                files["Makerules"].read_text(), re.M | re.S).group()
            defaults = re.search(r"^ifndef abi-includes\n.*?^endif$", files["Makeconfig"].read_text(), re.M | re.S).group()
            paths = list(files.values())
            index = {str(path): {"component": "glibc", "sha256": headers.sha256(path)} for path in paths}
            abi = paths[-1]
            body = defaults + "\ninclude " + str(abi) + "\ncommon-objpfx :=\n" + wrapper
            with patch.object(headers.tempfile, "TemporaryDirectory", side_effect=lambda **kw: constructor(dir=root)):
                result = headers.make_header("glibc", paths, body, "gnu/lib-names.h", index, retained,
                                             ["default-abi=" + ("lp64" if architecture == "aarch64" else "64")])
            self.assertEqual(result["sha256"], expected["/build/source-sysroot/usr/include/gnu/lib-names.h"])
            with tarfile.open(inputs / "linux_6.12.107.orig.tar.xz") as archive:
                path = root / "kernel.Makefile"
                path.write_bytes(archive.extractfile("linux-6.12.107/Makefile").read())
            text = path.read_text()
            values = "\n".join(re.findall(r"^(?:VERSION|PATCHLEVEL|SUBLEVEL) = [0-9]+$", text, re.M))
            macro = re.search(r"^define filechk_version.h\n.*?^endef$", text, re.M | re.S).group()
            index = {str(path): {"component": "linux", "sha256": headers.sha256(path)}}
            with patch.object(headers.tempfile, "TemporaryDirectory", side_effect=lambda **kw: constructor(dir=root)):
                result = headers.make_header("linux", [path], values + "\n" + macro +
                                             "\nversion.h:\n\t{ $(filechk_version.h); } > $@\n",
                                             "version.h", index, retained)
            self.assertEqual(result["sha256"], expected["/build/linux/linux-6.12.107/usr/include/linux/version.h"])

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
                    if producer.get("recipe_sha256"):
                        recipe = evidence / "header-inputs" / producer["recipe_sha256"]
                        self.assertEqual(hashlib.sha256(recipe.read_bytes()).hexdigest(), producer["recipe_sha256"])
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
