import importlib.util
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch


RECIPE = Path(__file__).resolve().parents[1] / "images/source-minimal"
compiler_spec = importlib.util.spec_from_file_location("source_compiler", RECIPE / "compiler.py")
compiler = importlib.util.module_from_spec(compiler_spec)
compiler_spec.loader.exec_module(compiler)
spec = importlib.util.spec_from_file_location("source_origins", RECIPE / "origins.py")
origins = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"compiler": compiler}):
    spec.loader.exec_module(origins)
header_spec = importlib.util.spec_from_file_location("gnu_headers", RECIPE.parent / "debian-slim/headers.py")
headers = importlib.util.module_from_spec(header_spec)
with patch.dict(sys.modules, {"origins": origins}):
    header_spec.loader.exec_module(headers)
trace_spec = importlib.util.spec_from_file_location("gnu_trace_compiler", RECIPE.parent / "debian-slim/trace_compiler.py")
trace = importlib.util.module_from_spec(trace_spec)
with patch.dict(sys.modules, {"compiler": compiler}):
    trace_spec.loader.exec_module(trace)


class SourceOrigins(unittest.TestCase):
    def test_gnu_assembly_generation_has_separate_records(self):
        arguments = ["-c", "-S", "-pipe", "-o", "/build/generated.S", "/source/input.c",
                     "-Wp,-MD,/build/generated.S.d", "-MF", "/build/generated.S.dt"]
        with patch.object(trace.subprocess, "run") as run, patch.object(Path, "mkdir"), \
                patch.object(Path, "read_bytes", return_value=b"retained bytes"), \
                patch.object(Path, "read_text", return_value="object: /source/input.c\n"), \
                patch.object(Path, "write_bytes") as write, patch.object(Path, "write_text") as record, \
                patch.object(trace.compiler, "digest", return_value="a" * 64), \
                patch.object(trace.compiler, "main") as compile_object:
            trace.main(arguments)
        compile_object.assert_not_called()
        command = run.call_args.args[0]
        self.assertNotIn("-pipe", command)
        self.assertNotIn("-Wp,-MD,/build/generated.S.d", command)
        self.assertEqual(command[-3:-1], ["-MD", "-MF"])
        self.assertIn("/evidence/sources/generation/", command[-1])
        self.assertFalse(any(item.startswith("-Wl,-Map") for item in command))
        value = json.loads(record.call_args.args[0])
        self.assertNotIn("object", value)
        self.assertEqual(value["output"], "/build/generated.S")
        self.assertEqual(value["inputs"], [{"path": "/source/input.c", "sha256": "a" * 64}])
        self.assertEqual(write.call_count, 4)

    def test_gnu_vendor_link_map_is_preserved_and_copied(self):
        arguments = ["-r", "-o", "/build/partial.o", "-Wl,-Map,/build/vendor.mapT"]
        with patch.object(trace.compiler, "main") as run, patch.object(Path, "mkdir"), \
                patch.object(Path, "read_bytes", return_value=b"LOAD object.o\n"), \
                patch.object(Path, "write_bytes") as write:
            trace.main(arguments)
        run.assert_called_once_with(arguments)
        write.assert_called_once_with(b"LOAD object.o\n")

    def test_gnu_stdin_assembly_is_retained_before_tracing(self):
        arguments = ["-c", "-x", "assembler", "-", "-o", "/build/stubs.o"]
        with patch.object(trace.sys, "stdin") as stream, patch.object(Path, "write_bytes") as write, \
                patch.object(trace.compiler, "main") as run:
            stream.buffer = io.BytesIO(b".globl malloc\nmalloc:\n")
            trace.main(arguments)
        write.assert_called_once_with(b".globl malloc\nmalloc:\n")
        run.assert_called_once_with(["-c", "-x", "assembler", "/build/stubs.o.stdin.s", "-o", "/build/stubs.o"])

    def test_dependency_phony_targets_are_not_compiler_inputs(self):
        text = "object.o: /source.c \\\n /header.h\n/header.h:\n"
        self.assertEqual(compiler.dependency_inputs(text), [Path("/source.c"), Path("/header.h")])

    def test_retained_dependencies_use_recorded_cwd_without_host_resolution(self):
        text = "object.o: ../include/header.h /build/source.c ./input.c\n"
        with patch.object(Path, "resolve", side_effect=AssertionError("Host resolution is forbidden")):
            self.assertEqual(compiler.dependency_inputs(text, "/build/glibc/csu"),
                             [Path("/build/glibc/include/header.h"), Path("/build/source.c"),
                              Path("/build/glibc/csu/input.c")])
        for cwd in ("relative", "", 1):
            with self.subTest(cwd=cwd), self.assertRaisesRegex(ValueError, "cwd must be absolute"):
                compiler.dependency_inputs(text, cwd)

    def test_assembly_generation_is_not_an_object_record(self):
        arguments = ["-c", "-S", "-o", "/build/generated.S", "/source.c"]
        with patch.object(compiler.subprocess, "run") as run:
            compiler.main(arguments)
        run.assert_called_once_with(["gcc", *arguments], check=True)

    def test_gnu_link_trace_adds_distinct_maps(self):
        with patch.object(trace.compiler, "main") as run, patch.object(Path, "mkdir"):
            trace.main(["-o", "/build/libc.so", "object.o"])
            first = run.call_args.args[0][-1]
            trace.main(["-o", "/build/ld.so", "object.o"])
            second = run.call_args.args[0][-1]
        self.assertTrue(first.startswith("-Wl,-Map=/evidence/sources/link-maps/"))
        self.assertNotEqual(first, second)

    def test_gnu_compile_trace_does_not_add_link_map(self):
        for arguments in (["-c", "-o", "/build/object.o"], ["-E", "-o", "/build/preprocessed.i"],
                          ["-o", "/tmp/bootstrap-test"]):
            with self.subTest(arguments=arguments), patch.object(trace.compiler, "main") as run:
                trace.main(arguments)
                run.assert_called_once_with(arguments)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.lock = json.loads((RECIPE / "sources.lock.json").read_text())

    def test_shipped_file_mapping(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/busybox").write_bytes(b"fixture")
        (self.root / "bin/sh").symlink_to("busybox")
        items = {item["path"]: item for item in origins.file_origins(self.root, self.lock)}
        self.assertEqual(items["bin/busybox"]["kind"], "compiled")
        self.assertEqual({x["name"] for x in items["bin/busybox"]["sources"]}, {"busybox", "musl", "compiler-rt-builtins"})
        self.assertEqual(items["bin/sh"]["target"], "busybox")
        self.assertNotIn("sha256", items["usr/share/rootloom/rootfs.sha256"])

    def test_unknown_shipped_file_rejected(self):
        (self.root / "unexpected").write_bytes(b"binary or script")
        with self.assertRaisesRegex(ValueError, "Unmapped shipped file"):
            origins.file_origins(self.root, self.lock)

    def test_unknown_symlink_rejected(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/sh").symlink_to("/bootstrap/bin/sh")
        with self.assertRaisesRegex(ValueError, "Unmapped shipped symlink"):
            origins.file_origins(self.root, self.lock)

    def test_bootstrap_header_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            origins.input_origin("/usr/lib/gcc/aarch64-linux-gnu/15/include/stddef.h", {})

    def test_source_directory_prefix_escape_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            origins.input_origin("/build/musl-1.2.6-unreviewed/header.h", {})

    def test_known_source_headers(self):
        header = self.root / "header.h"
        header.write_bytes(b"source header")
        index = {str(header): {"component": "musl", "sha256": origins.sha256(header)}}
        self.assertEqual(origins.input_origin(header, index), "musl")
        header.write_bytes(b"copied bootstrap header")
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            origins.input_origin(header, index)

    def test_snapshot_freezes_gnu_source_inputs(self):
        source = self.root / "gcc"
        source.mkdir()
        header = source / "stddef.h"
        header.write_bytes(b"verified source header")
        output = self.root / "source-files.json"
        origins.snapshot_sources({source: "gcc"}, output)
        index = json.loads(output.read_text())
        self.assertEqual(origins.input_origin(header, index), "gcc")
        header.write_bytes(b"unrecorded generated input")
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            origins.input_origin(header, index)

    def test_snapshot_rejects_escaping_source_symlink(self):
        source = self.root / "gcc"
        source.mkdir()
        (self.root / "bootstrap.h").write_bytes(b"binary bootstrap header")
        (source / "header.h").symlink_to(self.root / "bootstrap.h")
        with self.assertRaisesRegex(ValueError, "Source symlink escapes locked tree"):
            origins.snapshot_sources({source: "gcc"}, self.root / "source-files.json")

    def test_snapshot_rejects_missing_source_tree(self):
        with self.assertRaisesRegex(ValueError, "Missing locked source tree"):
            origins.snapshot_sources({self.root / "missing": "gcc"}, self.root / "source-files.json")

    def test_installed_gnu_header_requires_unchanged_source(self):
        source = self.root / "source.h"
        source.write_bytes(b"verified GNU source")
        installed = self.root / "include"
        installed.mkdir()
        (installed / "copied.h").write_bytes(source.read_bytes())
        (installed / "unknown.h").write_bytes(b"bootstrap header")
        index = {str(source): {"component": "gcc", "sha256": origins.sha256(source)}}
        records = headers.audit_headers([installed], index)
        self.assertEqual([item["verified"] for item in records], [True, False])
        self.assertEqual(records[0]["sources"], [{"path": str(source), "component": "gcc"}])
        source.write_bytes(b"changed after source snapshot")
        self.assertFalse(any(item["verified"] for item in headers.audit_headers([installed], index)))

    def test_installed_gnu_header_escape_rejected(self):
        installed = self.root / "include"
        installed.mkdir()
        source = self.root / "source.h"
        source.write_bytes(b"verified source")
        (installed / "escaped.h").symlink_to(source)
        with self.assertRaisesRegex(ValueError, "Installed header symlink escapes"):
            headers.audit_headers([installed], {})

    def test_generated_header_requires_exact_producer_bytes(self):
        installed = self.root / "include"
        installed.mkdir()
        header = installed / "limits.h"
        header.write_bytes(b"generated from verified fragments")
        source = self.root / "fragment.txt"
        source.write_bytes(header.read_bytes())
        reference = {"path": str(source), "sha256": origins.sha256(source), "component": "gcc"}
        index = {str(source): {"sha256": reference["sha256"], "component": "gcc"}}
        producer = {"sha256": origins.sha256(header), "inputs": [reference], "command": ["cat"]}
        self.assertTrue(headers.audit_headers([installed], index, {str(header): producer})[0]["verified"])
        with self.assertRaisesRegex(ValueError, "lacks source producer inputs"):
            headers.audit_headers([installed], {}, {str(header): {**producer, "inputs": []}})
        header.write_bytes(b"different bootstrap bytes")
        with self.assertRaisesRegex(ValueError, "Generated header differs"):
            headers.audit_headers([installed], index, {str(header): producer})

    def test_unindexed_source_tree_header_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unreviewed compiler input"):
            origins.input_origin("/build/musl-1.2.6/include/copied-bootstrap.h", {})

    def test_assembler_imports_rejected(self):
        for text in ['.include "/bootstrap/header.s"', '.incbin "/bootstrap/lib.o"', '.INCLUDE "nested.inc"']:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "Assembler file imports"):
                compiler.reject_assembler_imports(text)
        compiler.reject_assembler_imports(".text\n.globl foo\nfoo:\nret\n")

    def test_arbitrary_link_input_rejected(self):
        (self.root / "innocent-name.o").write_bytes(b"prebuilt")
        with self.assertRaisesRegex(ValueError, "Unrecorded linker input"):
            origins.verify_links("LOAD innocent-name.o\n", self.root, [], self.root)

    def test_missing_link_map_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing linker inputs"):
            origins.verify_links("", self.root, [], self.root)

    def test_linker_generated_stub_marker_not_a_file(self):
        with self.assertRaisesRegex(ValueError, "Missing source-built compiler runtime"):
            origins.verify_links("LOAD linker stubs\n", self.root, [], self.root)
        (self.root / "linker stubs").write_bytes(b"unknown object")
        with self.assertRaisesRegex(ValueError, "Unrecorded linker input"):
            origins.verify_links("LOAD linker stubs\n", self.root, [], self.root)

    def test_archive_members_require_compilation(self):
        (self.root / "lib.a").write_bytes(b"archive fixture")
        with patch.object(origins.subprocess, "check_output", side_effect=["innocent.o\n", b"prebuilt"]):
            with self.assertRaisesRegex(ValueError, "Unrecorded linker input"):
                origins.verify_links("LOAD lib.a\n", self.root, [], self.root)

    def test_duplicate_archive_members_rejected(self):
        with patch.object(origins.subprocess, "check_output", return_value="same.o\nsame.o\n"):
            with self.assertRaisesRegex(ValueError, "Duplicate archive member"):
                origins.verify_links("LOAD lib.a\n", self.root, [], self.root)

    def test_changed_preprocessing_rejected(self):
        (self.root / "record.i").write_bytes(b"changed")
        record = {"preprocessed": "record.i", "preprocessed_sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "Compiler evidence checksum mismatch"):
            origins.verify_record(record, self.root)

    def test_consumed_generated_inputs_retained(self):
        header = self.root / "generated.h"
        header.write_bytes(b"#define GENERATED 1\n")
        for name in ["record.i", "record.d", "record.s"]:
            (self.root / name).write_bytes(b"fixture")
        record = {"inputs": [{"path": str(header), "sha256": origins.sha256(header)}]}
        for kind, name in [("preprocessed", "record.i"), ("dependencies", "record.d"), ("assembly", "record.s")]:
            record[kind] = name
            record[kind + "_sha256"] = origins.sha256(self.root / name)
        with patch.object(origins, "input_origin", return_value="musl"):
            self.assertEqual(origins.verify_record(record, self.root), ["musl"])
        self.assertEqual((self.root / "inputs" / origins.sha256(header)).read_bytes(), header.read_bytes())

    def test_builder_headers_removed(self):
        builtins = (RECIPE / "builtins.py").read_text()
        self.assertNotIn("-print-file-name=include", builtins)
        self.assertIn('"-nostdinc"', builtins)
        self.assertIn('"/recipe/compiler.sh"', builtins)
        self.assertIn("text.replace(' -isystem include%s', '')", (RECIPE / "build.sh").read_text())

    def test_configure_discarded_objects_do_not_need_records(self):
        args = ["-x", "c", "-", "-c", "-o", "/dev/null"]
        with patch.object(compiler.subprocess, "run") as run:
            compiler.main(args)
        run.assert_called_once_with(["gcc", *args], check=True)

    def test_recorder_preserves_busybox_dependencies_and_exact_inputs(self):
        source = self.root / "source.c"
        source.write_bytes(b"int fixture;\n")
        output = self.root / "source.o"
        make_dependency = self.root / "make.d"
        records = self.root / "records"
        args = ["-pipe", "-Wp,-MD," + str(make_dependency), "-c", str(source), "-o", str(output)]
        def compile_fixture(command, **kwargs):
            self.assertNotIn("-pipe", command)
            self.assertFalse(any(arg.startswith("-Wp,-MD,") for arg in command))
            output.write_bytes(b"source-built object")
            output.with_suffix(".i").write_bytes(source.read_bytes())
            output.with_suffix(".s").write_bytes(b".text\n")
            Path(command[command.index("-MF") + 1]).write_text("object: " + str(source) + "\n")
        with patch.object(compiler, "BUILD_ROOT", self.root), patch.object(compiler, "RECORDS", records), patch.object(compiler.subprocess, "run", side_effect=compile_fixture):
            compiler.main(args)
        record = json.loads(next(records.glob("*.json")).read_text())
        self.assertEqual(record["object_sha256"], origins.sha256(output))
        self.assertEqual(record["inputs"], [{"path": str(source), "sha256": origins.sha256(source)}])
        self.assertEqual(make_dependency.read_bytes(), (records / record["dependencies"]).read_bytes())
        self.assertEqual((records / record["preprocessed"]).read_bytes(), source.read_bytes())

    def test_link_script_and_response_input_policy(self):
        script = self.root / "source.ld"
        script.write_bytes(b"SECTIONS {}\n")
        expected = [{"path": str(script), "sha256": origins.sha256(script)}]
        self.assertEqual(compiler.link_scripts(["-Wl,-T," + str(script)]), expected)
        self.assertEqual(compiler.link_scripts(["-Wl,-T=" + str(script)]), expected)
        self.assertEqual(compiler.link_scripts(["-Xlinker", "--script", "-Xlinker", str(script)]), expected)
        self.assertEqual(compiler.link_scripts(["-Wl,--dynamic-list=" + str(script)]), expected)
        self.assertEqual(compiler.link_scripts(["-specs=" + str(script)]), expected)
        with self.assertRaisesRegex(ValueError, "response file"):
            compiler.link_scripts(["-Wl,@/bootstrap/link.args"])

    def test_partial_link_requires_recorded_source_inputs(self):
        source_object = self.root / "input.o"
        source_object.write_bytes(b"compiled input")
        combined = self.root / "built-in.o"
        combined.write_bytes(b"relocatable link output")
        link_map = self.root / "partial.map"
        link_map.write_text("LOAD input.o\n")
        record = {"output": str(combined), "output_sha256": origins.sha256(combined), "map": str(link_map),
                  "map_sha256": origins.sha256(link_map), "scripts": [], "cwd": str(self.root)}
        compiled = {"object": str(source_object), "object_sha256": origins.sha256(source_object)}
        with patch.object(origins, "verify_record", return_value=["musl"]):
            result = origins.verify_links("LOAD built-in.o\n", self.root, [compiled], self.root,
                                          partial_links={record["output_sha256"]: record}, require_runtime=False)
        self.assertEqual(result[0]["components"], ["musl"])
        self.assertEqual(len(result[0]["compilation_records"]), 1)
        link_map.write_text("LOAD unreviewed.o\n")
        with self.assertRaisesRegex(ValueError, "Partial link evidence checksum mismatch"):
            origins.verify_links("LOAD built-in.o\n", self.root, [compiled], self.root,
                                 partial_links={record["output_sha256"]: record}, require_runtime=False)

    def test_partial_link_cycle_rejected(self):
        combined = self.root / "built-in.o"
        combined.write_bytes(b"relocatable output")
        link_map = self.root / "partial.map"
        link_map.write_text("LOAD built-in.o\n")
        record = {"output": str(combined), "output_sha256": origins.sha256(combined), "map": str(link_map),
                  "map_sha256": origins.sha256(link_map), "scripts": [], "cwd": str(self.root)}
        with self.assertRaisesRegex(ValueError, "cyclic partial link"):
            origins.verify_links("LOAD built-in.o\n", self.root, [], self.root,
                                 partial_links={record["output_sha256"]: record}, require_runtime=False)


if __name__ == "__main__":
    unittest.main()
