"""Check retained config.h evidence without admitting configure probe results.

This checker does not execute configure, config.status, or compiler probes.
Selected source replay and retained input links do not prove probe outcomes.
"""

import hashlib
import json
from pathlib import Path
import posixpath
import re
import subprocess
import tarfile
import tempfile

from bootstrap import SOURCES
from compiler import dependency_inputs


SOURCE_ROOT = "/build/glibc/glibc-2.41/"
CONFIG = "/build/glibc-runtime/config.h"
SOURCE_NAMES = ("configure", "config.h.in")
BLOCKERS = (
    "Missing verified configure invocation, cwd, environment, and cache inputs",
    "Missing retained config.status, config.log, and confdefs.h producer bytes",
    "Missing complete probe commands, results, tools, and consumed input provenance",
    "Missing verified sysdeps configure selection and source closure",
    "Missing config.h output replay with verified probe results",
)


def checked(root, name, digest):
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Invalid config evidence digest")
    if not isinstance(name, str) or Path(name).name != name:
        raise ValueError("Invalid config evidence reference")
    root = Path(root).resolve()
    path = root / name
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError("Missing or unsafe config evidence: " + name)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Config evidence checksum mismatch: " + name)
    return data


def verify_config_sources(evidence, inputs, names=SOURCE_NAMES):
    """Replay only the selected sources from checksum-pinned vendor archives."""
    evidence, inputs = Path(evidence), Path(inputs)
    materials = next(item[-1] for item in SOURCES if item[0] == "glibc")
    for name, digest in materials:
        checked(inputs, name, digest)
    bootstrap = json.loads((evidence / "bootstrap.json").read_text())
    vendor = next(item for item in bootstrap["sources"] if item["name"] == "glibc")
    snapshot = json.loads(checked(evidence, "glibc.source-files.json",
                                 vendor["source_snapshot_sha256"]))
    patches = {item["path"]: item["sha256"] for item in vendor["patches"]}
    with tempfile.TemporaryDirectory(prefix="glibc-config-source-") as directory:
        root = Path(directory)
        with tarfile.open(inputs / "glibc_2.41.orig.tar.xz") as archive:
            for name in names:
                if not name or Path(name).is_absolute() or ".." in Path(name).parts:
                    raise ValueError("Invalid config source name")
                member = archive.getmember("glibc-2.41/" + name)
                if not member.isfile():
                    raise ValueError("Invalid config source archive member")
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(archive.extractfile(member).read())
        with tarfile.open(inputs / "glibc_2.41-12+deb13u4.debian.tar.xz") as archive:
            series = archive.extractfile("debian/patches/series").read().decode().splitlines()
            seen = set()
            for line in series:
                fields = line.split("#", 1)[0].split()
                if not fields:
                    continue
                if len(fields) != 1 or ".." in Path(fields[0]).parts or fields[0] in seen:
                    raise ValueError("Unsupported config source patch series")
                name = fields[0]
                seen.add(name)
                data = archive.extractfile("debian/patches/" + name).read()
                if hashlib.sha256(data).hexdigest() != patches.get(name):
                    raise ValueError("Unverified config source patch")
                subprocess.run(["git", "apply", "-p1", *[
                    "--include=" + source for source in names]],
                    input=data, cwd=root, check=True, capture_output=True)
            if seen != set(patches):
                raise ValueError("Config source patch list mismatch")
        sources = []
        for name in names:
            digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
            if snapshot.get(SOURCE_ROOT + name) != {"component": "glibc", "sha256": digest}:
                raise ValueError("Config source snapshot mismatch: " + name)
            sources.append({"path": SOURCE_ROOT + name, "component": "glibc", "sha256": digest})
    return sources


def inspect_capture(evidence, inputs, trace):
    digest = trace.get("configure_capture_sha256")
    if digest is None:
        return None
    capture = json.loads(checked(evidence, "glibc-configure-capture.json", digest))
    if (capture.get("schema_version") != 1 or capture.get("scope") != "glibc-configure-capture"
            or any(capture.get(key) is not False for key in
                   ("admitted", "release_qualified", "environment_complete",
                    "sysdeps_selection_verified", "probe_provenance_verified", "output_replayed"))):
        raise ValueError("Unproved configure capture admission")
    if capture.get("command") != trace["commands"][0] or capture.get("cwd") != str(Path(CONFIG).parent):
        raise ValueError("Configure capture invocation mismatch")
    references = capture["files"]
    keys = [(item["path"], item["role"]) for item in references]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate configure capture input")
    retained = Path(evidence) / "sources/configure"
    if {path.name for path in retained.iterdir()} != {item["sha256"] for item in references}:
        raise ValueError("Unlisted or missing configure capture input")
    names = []
    outputs = set()
    for item in references:
        checked(retained, item["sha256"], item["sha256"])
        if item["role"] == "source":
            if not item["path"].startswith(SOURCE_ROOT):
                raise ValueError("Invalid configure capture source")
            names.append(item["path"][len(SOURCE_ROOT):])
        elif item["role"] not in ("output", "pre-cache", "site"):
            raise ValueError("Invalid configure capture role")
        if item["role"] in ("output", "pre-cache"):
            path = item["path"]
            if posixpath.dirname(path) != capture["cwd"]:
                raise ValueError("Invalid configure capture output path")
            if item["role"] == "output":
                outputs.add(posixpath.basename(path))
    required = {"config.h", "config.status", "config.log", "confdefs.h", "config.make", "config.cache"}
    if outputs - required or set(capture["missing_outputs"]) != required - outputs:
        raise ValueError("Configure capture missing output list mismatch")
    if not set(SOURCE_NAMES).issubset(names):
        raise ValueError("Missing configure capture source")
    sources = verify_config_sources(evidence, inputs, tuple(names))
    expected = {item["path"]: item for item in sources}
    for item in references:
        if item["role"] == "source" and expected.get(item["path"]) != {
                key: item.get(key) for key in ("path", "component", "sha256")}:
            raise ValueError("Configure capture source binding mismatch")
        if item["path"] == CONFIG and item["role"] == "output":
            if item["sha256"] != trace["unknown_inputs"][CONFIG]:
                raise ValueError("Configure capture output mismatch")
    return capture


def inspect_retained_config(evidence, inputs):
    """Return a non-admitting blocker report; malformed retained links raise."""
    evidence = Path(evidence)
    sources = verify_config_sources(evidence, inputs)
    trace = json.loads((evidence / "gnu-libc-trace.json").read_text())
    if trace.get("scope") != "gnu-runtime-trace" or trace.get("release_qualified") is not False:
        raise ValueError("Unexpected config trace scope")
    if CONFIG in trace.get("verified_inputs", {}):
        raise ValueError("Unproved config.h admission claim")
    digest = trace.get("unknown_inputs", {}).get(CONFIG)
    checked(evidence / "sources/trace-inputs", digest, digest)
    generations = evidence / "sources/generation"
    records = trace["generation_records"]
    if set(records) != {path.name for path in generations.glob("*.json")}:
        raise ValueError("Unlisted or missing config generation record")
    consumed = []
    unproved = set()
    for name, record_digest in records.items():
        record = json.loads(checked(generations, name, record_digest))
        dependencies = checked(generations, record["dependencies"], record["dependencies_sha256"])
        references = record["inputs"]
        paths = [item["path"] for item in references]
        if len(paths) != len(set(paths)) or any(not Path(path).is_absolute() for path in paths if path != "<stdin>"):
            raise ValueError("Invalid config generation inputs")
        cwd = record.get("cwd", "")
        if not cwd.startswith("/") or posixpath.normpath(cwd) != cwd:
            raise ValueError("Missing or invalid config generation cwd")
        dependency_paths = {str(path) for path in dependency_inputs(dependencies.decode(), cwd)}
        if dependency_paths != set(paths) - {"<stdin>"}:
            raise ValueError("Config generation dependency list mismatch")
        for item in references:
            checked(generations / "inputs", item["sha256"], item["sha256"])
            if item["path"] in trace["unknown_inputs"]:
                if trace["unknown_inputs"][item["path"]] != item["sha256"]:
                    raise ValueError("Config generation input digest mismatch")
                unproved.add(item["path"])
        matches = [item for item in references if item["path"] == CONFIG]
        if matches:
            if matches[0]["sha256"] != digest:
                raise ValueError("Config generation output digest mismatch")
            consumed.append(name)
    if not consumed:
        raise ValueError("Missing retained config.h consumer")
    commands = trace.get("commands", [])
    if not commands or not commands[0] or commands[0][0] != SOURCE_ROOT + "configure":
        raise ValueError("Missing claimed configure invocation")
    capture = inspect_capture(evidence, inputs, trace)
    return {"schema_version": 1, "scope": "glibc-config-retained-blocker",
            "release_qualified": False, "admitted": False,
            "config_path": CONFIG, "sha256": digest, "sources": sources,
            "claimed_command": commands[0], "invocation_verified": False,
            "capture": capture,
            "retained_consumers": consumed, "unproved_generation_inputs": sorted(unproved),
            "output_replayed": False, "blockers": list(BLOCKERS)}


def require_config_producer(evidence, inputs):
    report = inspect_retained_config(evidence, inputs)
    raise ValueError("Unproved glibc config.h producer: " + "; ".join(report["blockers"]))
