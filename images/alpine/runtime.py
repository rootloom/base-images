"""Prepare and assemble the Alpine-derived source runtime."""

import json
from pathlib import Path
import shutil
import sys

import source


APPLET_CONFIG = {
    "HAVE_DOT_CONFIG", "BUSYBOX", "LONG_OPTS", "SHOW_USAGE", "FEATURE_VERBOSE_USAGE",
    "FEATURE_INSTALLER", "INSTALL_APPLET_SYMLINKS", "NO_DEBUG_LIB", "PIE", "SH_IS_ASH",
    "ASH", "AWK", "BASENAME", "CAT", "CHMOD", "CP", "CUT", "DATE", "DIRNAME", "ECHO",
    "ENV", "FALSE", "GREP", "HEAD", "ID", "LN", "LS", "MKDIR", "MKTEMP", "MV", "PRINTF",
    "PWD", "READLINK", "RM", "RMDIR", "SED", "SHA256SUM", "SLEEP", "SORT", "STAT", "TAIL",
    "TEST", "TEST1", "TEST2", "TOUCH", "TR", "TRUE", "UNAME", "WC", "KILL", "XARGS",
}


def prepare_recipe(recipe, inputs):
    recipe, inputs = Path(recipe), Path(inputs)
    alpine = source.verify(source.HERE / "sources.lock.json", inputs)
    lock = json.loads((recipe / "sources.lock.json").read_bytes())
    lock["image_version"] = "alpine-3.24.2-musl-1.2.6-r2-busybox-1.37.0-r31-rt-23.1.3-r1"
    lock["distribution"] = {"name": "Alpine-derived", "version": "3.24.2", "package_manager": False,
        "aports_commit": alpine["aports_commit"], "lock_sha256": source.digest((source.HERE / "sources.lock.json").read_bytes()),
        "trust_overlay": "Pinned dated Mozilla CA data from curl; not the Alpine ca-certificates package"}
    lock["patches"] = []
    for package in alpine["packages"][2:]:
        for entry in package["sources"]:
            if not entry["filename"].endswith(".patch"):
                continue
            path = inputs / "main" / package["name"] / entry["filename"]
            lock["patches"].append({"name": package["name"] + "-" + entry["filename"], "component": package["name"],
                "filename": package["name"] + "-" + entry["filename"], "license": package["license"],
                "sha256": source.digest(path.read_bytes()), "url": "https://github.com/alpinelinux/aports/raw/" +
                alpine["aports_commit"] + "/main/" + package["name"] + "/" + entry["filename"]})
    original = (inputs / "main/busybox/busyboxconfig").read_text().splitlines()
    selected = []
    for line in original:
        if not line.startswith("CONFIG_") or "=" not in line:
            continue
        key = line.split("=", 1)[0][7:]
        if key in {"FEATURE_SH_MATH", "FEATURE_SH_MATH_64"}:
            continue
        if key in APPLET_CONFIG or key.startswith(("ASH_", "FEATURE_SH_")):
            selected.append(line)
    if not {"CONFIG_ASH=y", "CONFIG_SH_IS_ASH=y", "CONFIG_PIE=y"}.issubset(selected):
        raise ValueError("Required Alpine shell or hardening configuration is missing")
    (recipe / "busybox.config").write_text("\n".join(selected) + "\n")
    (recipe / "alpine-original-busybox.config").write_text("\n".join(original) + "\n")
    (recipe / "alpine-config-delta.json").write_text(json.dumps({"retained": selected,
        "omitted": [line for line in original if line.startswith("CONFIG_") and line not in selected],
        "scope": "Minimal container subset. No shell arithmetic, APK, init services, TLS client, utmps, or privilege-changing applets."}, indent=2) + "\n")
    (recipe / "sources.lock.json").write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n")


def merge_layout(root, layout, evidence, arch, inputs):
    root, layout, evidence = Path(root), Path(layout), Path(evidence)
    data = json.loads((layout.parent / "layout-evidence.json").read_bytes())
    origins_path = root / "usr/share/rootloom/source-origins.json"
    origins = json.loads(origins_path.read_bytes())
    records = {item["path"]: item for item in data["files"]}
    for name in ("bin", "lib"):
        item = records.get(name)
        if item and item["type"] == "symlink":
            if item["target"] != "usr/" + name:
                raise ValueError("Unexpected Alpine runtime directory alias")
            target = root / "usr" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(root / name), str(target))
            (root / name).symlink_to(item["target"])
            for record in origins["files"]:
                if record["path"] == name or record["path"].startswith(name + "/"):
                    record["path"] = "usr/" + record["path"]
    for item in sorted(data["files"], key=lambda x: (x["type"] != "directory", x["path"])):
        name = str(source.safe_path(item["path"]))
        src, dst = layout / name, root / name
        if item["type"] == "directory":
            dst.mkdir(parents=True, exist_ok=True)
            dst.chmod(int(item["mode"], 8))
        elif item["type"] == "symlink":
            if src.readlink().as_posix() != item["target"]:
                raise ValueError("Alpine layout link mismatch")
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() or dst.is_symlink():
                if not dst.is_symlink() or dst.readlink().as_posix() != item["target"]:
                    raise ValueError("Alpine layout link conflicts with compiled output")
            else:
                dst.symlink_to(item["target"])
        else:
            payload = src.read_bytes()
            if source.digest(payload) != item["sha256"] or payload.startswith(b"\x7fELF"):
                raise ValueError("Alpine source-data checksum mismatch")
            if dst.is_symlink():
                raise ValueError("Alpine data would overwrite a runtime link")
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(payload)
            dst.chmod(int(item["mode"], 8))
        origins["files"] = [record for record in origins["files"] if record["path"] != name]
        origins["files"].append(dict(item, kind="alpine-source-data", recipe="Pinned Alpine APKBUILD functions and container overlay"))
    lock_data = (source.HERE / "sources.lock.json").read_bytes()
    (root / "usr/share/rootloom/alpine-sources.lock.json").write_bytes(lock_data)
    origins["files"].append({"path": "usr/share/rootloom/alpine-sources.lock.json", "kind": "generated-data",
        "sha256": source.digest(lock_data), "recipe": "Pinned Alpine source lock"})
    library = (root / "lib").resolve() / ("libc.musl-" + arch + ".so.1")
    library.symlink_to("libc.so")
    origins["files"].append({"path": library.relative_to(root).as_posix(), "kind": "symlink", "target": "libc.so",
        "recipe": "Alpine ABI name alias for the verified source-built musl library"})
    origins["distribution"] = "Alpine-derived minimal container subset; no package installation contract"
    text = json.dumps(origins, sort_keys=True, indent=2) + "\n"
    origins_path.write_text(text)
    (evidence / "source-origins.json").write_text(text)
    shutil.copytree(source.HERE, evidence / "sources/alpine-recipe", ignore=shutil.ignore_patterns(".work*", "__pycache__"))
    shutil.copytree(inputs, evidence / "sources/alpine-inputs")
    shutil.copyfile(layout.parent / "layout-evidence.json", evidence / "sources/alpine-layout-evidence.json")


if __name__ == "__main__":
    if sys.argv[1] == "prepare-recipe":
        prepare_recipe(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "merge-layout":
        merge_layout(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    else:
        raise ValueError("Unknown Alpine runtime operation")
