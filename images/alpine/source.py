"""Verified Alpine inputs and the offline packaging-only build slice."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
COMMIT = "3c2c2436e397ea23073cde73138f60e0d5c537b4"
ARCHIVE_HASH = "7b9245e0d68cadc91151d0ad5a16d166b36ff6a8b776076ea9c051716aa23fcf"
PACKAGES = ("alpine-baselayout", "alpine-base", "musl", "busybox")
EXTERNAL = {
    "protocols-6.4": "https://salsa.debian.org/md/netbase/-/raw/v6.4/etc/protocols",
    "services-6.4": "https://salsa.debian.org/md/netbase/-/raw/v6.4/etc/services",
    "musl-1.2.6.tar.gz": "https://musl.libc.org/releases/musl-1.2.6.tar.gz",
    "busybox-1.37.0.tar.bz2": "https://busybox.net/downloads/busybox-1.37.0.tar.bz2",
}


def digest(data, algorithm="sha256"):
    return hashlib.new(algorithm, data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("Unsafe input path")
    return path


def archive_files(archive):
    if digest(Path(archive).read_bytes()) != ARCHIVE_HASH:
        raise ValueError("aports archive checksum mismatch")
    prefix = "aports-" + COMMIT + "/"
    files = {}
    with tarfile.open(archive) as tar:
        for entry in tar:
            safe_path(entry.name)
            if entry.name == prefix.rstrip("/") and entry.isdir():
                continue
            if not entry.name.startswith(prefix):
                raise ValueError("Unexpected archive root")
            relative = entry.name[len(prefix):]
            if entry.isdir():
                continue
            if not entry.isfile():
                # Only regular recipe inputs are admitted; no archive links are extracted.
                continue
            if relative in files:
                raise ValueError("Duplicate archive input")
            files[relative] = tar.extractfile(entry).read()
    return files


def make_lock(archive, output):
    """Mechanically inventory the reviewed archive; do not discover new versions."""
    files = archive_files(archive)
    packages = []
    for package in PACKAGES:
        prefix = "main/" + package + "/"
        recipe = files[prefix + "APKBUILD"].decode()
        local = [{"path": name, "sha256": digest(data)}
                 for name, data in sorted(files.items()) if name.startswith(prefix)]
        inputs = []
        for checksum, filename in re.findall(r"^([a-f0-9]{128})  (\S+)$", recipe, re.M):
            safe_path(filename)
            path = prefix + filename
            if path in files:
                if digest(files[path], "sha512") != checksum:
                    raise ValueError("APKBUILD local source checksum mismatch: " + path)
                inputs.append({"filename": filename, "path": path, "sha512": checksum})
            else:
                inputs.append({"filename": filename, "url": EXTERNAL[filename],
                               "sha512": checksum})
        packages.append({"name": package,
                         "version": re.search(r"^pkgver=(\S+)$", recipe, re.M)[1],
                         "revision": int(re.search(r"^pkgrel=(\d+)$", recipe, re.M)[1]),
                         "license": re.search(r'^license="([^"]+)"$', recipe, re.M)[1],
                         "recipe_files": local, "sources": inputs})
    lock = {"schema_version": 1, "distribution": "Alpine", "branch": "3.24-stable",
            "aports_commit": COMMIT,
            "aports": {"filename": "aports.tar.gz", "sha256": ARCHIVE_HASH,
                       "url": "https://codeload.github.com/alpinelinux/aports/tar.gz/" + COMMIT},
            "authentication": "HTTPS and pinned hashes; no aports commit signature verified",
            "scope": "baselayout/release slice and musl/BusyBox inputs, not full runtime closure",
            "packages": packages}
    Path(output).write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")


def load_lock(path):
    lock = json.loads(Path(path).read_text())
    if lock["schema_version"] != 1 or lock["aports_commit"] != COMMIT:
        raise ValueError("Unsupported Alpine source lock")
    if lock["aports"]["sha256"] != ARCHIVE_HASH:
        raise ValueError("Unexpected aports archive hash")
    if tuple(package["name"] for package in lock["packages"]) != PACKAGES:
        raise ValueError("Unexpected Alpine package set")
    return lock


def download(url, target):
    subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
                    "--proto", "=https", "--proto-redir", "=https", "--retry", "3",
                    "--connect-timeout", "30", "--max-time", "180", "--output",
                    str(target), url], check=True)


def fetch(lock_path, destination):
    lock = load_lock(lock_path)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / "aports.tar.gz"
    if not archive.exists():
        download(lock["aports"]["url"], archive)
    files = archive_files(archive)
    for package in lock["packages"]:
        for entry in package["recipe_files"]:
            path = safe_path(entry["path"])
            data = files[str(path)]
            if digest(data) != entry["sha256"]:
                raise ValueError("Recipe checksum mismatch: " + str(path))
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        for entry in package["sources"]:
            target = destination / "main" / package["name"] / safe_path(entry["filename"])
            if "url" in entry and not target.exists():
                # Alpine's distfiles mirror preserves the exact recipe checksum.
                download("https://distfiles.alpinelinux.org/distfiles/v3.24/" + entry["filename"], target)
            if digest(target.read_bytes(), "sha512") != entry["sha512"]:
                raise ValueError("Source checksum mismatch: " + entry["filename"])
    verify(lock_path, destination)


def verify(lock_path, destination):
    lock = load_lock(lock_path)
    destination = Path(destination)
    archive_files(destination / "aports.tar.gz")
    for package in lock["packages"]:
        for entry in package["recipe_files"]:
            target = destination / safe_path(entry["path"])
            if target.is_symlink() or digest(target.read_bytes()) != entry["sha256"]:
                raise ValueError("Recipe checksum mismatch: " + entry["path"])
        for entry in package["sources"]:
            target = destination / "main" / package["name"] / safe_path(entry["filename"])
            if target.is_symlink() or digest(target.read_bytes(), "sha512") != entry["sha512"]:
                raise ValueError("Source checksum mismatch: " + entry["filename"])
    return lock


def install(arguments):
    """Portable install adapter for the pinned baselayout package function."""
    mode, directory, parents, target_dir, paths = 0o755, False, False, None, []
    args = iter(arguments)
    for arg in args:
        if arg == "-d":
            directory = True
        elif arg == "-D":
            parents = True
        elif arg.startswith("-Dm"):
            parents = True
            mode = int(arg[3:] or next(args), 8)
        elif arg == "-m":
            mode = int(next(args), 8)
        elif arg.startswith("-m"):
            mode = int(arg[2:], 8)
        elif arg == "-g":
            if next(args) != "shadow":
                raise ValueError("Unexpected install group")
        elif arg == "-t":
            target_dir = Path(next(args))
        elif arg.startswith("-"):
            raise ValueError("Unsupported install option: " + arg)
        else:
            paths.append(Path(arg))
    if directory:
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)
        return
    target = target_dir or paths.pop()
    if target_dir is not None and parents:
        target.mkdir(parents=True, exist_ok=True)
    for source in paths:
        dest = target / source.name if target.is_dir() else target
        if parents:
            dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        dest.chmod(mode)


def build_layout(lock_path, inputs, output):
    lock = verify(lock_path, inputs)
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Build output must be empty")
    root = output / "rootfs"
    root.mkdir(parents=True)
    script = str(Path(__file__).resolve())
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        source = work / "sources"
        shutil.copytree(Path(inputs) / "main/alpine-baselayout", source)
        env = {"PATH": os.environ["PATH"], "LC_ALL": "C", "srcdir": str(source),
               "pkgdir": str(root), "subpkgdir": str(root), "ADAPTER": script,
               "PYTHON": sys.executable}
        command = '''set -eu
install() { "$PYTHON" "$ADAPTER" install "$@"; }
default_prepare() { :; }
. "$srcdir/APKBUILD"
prepare
cd "$builddir"
build
package
'''
        subprocess.run(["/bin/sh", "-c", command], env=env, check=True)
        release = Path(inputs).resolve() / "main/alpine-base/APKBUILD"
        subprocess.run(["/bin/sh", "-c", 'set -eu; . "$1"; release', "sh", str(release)],
                       env=env, check=True)
    # Container overlay: locked accounts and no promise of init/package installation.
    for name in ("passwd", "group"):
        path = root / "etc" / name
        data = path.read_text()
        if name == "passwd":
            data = re.sub(r"^root:[^:]*:", "root:!:", data, flags=re.M)
            data += "rootloom:x:65532:65532:Rootloom:/home/rootloom:/bin/sh\n"
        else:
            data += "rootloom:x:65532:\n"
        path.write_text(data)
        path.chmod(0o444)
    shadow = root / "etc/shadow"
    shadow.write_text(re.sub(r"^root::", "root:!:", shadow.read_text(), flags=re.M)
                      + "rootloom:!:0:::::\n")
    shadow.chmod(0o600)
    for directory in ("app", "home/rootloom"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    # No APK is retained. Its commit hook has no runtime purpose.
    (root / "lib/apk/commit_hooks.d/usr_merge_nag.sh").unlink()
    (root / "etc/motd").write_text("Rootloom Alpine-derived container. No apk, OpenRC, or setup-alpine.\n")
    records = []
    data_sources = {}
    for package in lock["packages"][:2]:
        for entry in package["recipe_files"]:
            data_sources.setdefault(entry["sha256"], []).append(entry["path"])
        for entry in package["sources"]:
            path = Path(inputs) / "main" / package["name"] / entry["filename"]
            data_sources.setdefault(digest(path.read_bytes()), []).append(str(path.relative_to(inputs)))
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        record = {"path": name, "mode": oct(path.lstat().st_mode & 0o7777),
                  "uid": 65532 if name in {"app", "home/rootloom"} else 0,
                  "gid": 65532 if name in {"app", "home/rootloom"} else 0}
        if path.is_symlink():
            record.update(type="symlink", target=os.readlink(path))
        elif path.is_dir():
            record.update(type="directory")
        else:
            data = path.read_bytes()
            if data.startswith(b"\x7fELF"):
                raise ValueError("ELF in packaging-only slice")
            record.update(type="file", sha256=digest(data),
                          source=data_sources.get(digest(data), ["main/alpine-baselayout/APKBUILD",
                                                               "main/alpine-base/APKBUILD", "source.py:container-overlay"]))
        records.append(record)
    evidence = {"schema_version": 1, "status": "packaging-only; not runnable or release-qualified",
                "lock_sha256": digest(Path(lock_path).read_bytes()),
                "recipe_adapter_sha256": digest(Path(__file__).read_bytes()),
                "aports_commit": COMMIT, "network": "no fetch operations during build-layout",
                "ownership": "logical target ownership; host output ownership is not changed",
                "files": records}
    (output / "layout-evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def prepare_runtime(lock_path, inputs, output):
    """Apply the complete locked Alpine patch sets without network access."""
    lock = verify(lock_path, inputs)
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Runtime source output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    records = []
    for package in lock["packages"][2:]:
        source = Path(inputs) / "main" / package["name"]
        archive = next(entry for entry in package["sources"] if "url" in entry)
        with tarfile.open(source / archive["filename"]) as tar:
            for entry in tar:
                relative = safe_path(entry.name)
                if relative.parts[0] != package["name"] + "-" + package["version"]:
                    raise ValueError("Unexpected runtime source root")
                target = output / relative
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(entry).read())
                    target.chmod(entry.mode & 0o777)
                else:
                    raise ValueError("Non-regular runtime source input")
        build = output / (package["name"] + "-" + package["version"])
        patches = [entry for entry in package["sources"] if entry["filename"].endswith(".patch")]
        for entry in patches:
            with (source / entry["filename"]).open("rb") as patch:
                result = subprocess.run(["patch", "--batch", "--fuzz=2", "-p1"], cwd=build,
                                        stdin=patch, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise ValueError("Patch failed: " + entry["filename"] + "\n" + result.stdout.decode())
                (output / (package["name"] + "-" + entry["filename"] + ".log")).write_bytes(result.stdout)
        if package["name"] == "musl":
            (build / "VERSION").write_text(package["version"] + "\n")
            for name in ("memcpy.s", "memmove.s"):
                (build / "src/string/x86_64" / name).unlink()
        else:
            shutil.copyfile(source / "busyboxconfig", build / ".config")
        records.append({"package": package["name"], "version": package["version"],
                        "revision": package["revision"], "patches": patches})
    evidence = {"status": "Alpine-patched sources only; not compiled runtime",
                "lock_sha256": digest(Path(lock_path).read_bytes()), "packages": records}
    (output / "runtime-source-evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "install":
        install(sys.argv[2:])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("lock", "fetch", "verify", "build-layout", "prepare-runtime"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--lock", type=Path, default=HERE / "sources.lock.json")
    args = parser.parse_args()
    if args.action == "lock":
        make_lock(args.input, args.output)
    elif args.action == "fetch":
        fetch(args.lock, args.input)
    elif args.action == "verify":
        verify(args.lock, args.input)
    elif args.action == "build-layout":
        build_layout(args.lock, args.input, args.output)
    else:
        prepare_runtime(args.lock, args.input, args.output)


if __name__ == "__main__":
    main()
