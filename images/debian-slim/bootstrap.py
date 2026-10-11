"""Build temporary GNU bootstrap tools and libc, not a qualified runtime."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile


SOURCES = (
    ("bison", "3.8.2+dfsg-1", "bison-3.8.2", "A63A3F516EA2FCA2A2FB638D01B3A9952AAE4713", (
        ("bison_3.8.2+dfsg-1.dsc", "62069748f3e82bff18e7e1e4f96e7a55606305623be4bec435d4d016e7c4c7d9"),
        ("bison_3.8.2+dfsg.orig.tar.xz", "dff8a3c96dd34121828f62a7fa49e1f7765815b89e59f564e8d2a9e71c177be5"),
        ("bison_3.8.2+dfsg-1.debian.tar.xz", "e878473ddbc8601c1b9b8558fab86950ae6ae5b7c146802d587e284d5e1c9abb"),
        ("debian-bison-source-key.asc", "8ceba1ef615ce98472715d985775b9b57c0854415fd0673e637ed099024185a2"))),
    ("gawk", "5.2.1-2", "gawk-5.2.1", "3AFA757FAC6EA11D2FF45DF088D24287A2D898B1", (
        ("gawk_5.2.1-2.dsc", "1f2d11cd9b09419e86cf069571728802a068bb94d1947f3328ed430ab9b7540e"),
        ("gawk_5.2.1.orig.tar.xz", "2337a0283b180ec1b9c727973a34781c6478b3ae9bcbdcca0a4dc49861d75a65"),
        ("gawk_5.2.1-2.debian.tar.xz", "ae031782d073e8d1670b4d9ced47b3adecde2f314d824339673d163ba7029f4b"),
        ("debian-gawk-source-key.asc", "07d2894e7e3de86e8fa5a0368e4db74bff0fe0803e96aebba8716b4b28c60f86"))),
    ("autoconf", "2.69-3.1", "autoconf-2.69", "3AFA757FAC6EA11D2FF45DF088D24287A2D898B1", (
        ("autoconf2.69_2.69-3.1.dsc", "226b5d3e8172f6a87400cab2df0e3a8484ef44f19c052cc4edbb778c7d45f43f"),
        ("autoconf2.69_2.69.orig.tar.xz", "64ebcec9f8ac5b2487125a86a7760d2591ac9e1d3dbd59489633f9de62a57684"),
        ("autoconf2.69_2.69-3.1.debian.tar.xz", "fe908dbfc5669ff63fccefa9ec1affc11b6c07a6781028baee7ced77f4f0c2fb"),
        ("debian-gawk-source-key.asc", "07d2894e7e3de86e8fa5a0368e4db74bff0fe0803e96aebba8716b4b28c60f86"))),
    ("quilt", "0.68-1", "quilt-0.68", "D1CB8F39BC5DED24C5D2C78C1302F1F036EBEB19", (
        ("quilt_0.68-1.dsc", "3202ab7bf40fd893a1e39b366ec3f637eb3d3e2bf2333c7994874a953024f908"),
        ("quilt_0.68.orig.tar.gz", "fe8c09de03c106e85b3737c8f03ade147c956b79ed7af485a1c8a3858db38426"),
        ("quilt_0.68-1.debian.tar.xz", "ab560660e93a5d658f3a6300054b91e8a566b6933e14e17dad6a856d7693c2b9"),
        ("debian-quilt-source-key.asc", "344f9e8f82367e035f201d2d553180dd8e4b56ac4ba408b4f5bd7ef20cc81270"))),
    ("patchutils", "0.4.2-1", "patchutils-0.4.2", "7D887DC8BA7BBBA7B835E3BADCE310E7864CC8BF", (
        ("patchutils_0.4.2-1.dsc", "f7b18896c30d7a78516a23cdf651ce913774fa401ae0f3e2d6666a5ee9621031"),
        ("patchutils_0.4.2.orig.tar.gz", "2ff95f11946558ce63f4d1167abaccbffd49750152346d5304e03ad884304ad6"),
        ("patchutils_0.4.2-1.debian.tar.xz", "2c5ba4449cbc472d2d9395c6f618c7e12e7d8760834033ea85bd2bd249e691ea"),
        ("debian-patchutils-source-key.asc", "e6d6acf96e7fbaa752d603fc43b5f96eea06045f53b9c4367a1864519eaff3c2"))),
    ("linux", "6.12.107-1", "linux-6.12.107", "4644409808C171E05531DDEE054CB8F31343CF44", (
        ("linux_6.12.107-1.dsc", "00f5874a383295a3237321cf59a0f172495084f16cb3dac24ee5aae6649d809a"),
        ("linux_6.12.107.orig.tar.xz", "efc76d3c78a5d65f42724118c437d11db1c9f6309a5f024ee9a8b1978fdc6919"),
        ("linux_6.12.107-1.debian.tar.xz", "d8c003ecac7c54f59c69dc61258f93d937dce90e70f53bb5a34dd58db13028ed"),
        ("debian-linux-source-key.asc", "688c7897e208efa00d38e6c1f0330990bdf0e20293c5344f555e16011d362c62"))),
    ("glibc", "2.41-12+deb13u4", "glibc-2.41", "52BC8695BE34F90AD7D40CB81388C0F899E8336B", (
        ("glibc_2.41-12+deb13u4.dsc", "0915324aa646bb99abfaa9aa6ecb734b30babd28454a3e51f3152912370fbd3e"),
        ("glibc_2.41.orig.tar.xz", "f24aa441021121a79266f0d75242706cab8843a47901fefe74527491807f1998"),
        ("glibc_2.41-12+deb13u4.debian.tar.xz", "dda4153511bfd543502d18e5bc9323110996fe9c531f14ae3fad6eb17f027c7d"),
        ("debian-glibc-source-key.asc", "eba1f3b38c3d166f311ca6fa5cd1a6834b536ea3f341f9e4b5afd02ec2f17e25"))),
)


def main():
    inputs, build, evidence = Path("/inputs"), Path("/build"), Path("/evidence")
    build.mkdir()
    evidence.mkdir()
    record = {"release_qualified": False, "scope": "temporary-bootstrap",
              "bootstrap_headers_and_runtime_allowed": True, "sources": []}
    for name, version, root, signer, materials in SOURCES:
        directory = build / name
        directory.mkdir()
        descriptor = (inputs / materials[0][0]).read_text()
        for filename, expected in materials:
            data = (inputs / filename).read_bytes()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("Source checksum mismatch: " + filename)
            if ".tar." in filename and not re.search(
                    rf"^ {expected} {len(data)} {re.escape(filename)}$", descriptor, re.MULTILINE):
                raise ValueError("Descriptor does not bind archive: " + filename)
        home = directory / "gnupg"
        home.mkdir(mode=0o700)
        subprocess.run(["gpg", "--no-options", "--homedir", str(home), "--batch", "--dearmor",
                        "--output", str(home / "key.gpg"), str(inputs / materials[3][0])], check=True)
        signature = subprocess.run([
            "gpg", "--no-options", "--homedir", str(home), "--batch", "--no-auto-key-retrieve",
            "--no-default-keyring", "--keyring", str(home / "key.gpg"), "--status-fd", "1",
            "--verify", str(inputs / materials[0][0])], check=True, capture_output=True, text=True)
        signatures = [line.split() for line in signature.stdout.splitlines()
                      if line.startswith("[GNUPG:] VALIDSIG ")]
        if len(signatures) != 1 or signatures[0][2] != signer:
            raise ValueError("Unexpected source descriptor signer")
        for filename, _ in materials[1:3]:
            with tarfile.open(inputs / filename) as archive:
                archive.extractall(directory if filename == materials[1][0] else directory / root, filter="data")
        source = directory / root
        patch_records = []
        with (evidence / (name + ".patch.log")).open("wb") as log:
            for line in (source / "debian/patches/series").read_text().splitlines():
                fields = line.split("#", 1)[0].split()
                if not fields:
                    continue
                patch = source / "debian/patches" / fields[0]
                if patch.is_symlink() or not patch.resolve().is_relative_to((source / "debian/patches").resolve()):
                    raise ValueError("Patch must remain inside the vendor patch directory")
                with patch.open("rb") as patch_input:
                    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", *fields[1:]],
                                   cwd=source, stdin=patch_input, stdout=log, stderr=subprocess.STDOUT, check=True)
                patch_records.append({"path": fields[0], "sha256": hashlib.sha256(patch.read_bytes()).hexdigest()})
        commands = [[str(source / "configure"), "--prefix=/bootstrap", "--disable-nls"]]
        work = source
        if name == "bison":
            # Debian replaces the removed documentation before autoreconf.
            (source / "doc/bison.texi").write_text("@setfilename bison.info\n")
            (source / "doc/figs").mkdir(exist_ok=True)
            documentation = [source / "doc" / name for name in ("bison.info", "bison.help")]
            documentation += [source / "doc/figs" / name for name in
                              ("example.txt", "example-reduce.txt", "example-shift.txt")]
            documentation += list((source / "doc").glob("*.texi"))
            documentation += [source / "build-aux/cross-options.pl", source / "src/getargs.c"]
            for path in documentation:
                path.touch()
                os.utime(path, (946684800, 946684800))
            commands.insert(0, ["autoreconf", "-fi"])
        if name == "gawk":
            commands[0] += ["--without-readline", "--without-mpfr"]
        if name == "autoconf":
            commands = [[str(source / "configure"), "--prefix=/bootstrap", "--program-suffix=2.69"]]
        if name == "quilt":
            commands[0] += ["--with-awk=/bootstrap/bin/gawk", "--with-bash=/bin/bash"]
        if name == "patchutils":
            commands.insert(0, ["autoreconf", "-fi"])
        if name == "glibc":
            work = directory / "objects"
            work.mkdir()
            commands = [[str(source / "configure"), "--prefix=/usr", "--disable-werror", "--without-selinux",
                         "--with-headers=/build/linux/linux-6.12.107/usr/include"]]
        commands.append(["make", "-j2"])
        if name == "autoconf":
            commands[-1].append("pkgdatadir=/bootstrap/share/autoconf2.69")
        if name == "bison":
            commands[-1].append("INFO_DEPS=")
            commands.append(["make", "install-binPROGRAMS", "install-dist_pkgdataDATA",
                             "install-dist_skeletonsDATA", "install-dist_m4sugarDATA", "install-dist_xsltDATA"])
        elif name == "gawk":
            commands[-1].append("gawk")
            commands.insert(-1, ["make", "-C", "support", "-j2"])
            commands.append(["make", "install-binPROGRAMS"])
        elif name == "linux":
            architecture = {"aarch64": "arm64", "x86_64": "x86"}[os.uname().machine]
            commands = [["make", "-j2", "headers", "ARCH=" + architecture]]
        elif name == "autoconf":
            commands.append(["make", "install", "pkgdatadir=/bootstrap/share/autoconf2.69"])
        elif name in ("quilt", "patchutils"):
            commands.append(["make", "install"])
        record["sources"].append({"name": name, "version": version, "materials": dict(materials),
                                  "signing_fingerprint": signer, "primary_fingerprint": signatures[0][-1],
                                  "patches": patch_records, "commands": commands, "completed": False})
        (evidence / "bootstrap.json").write_text(json.dumps(record, indent=2) + "\n")
        with (evidence / (name + ".build.log")).open("wb") as log:
            for command in commands:
                print("Building", name, command, flush=True)
                result = subprocess.run(command, cwd=work, stdout=log, stderr=subprocess.STDOUT,
                                        # Keep the verified tarball's gettext macros; NLS is disabled.
                                        env={**os.environ, "CFLAGS": "-O2 -std=gnu11", "AUTOPOINT": "true"})
                if result.returncode:
                    print((evidence / (name + ".build.log")).read_text(errors="replace")[-12000:], flush=True)
                    raise RuntimeError("GNU bootstrap command failed: " + name)
        record["sources"][-1]["completed"] = True
        (evidence / "bootstrap.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
