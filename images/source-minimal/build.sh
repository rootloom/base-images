#!/bin/sh
set -eu
umask 022
arch=$1
case "$arch" in
    amd64) musl_arch=x86_64 ;;
    arm64) musl_arch=aarch64 ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
esac
export KCONFIG_NOTIMESTAMP=1
mkdir -p /build /rootfs/bin /rootfs/lib /evidence/sources
cd /build
tar -xzf /downloads/musl-1.2.6.tar.gz
tar -xjf /downloads/busybox-1.37.0.tar.bz2
tar -xJf /downloads/llvm-project-23.1.3.src.tar.xz llvm-project-23.1.3.src/compiler-rt
cd /build/musl-1.2.6
patch --batch --fuzz=0 -p1 < /downloads/musl-iconv-gb18030.patch
patch --batch --fuzz=0 -p1 < /downloads/musl-qsort-CVE-2026-40200.patch
./configure --prefix=/opt/musl --syslibdir=/lib \
    LIBCC=/build/compiler-builtins.a \
    CFLAGS='-O2 -fstack-protector-strong -fstack-clash-protection -ffile-prefix-map=/build=.' \
    LDFLAGS='-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none,-Map,/evidence/musl.link.map'
make -s obj/include/bits/alltypes.h obj/include/bits/syscall.h
python3 /recipe/builtins.py "$musl_arch"
make -s -j2
make -s install
python3 - <<'PY'
from pathlib import Path
specs = Path('/opt/musl/lib/musl-gcc.specs')
text = specs.read_text()
text = text.replace('libgcc.a%s %:if-exists(libgcc_eh.a%s)', '/build/compiler-builtins.a')
text = text.replace(' crtbeginS.o%s', '').replace('crtendS.o%s ', '')
if 'libgcc.a' in text or 'crtbegin' in text or 'crtend' in text:
    raise ValueError('Bootstrap runtime remains in compiler specs')
specs.write_text(text)
PY
cp /opt/musl/lib/libc.so /rootfs/lib/libc.so
ln -s libc.so "/rootfs/lib/ld-musl-$musl_arch.so.1"
cd /build/busybox-1.37.0
make allnoconfig > /dev/null
python3 - <<'PY'
from pathlib import Path
config = Path('.config')
lines = config.read_text().splitlines()
for line in Path('/recipe/busybox.config').read_text().splitlines():
    key = line.split('=')[0]
    lines = [x for x in lines if not x.startswith(key + '=') and x != '# ' + key + ' is not set']
    lines.append(line)
config.write_text('\n'.join(lines) + '\n')
PY
yes '' | make oldconfig > /dev/null
make -s -j2 CC=/opt/musl/bin/musl-gcc \
    EXTRA_CFLAGS='-std=gnu11 -O2 -fPIE -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -ffile-prefix-map=/build=.' \
    EXTRA_LDFLAGS='-pie -Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none,-Map,/evidence/busybox.link.map' \
    || { cat busybox_unstripped.out; exit 1; }
cp busybox /rootfs/bin/busybox
for applet in $(/opt/musl/lib/libc.so /rootfs/bin/busybox --list); do
    ln -s busybox "/rootfs/bin/$applet"
done
test -L /rootfs/bin/sh
mkdir -p /rootfs/etc/ssl/certs /rootfs/usr/share/rootloom /rootfs/usr/share/licenses \
    /rootfs/app /rootfs/home/rootloom /rootfs/tmp /rootfs/proc /rootfs/dev /rootfs/sys
printf 'root:x:0:0:root:/root:/bin/false\nrootloom:x:65532:65532:Rootloom:/home/rootloom:/bin/sh\n' > /rootfs/etc/passwd
printf 'root:x:0:\nrootloom:x:65532:\n' > /rootfs/etc/group
printf 'root:!:0:0:99999:7:::\nrootloom:!:0:0:99999:7:::\n' > /rootfs/etc/shadow
chmod 0600 /rootfs/etc/shadow
chmod 1777 /rootfs/tmp
chown 65532:65532 /rootfs/app /rootfs/home/rootloom
cp /downloads/cacert-2026-09-25.pem /rootfs/etc/ssl/certs/ca-certificates.crt
ln -s certs/ca-certificates.crt /rootfs/etc/ssl/cert.pem
cp /build/musl-1.2.6/COPYRIGHT /rootfs/usr/share/licenses/musl.txt
cp /build/busybox-1.37.0/LICENSE /rootfs/usr/share/licenses/busybox.txt
cp /build/llvm-project-23.1.3.src/compiler-rt/LICENSE.TXT /rootfs/usr/share/licenses/compiler-rt.txt
cp /recipe/CA-NOTICE.txt /rootfs/usr/share/licenses/mozilla-ca-bundle.txt
cp /downloads/* /evidence/sources/
cp -R /recipe /evidence/sources/recipe
cp .config /evidence/sources/busybox.effective.config
python3 /recipe/evidence.py "$arch"
find /rootfs -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --numeric-owner \
    -C /rootfs -cf /evidence/rootfs.tar .
cd /evidence
sha256sum rootfs.tar > rootfs.sha256
cp rootfs.sha256 /rootfs/usr/share/rootloom/rootfs.sha256
touch -d "@$SOURCE_DATE_EPOCH" /rootfs/usr/share/rootloom/rootfs.sha256 /rootfs/usr/share/rootloom
tar --sort=name --format=gnu --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -cf corresponding-source.tar sources
