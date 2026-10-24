# syntax=docker/dockerfile:1.7
FROM docker.io/library/gcc:16.1.0@sha256:d8dec2859f964120119abd1380563247bf02c5d64f5bcdea496dbace1f48c6f0 AS bootstrap
COPY images/debian-slim/bootstrap.py /recipe/bootstrap.py
COPY images/source-minimal/compiler.py images/source-minimal/origins.py /recipe/
COPY --from=inputs bison_3.8.2+dfsg-1.dsc bison_3.8.2+dfsg.orig.tar.xz bison_3.8.2+dfsg-1.debian.tar.xz debian-bison-source-key.asc /inputs/
COPY --from=inputs gawk_5.2.1-2.dsc gawk_5.2.1.orig.tar.xz gawk_5.2.1-2.debian.tar.xz debian-gawk-source-key.asc /inputs/
COPY --from=inputs autoconf2.69_2.69-3.1.dsc autoconf2.69_2.69.orig.tar.xz autoconf2.69_2.69-3.1.debian.tar.xz /inputs/
COPY --from=inputs quilt_0.68-1.dsc quilt_0.68.orig.tar.gz quilt_0.68-1.debian.tar.xz debian-quilt-source-key.asc /inputs/
COPY --from=inputs patchutils_0.4.2-1.dsc patchutils_0.4.2.orig.tar.gz patchutils_0.4.2-1.debian.tar.xz debian-patchutils-source-key.asc /inputs/
COPY --from=inputs glibc_2.41-12+deb13u4.dsc glibc_2.41.orig.tar.xz glibc_2.41-12+deb13u4.debian.tar.xz debian-glibc-source-key.asc /inputs/
COPY --from=inputs linux_6.12.107-1.dsc linux_6.12.107.orig.tar.xz linux_6.12.107-1.debian.tar.xz debian-linux-source-key.asc /inputs/
ENV PYTHONDONTWRITEBYTECODE=1 PATH=/bootstrap/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN --network=none python3 /recipe/bootstrap.py

FROM bootstrap AS gnu-compiler
COPY images/debian-slim/gcc_bootstrap.py /recipe/gcc_bootstrap.py
COPY --from=inputs gcc-14_14.2.0-19.dsc gcc-14_14.2.0.orig.tar.gz gcc-14_14.2.0-19.debian.tar.xz debian-gcc-source-key.asc /inputs/
COPY --from=inputs gmp-6.2.1.tar.bz2 mpfr-4.1.0.tar.bz2 mpc-1.2.1.tar.gz /inputs/
RUN --network=none ln -s /bootstrap/bin/autom4te2.69 /usr/bin/autom4te2.69
RUN --network=none python3 /recipe/gcc_bootstrap.py

FROM gnu-compiler AS gnu-headers
COPY images/debian-slim/headers.py /recipe/headers.py
RUN --network=none python3 /recipe/headers.py

FROM scratch AS header-evidence
COPY --from=gnu-headers /evidence/ /

FROM gnu-headers AS gnu-libgcc
COPY images/debian-slim/libgcc.py images/debian-slim/trace_compiler.py /recipe/
RUN --network=none python3 /recipe/libgcc.py

FROM scratch AS libgcc-evidence
COPY --from=gnu-libgcc /evidence/ /

FROM gnu-headers AS gnu-runtime-trace
COPY images/debian-slim/runtime.py images/debian-slim/trace_compiler.py /recipe/
RUN --network=none python3 /recipe/runtime.py

FROM scratch AS runtime-trace-evidence
COPY --from=gnu-runtime-trace /evidence/ /

FROM scratch AS compiler-evidence
COPY --from=gnu-compiler /evidence/ /

# Export build records only. Bootstrap objects and headers are not release inputs.
FROM scratch AS evidence
COPY --from=bootstrap /evidence/ /
