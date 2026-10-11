# syntax=docker/dockerfile:1.7
FROM docker.io/library/gcc:15.2.0@sha256:3ae15afe768b06d0c0fe088d822ba5f8045c26630bdacc8d8e7713cf5d8e7289 AS bootstrap
COPY images/debian-slim/bootstrap.py /recipe/bootstrap.py
COPY --from=inputs bison_3.8.2+dfsg-1.dsc bison_3.8.2+dfsg.orig.tar.xz bison_3.8.2+dfsg-1.debian.tar.xz debian-bison-source-key.asc /inputs/
COPY --from=inputs gawk_5.2.1-2.dsc gawk_5.2.1.orig.tar.xz gawk_5.2.1-2.debian.tar.xz debian-gawk-source-key.asc /inputs/
COPY --from=inputs glibc_2.41-12+deb13u4.dsc glibc_2.41.orig.tar.xz glibc_2.41-12+deb13u4.debian.tar.xz debian-glibc-source-key.asc /inputs/
COPY --from=inputs linux_6.12.107-1.dsc linux_6.12.107.orig.tar.xz linux_6.12.107-1.debian.tar.xz debian-linux-source-key.asc /inputs/
ENV PYTHONDONTWRITEBYTECODE=1 PATH=/bootstrap/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN --network=none python3 /recipe/bootstrap.py

# Export build records only. Bootstrap objects and headers are not release inputs.
FROM scratch AS evidence
COPY --from=bootstrap /evidence/ /
