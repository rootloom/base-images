FROM docker.io/library/gcc:16.2.0@sha256:17043c23ec2ad97fc3beca18da77275d26be5db5cd70ea0a5d73200e21a8e999 AS fetch
ENV PYTHONDONTWRITEBYTECODE=1
COPY images/source-minimal/ /recipe/
COPY images/alpine/ /alpine/
RUN python3 /alpine/source.py fetch /alpine-inputs && python3 /alpine/runtime.py prepare-recipe /recipe /alpine-inputs && python3 /recipe/fetch.py /recipe/sources.lock.json /downloads

FROM fetch AS compile
ARG TARGETARCH
ARG REBUILD_NONCE
ENV SOURCE_DATE_EPOCH=1789689600
RUN --network=none ALPINE_SOURCE_INPUTS=/alpine-inputs sh /recipe/build.sh "$TARGETARCH"

FROM scratch AS evidence
COPY --from=compile /evidence/ /

FROM scratch AS runtime
COPY --from=compile /rootfs/ /
LABEL org.opencontainers.image.title="Rootloom Alpine-derived source runtime"
LABEL org.opencontainers.image.description="Alpine 3.24 patched musl and BusyBox subset; no apk or init services; bootstrap compiler disclosed"
ENV HOME=/home/rootloom PATH=/bin:/usr/bin SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
USER 65532:65532
CMD ["/bin/sh"]
