FROM docker.io/library/gcc:15.2.0@sha256:3ae15afe768b06d0c0fe088d822ba5f8045c26630bdacc8d8e7713cf5d8e7289 AS fetch
WORKDIR /recipe
COPY images/source-minimal/sources.lock.json images/source-minimal/fetch.py /recipe/
RUN python3 /recipe/fetch.py /recipe/sources.lock.json /downloads

FROM fetch AS compile
COPY images/source-minimal/ /recipe/
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=1789689600
ARG BUILD_NONCE=0
ENV LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
RUN --network=none test -n "$BUILD_NONCE" && /bin/sh /recipe/build.sh "$TARGETARCH"

FROM scratch AS evidence
COPY --from=compile /evidence/ /

FROM scratch AS runtime
COPY --from=compile /rootfs/ /
ENV PATH=/bin HOME=/home/rootloom SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
WORKDIR /app
CMD ["/bin/sh"]
