# Historical binary recipe. Not eligible for source-only promotion.
# The executable pinned source slice is source.py; runtime closure is unfinished.
ARG BASE_IMAGE=alpine:3.24
FROM ${BASE_IMAGE}

RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache ca-certificates; \
    addgroup -g 65532 rootloom; \
    adduser -D -u 65532 -G rootloom -h /home/rootloom -s /bin/sh rootloom; \
    mkdir -p /app; \
    chown 65532:65532 /home/rootloom /app

ENV HOME=/home/rootloom
USER 65532:65532
WORKDIR /app
CMD ["/bin/sh"]
