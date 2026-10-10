ARG BASE_IMAGE=debian:13-slim
FROM ${BASE_IMAGE}

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    printf 'rootloom:x:65532:\n' >> /etc/group; \
    printf 'rootloom:x:65532:65532:Rootloom:/home/rootloom:/bin/sh\n' >> /etc/passwd; \
    printf 'rootloom:!:0:0:99999:7:::\n' >> /etc/shadow; \
    mkdir -p /home/rootloom /app; \
    chown 65532:65532 /home/rootloom /app

ENV HOME=/home/rootloom
USER 65532:65532
WORKDIR /app
CMD ["/bin/sh"]
