ARG BASE_IMAGE=registry.access.redhat.com/ubi9/ubi-minimal:9.7
FROM ${BASE_IMAGE}

RUN set -eux; \
    microdnf upgrade -y --setopt=install_weak_deps=0 --setopt=tsflags=nodocs; \
    microdnf install -y ca-certificates --setopt=install_weak_deps=0 --setopt=tsflags=nodocs; \
    microdnf clean all; \
    rm -rf /var/cache/dnf /var/cache/yum; \
    printf 'rootloom:x:65532:\n' >> /etc/group; \
    printf 'rootloom:x:65532:65532:Rootloom:/home/rootloom:/bin/sh\n' >> /etc/passwd; \
    printf 'rootloom:!:0:0:99999:7:::\n' >> /etc/shadow; \
    mkdir -p /home/rootloom /app; \
    chown 65532:65532 /home/rootloom /app

ENV HOME=/home/rootloom
USER 65532:65532
WORKDIR /app
CMD ["/bin/sh"]
