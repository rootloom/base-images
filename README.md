# Rootloom Base Images

Slim community Linux bases for `linux/amd64` and `linux/arm64`.

The initial set contains Debian slim, Red Hat UBI minimal, Alpine, Ubuntu LTS,
and Rocky Linux minimal. Standard variants come first. These images do not
claim FIPS validation. FIPS variants need separate validation evidence and
redistribution review before publication.

| Image | Upstream Base | Architectures |
| --- | --- | --- |
| `debian-slim` | Debian 13 slim | amd64, arm64 |
| `ubi-minimal` | Red Hat UBI 9.7 minimal | amd64, arm64 |
| `alpine` | Alpine 3.24 | amd64, arm64 |
| `ubuntu` | Ubuntu 24.04 LTS | amd64, arm64 |
| `rocky-minimal` | Rocky Linux 9 minimal | amd64, arm64 |

## Image Contract

- Images use the non-root user `rootloom`, with UID and GID `65532`.
- `/app` and `/home/rootloom` are writable by that user.
- Images include CA certificates and a shell. They keep package metadata for scans.
- Builds apply package updates and remove package download caches in the same layer.
- Downstream builds can use `USER 0` to install packages, then restore `USER 65532:65532`.
- Use an image digest for deployments. Version tags and `latest` can change.

## Publication

GitHub Actions builds both architectures and publishes images to
`ghcr.io/rootloom/<image>`. Pull requests do not receive publishing credentials.
Scheduled builds refresh upstream inputs and vulnerability data.

Each published image has public GitHub Release evidence. This includes
platform digests, SPDX SBOMs, raw CVE reports, checksums, scan metadata,
the source commit, and the workflow URL. Review the workflow and scripts for
the exact evidence format and release policy.

Each image gets its OS-version tag, `latest`, and a
`standard-<run_id>-<attempt>` tag after qualification. Evidence releases use
`standard-<image>-<run_id>-<attempt>`. Daily rebuilds also refresh CVE reports.
Reports for older digests remain available, but are not rescanned separately.

Promotion must pass runtime checks and vulnerability policy for both
architectures. Fixable High or Critical findings block promotion. Failed scans
are failures, not empty CVE reports. Other findings remain visible in the reports.
No image can guarantee that it has no CVEs. Reports describe scanner coverage
and known vulnerabilities at the recorded scan time.

New GHCR packages can default to private visibility. A package owner must
make each package public before community release. Anonymous pulls must work
before supported tags are promoted. GitHub Release evidence is public because
this repository is public.

## Local Builds

Build one image with Docker:

```sh
docker build --pull -t rootloom-local images/debian-slim
docker run --rm rootloom-local sh -ec 'test "$(id -u)" = 65532; test -w /app; test -s /etc/ssl/certs/ca-certificates.crt'
```

Use Docker Buildx for multi-platform builds. Local builds need network access
to upstream registries and package repositories. Package updates make builds
time-dependent, even when the upstream image digest is fixed.

Run the release-policy tests from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

## Contributions

Keep image dependencies small. Add tests for changes to scan or release policy.
Do not add FIPS tags based only on a distribution name or an enabled setting.
Do not remove package metadata to hide findings.
