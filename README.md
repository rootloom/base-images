# Rootloom Base Images

[Overview](README.md) | [Latest Images](latest.md) | [Version History](https://github.com/rootloom/base-images/releases)

The target is six minimal source-built bases for `linux/amd64` and `linux/arm64`.
Each final image must start with `FROM scratch`. Its distribution components
and packages must come from compiled, verified source, not upstream binary
images or downloaded binary packages.

Conversion is unfinished. The five distribution recipes remain legacy binary
builds. `source-minimal` is an experimental custom runtime, not a distribution
replacement. No current image is accepted as completing this source workstream.
See the [source conversion ledger](docs/source-build-workstream.md) for gaps,
source verification, bootstrap decisions, acceptance gates, and next owners.

| Image | Target Identity | Architectures |
| --- | --- | --- |
| `debian-slim` | Debian 13 slim | amd64, arm64 |
| `ubi-minimal` | Red Hat UBI 9.7 minimal | amd64, arm64 |
| `alpine` | Alpine 3.24 | amd64, arm64 |
| `ubuntu` | Ubuntu 24.04 LTS | amd64, arm64 |
| `rocky-minimal` | Rocky Linux 9 minimal | amd64, arm64 |
| `source-minimal` | Custom musl/BusyBox runtime | amd64, arm64 |

## Image Contract

This contract applies to all six source conversions. Distribution identity
requires the distribution's source packaging, patches, configuration, and
metadata. A shared BusyBox filesystem cannot stand in for five distributions.

- Images use the non-root user `rootloom`, with UID and GID `65532`.
- `/app` and `/home/rootloom` are writable by that user.
- Images include CA trust data and a shell. They keep truthful component metadata for scans.
- Compile all shipped binaries from pinned source. Record generated files and non-code data separately.
- Exclude bootstrap binaries and build tools from the final root filesystem.
- Do not promise package installation until each distribution's source-built package manager is qualified.
- Use an image digest for deployments. Version tags and `latest` can change.
- No image claims FIPS validation. FIPS variants require separate module, environment, license, and runtime evidence.

## Publication

The intended registry is `ghcr.io/rootloom/<image>`. Pull requests must not
receive publishing credentials. Legacy binary releases are not an accepted
delivery path. Their historical tags and evidence do not prove source conversion.
Source admission must pass before registry writes or promotion.
The local legacy release guard rejects release and direct promotion calls.
Its scheduled/push triggers are removed, and its manual workflow job is disabled.
Remote enforcement requires integration of these changes; this is not a publication claim.

Each published image has public GitHub Release evidence. This includes
platform digests, SPDX SBOMs, raw CVE reports, checksums, scan metadata,
the source commit, and the workflow URL. Review the workflow and scripts for
the exact evidence format and release policy.

Historical distribution evidence uses `standard-<image>-<run_id>-<attempt>`.
Those releases describe binary-based candidates. They are not source releases.
Source-minimal evidence uses `source-source-minimal-<run_id>-<attempt>`.
Extending source evidence to the other five images remains implementation work.
Version tags and `latest` must move only after source qualification, signing,
and public verification. Use immutable digests for deployment and rollback.

Promotion must pass runtime checks and vulnerability policy for both
architectures. All High or Critical source findings block promotion, including
findings without fix metadata. Failed scans
are failures, not empty CVE reports. Other findings remain visible in the reports.
No image can guarantee that it has no CVEs. Reports describe scanner coverage
and known vulnerabilities at the recorded scan time.

New GHCR packages can default to private visibility. A package owner must
make each package public before community release. Anonymous pulls must work
before supported tags are promoted. GitHub Release evidence is public because
this repository is public.

## Source Builds

The `source-minimal` track builds a custom runtime from source and uses
`FROM scratch` for the final image. It is not Debian, Alpine, Ubuntu, UBI,
or Rocky Linux. It does not provide their package managers or compatibility
contracts. It does not claim FIPS validation.

This track is experimental and is not release-qualified. Its reviewed lock
includes musl, BusyBox, compiler-rt builtins, and CA trust data. Scanner coverage
currently supports musl and BusyBox through limited NVD-CPE matching.
Compiler-rt builtins coverage remains unresolved and blocks promotion.
Current component matches also block the vulnerability policy. Do not treat
an experimental candidate as a supported release.

The current `r3` lock pins BusyBox `1.37.0` and musl patches.
Compiler-rt coverage and the reported musl finding remain unresolved release
gates. An updated lock or a skipped workflow is not qualification.
Community release requires native hosted builds and matching public evidence.
No finding may be suppressed to make conversion appear complete.

The user approved a pinned prebuilt compiler only for bootstrap.
Every shipped executable and library must compile from verified source.
The existing builder is digest-pinned GCC `15.2.0`.
A full source compiler bootstrap is not implemented or claimed.

The factory must publish reviewed changes to this repository and use GitHub
Actions for release builds. Local-only results are not accepted delivery.
Delivery requires anonymous GHCR access by digest and matching public CVE
manifests, SBOMs, quality results, and signatures. Failed publication remains
unfinished work until the public delivery checks pass.

The source-build contract requires these controls:

- Pin source archive URLs, versions, checksums, and licenses in a reviewed lock file.
- Disclose all bootstrap inputs. Prevent prebuilt runtime objects from shipping and trace contributing headers to source.
- Fetch inputs before compilation. Compile without network access.
- Copy only required runtime files into the scratch image. Exclude build tools.
- Test the non-root runtime on both architectures.
- Compare repeated build outputs before promotion. Record the comparison in evidence.
- Publish source inventory, source archives, licenses, SBOMs, and component CVE reports.
- Test scanner coverage with known vulnerable component versions. Missing coverage blocks promotion.
- Verify public access, signatures, and exact digests before moving version and `latest` tags.

An empty OS scan does not prove that source-built components have no CVEs.
Component reports describe known findings and scanner coverage, not a security guarantee.
Source changes need reviewed lock updates. A scheduled rebuild cannot safely adopt
a new source checksum without checking its origin.

`Source image release` checks the lock, build inputs, and fresh scanner database
every 15 minutes. It uses native amd64 and arm64 runners. Unchanged, measured
attempts can skip repeat builds until the daily refresh. A blocked attempt never
justifies a promotion claim. Public reports retain unknown coverage and raw findings.
The status page reads source evidence separately from distribution reports.

Source jobs transfer checksum-verified evidence through a run-scoped draft
GitHub Release, not Actions artifacts. Each architecture uploads one source
bundle. The final job removes the temporary scanner database before public
publication. Failed or blocked evidence does not authorize tag promotion.

All six directories belong to this source conversion workstream. Copying
downloaded binary packages into scratch is assembly, not source compilation.
Do not use source-build labels until complete source closure and release
evidence support the claim. Existing checks are reusable, but do not yet
implement source closure for the five distributions.

## Current CVEs

The table updates automatically from public evidence and the live `latest` digests.
Failed candidates do not replace the reported current image.
Counts describe findings per package, not unique CVE identifiers.
A question mark means unknown data, not zero findings.
See [Latest Images](latest.md) for digests, scan times, sizes, packages, and failed attempts.

<!-- image-status:start -->
| Image | Arch | Latest Status | Critical | High | Medium | Low | Unknown | Scan (UTC) | Evidence |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| debian-slim | amd64 | registry-verified | 0 | 43 | 58 | 60 | 1 | 2026-10-10T14:43:46.850333+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38060528323-1) |
| debian-slim | arm64 | registry-verified | 0 | 43 | 58 | 60 | 1 | 2026-10-10T14:43:46.850333+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38060528323-1) |
| ubi-minimal | amd64 | registry-verified | 0 | 12 | 102 | 75 | 0 | 2026-10-10T14:43:46.701539+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38060528323-1) |
| ubi-minimal | arm64 | registry-verified | 0 | 12 | 104 | 77 | 0 | 2026-10-10T14:43:46.701539+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38060528323-1) |
| alpine | amd64 | registry-verified | 0 | 0 | 0 | 0 | 0 | 2026-10-10T14:45:04.622324+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38060528323-1) |
| alpine | arm64 | registry-verified | 0 | 0 | 0 | 0 | 0 | 2026-10-10T14:45:04.622324+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38060528323-1) |
| ubuntu | amd64 | registry-verified | 0 | 0 | 9 | 4 | 0 | 2026-10-10T14:46:13.465784+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38060528323-1) |
| ubuntu | arm64 | registry-verified | 0 | 0 | 9 | 4 | 0 | 2026-10-10T14:46:13.465784+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38060528323-1) |
| rocky-minimal | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| rocky-minimal | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| source-minimal | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| source-minimal | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
<!-- image-status:end -->

## Version Control

Git records image definitions, pinned CI tools, policy changes, and status updates.
Each accepted source build must record its commit, source lock, and bootstrap identity.
Unique run-attempt tags retain qualified releases. Use digests for deployment and rollback.
The OS-version tag and `latest` move only after qualification and signing.
Public evidence remains available for failed and blocked attempts.
Concurrent release runs do not promote images at the same time.
Status automation commits only changed data. It does not trigger another release build.
Legacy binary package updates are time-dependent. Source conversion requires
immutable inputs and measured repeat-rootfs equality for each architecture.

## Local Builds

The five legacy Dockerfiles do not test the requested source-build target.
Do not treat a local build as release qualification. Use the approved
bootstrap-only boundary. Source qualification uses
native amd64 and arm64 runners, not emulated runtime tests.

Run the release-policy tests from the repository root:

```sh
python3 -m unittest discover -s tests -v
```

## Contributions

Keep image dependencies small. Add tests for changes to scan or release policy.
Do not add FIPS tags based only on a distribution name or an enabled setting.
Do not remove package metadata to hide findings.
