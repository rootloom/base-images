# Alpine Source Slice

This directory now has an executable source slice, not a release-qualified Alpine runtime.
The existing Dockerfile remains a historical binary recipe and cannot enter source promotion.
No source-minimal files supply this slice. No downloaded binary package supplies output files.

`Source.Dockerfile` now defines a separate scratch runtime build.
It reuses the audited compiler helpers, but uses Alpine's complete musl/BusyBox patches and a recorded Alpine configuration delta.
The runtime omits package installation, init services, TLS clients, utmps, and privilege-changing applets.
It adds Alpine's source-built layout/release data and a disclosed pinned Mozilla trust-data overlay.
The `Alpine source runtime` workflow compiles twice on native amd64 and arm64 workers and runs non-root smoke checks.
Runtime build success, advisory coverage, public evidence, signatures, and promotion are not yet established for this recipe.

## Locked Inputs

The primary `3.24-stable` branch returned commit `3c2c2436e397ea23073cde73138f60e0d5c537b4` during implementation.
The lock pins the official aports mirror archive and every selected recipe file by SHA-256.
It also pins all declared package source inputs by the APKBUILD SHA-512 values.
The retained recipe sets are:

| Recipe | Version | Role |
| --- | --- | --- |
| alpine-baselayout | 3.7.2-r1 | Actual directory/data recipe, with a disclosed container overlay |
| alpine-base | 3.24.2-r0 | Only the actual alpine-release function; no alpine-base dependency installation |
| musl | 1.2.6-r2 | Complete pinned Alpine source/patch/utility inputs; preparation only |
| BusyBox | 1.37.0-r31 | Complete pinned Alpine source/configuration/patch inputs; preparation only |

Source acquisition uses Alpine's checksum-preserving distfiles mirror for external recipe inputs.
The lock keeps their original primary URLs. Hash failures stop extraction or recipe execution.
HTTPS and checksum verification do not establish independent signer authentication.
No aports commit signature or musl detached signature is verified by this slice.
The lock is a selected source inventory, not a complete runtime or build-tool dependency graph.

## Invocation

Run these commands from the repository root. No host package installation is needed.

```sh
python3 images/alpine/source.py fetch /tmp/rootloom-alpine-inputs
python3 images/alpine/source.py verify /tmp/rootloom-alpine-inputs
python3 images/alpine/source.py build-layout /tmp/rootloom-alpine-inputs /tmp/rootloom-alpine-layout
python3 images/alpine/source.py prepare-runtime /tmp/rootloom-alpine-inputs /tmp/rootloom-alpine-runtime-sources
ALPINE_SOURCE_INPUTS=/tmp/rootloom-alpine-inputs PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_alpine_source.py -v
```

`fetch` writes verified source files and the pinned aports archive into the input directory.
`build-layout` and `prepare-runtime` require empty output directories. Neither command fetches inputs.
Use a network-disabled container to enforce offline execution. Host execution alone does not enforce network isolation.
`build-layout` runs the actual pinned `prepare`, `build`, `package`, and `release` shell functions.
The portable `install` adapter implements their selected installation options without changing host users or groups.
It does not execute abuild package scripts or install packages.

The layout output contains `rootfs/` and `layout-evidence.json`.
Evidence maps all directories, links, file hashes, modes, logical target owners, and source/generated-file origins.
It binds the source lock and adapter hashes. Host filesystem owners remain unchanged.
The slice combines baselayout/data without producing APK archives or APK package metadata.
The container overlay locks root, adds UID/GID 65532, protects account files, and creates `/app` and `/home/rootloom`.
It removes the unused APK commit hook and replaces the full-system setup message.
The source recipes and overlay remain required corresponding-source inputs.

`prepare-runtime` extracts verified upstream archives and applies every locked Alpine patch in recipe checksum order.
It preserves Alpine's musl version file and removal of the x86-64 assembly memcpy/memmove implementations.
It copies Alpine's exact BusyBox configuration, not a custom source-minimal configuration.
It retains patch logs and `runtime-source-evidence.json`.
The patch command permits the default context tolerance of two lines.
One BusyBox test hunk needs that tolerance after an earlier Alpine patch changes the surrounding test.
Successful patch preparation is not binary compilation or runtime qualification.

## Runtime Contract And Blockers

The target is an Alpine-derived 3.24 container subset, not an official Alpine-built image or full alpine-base installation.
Omit APK, Alpine repository keys, OpenRC, mdev services, BusyBox setuid helpers, and package installation promises.
These omissions must remain explicit in final image metadata and tests.

The packaging slice has no shell, loader, libc, compiled utilities, or CA bundle. It is not runnable.
Do not publish it or move Alpine/latest tags to it.
Do not copy bootstrap compiler libraries or startup objects into the eventual rootfs.
The historical Dockerfile still violates the source-only requirement.

Next, build Alpine-patched musl with source-built compiler helpers and audited header/startup/link inputs on native workers.
Then build Alpine-configured BusyBox against that musl, with explicit decisions for its utmps and OpenSSL dependency paths.
If features are removed, retain the configuration delta and disclose the changed compatibility contract.
Build the CA bundle from the selected Alpine certificate recipe and lock its trust data and generated-file dependencies.
Retain licenses, effective configurations, all contributing sources, and per-file origins for compiled outputs.
Native amd64/arm64 runtime tests, independent repeat builds, advisory coverage, and source promotion integration remain required.

## Observed Verification

The implementation fetched all locked primary inputs and verified every recipe SHA-256 and source SHA-512 value.
The regenerated lock matched the reviewed lock byte-for-byte.
Its SHA-256 is `d8384369acbe826c7c18021d988d6b7ce870863a331e38383e7043260663f9e4`.
The focused suite passed 11 tests with `ALPINE_SOURCE_INPUTS` set, including actual recipe execution and tampered-input controls.
The concurrent repository suite discovered 107 tests: 106 passed and one unrelated runtime test skipped.
`git diff --check` passed. These results do not qualify an Alpine runtime image.

Two fresh packaging runs passed inside native Linux arm64 containers with network disabled and all capabilities removed.
The approved GCC bootstrap platform digest was `sha256:e55a45ec94b8f1dc59f08e3b25b8e7f23b96220235da707ae2cc0dce47f6b46c`.
Its files supplied build tools only. No compiler/runtime objects entered the packaging output.
Both normalized evidence files matched byte-for-byte, including hashes, modes, links, and logical target owners.
Their SHA-256 was `1c049d329a0bc510f269382aaa1425cacd9355acabb30c61d097be062fc0dbdf`.
A fresh macOS packaging run produced identical normalized evidence.
These data-only checks are not independent runtime compilation or cross-architecture ABI qualification.

The native network-disabled `prepare-runtime` command also passed.
GNU patch reported fuzz 2 on the documented BusyBox test hunk and retained its log.
No musl, BusyBox, or compiler-runtime binary was compiled during these checks.

The exact native invocation used these mounts, with repository-relative paths shown for reuse:

```sh
mkdir -p images/alpine/.work-output
# Place verified fetch output in images/alpine/.work-inputs before this command.
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,nosuid,nodev \
  --mount type=bind,source="$(pwd)/images/alpine",target=/recipe,readonly \
  --mount type=bind,source="$(pwd)/images/alpine/.work-inputs",target=/inputs,readonly \
  --mount type=bind,source="$(pwd)/images/alpine/.work-output",target=/out \
  docker.io/library/gcc@sha256:e55a45ec94b8f1dc59f08e3b25b8e7f23b96220235da707ae2cc0dce47f6b46c \
  python3 /recipe/source.py build-layout /inputs /out/native-layout-1
```

The second run used `/out/native-layout-2`.
The source preparation run used `prepare-runtime /inputs /out/native-runtime-sources-1` instead of the final command arguments.
`cmp` compared both `layout-evidence.json` files and returned exit 0.
The ignored `.work-inputs/` and `.work-output/` directories retain verified inputs and local evidence for coordinator inspection.
No host dependencies, global settings, commits, pushes, or publication changed.
