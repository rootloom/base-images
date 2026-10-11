# Source Build Inputs

This file records implementation dependencies, not completed source conversions.
The release contract and ownership ledger belong in `docs/source-build-workstream.md`.
The user approved a pinned prebuilt compiler only for bootstrap.
Every shipped executable and library must compile from verified source. Host dependency installation remains prohibited.

## Current Recipes

| Directory | Current Inputs | Source Conversion Status |
| --- | --- | --- |
| `debian-slim` | `debian:13-slim`, APT binary packages | Not converted |
| `ubuntu` | `ubuntu:24.04`, APT binary packages | Not converted |
| `alpine` | `alpine:3.24`, APK binary packages | Not converted |
| `rocky-minimal` | Rocky Linux 9 minimal, RPM binary packages | Not converted |
| `ubi-minimal` | Red Hat UBI 9.7 minimal, RPM binary packages | Not converted; rebuilt identity needs review |
| `source-minimal` | Compiled musl, BusyBox, compiler-rt builtins; pinned trust data | Scratch runtime exists; coverage and source-origin audits remain unresolved |

The five legacy Dockerfiles do not meet the source-build requirement.
Changing their final stage to `scratch` would not make their binary packages source-built.
Replacing their userland with source-minimal would not preserve distribution identity.

## Common Build Boundary

Each shipped binary needs a source input, distribution recipe, patch set, build configuration, and output hash.
Generated files and trust data also need recorded inputs and licenses.
The final root filesystem starts empty. It receives only verified outputs from the recorded build graph.
Locally built package archives can preserve package metadata. Downloaded binary package payloads cannot populate the final filesystem.
Source packages can contain generated or vendored binaries. Inspect them before admitting their contents.

Keep the build-tool graph separate from the shipped runtime graph.
A pinned binary compiler may start the build-tool graph. It must not supply prebuilt shipped runtime objects.
If compiler bootstrap must also use source, define and verify that graph before distribution builds.
Do not interpret the existing GCC builder as approval for new bootstrap inputs.

Resolve dependencies separately for `amd64` and `arm64`, including architecture conditions and alternative dependencies.
Reject missing inputs, unresolved dependency cycles, unexpected ELF dependencies, and unrecorded files.
Retain native tests, normalized repeat-rootfs checks, complete vulnerability coverage, and signed promotion gates.

GNU construction now retains temporary compiler generation inputs and can replay glibc constant scripts against exact retained stdin and assembly.
Fresh libgcc construction records byte-bound `libgcc_tm.h` and `auto-target.h` replay evidence, but does not admit those headers.
Configure probe inputs, compiler generated headers, bootstrap runtime replacement, and explicit GNU final-link policy remain unresolved.
These construction controls do not complete the Debian runtime graph or qualify any release.
Source promotion rejects all candidates until authenticated independent exact-digest quality approval is implemented.
The current task IDs, scoped tests, native follow-up, and finite duty expiry are recorded in the workstream ledger.

## Debian 13 Slim

Use Debian source packages, including Debian patches and `debian/rules`. Upstream tarballs alone do not preserve Debian packaging.
The source graph is:

```text
authenticated archive snapshot -> Sources/Packages metadata -> selected runtime packages
selected packages -> source/version mapping -> .dsc -> upstream/native tarball + Debian delta
source control -> architecture-specific Build-Depends + build-essential -> build-tool graph
source + patches + build tools -> dpkg-buildpackage/sbuild -> locally built packages
locally built packages -> Depends/Pre-Depends + maintainer scripts/triggers -> empty rootfs
```

Runtime seed families include `base-files`, `base-passwd`, `glibc`, `gcc` runtime libraries, `dash`, and `coreutils`.
Preserving ordinary slim package-manager behavior also requires `dpkg`, `apt`, and their complete runtime dependencies.
Essential packages have implicit dependencies. Resolving only explicit `Depends` is insufficient.
Certificates require the `ca-certificates` source and the tools used by its scripts, including the selected OpenSSL package.
Derive the complete runtime set from the selected slim contract and authenticated package metadata, not this seed list.

The toolchain cycle includes binutils, GCC, Linux headers, glibc headers/start files, and compiler runtime libraries.
Package builds also need source-specific debhelper, Perl, Python, compression tools, and other declared build dependencies.
The exact package versions, source hashes, and cycle-breaking build profiles are not locked here.

First unit: freeze the Debian snapshot and resolve the complete runtime/source mapping for both architectures.
Record `.dsc` signatures, every `Checksums-Sha256` input, build dependencies, Essential packages, and script interpreters.
Then rebuild `base-files` and `base-passwd` as a packaging-only slice. This does not produce a runnable Debian image.

Primary references:
- [Debian source and binary control fields](https://www.debian.org/doc/debian-policy/ch-controlfields.html)
- [Debian dependency relationships](https://www.debian.org/doc/debian-policy/ch-relationships.html)
- [Debian package build commands](https://www.debian.org/doc/manuals/debmake-doc/ch05.en.html)
- [Debian snapshots](https://snapshot.debian.org/)

## Ubuntu 24.04

Use the Debian package graph above, with Ubuntu's own source versions, patches, archive keys, and release pockets.
Do not substitute Debian 13 source inputs for Noble packages.
Resolve Noble, Noble updates, and Noble security through one reviewed immutable metadata set.
Runtime seed families match the Debian graph, but their versions and dependency edges can differ.
Ubuntu's `base-files` supplies Ubuntu release identity. Preserve its source changes and disclose Rootloom modifications.
Launchpad's standard build dependency installation does not prove source closure for the final filesystem.

First unit: produce the Noble runtime/source mapping independently from Debian's lock.
Rebuild Noble `base-files` and `base-passwd` after locking their full source inputs and build requirements.
Next, rebuild the Noble glibc/compiler-runtime slice before adding shell, core tools, package managers, and certificates.

Primary references:
- [Ubuntu source retrieval](https://documentation.ubuntu.com/project/contributors/setup/get-the-source-of-a-package)
- [Ubuntu local package builds](https://documentation.ubuntu.com/project/contributors/bug-fix/build-packages-locally)
- [Launchpad source packages and build dependencies](https://documentation.ubuntu.com/launchpad/user/reference/packaging/ppas/building-a-source-package)
- [Ubuntu archive](https://archive.ubuntu.com/ubuntu/)
- [Ubuntu ports archive](https://ports.ubuntu.com/ubuntu-ports/)

## Alpine 3.24

Reuse Alpine's aports recipes and abuild bootstrap graph, not source-minimal's generic musl/BusyBox configuration.
The inspected `3.24-stable` branch is a discovery reference, not an immutable build pin.
Its bootstrap order is:

```text
abuild host tools -> cross binutils -> musl headers -> minimal cross GCC
minimal cross GCC -> bootstrap musl -> libucontext -> full cross GCC -> build-base
target toolchain -> selected APKBUILD sources/patches/configurations -> local packages
local runtime dependency closure + Alpine release/baselayout/keys -> empty rootfs
```

Runtime seeds include musl, Alpine-configured BusyBox, alpine-baselayout/data, alpine-release, alpine-keys, apk-tools, and certificates.
The inspected apk-tools recipe is `3.0.8-r0`. It uses Meson/Ninja, not the apk-tools 2 Make-only recipe.
Its declared runtime inputs include musl, OpenSSL `libcrypto3>=3.5`, matching `libapk`, and the CA bundle outside bootstrap mode.
Its build inputs include Linux headers, OpenSSL/zlib development and static libraries, Lua, Meson, and documentation tools.
Non-bootstrap builds also add Lua/Python bindings and tests. Record selected subpackages and their actual output dependencies.
Keep the recipe's `repo-hash-sha1.patch` and its verified checksum.
Generate the CA bundle from the distribution source recipe, not from a downloaded binary certificate package.

The `alpine-base` meta-package adds OpenRC, mdev, and BusyBox setuid packages.
Do not install that whole meta-package blindly into a non-root container.
Define a container subset, record exclusions, and preserve authentic release/baselayout data without claiming full Alpine-base equivalence.
The musl recipe also carries Alpine patches and utility sources absent from source-minimal.

First unit: pin one reviewed aports commit and enumerate every source, local patch, recipe checksum, and dependency for these runtime seeds.
Rebuild alpine-baselayout/data and alpine-release as the first packaging-only slice.
Next, rebuild the Alpine musl/BusyBox pair, then OpenSSL/zlib/apk-tools and the certificate bundle.
An APK index assembled from upstream binary packages does not qualify.

Primary references:
- [Alpine bootstrap order](https://github.com/alpinelinux/aports/blob/3.24-stable/scripts/bootstrap.sh)
- [Alpine apk-tools recipe](https://github.com/alpinelinux/aports/blob/3.24-stable/main/apk-tools/APKBUILD)
- [Alpine musl recipe](https://github.com/alpinelinux/aports/blob/3.24-stable/main/musl/APKBUILD)
- [Alpine baselayout recipe](https://github.com/alpinelinux/aports/blob/3.24-stable/main/alpine-baselayout/APKBUILD)
- [Alpine release recipe](https://github.com/alpinelinux/aports/blob/3.24-stable/main/alpine-base/APKBUILD)
- [Alpine certificate recipe](https://github.com/alpinelinux/aports/blob/3.24-stable/main/ca-certificates/APKBUILD)

## Rocky Linux 9 Minimal

Use Rocky source RPMs and distribution spec files, including patches, macros, configuration, and release data.
Peridot is Rocky's build system. Installing its infrastructure is not required for an initial bounded package rebuild.
The source graph is:

```text
authenticated repository snapshot -> runtime RPM identities -> matching source RPMs
source RPM -> spec + Source/Patch files -> BuildRequires + RPM macro/tool graph
source rebuild -> local RPMs -> Requires + scriptlets/triggers + ELF dependencies
verified local outputs + Rocky release data -> empty rootfs
```

Seed families include rocky-release/repos/gpg-keys, filesystem, setup, basesystem, glibc, GCC runtime libraries, bash, and coreutils.
Preserving the minimal package-manager contract also needs RPM, microdnf, libdnf, librepo, libsolv, and their resolved dependencies.
Certificates add ca-certificates, p11-kit, and the selected trust extraction tools.
These are seed families, not a verified exhaustive package list.
Spec macros, conditional BuildRequires, generated sources, and script interpreters must enter the lock.
Source RPM availability does not prove that every build dependency is available or reproducible.

First unit: freeze the repository metadata and map each selected binary RPM to a signed, checksum-pinned source RPM.
Inspect and rebuild the release/filesystem/setup packaging slice before the glibc/compiler-runtime slice.
Use local outputs only for final assembly. Do not use `microdnf --installroot` against public binary repositories.

Primary references:
- [Rocky Peridot](https://github.com/rocky-linux/peridot)
- [Rocky BaseOS source RPMs](https://download.rockylinux.org/pub/rocky/9/BaseOS/source/tree/Packages/)
- [Rocky AppStream source RPMs](https://download.rockylinux.org/pub/rocky/9/AppStream/source/tree/Packages/)

## UBI 9.7 Minimal

Red Hat publishes source containers for UBI. Inspect the source container matching the exact selected binary image digest.
The source graph follows the RPM graph above, using the matching Red Hat sources, patches, macros, and package selection.
Do not replace those sources with Rocky SRPMs and call the result UBI.
Inspect the complete source-container inventory before claiming that the graph can be rebuilt without additional source access.
Build dependencies can extend beyond UBI's publicly available binary repository subset.
Release data, branding, redistribution terms, and rebuilt image naming need explicit review.
A Rootloom rebuild must not claim Red Hat-built, Red Hat-supported, certified, or validated status.
FIPS mode does not establish validation for rebuilt cryptographic libraries.

First unit: record the exact UBI digest, corresponding source-container digest, source RPM inventory, licenses, and missing build inputs.
Resolve the rebuilt identity with the architecture and FIPS owners before constructing the release-data slice.
This remains a UBI conversion dependency, not permission to rename or replace the image.

Primary references:
- [Red Hat UBI images, repositories, packages, and source code](https://access.redhat.com/articles/4238681)
- [Red Hat UBI source retrieval](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index#proc_getting-ubi-container-image-source-code_assembly_types-of-container-images)

## Source-Minimal Reuse

Reuse `fetch.py` checksum rejection, the network-disabled compile stage, and the separate scratch runtime/evidence stages.
Reuse normalized timestamps, non-root filesystem ownership, licenses, corresponding-source archives, and native qualification.
Do not generalize its lock parser into a distribution dependency solver without supporting each distribution's metadata semantics.
Its exact shipped components are musl `1.2.6`, BusyBox `1.37.0`, compiler-rt builtins `23.1.3`, and dated Mozilla trust data.
The lock records two musl remediation patches and the binary bootstrap boundary.
No distribution identity is implied by those components.
The existing evidence is not a complete shipped-file-to-source map.
`builtins.py` consumes GCC headers from the binary builder. Record those inputs and inspect any code contributed by headers.
The link-map checks reject selected bootstrap runtime names; they do not allowlist every input object.
Resolve these source-audit gaps before claiming complete shipped-source closure.

Run [38084184817](https://github.com/rootloom/base-images/actions/runs/38084184817) built commit `a2688330a63a13b0ff53fecb9ce63e18eaecbdb6`.
Both native build records report passed quality and repeat-rootfs checks, but partial scans and unsupported source component coverage.
The evidence job reports blocked evidence publication and no promotion.
The checksum-verified amd64 CVE report still lists musl `CVE-2026-40200` as High, despite the recorded patch.
It lists compiler-rt builtins as unscanned. BusyBox `1.37.0` no longer matches `CVE-2022-48174` in that report.
The report SHA-256 is `1697600daa46c7457930eb1612d7408f80eb38b2b03a4c8a05871667d178fbfd`.
These results do not establish completed delivery or complete source-origin evidence.
The smallest next source-minimal unit is verified component coverage and patched-musl advisory evidence, not a distribution relabel.
