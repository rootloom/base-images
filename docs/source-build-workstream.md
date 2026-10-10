# Source Build Workstream

## Scope And State

All six directories under `images/` must become minimal source-built images.
The final root filesystem starts empty with `FROM scratch`.
Every shipped executable, library, loader, and compiler runtime must trace to compiled source.
Downloaded binary distribution images or packages cannot supply runtime files.
Packages built by this workstream may supply files only with matching source-build evidence.

This ledger records implementation gaps, not conversion or delivery.
The inventory baseline is commit `a2688330a63a13b0ff53fecb9ce63e18eaecbdb6`.
The five distribution Dockerfiles still use binary upstream images and package repositories.
`source-minimal` has a compiled custom runtime, but unresolved source-origin and security gates.
No row below is release-qualified under the new contract.

## Conversion Ledger

Implemented first slices now exist for Debian, Ubuntu, and Alpine.
[`docs/source-slices.md`](source-slices.md) records the Debian/Ubuntu locks, offline data build, and signature boundaries.
[`images/alpine/SOURCE.md`](../images/alpine/SOURCE.md) records the pinned Alpine packaging recipe and patched-source preparation.
These locks cover selected slices only, not complete runtime or build-tool dependency graphs.
The baseline table below records the remaining full conversions; no distribution runtime is yet source-qualified.

The component lists are first closure candidates, not verified complete package sets.
The implementation owner must resolve the exact source and runtime dependency graph for both architectures.
Build-only dependencies need provenance even when they do not ship.
The concrete dependency graphs and packaging-only first slices are in
[`images/SOURCE-BUILD-INPUTS.md`](../images/SOURCE-BUILD-INPUTS.md), owned by `@linux`.
Debian/Ubuntu start with `base-files` and `base-passwd`; Alpine starts with baselayout/release data.
Rocky starts with release/filesystem/setup. UBI starts with exact source-container correspondence and license review.
These first slices do not produce runnable distribution images.

| Directory And Identity | Current Evidence | Required Source Closure And First Implementation Unit | Next Owner |
| --- | --- | --- | --- |
| `images/debian-slim/`: Debian 13 derived minimal runtime | `Dockerfile:1-8` uses `debian:13-slim`, APT upgrade, and binary CA installation. No source lock exists. | Resolve Debian 13 Essential/required and chosen shell, CA, and package-manager sources. Include glibc/loader, compiler runtime, `base-files`, `base-passwd`, shell, core utilities, and all resulting dependencies. First add a verified signed snapshot source manifest and a build dependency graph. Build one leaf source package with Debian patches before attempting the full rootfs. | `@linux`; `@rootboss` orders the full graph |
| `images/ubuntu/`: Ubuntu 24.04 LTS derived minimal runtime | `Dockerfile:1-8` uses `ubuntu:24.04` and binary APT installation. No source lock exists. | Resolve Noble source packages separately from Debian. Preserve Ubuntu revisions, patches, loader, identity files, shell, CA trust, and chosen package-manager dependencies. First add signed Noble/security source indexes and one independently rebuilt leaf package. A Debian rootfs is not Ubuntu. | `@linux` |
| `images/alpine/`: Alpine 3.24 derived minimal runtime | `Dockerfile:1-6` uses `alpine:3.24`, `apk upgrade`, and binary CA installation. No source lock exists. | Pin the matching `aports` commit and APKBUILD inputs. Resolve musl, BusyBox, Alpine baselayout, keys, CA trust, apk-tools if retained, and their linked dependencies. First produce a verified APKBUILD source closure and rebuild one selected package offline. Do not relabel the custom runtime as Alpine. | `@linux` |
| `images/rocky-minimal/`: Rocky Linux 9 derived minimal runtime | `Dockerfile:1-8` uses Rocky's binary minimal image and microdnf. No source lock exists. | Resolve Rocky SRPM/spec/patch sources for glibc, runtime libraries, shell, `setup`, release identity, CA trust, and retained RPM/microdnf dependencies. First pin signed repository metadata, exact SRPM inputs, and one `rpmbuild` leaf recipe. Expand BuildRequires and scriptlet dependencies before rootfs assembly. | `@linux`; `@rootboss` confirms exact Rocky minor version |
| `images/ubi-minimal/`: proposed RHEL 9.7/UBI-derived minimal runtime | `Dockerfile:1-8` uses Red Hat's binary UBI minimal image and microdnf. No source lock exists. | Map every intended UBI runtime package to obtainable Red Hat corresponding source, spec, patches, BuildRequires, and redistribution terms. First produce the exact availability/license matrix. Then rebuild a verified leaf SRPM. A scratch rebuild is not automatically an official UBI image. Missing source or branding permission blocks that claim; do not substitute Rocky. | `@linux` inventories; `@architect` reviews identity; `@rootboss` resolves access/license decisions |
| `images/source-minimal/`: custom musl/BusyBox runtime, not a distribution | `Dockerfile:17-22` starts runtime from scratch. `build.sh` builds musl, BusyBox, and numeric compiler-rt builtins. `sources.lock.json` pins source and trust data. | Existing lock: musl `1.2.6` plus two patches, BusyBox `1.37.0`, compiler-rt builtins `23.1.3`, dated CA data. Link maps reject bootstrap libgcc/CRT objects. First resolve compiler-rt advisory coverage and the musl finding without suppression. Requalify the exact `r3` output on native workers. Bootstrap-only use is approved; complete source-origin evidence remains unfinished. | `@linux` musl/runtime; `@compiled` coverage through a separate assignment; `@release` admission |

## Immutable Source Verification

Each distribution needs its own reviewed lock. None of the five distribution locks exists at the baseline.
Reuse `images/source-minimal/fetch.py` verification patterns where their semantics apply.
Do not apply its four-component inventory as a distribution package closure.

| Image | Source Authority And Verification To Implement | License Evidence To Retain |
| --- | --- | --- |
| Debian | Signed snapshot Release/InRelease to Sources index to `.dsc` and all listed source archives. Pin versions, revisions, SHA-256, signer fingerprints, patches, and build profiles. | Per-source `debian/copyright`, upstream notices, and license texts. GPL/LGPL obligations vary by package. |
| Ubuntu | Signed Noble and security archive metadata to Sources and `.dsc` inputs. Pin Ubuntu revisions and Ubuntu patches independently. | Per-source copyright files and upstream notices; do not infer rights from Debian. |
| Alpine | Full `aports` commit, APKBUILD recipes, upstream archive hashes, patches, and signature/key evidence where available. Record authenticity gaps. | APKBUILD license plus actual upstream license texts and notices. |
| Rocky | Signed repository metadata, exact SRPM hashes, spec files, source archives, patches, and build macros. Preserve upstream/source verification separately. | SRPM license declarations, actual texts, and redistribution notices for each shipped component. |
| UBI-derived | Exact UBI package/source correspondence and Red Hat source retrieval evidence. Pin SRPM/spec/input hashes and repository signing identities. Availability and identity rights remain unverified. | Per-package rights, source obligations, Red Hat redistribution terms, and branding review. |
| Custom runtime | Existing SHA-256 lock; musl detached signature and pinned fingerprint; BusyBox upstream checksum; LLVM release asset checksum; dated curl CA checksum. LLVM signature is not verified. | musl MIT; BusyBox GPL-2.0-only; compiler-rt Apache-2.0 WITH LLVM-exception; CA data MPL-2.0. Retain corresponding source, patches, effective config, and build recipes. |

Source URLs are acquisition locations, not immutable identity by themselves.
Verify bytes before extraction. Reject mismatched checksums and unreviewed source changes.
Pin source signature keys and document how their identity was verified.
Record unsigned sources honestly. A checksum from the same HTTPS origin is not independent signer authentication.
Compile without network access after all verified inputs are available.

## Bootstrap Boundary

**User decision:** A pinned prebuilt compiler is approved only for bootstrap.
Every shipped executable and library must compile from verified source.
This approval does not authorize host dependency installations or unreviewed binary runtime inputs.

The existing custom builder is `docker.io/library/gcc:15.2.0`, pinned by index and platform digest in its lock.
Its recorded scope is binary bootstrap compiler/build tools, not a full compiler bootstrap.
Compiler approval does not prove that the existing implementation has complete source-origin evidence.

Inventory all build executables, libraries, headers, generators, and platform digests.
Prove that no prebuilt loader, libc, libgcc, CRT object, helper, or package payload enters the final rootfs.
Retain link maps, ELF dependency checks, file-origin records, and exact exported-rootfs comparison.
Distribution recipes may generate code or embed data from build dependencies; include those origins in the shipped closure.

Independent `@quality` review found that `source-minimal/builtins.py:22-25` consumes GCC's bootstrap include directory.
Headers can contribute inline code or macros. This is an unresolved source audit gap, not proven binary leakage.
Record consumed headers and inspect dependency/preprocessed inputs; retain contributing sources and licenses.
`source-minimal/evidence.py:20-27` rejects selected bootstrap object names, not all unlisted link inputs.
Its archive SBOM uses `filesAnalyzed=false`; no shipped-file-to-source mapping exists yet.
Repeat-rootfs equality proves byte consistency, not complete source origin.

If the user requires source-built compiler tools, `@rootboss` must assign a separate toolchain closure implementation.
Record the seed trust boundary, compiler/binutils stages, headers, libc, generators, and architecture-specific runtime sources.
Do not claim a compiler built with a binary seed removes that seed trust boundary.

## Runtime And Identity

Preserve UID/GID `65532`, `HOME=/home/rootloom`, `/app`, a shell, and CA trust data.
Test writable application/home paths while the rest of the rootfs remains read-only.
Exclude unnecessary executables, build tools, caches, setuid/setgid files, and privilege-changing tools.
Keep required license and scan metadata. Removing metadata cannot hide components from CVE policy.

Trace every regular file and symlink to a source build, generated configuration, or declared non-code data input.
The runtime closure must include ELF interpreters, shared libraries, NSS/resolver behavior, scripts, and script interpreters.
CA bundles and distribution keys are data, not compiled executables. Pin and review their update and license paths.
No kernel is shipped in these container root filesystems; the host supplies it.

Preserve distribution patches, release files, and ABI expectations before claiming a distribution-derived identity.
Document omitted package managers and compatibility limits instead of promising full distribution behavior.
Do not invent a version-support lifetime. Initially track the listed release lines and upstream security availability.
Before support begins, record the exact minor release, update channels, support end, and owner.

FIPS is a separate release boundary for every image.
Recompiling cryptographic code does not preserve a validation claim automatically.
`@fips` must verify certificate scope, operating environment, module configuration, runtime crypto paths, and redistribution rights.
No FIPS tag is accepted without that evidence.

## Acceptance And Promotion

| Gate | Required Evidence | Owner |
| --- | --- | --- |
| Source admission | Six independent image identities; complete shipped source closure; approved bootstrap route; verified lock and license records. Reject binary assembly before registry writes. | `@architect`, `@linux`, `@release` |
| Build | Native amd64 and arm64; network-isolated compile; logs, effective configuration, build dependencies, patches, and exact compiler identity. | `@linux` |
| Quality | Exact-digest shell/CA/non-root tests; filesystem ownership; ELF dependency/hardening checks; no bootstrap runtime leakage; distribution-specific behavior. Skipped checks are not passes. | `@quality` |
| Repeatability | Two fresh compile outputs with matching normalized rootfs inventories and hashes per architecture. Match the exported exact-digest runtime to that rootfs. | `@quality` |
| CVE | Complete component inventory and maintained advisory mapping; positive affected-version controls; fresh pinned scanner/database evidence. Unknown coverage and failed scans block promotion. | `@compiled`, `@release` |
| Vulnerability policy | Preserve raw findings and existing source gates. Resolve the reported High/Critical component blockers without suppressions. Rebuilt patches need verified advisory/version interpretation. | `@linux`, `@release` |
| Provenance/licenses | Exact commit, lock hash, bootstrap materials, build invocation, platform/index digests, SBOMs, source bundles, notices, report hashes, and workflow URL. | `@release` |
| Public delivery | Anonymous exact-digest pulls and checksum-verified public evidence; verified signatures; promotion record matching both qualified architectures. | `@release`, `@rootboss` |

The existing `scripts/source_release.py` implements checks only for `source-minimal`.
Reuse its gate order and evidence binding when extending the other five images.
Do not weaken its unsupported-coverage failure or replace it with an empty distribution scan.
Legacy `scripts/release.py` admission must reject the five binary recipes.
`@release` owns that transition and its scheduled/manual workflow regression tests.
The local implementation rejects legacy release admission and direct `promote()` calls.
It removes scheduled/push release triggers and skips the retained manual workflow job.
PR checks run repository tests, not binary image qualification. Coordinator integration is still required for remote enforcement.
Historical evidence remains public; it must not be reclassified as source-built evidence.

All High/Critical source findings block promotion, even without fixed-version metadata.
Do not inherit the legacy fixable-only rule.
Same-run repeated builds do not establish reproducibility across independent builders.
CA file-presence checks do not establish TLS behavior without a qualified TLS client.

`@linux` inspected source run [38084184817](https://github.com/rootloom/base-images/actions/runs/38084184817) at the baseline commit.
Both native records report passed quality/repeat-rootfs checks, partial scans, and `Unsupported source component coverage`.
Blocked evidence was published without promotion. That result does not prove complete source closure.

Unique source attempt tags and evidence identify candidates, not support commitments.
Only a passed source promotion may move an OS-version tag or `latest`.
Serialize promotion and preserve prior digests for rollback.
Refreshing a database or receiving a green skipped workflow is not a fresh build or delivery.

## Maintenance And Next Units

Use the existing scheduled source checks; do not start another factory or dispatch from this ledger.
Each cycle checks unfinished runs first, then source advisories, distribution source revisions, trust data, and scanner coverage.
Source checksum changes require origin review before a lock update.
Rebuild changed closures and perform the daily repeat check with recorded fresh database inputs.
Record failed, partial, skipped, and blocked checks separately. Preserve public reports for prior digests.
The current source script is hard-coded to one image; six-image maintenance is not implemented yet.

1. `@rootboss`: enforce the approved bootstrap-only boundary and assign exact distribution support/identity decisions.
2. `@release`: block legacy registry writes and promotion; test scheduled and manual entry points.
3. `@linux`: implement per-directory immutable source manifests and dependency graphs from the ledger.
4. `@linux`: rebuild one verified distribution leaf package, then resolve libc/toolchain cycles and complete each runtime closure.
5. `@compiled`: verify component-specific compiler-rt advisory coverage; keep promotion blocked until supported.
6. `@quality`: qualify native repeat builds, source origins, exact runtime bytes, and distribution behavior.
7. `@release`: extend source admission/evidence to all six only after each closure is demonstrated.
8. `@rootboss`: close the workstream only with six accepted source releases and verified public delivery.

## Primary References And Checks

- [Debian source package build procedure](https://www.debian.org/doc/manuals/maint-guide/build.en.html) describes source archives, packaging patches, and Build-Depends.
- [Debian source snapshots](https://snapshot.debian.org/) provide historical source acquisition; signed metadata must still be pinned and verified.
- [Ubuntu source archive](https://archive.ubuntu.com/ubuntu/), [ports archive](https://ports.ubuntu.com/ubuntu-ports/), and [security archive](https://security.ubuntu.com/ubuntu/) are acquisition roots, not selected immutable inputs.
- [Alpine aports](https://gitlab.alpinelinux.org/alpine/aports) contains distribution APKBUILD recipes; select and pin the matching branch commit.
- [Rocky source repositories](https://download.rockylinux.org/pub/rocky/) require exact release and source selection.
- [Red Hat UBI documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/assembly_types-of-container-images_building-running-and-managing-containers) is the identity/redistribution review starting point.
- [LLVM 23.1.3 release](https://github.com/llvm/llvm-project/releases/tag/llvmorg-23.1.3), [BusyBox sources](https://busybox.net/downloads/), and [musl sources](https://musl.libc.org/releases/) correspond to current custom-runtime lock entries.

Read-only local checks from the repository root:

```sh
git diff --check
python3 -m unittest discover -s tests -v
```

Unit tests check policy and recipe contracts. They do not compile the distributions or prove hosted delivery.
Native source qualification requires the approved runner workflow and exact public evidence.
No new build, installation, publication, remote write, or workflow dispatch is authorized by this document.
