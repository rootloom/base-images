# Rootloom Operating Plan

## Product Scope

Rootloom aims to provide free public base images built from verified source.
No Rootloom account or paid subscription should be necessary to pull a supported image or inspect its release evidence.

Ship `source-minimal` first for self-contained Linux applications on `linux/amd64` and `linux/arm64`.
It is not a distribution replacement and does not include a distribution package manager.
Keep all six targets in the [source conversion ledger](source-build-workstream.md).
Apply the same evidence requirements to each target. Do not claim FIPS validation or catalog parity.

## Decision Owners

| Role | Owns |
| --- | --- |
| Boss | Product scope, priorities, task boundaries, and GitHub integration. |
| Builder | Verified inputs, source recipes, staging tools, and native CI. |
| Release Review | Independent source, advisory, and exact-digest evidence review. |

The Boss makes routine product and integration decisions without waiting for the project owner.
The reviewer must not approve a candidate they built. A team message does not count as authenticated release approval.
Use an isolated branch or checkout when the shared checkout contains unfinished work. Do not include someone else's unpublished changes.
Use normal GitHub pull requests. Do not bypass branch protections, change organization access, or start recurring work as part of routine integration.

## Stage Source Updates

1. Record the upstream version or commit, origin, license, and expected checksum from reviewed upstream evidence.
2. Verify the downloaded bytes against that evidence. A new checksum from an update detector is not independent verification.
3. Prepare a reviewable diff against a recorded base commit. Include the source lock and any necessary recipe changes.
4. Use the [source pull request workflow](../.github/workflows/source-pr.yml) to compile the proposed inputs on both native architectures.
5. Record runtime smoke results and repeat root filesystem hashes for both architectures.

A staged update is not a release. Do not give pull requests publishing credentials or let them write registry or release tags.
An unchanged rebuild tests existing pins. It does not validate a proposed update.

## Qualify A Release

1. Prove verified source origins and repeatable native builds for both platforms.
2. Resolve advisory applicability for the shipped components. Test component coverage and block unknown coverage, scan failures, and all High or Critical findings.
3. Obtain authenticated independent approval for the exact candidate digests and evidence. Until this control is enforced, do not promote.
4. Verify anonymous GHCR pulls, index membership, signatures, and matching public SBOMs, CVE reports, and build evidence.
5. Move supported tags only after all required gates pass. Retain the previous digests for rollback.

The immediate security work is to substantiate the musl finding disposition and verify advisory coverage for compiler-rt builtins.
Use the [status page](../latest.md) for live digest and scan status. Blocked evidence, partial results, and skipped jobs do not qualify a release.

Report zero known findings only for exact digests with fresh, complete scans and no applicable findings at any severity.
Include the scan time and scope. Never report unknown or missing results as zero. A policy pass is not a zero-findings claim.
