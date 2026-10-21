# Latest Images

[Overview](README.md) | **Latest** | [Machine-readable status](status.json)

These counts describe the exact digests observed at `latest`, not an unpromoted candidate.
Registry verification does not prove that an image has no CVEs.

| Image | Arch | Latest Status | Critical | High | Medium | Low | Unknown | Scan (UTC) | Evidence |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| debian-slim | amd64 | registry-verified; scan &gt;48h old | 0 | 43 | 58 | 60 | 1 | 2026-10-10T14:43:46.850333+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38060528323-1) |
| debian-slim | arm64 | registry-verified; scan &gt;48h old | 0 | 43 | 58 | 60 | 1 | 2026-10-10T14:43:46.850333+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38060528323-1) |
| ubi-minimal | amd64 | registry-verified; scan &gt;48h old | 0 | 12 | 102 | 75 | 0 | 2026-10-10T14:43:46.701539+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38060528323-1) |
| ubi-minimal | arm64 | registry-verified; scan &gt;48h old | 0 | 12 | 104 | 77 | 0 | 2026-10-10T14:43:46.701539+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38060528323-1) |
| alpine | amd64 | registry-verified; scan &gt;48h old | 0 | 0 | 0 | 0 | 0 | 2026-10-10T14:45:04.622324+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38060528323-1) |
| alpine | arm64 | registry-verified; scan &gt;48h old | 0 | 0 | 0 | 0 | 0 | 2026-10-10T14:45:04.622324+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38060528323-1) |
| ubuntu | amd64 | registry-verified; scan &gt;48h old | 0 | 0 | 9 | 4 | 0 | 2026-10-10T14:46:13.465784+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38060528323-1) |
| ubuntu | arm64 | registry-verified; scan &gt;48h old | 0 | 0 | 9 | 4 | 0 | 2026-10-10T14:46:13.465784+00:00 | [reports](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38060528323-1) |
| rocky-minimal | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| rocky-minimal | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| source-minimal | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| source-minimal | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |

`promotion-confirmed` also requires the post-promotion record.
`registry-verified` confirms live digests and scan bytes, but not all release tags or signatures.
Counts are scanner findings per package, not unique CVE identifiers.
A question mark means unknown data. It does not mean zero findings.
Reports cover known vulnerabilities at scan time. Older digests are not rescanned separately.

## Digest And Attempt Details

### debian-slim

- Live index digest: `sha256:ba3bcd37fd00e37daaef122427da9f672fc5500ddf8287d45b118545c05c5e00`
- Source commit: `401afc1204c0a930e2562a677d3eab242396d330`
- Scanner: Trivy `0.75.0`
- Public SBOMs, CVE reports, and checksums: [evidence](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38060528323-1)
- Upstream: `debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f`
- amd64 digest: `sha256:06ba36b3ff141f7c5a0da793d63560899acda578bf6adbd6bba92f34b1c5a3ea`
- arm64 digest: `sha256:5fd7beee460b94036a5f304b18ec77dc6f388c678826ff496ac0be5137eab11c`
- Last attempt qualification: passed, 2026-10-10T22:30:36.187441+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38091536242-1)

### ubi-minimal

- Live index digest: `sha256:56bd349c428e823c3b9d2bf62c1f0f97df9913272fb813ac8523660204203db0`
- Source commit: `401afc1204c0a930e2562a677d3eab242396d330`
- Scanner: Trivy `0.75.0`
- Public SBOMs, CVE reports, and checksums: [evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38060528323-1)
- Upstream: `registry.access.redhat.com/ubi9/ubi-minimal:9.7@sha256:907b68736aa798b2d38255b7aa070b2a70acb90803864a40f05d0ec47556ddd0`
- amd64 digest: `sha256:c82031db52a1cc77806cdbef05109a53a8ef00d82c00b7fd29b987c89df7af07`
- arm64 digest: `sha256:54dace07c7a651cdc98025a192870876577342e37408bf42d6c1ff740abbc2df`
- Last attempt qualification: passed, 2026-10-10T22:29:57.711394+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38091536242-1)

### alpine

- Live index digest: `sha256:e4a5bdc7ffdd0de4c2282998741b0dd4052679b7eca31bffa94177df0dda7423`
- Source commit: `401afc1204c0a930e2562a677d3eab242396d330`
- Scanner: Trivy `0.75.0`
- Public SBOMs, CVE reports, and checksums: [evidence](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38060528323-1)
- Upstream: `alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6`
- amd64 digest: `sha256:961a8c735c2911350819ef927103b98c69af1b21a0b5012045c1665f2152483b`
- arm64 digest: `sha256:ac1ebc1606fbe65206667665fe4ba6cfda89b70c5854b69301784aa0221b95df`
- Last attempt qualification: passed, 2026-10-10T22:30:51.024823+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38091536242-1)

### ubuntu

- Live index digest: `sha256:af17ba960f012d72beb33ad501695f1b487cb9968993d842bf12d4bec60e5254`
- Source commit: `401afc1204c0a930e2562a677d3eab242396d330`
- Scanner: Trivy `0.75.0`
- Public SBOMs, CVE reports, and checksums: [evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38060528323-1)
- Upstream: `ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55`
- amd64 digest: `sha256:f5d44acbfd4ae68b27a31388351d06abf355ba028cf2db78cdc280d3a3d1f3e5`
- arm64 digest: `sha256:a6e3daee0e76ec74131c609b3531e3e8cb35d10ebdc74769290bece8a96866e2`
- Last attempt qualification: passed, 2026-10-10T22:33:01.574127+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38091536242-1)

### rocky-minimal

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T22:33:31.230311+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-rocky-minimal-38091536242-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### source-minimal

- Live index digest: `unknown`
- Last attempt qualification: blocked, 2026-10-21T15:11:07.363095+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/source-source-minimal-39620460276-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.
- Coverage: NVD-CPE component matching only; not distribution advisory coverage
