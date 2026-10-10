# Latest Images

[Overview](README.md) | **Latest** | [Machine-readable status](status.json)

These counts describe the exact digests observed at `latest`, not an unpromoted candidate.
Registry verification does not prove that an image has no CVEs.

| Image | Arch | Latest Status | Critical | High | Medium | Low | Unknown | Scan (UTC) | Evidence |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| debian-slim | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| debian-slim | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| ubi-minimal | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| ubi-minimal | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| alpine | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| alpine | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| ubuntu | amd64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
| ubuntu | arm64 | unverified | ? | ? | ? | ? | ? | ? | unavailable |
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

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T16:28:03.694171+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-debian-slim-38067099299-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### ubi-minimal

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T16:27:12.282189+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubi-minimal-38067099299-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### alpine

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T16:28:24.480741+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-alpine-38067099299-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### ubuntu

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T16:30:28.458323+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-ubuntu-38067099299-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### rocky-minimal

- Live index digest: `unknown`
- Last attempt qualification: passed, 2026-10-10T16:30:47.852414+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/standard-rocky-minimal-38067099299-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.

### source-minimal

- Live index digest: `unknown`
- Last attempt qualification: blocked, 2026-10-10T16:38:53.590625+00:00. [Evidence](https://github.com/rootloom/base-images/releases/tag/source-source-minimal-38067099244-1)
- Latest tag could not be read. Do not treat missing data as zero CVEs.
- Coverage: NVD-CPE component matching only; not distribution advisory coverage
