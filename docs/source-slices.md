# Distribution Source Slices

These slices implement the first distribution-specific source build steps.
They do not create runnable images or qualify releases.
The five distribution Dockerfiles remain historical binary recipes and cannot promote tags.

## Debian And Ubuntu

`scripts/base_files_slice.py` uses the Python standard library and an existing `gpg` executable.
It fetches pinned sources in one step and builds identity/license data offline in another step.
It does not run downloaded maintainer scripts or copy binary package payloads.

| Target | Source Package | Signature Evidence | Output Records |
| --- | --- | --- | --- |
| Debian 13 | `base-files 13.8+deb13u7` | Pinned Debian developer key from Debian's official keyring server | 31 |
| Ubuntu 24.04 | `base-files 13ubuntu10.5` | Pinned key from Ubuntu's keyserver; owner identity needs independent verification | 24 |

Both source descriptors bind the archive SHA-256 and size.
The build verifies the descriptor signature before writing output.
Signed distribution index membership remains unfinished for both targets.
The Ubuntu archive contains Noble-specific identity data and packaging changes; it is not a Debian substitute.

Run these commands from the repository root:

```sh
python3 scripts/base_files_slice.py --lock images/debian-slim/source-slice.lock.json --inputs evidence/debian-inputs --fetch-only
python3 scripts/base_files_slice.py --lock images/debian-slim/source-slice.lock.json --inputs evidence/debian-inputs --output evidence/debian-first
python3 scripts/base_files_slice.py --lock images/debian-slim/source-slice.lock.json --inputs evidence/debian-inputs --output evidence/debian-second
diff -r evidence/debian-first evidence/debian-second
```

For Ubuntu, use `images/ubuntu/source-slice.lock.json` and separate Ubuntu input/output directories.
The output directory must not exist before each build.
The fetch step rejects changed cached inputs; it does not replace them silently.
Do not install missing host tools without approval.

Input is the reviewed JSON lock plus the exact files named in `sources` and `verification_inputs`.
Output contains `rootfs/`, `corresponding-source/`, and `source-origins.json`.
The source bundle retains the descriptor, archive, key, lock, and build script.
Each retained file has an archive member, source hash, output hash, and mode.
Generated identity files record the upstream `#OSNAME#` transformation.
The manifest always reports `release_qualified=false`.

The selected upstream packaging step installs identity data, notices, and common license texts.
It omits shell templates, MOTD scripts/services, package metadata, maintainer scripts, and package managers.
Ubuntu's `locale-check` binary and its profile script are omitted together.
These choices do not establish a complete minimal-runtime compatibility contract.

Observed local verification:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_debian_source.py -v
```

Nine tests passed. Live fetch and signature-verified data builds passed for both locks.
The `Distribution source slices` workflow repeats these data builds on native amd64 and arm64 runners.
Its successful data checks must not count as compiled-runtime qualification.

Next, authenticate distribution metadata and lock the retained runtime/source graph.
Then build the distribution's patched libc, loader, compiler runtime, shell, utilities, and certificate inputs.
Retain source origins, native runtime tests, advisory coverage, and repeat-rootfs evidence before replacing a Dockerfile.
