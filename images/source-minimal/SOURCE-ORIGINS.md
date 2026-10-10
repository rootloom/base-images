# Source-Origin Evidence

The recipe uses the approved pinned binary compiler only as a bootstrap tool.
The runtime contains source-built musl, BusyBox, and linked compiler-rt helpers.
CA certificates are trust data, not compiled code.

## Checks

- `build.sh` requires empty build and runtime directories.
- `origins.py snapshot` indexes verified extracted sources after the locked musl patches.
- `compiler.sh` passes compiler arguments to `compiler.py`.
- The recorder retains exact GCC saved preprocessed and assembler inputs, dependencies, commands, and object hashes.
- Link checks require matching recorded compilation for each object and archive member, including startup objects.
- `linker.sh` records BusyBox partial links; checks trace each combined object back to recorded compilation inputs.
- Final link commands retain source linker scripts and the generated musl GCC specs.
- Compiler and linker response files fail closed.
- GNU ld branch veneers use an explicit linker-generated origin, not a nonexistent source file.
- Header checks require source-index matches or explicit generated-header recipes.
- Installed musl headers must match reviewed source or generated headers byte-for-byte.
- Compiler-rt and the musl GCC wrapper do not use bootstrap GCC headers.
- Assembler `.include` and `.incbin` imports fail closed.
- The source bundle retains consumed input bytes by SHA-256, including generated headers.
- File mapping rejects undeclared runtime files, directories, and symbolic links.
- Compiled runtime copies and license copies must match their declared build outputs.

`source-origins.json` maps runtime paths to sources, licenses, patches, and generated-data recipes.
It records hashes, modes, owners, and symbolic-link targets where available.
The manifest excludes its own hash and the generated `rootfs.sha256` hash to avoid checksum cycles.
The normalized rootfs tar includes the origin manifest and excludes only `rootfs.sha256`.

The evidence output contains `source-origins.json` and `corresponding-source.tar`.
The source tar contains the source index, compilation records, partial-link records, final-link records, source archives, patches, recipes, and effective BusyBox configuration.
These records use `sources/source-files.json`, `sources/compilation/`, `sources/partial-links/`, and `sources/linking/`.
Compilation JSON records bind object hashes to retained input and preprocessing hashes.
The runtime retains component license files under `/usr/share/licenses/`.

## Local Checks

From the repository root, run the focused tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_source_origins.py' -v
```

On a native arm64 Docker worker, build the evidence target:

```sh
docker build --platform linux/arm64 --target evidence -f images/source-minimal/Dockerfile -t rootloom-source-origins-check .
```

Use a separate native amd64 worker with `--platform linux/amd64` for amd64 qualification.
These commands do not publish artifacts.
A failed or skipped build does not establish source closure.
This evidence does not establish full compiler bootstrap, advisory completeness, trust-data behavior, independent-builder reproducibility, or FIPS validation.
