"""Record BusyBox relocatable links before the final compiler-driver link."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from compiler import digest, link_scripts


def main(args):
    if "-r" not in args or "-o" not in args:
        raise ValueError("Only declared relocatable linker operations are allowed")
    output = Path(args[args.index("-o") + 1]).resolve()
    directory = Path("/evidence/sources/partial-links")
    directory.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(str(output).encode()).hexdigest()
    link_map = directory / (key + ".map")
    scripts = link_scripts(["-specs=/opt/musl/lib/musl-gcc.specs", *args])
    command = ["/opt/musl/bin/musl-gcc", *args, "-Wl,-Map=" + str(link_map)]
    subprocess.run(command, check=True)
    record = {"output": str(output), "output_sha256": digest(output), "cwd": str(Path.cwd()),
              "command": command, "scripts": scripts, "map": str(link_map), "map_sha256": digest(link_map)}
    (directory / (key + ".json")).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(sys.argv[1:])
