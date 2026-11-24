"""Print a source-minimal Git diff from the repository root. Do not fetch or apply it.

Supply one MIT-licensed musl git-format-patch attachment. The operator must
independently review its origin, commit, license, contents, and expected SHA-256.
Matching a header and digest does not authenticate upstream or prove applicability.
"""

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from source_release import ROOT, checksum, lockfile


def proposal(review, patch):
    if set(review) != {'name', 'url', 'upstream_commit', 'sha256'}:
        raise ValueError('Expected name, url, upstream_commit, and sha256 from review')
    name = review['name']
    if not re.fullmatch(r'musl-[a-z0-9][a-z0-9-]{0,79}', name):
        raise ValueError('Invalid musl patch name')
    if not re.fullmatch(r'https://www\.openwall\.com/lists/(musl|oss-security)/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]+/[0-9]+', review['url']):
        raise ValueError('Expected a dated musl or oss-security list attachment')
    if not re.fullmatch(r'[0-9a-f]{40}', review['upstream_commit']):
        raise ValueError('Expected a full upstream commit ID')
    if not patch or hashlib.sha256(patch).hexdigest() != checksum(review['sha256']):
        raise ValueError('Patch does not match the reviewed SHA-256')
    header = f"From {review['upstream_commit']} Mon Sep 17 00:00:00 2001".encode()
    if patch.split(b'\n', 1)[0] != header or len(re.findall(rb'^From [a-f0-9]{40} Mon Sep 17 00:00:00 2001$', patch, re.M)) != 1:
        raise ValueError('Expected one format-patch header matching the reviewed commit')

    lock = lockfile()
    entry = dict(sorted(review.items()), component='musl', filename=name + '.patch', license='MIT')
    for item in lock['sources'] + lock['patches'] + lock['verification_inputs']:
        if any(item.get(k) == entry[k] for k in ('name', 'filename', 'url', 'sha256', 'upstream_commit')) or entry['upstream_commit'] in item.get('upstream_commits', []):
            raise ValueError('Input already exists in the lock')
    version = lock['image_version']
    match = re.fullmatch(r'(.+-r)([0-9]+)', version)
    if not match:
        raise ValueError('Expected an image revision suffix')
    lock['image_version'] = match[1] + str(int(match[2]) + 1)
    lock['patches'].append(entry)

    # Preserve the reviewed formatting of unchanged records.
    old = (ROOT / 'sources.lock.json').read_text()
    end = old.index('\n  ]', old.index('"patches": ['))
    record = '\n'.join('    ' + line for line in json.dumps(entry, indent=2).splitlines())
    new = (old[:end] + ',\n' + record + old[end:]).replace(json.dumps(version), json.dumps(lock['image_version']), 1)
    if json.loads(new) != lock:
        raise ValueError('Unexpected lock layout')
    build = (ROOT / 'build.sh').read_text()
    marker = '    cd /build\nfi\n'
    if build.count(marker) != 1:
        raise ValueError('Unexpected musl build recipe')
    command = '    patch --batch --fuzz=0 -p1 < /downloads/' + entry['filename'] + '\n'
    changes = [('sources.lock.json', old, new), ('build.sh', build, build.replace(marker, command + marker))]
    base = subprocess.check_output(['git', 'rev-parse', '--verify', 'HEAD^{commit}'], text=True).strip()
    result = [f'Rootloom source base: {base}\n\n']
    for filename, before, after in changes:
        path = 'images/source-minimal/' + filename
        if before.encode() != subprocess.check_output(['git', 'show', f'{base}:{path}']):
            raise ValueError(f'Input differs from recorded base: {path}')
        result.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True), 'a/' + path, 'b/' + path))
    return ''.join(result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('review', type=Path, help='Independently reviewed metadata JSON')
    parser.add_argument('patch', type=Path, help='Local upstream patch bytes')
    args = parser.parse_args()
    try:
        sys.stdout.write(proposal(json.loads(args.review.read_text()), args.patch.read_bytes()))
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')
