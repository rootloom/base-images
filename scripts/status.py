"""Generate public status from live tags and checksum-verified release evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from urllib.request import urlopen

from release import ARCHES, IMAGES, inspect, platforms, policy, run

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
START = '<!-- image-status:start -->'
END = '<!-- image-status:end -->'


def asset(repo, tag, name):
    # Use canonical public URLs, never URLs supplied by release content.
    url = f'https://github.com/{repo}/releases/download/{tag}/{name}'
    with urlopen(url, timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('Evidence asset exceeds size limit')
    return data


def manifest(repo, entry):
    tag = entry['tag_name']
    if not re.fullmatch(r'(?:standard-(?:' + '|'.join(IMAGES) + r')|source-source-minimal)-[0-9]+-[0-9]+', tag):
        raise ValueError('Unexpected evidence tag')
    data = asset(repo, tag, 'manifest.json')
    checksums = asset(repo, tag, 'SHA256SUMS').decode().splitlines()
    if f'{hashlib.sha256(data).hexdigest()}  manifest.json' not in checksums:
        raise ValueError('Manifest checksum mismatch')
    value = json.loads(data)
    if value['source_repository'] != repo or value['schema_version'] != 1:
        raise ValueError('Unexpected evidence source or schema')
    return value


def report_counts(report, ref):
    blocked = policy(report, ref)
    counts = dict.fromkeys(SEVERITIES, 0)
    for result in report['Results']:
        for finding in result.get('Vulnerabilities') or []:
            severity = finding['Severity']
            if severity not in counts:
                raise ValueError('Unknown severity')
            counts[severity] += 1
    return counts, len(blocked)


def collect(repo, entries):
    records = []
    for image in (*IMAGES, 'source-minimal'):
        source = image == 'source-minimal'
        prefix = ('source-' if source else 'standard-') + image + '-'
        registry = 'ghcr.io/rootloom/' + image
        record = {'image': image, 'registry': registry, 'state': 'unverified', 'platforms': {}}
        if source:
            record['coverage'] = 'NVD-CPE component matching only; not distribution advisory coverage'
        records.append(record)
        releases = [entry for entry in entries if entry['tag_name'].startswith(prefix)
                    and not entry.get('draft')]
        try:
            if releases:
                value = manifest(repo, releases[0])
                record['last_attempt'] = {'status': value['status'], 'finished_at': value['finished_at'],
                                         'url': f'https://github.com/{repo}/releases/tag/{releases[0]["tag_name"]}'}
        except Exception:
            record['last_attempt'] = {'status': 'unverified', 'finished_at': 'unknown',
                                     'url': f'https://github.com/{repo}/releases'}
        try:
            latest_digest, index = inspect(registry + ':latest')
            children = platforms(index)
            record['latest_digest'] = latest_digest
        except Exception:
            record['error'] = 'Latest tag could not be read. Do not treat missing data as zero CVEs.'
            continue
        try:
            matched = None
            for entry in releases:
                value = manifest(repo, entry)
                if value['image'] != registry:
                    raise ValueError('Evidence image mismatch')
                if value.get('index_digest') == latest_digest and value['status'] == 'passed':
                    matched = (entry, value)
                    break
            if matched is None:
                raise ValueError('No qualified evidence matches latest')
            entry, value = matched
            source_lock = None
            if source:
                if value['variant'] != 'source':
                    raise ValueError('Unexpected source variant')
                lock_bytes = asset(repo, entry['tag_name'], 'sources.lock.json')
                if hashlib.sha256(lock_bytes).hexdigest() != value['assets']['sources.lock.json']['sha256']:
                    raise ValueError('Source lock checksum mismatch')
                source_lock = json.loads(lock_bytes)
            record['promotion_confirmed'] = False
            if any(item['name'] == 'promotion.json' for item in entry.get('assets', [])):
                promotion = json.loads(asset(repo, entry['tag_name'], 'promotion.json'))
                if (promotion['status'] != 'promoted' or promotion['manifest_sha256'] !=
                        hashlib.sha256(asset(repo, entry['tag_name'], 'manifest.json')).hexdigest()):
                    raise ValueError('Promotion checksum or status mismatch')
                for key in ('image', 'index_digest', 'version_tag', 'supported_version_tag'):
                    if promotion[key] != value[key]:
                        raise ValueError('Promotion does not match live evidence')
                record['promotion_confirmed'] = True
            if source and not record['promotion_confirmed']:
                raise ValueError('Source publication requires confirmed promotion')
            record.update(evidence_url=f'https://github.com/{repo}/releases/tag/{entry["tag_name"]}', scan_finished_at=value['finished_at'],
                          source_commit=value['source_commit'], version_tag=value['version_tag'],
                          supported_version_tag=value['supported_version_tag'], upstream=value.get('upstream'),
                          scanner=value['scanner'])
            for arch in ARCHES:
                platform = value['platforms'][arch]
                if (platform.get('digest') != children[arch] or platform.get('scan_status') != 'complete'
                        or platform.get('quality') != 'passed' or platform.get('policy') != 'passed'):
                    raise ValueError('Incomplete or mismatched platform evidence')
                name = arch + '.cve.json'
                data = asset(repo, entry['tag_name'], name)
                if hashlib.sha256(data).hexdigest() != value['assets'][name]['sha256']:
                    raise ValueError('CVE report checksum mismatch')
                report = json.loads(data)
                if source:
                    from source_release import source_policy
                    blocked = source_policy(report, source_lock, registry + '@' + children[arch])
                    counts = dict.fromkeys(SEVERITIES, 0)
                    for component in report['components']:
                        for match in component['report']['matches']:
                            severity = match['vulnerability']['severity'].upper()
                            if severity == 'NEGLIGIBLE':
                                severity = 'LOW'
                            if severity not in counts:
                                raise ValueError('Unknown source severity')
                            counts[severity] += 1
                    blocked = len(blocked)
                else:
                    counts, blocked = report_counts(report, registry + '@' + children[arch])
                if blocked:
                    raise ValueError('Current report fails release policy')
                record['platforms'][arch] = {'digest': children[arch], 'severity_counts': counts,
                                            'fixable_high_critical': blocked,
                                            'os': platform.get('os'), 'package_count': platform.get('package_count'),
                                            'size_bytes': platform.get('size_bytes'),
                                            'report_url': f'https://github.com/{repo}/releases/download/{entry["tag_name"]}/{name}'}
            scan_time = datetime.fromisoformat(value['finished_at'].replace('Z', '+00:00'))
            record['scan_stale'] = (datetime.now(timezone.utc) - scan_time).total_seconds() > 48 * 3600
            record['state'] = 'promotion-confirmed' if record['promotion_confirmed'] else 'registry-verified'
        except Exception:
            record['platforms'] = {}
            record['error'] = 'Matching public scan evidence could not be verified. CVE counts are unknown.'
    return {'schema_version': 1, 'images': records}


def cell(value):
    return str(value).replace('|', '&#124;').replace('\n', ' ').replace('<', '&lt;').replace('>', '&gt;')


def table(snapshot):
    lines = ['| Image | Arch | Latest Status | Critical | High | Medium | Low | Unknown | Scan (UTC) | Evidence |',
             '| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |']
    for record in snapshot['images']:
        for arch in ARCHES:
            platform = record['platforms'].get(arch)
            counts = platform['severity_counts'] if platform else dict.fromkeys(SEVERITIES, '?')
            state = record['state'] + ('; scan >48h old' if record.get('scan_stale') else '')
            link = f"[reports]({record['evidence_url']})" if platform else 'unavailable'
            lines.append('| ' + ' | '.join([cell(record['image']), arch, cell(state),
                         *[str(counts[s]) for s in SEVERITIES], cell(record.get('scan_finished_at', '?')), link]) + ' |')
    return '\n'.join(lines)


def render(snapshot, root):
    summary = table(snapshot)
    readme = root / 'README.md'
    text = readme.read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError('README status markers must occur once')
    before, rest = text.split(START)
    _, after = rest.split(END)
    readme.write_text(before + START + '\n' + summary + '\n' + END + after)
    lines = ['# Latest Images', '', '[Overview](README.md) | **Latest** | [Machine-readable status](status.json)', '',
             'These counts describe the exact digests observed at `latest`, not an unpromoted candidate.',
             'Registry verification does not prove that an image has no CVEs.', '', summary, '',
             '`promotion-confirmed` also requires the post-promotion record.',
             '`registry-verified` confirms live digests and scan bytes, but not all release tags or signatures.',
             'Counts are scanner findings per package, not unique CVE identifiers.',
             'A question mark means unknown data. It does not mean zero findings.',
             'Reports cover known vulnerabilities at scan time. Older digests are not rescanned separately.', '',
             '## Digest And Attempt Details', '']
    for record in snapshot['images']:
        lines.extend(['### ' + record['image'], '', '- Live index digest: `' + record.get('latest_digest', 'unknown') + '`'])
        if record['state'] in ('registry-verified', 'promotion-confirmed'):
            if record['promotion_confirmed']:
                lines.append('- Confirmed version tags: `' + record['supported_version_tag'] + '`, `' + record['version_tag'] + '`, `latest`')
            lines.extend(['- Source commit: `' + record['source_commit'] + '`',
                          '- Scanner: ' + cell(record['scanner'].get('name', 'Trivy')) + ' `' + cell(record['scanner']['version']) + '`',
                          '- Public SBOMs, CVE reports, and checksums: [evidence](' + record['evidence_url'] + ')'])
            if record.get('upstream'):
                lines.append('- Upstream: `' + cell(record['upstream']['reference']) + '@' + record['upstream']['digest'] + '`')
            for arch, platform in record['platforms'].items():
                lines.append('- ' + arch + ' digest: `' + platform['digest'] + '`')
                if platform.get('package_count') is not None:
                    lines.append('- ' + arch + ' package count: ' + str(platform['package_count']))
                if platform.get('size_bytes') is not None:
                    lines.append('- ' + arch + ' local image size: ' + str(platform['size_bytes']) + ' bytes')
        if record.get('last_attempt'):
            attempt = record['last_attempt']
            lines.append('- Last attempt qualification: ' + cell(attempt['status']) + ', ' + cell(attempt['finished_at'])
                         + '. [Evidence](' + attempt['url'] + ')')
        if record.get('error'):
            lines.append('- ' + record['error'])
        if record.get('coverage'):
            lines.append('- Coverage: ' + record['coverage'])
        lines.append('')
    (root / 'latest.md').write_text('\n'.join(lines))
    (root / 'status.json').write_text(json.dumps(snapshot, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default='rootloom/base-images', choices=['rootloom/base-images'])
    args = parser.parse_args()
    entries = []
    # Bound historical lookup. An absent match remains explicitly unverified.
    for page in range(1, 11):
        batch = json.loads(run('gh', 'api', f'repos/{args.repo}/releases?per_page=100&page={page}'))
        entries.extend(batch)
        if len(batch) < 100:
            break
    render(collect(args.repo, entries), Path('.'))


if __name__ == '__main__':
    main()
