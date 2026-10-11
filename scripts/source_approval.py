"""Validate independent standard-image approval. This module never promotes images.

Public v1 contract: the signed JSON has schema_version, candidate, approver,
issued_at, expires_at, and results. candidate must exactly match the trusted
expected mapping, including repository, source_commit, producer (identity,
workflow_sha, run_id, run_attempt), image, index_digest, platforms (architecture
to digest), evidence (public asset name to SHA256), and variant='standard'.
approver must exactly match trusted identity/workflow_sha/run_id/run_attempt.
results maps each architecture to every REQUIRED_CHECKS entry set to 'passed'.

The caller must derive expected from independently checked retained evidence,
not approval JSON. Include every retained qualification asset in evidence.
Trust must come from reviewed release configuration and an
independently observed approval run. The approval workflow must report its own
run metadata and must not sign caller-provided statements without qualification.
Cosign authenticates identity, issuer and workflow SHA; signed run claims need
that workflow enforcement. Require a new-format Sigstore bundle and Cosign v2.5.0.
FIPS needs separate authenticated assurance and remains unsupported here.
Production's unconditional promotion guard must remain until real integration
and independent exact-digest qualification pass. Mocked tests are not approval.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import tempfile

from release import ARCHES, digest, run

ISSUER = 'https://token.actions.githubusercontent.com'
REQUIRED_CHECKS = ('source', 'license', 'native', 'repeat', 'security',
                   'sbom', 'provenance', 'anonymous_pull')
REQUIRED_EVIDENCE = ('manifest.json', 'sources.lock.json', 'index.json')
PLATFORM_EVIDENCE = ('.cdx.json', '.build.json', '.cve.json', '.sources.tar.gz')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate approval JSON key')
        result[key] = value
    return result


def _workflow(value, repository):
    if not isinstance(value, dict) or set(value) != {'identity', 'workflow_sha', 'run_id', 'run_attempt'}:
        raise ValueError('Incomplete workflow binding')
    identity = value['identity']
    if not isinstance(identity, str) or not re.fullmatch(
            r'https://github\.com/' + re.escape(repository) +
            r'/\.github/workflows/[A-Za-z0-9_-]+\.ya?ml@refs/heads/main', identity):
        raise ValueError('Untrusted workflow identity')
    if not isinstance(value['workflow_sha'], str) or not re.fullmatch(r'[0-9a-f]{40}', value['workflow_sha']):
        raise ValueError('Invalid workflow SHA')
    for field in ('run_id', 'run_attempt'):
        if not isinstance(value[field], str) or not re.fullmatch(r'[1-9][0-9]*', value[field]):
            raise ValueError('Invalid workflow run binding')


def _time(value):
    if not isinstance(value, str) or not value.endswith('Z'):
        raise ValueError('Approval time must be UTC')
    return datetime.fromisoformat(value[:-1] + '+00:00')


def validate_approval(approval_path, bundle_path, expected, trust, *, runner=run, now=None):
    """Return authenticated approval or raise before any promotion operation.

    runner must execute arguments without a shell and raise on nonzero exit.
    Production must use release.run, not a caller-selected untrusted verifier.
    """
    if not isinstance(expected, dict) or set(expected) != {
            'repository', 'source_commit', 'producer', 'image', 'index_digest',
            'platforms', 'evidence', 'variant'}:
        raise ValueError('Incomplete candidate binding')
    repository = expected['repository']
    if repository != 'rootloom/base-images':
        raise ValueError('Untrusted repository')
    if expected['variant'] != 'standard':
        raise ValueError('Separate authenticated FIPS approval is required')
    if not isinstance(expected['source_commit'], str) or not re.fullmatch(r'[0-9a-f]{40}', expected['source_commit']):
        raise ValueError('Invalid source commit')
    _workflow(expected['producer'], repository)
    _workflow(trust, repository)
    producer = expected['producer']
    if trust['identity'].split('@')[0] == producer['identity'].split('@')[0] or trust['run_id'] == producer['run_id']:
        raise ValueError('Self approval is forbidden')
    if producer['workflow_sha'] != expected['source_commit']:
        raise ValueError('Producer workflow SHA does not match source commit')
    if not isinstance(expected['image'], str) or not re.fullmatch(r'ghcr\.io/rootloom/[a-z0-9][a-z0-9._-]*', expected['image']):
        raise ValueError('Invalid image repository')
    digest(expected['index_digest'])
    if not isinstance(expected['platforms'], dict) or set(expected['platforms']) != set(ARCHES):
        raise ValueError('Both exact platforms are required')
    for value in expected['platforms'].values():
        digest(value)
    evidence = expected['evidence']
    if not isinstance(evidence, dict) or not set(REQUIRED_EVIDENCE).issubset(evidence):
        raise ValueError('Missing approval evidence')
    for arch in ARCHES:
        if not {arch + suffix for suffix in PLATFORM_EVIDENCE}.issubset(evidence):
            raise ValueError('Missing platform evidence')
    if any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name)
           or not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
           for name, value in evidence.items()):
        raise ValueError('Invalid evidence hash binding')

    blob = Path(approval_path).read_bytes()
    bundle = Path(bundle_path).read_bytes()
    if not blob or not bundle:
        raise ValueError('Signed approval and bundle are required')
    # Verify snapshots, then parse those same bytes. Never reread mutable inputs.
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'approval.json'
        signature = Path(directory) / 'approval.sigstore.json'
        snapshot.write_bytes(blob)
        signature.write_bytes(bundle)
        runner('cosign', 'verify-blob', '--new-bundle-format', '--bundle', str(signature),
               '--certificate-identity', trust['identity'],
               '--certificate-oidc-issuer', ISSUER,
               '--certificate-github-workflow-sha', trust['workflow_sha'], str(snapshot))
    approval = json.loads(blob, object_pairs_hook=_object)
    if not isinstance(approval, dict) or set(approval) != {
            'schema_version', 'candidate', 'approver', 'issued_at', 'expires_at', 'results'}:
        raise ValueError('Invalid approval schema')
    if type(approval['schema_version']) is not int or approval['schema_version'] != 1:
        raise ValueError('Unsupported approval schema')
    if approval['candidate'] != expected or approval['approver'] != trust:
        raise ValueError('Approval candidate or approver mismatch')
    issued, expires = _time(approval['issued_at']), _time(approval['expires_at'])
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or not issued <= current < expires or expires - issued > timedelta(hours=24):
        raise ValueError('Stale or invalid approval lifetime')
    results = approval['results']
    required = {check: 'passed' for check in REQUIRED_CHECKS}
    if not isinstance(results, dict) or set(results) != set(ARCHES) or any(results[arch] != required for arch in ARCHES):
        raise ValueError('Missing, failed or skipped quality results')
    return approval
