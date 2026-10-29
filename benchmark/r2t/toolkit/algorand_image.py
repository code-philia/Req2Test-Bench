"""Fresh-host acquisition of an Algorand runtime image by registry digest.

`JAVA_RESEARCH_MINIMAL_OCI_DISTRIBUTION_SPEC.md` section 6 defines the one
bundle-driven acquisition command; the reviewed Algorand bundle specifications
fix how it applies to `algorand-sdk`:
distribution is registry pull-by-digest of the stored manifest, the pull
reference is ``<repository>@<manifest_digest>``, never a tag, and the pulled
manifest's config descriptor digest must equal ``config_image_id`` before the
image can satisfy the bundle.  The two digests are distinct facts and are
never aliases.

The image identity comes only from the INSTALLED bundle's
``runtime/oci-image.json`` role, revalidated through the complete
native reader before any Docker contact: `algorand_bundle.validate_bundle`
for historical versions and `data.evaluation_bundle.validate_evaluation_bundle`
for V8, including an optional complete private release index. The command
accepts no caller-supplied digest, repository, archive name, platform, tag,
config image ID, or qualification bypass.

The v2 publication verifier in this module is the preceding owner gate: it
compares the preserved source manifest to the anonymous personal-package
bytes, performs a separate digest pull, and writes the existing publication
receipt only after both paths agree.

Two deliberate boundaries, stated rather than hidden:

- **``/opt/m2`` equality travels inside the config identity on this route.**
  The bundle ships no ``/opt/m2`` manifest hash and the canonical transcript
  is not a released artifact, so a fresh host holds no independent
  expectation to compare a captured tree against.  The config image ID pins
  the complete rootfs diff-ID chain, which the selected daemon verifies
  content-addressably during the pull; capturing the tree here to record an
  uncompared digest would prove nothing further.
- **The one-item gold smoke runs through the reviewed harness, not here.**
  `ALGORAND_BUNDLE_V1_SPEC.md` section 8 orders it after K=4 provisioning
  (items 3-5), and no provisioned worker exists at acquisition time.  The
  receipt records the qualification probe this command DID run and the
  literal ``gold_smoke: "deferred-to-harness"``: a successful acquisition is
  an acquired, qualified object, and the runbook's smoke step is what makes
  it runnable-benchmark evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Mapping, Optional, Sequence

from . import algorand_bundle
from .. import docker_authority as authority_evidence
from ..java import research_minimal as research
from ..java import research_minimal_oci as oci


ACQUISITION_SCHEMA = "r2t.algorand-image-acquisition/1"
SMOKE_DEFERRED = "deferred-to-harness"
PROBE_TEXT_LIMIT = 8192
PULL_DETAIL_LIMIT = 200
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
PUBLICATION_TAG = "v2"

_RECEIPT_KEYS = frozenset({
    "schema", "path", "project", "platform", "distribution_mode",
    "repository", "pull_reference", "manifest_digest", "config_image_id",
    "imported_config_id", "bundle_manifest_sha256", "oci_image_sha256",
    "docker_authority", "qualification", "gold_smoke", "digest",
})
_REFERENCE_KEYS = frozenset({"path", "file_sha256", "digest"})


class ImageAcquisitionRefused(ValueError):
    """The requested acquisition is outside the reviewed contract."""


def _refuse(message: str) -> ImageAcquisitionRefused:
    return ImageAcquisitionRefused("REFUSED: " + message)


def _absolute(value: object, label: str) -> str:
    if not isinstance(value, str) or not os.path.isabs(value) \
            or os.path.normpath(value) != value:
        raise _refuse(f"{label} is not one normalized absolute path")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) \
            or algorand_bundle._SHA256.fullmatch(value) is None:
        raise _refuse(f"{label} is not lower-case SHA-256")
    return value


def _bounded_text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")[:PROBE_TEXT_LIMIT]


def _pull_condition(result: research.CommandResult) -> str:
    """Name the condition a failed registry pull reported.

    Docker's last stderr line IS the registry's own decision -- ``denied``
    for an unauthorized package, ``manifest unknown`` for one that was never
    published at this digest, a DNS or TLS message for an unreachable
    registry -- and it carries no credential: the auth material lives in the
    client's configuration and request headers, never in this output.  A
    refusal that collapses those causes into one string leaves a consumer no
    way to tell "not published" from "not authorized" except an off-runbook
    raw ``docker pull``, so the condition travels with the refusal instead.
    """
    if result.timed_out:
        return "timed out"
    if result.overflowed:
        return "output overflowed"
    lines = [line.strip() for line
             in result.stderr.decode("utf-8", "replace").splitlines()]
    detail = ([line for line in lines if line] or [""])[-1]
    return detail[:PULL_DETAIL_LIMIT] if detail \
        else f"exit {result.returncode} with no diagnostic"


def _publication_target(*, manifest_digest: Optional[str] = None,
                        config_image_id: Optional[str] = None) -> dict:
    """The fixed v2 public-package identity; optional values are test seams."""
    selected = algorand_bundle.layout("2")
    registry_name = selected.image_repository.removeprefix("ghcr.io/")
    return {
        "repository": selected.image_repository,
        "registry_name": registry_name,
        "tag": PUBLICATION_TAG,
        "manifest_digest": manifest_digest
        or algorand_bundle.IMAGE_MANIFEST_DIGEST,
        "config_image_id": config_image_id or algorand_bundle.IMAGE_CONFIG_ID,
    }


class _AnonymousRedirect(urllib.request.HTTPRedirectHandler):
    """Follow blob redirects without forwarding the registry bearer."""

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != "https":
            raise _refuse("anonymous HTTP redirect is not HTTPS")
        redirected = super().redirect_request(
            request, fp, code, msg, headers, newurl)
        source = urllib.parse.urlsplit(request.full_url)
        if target.hostname != source.hostname:
            publication = _publication_target()
            allowed_blob = (
                "https://ghcr.io/v2/" + publication["registry_name"]
                + "/blobs/" + publication["config_image_id"])
            if request.full_url != allowed_blob:
                raise _refuse(
                    "anonymous HTTP redirect changed host outside config blob")
            redirected.remove_header("Authorization")
        return redirected


def _anonymous_urlopen(request):
    """One no-proxy, no-cookie opener; authentication is registry-issued."""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _AnonymousRedirect())
    return opener.open(request, timeout=60)


def _header(headers, name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _http_get(opener, url: str, *, accept: str, label: str,
              bearer: Optional[str] = None,
              allow_challenge: bool = False) -> tuple[bytes, object]:
    headers = {
        "Accept": accept,
        "Accept-Encoding": "identity",
        "User-Agent": "req2test-bench",
    }
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    request = urllib.request.Request(url, headers=headers)
    try:
        response = opener(request)
        with response:
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status != 200:
                raise _refuse(f"{label} returned HTTP {status}")
            return response.read(), response.headers
    except ImageAcquisitionRefused:
        raise
    except urllib.error.HTTPError as exc:
        if allow_challenge and exc.code == 401:
            return b"", exc.headers
        raise _refuse(f"{label} returned HTTP {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise _refuse(f"{label} could not be read") from exc


def _anonymous_bearer_challenge(headers, target: Mapping[str, str]) -> dict:
    value = _header(headers, "WWW-Authenticate") or ""
    scheme, separator, parameters = value.partition(" ")
    try:
        fields = urllib.request.parse_keqv_list(
            urllib.request.parse_http_list(parameters))
    except (TypeError, ValueError) as exc:
        raise _refuse("GHCR anonymous challenge is malformed") from exc
    expected = {
        "realm": "https://ghcr.io/token",
        "service": "ghcr.io",
        "scope": f"repository:{target['registry_name']}:pull",
    }
    if scheme.lower() != "bearer" or not separator or fields != expected:
        raise _refuse("GHCR anonymous challenge differs from the v2 package")
    return fields


def _json_document(raw: bytes, label: str):
    try:
        return authority_evidence.loads_exact_json(raw, label=label)
    except (UnicodeDecodeError, RuntimeError, ValueError) as exc:
        raise _refuse(f"{label} is not exact JSON") from exc


def _manifest_config(raw: bytes, target: Mapping[str, str],
                     label: str) -> dict:
    actual = "sha256:" + hashlib.sha256(raw).hexdigest()
    document = _json_document(raw, label)
    config = document.get("config") if isinstance(document, dict) else None
    if actual != target["manifest_digest"]:
        raise _refuse(f"{label} differs from the reviewed manifest digest")
    if not isinstance(document, dict) \
            or document.get("schemaVersion") != 2 \
            or document.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE \
            or not isinstance(document.get("layers"), list) \
            or not isinstance(config, dict) \
            or set(config) != {"mediaType", "digest", "size"} \
            or config.get("mediaType") != OCI_CONFIG_MEDIA_TYPE \
            or config.get("digest") != target["config_image_id"] \
            or not isinstance(config.get("size"), int) \
            or isinstance(config.get("size"), bool) \
            or config.get("size") <= 0:
        raise _refuse(f"{label} differs from the reviewed OCI identities")
    return config


def _manifest_response(raw: bytes, headers, source_raw: bytes,
                       target: Mapping[str, str], label: str) -> None:
    content_type = (_header(headers, "Content-Type") or "").split(
        ";", 1)[0].strip()
    if content_type != OCI_MANIFEST_MEDIA_TYPE \
            or _header(headers, "Docker-Content-Digest") \
            != target["manifest_digest"] \
            or raw != source_raw \
            or "sha256:" + hashlib.sha256(raw).hexdigest() \
            != target["manifest_digest"]:
        raise _refuse(f"{label} differs from the reviewed raw manifest")


def _anonymous_pull_token(opener, digest_url: str,
                          target: Mapping[str, str]) -> str:
    _body, challenge_headers = _http_get(
        opener, digest_url, accept=OCI_MANIFEST_MEDIA_TYPE,
        label="public digest manifest", allow_challenge=True)
    challenge = _anonymous_bearer_challenge(challenge_headers, target)
    token_query = urllib.parse.urlencode({
        "service": challenge["service"],
        "scope": challenge["scope"],
    })
    token_raw, _headers = _http_get(
        opener, challenge["realm"] + "?" + token_query,
        accept="application/json", label="anonymous GHCR token")
    token_document = _json_document(token_raw, "anonymous GHCR token")
    token = token_document.get("token") \
        if isinstance(token_document, dict) else None
    if not isinstance(token, str) or not token \
            or "\r" in token or "\n" in token:
        raise _refuse("anonymous GHCR token response is malformed")
    return token


def _anonymous_registry_facts(source_raw: bytes, *, target: Mapping[str, str],
                              opener) -> dict:
    config = _manifest_config(source_raw, target, "source OCI manifest")
    registry_root = "https://ghcr.io/v2/" + target["registry_name"]
    manifest_base = registry_root + "/manifests/"
    digest_url = manifest_base + target["manifest_digest"]
    token = _anonymous_pull_token(opener, digest_url, target)

    digest_raw, digest_headers = _http_get(
        opener, digest_url,
        accept=OCI_MANIFEST_MEDIA_TYPE, label="public digest manifest",
        bearer=token)
    _manifest_response(
        digest_raw, digest_headers, source_raw, target,
        "public digest manifest")

    config_raw, _config_headers = _http_get(
        opener, registry_root + "/blobs/" + target["config_image_id"],
        accept=OCI_CONFIG_MEDIA_TYPE, label="public image config",
        bearer=token)
    config_document = _json_document(config_raw, "public image config")
    if len(config_raw) != config["size"] \
            or "sha256:" + hashlib.sha256(config_raw).hexdigest() \
            != target["config_image_id"] \
            or not isinstance(config_document, dict) \
            or config_document.get("os") != "linux" \
            or config_document.get("architecture") != "amd64":
        raise _refuse("public image config differs from linux/amd64")

    tags_raw, tags_headers = _http_get(
        opener, registry_root + "/tags/list", accept="application/json",
        label="public tag inventory", bearer=token)
    tags_document = _json_document(tags_raw, "public tag inventory")
    if _header(tags_headers, "Link") is not None \
            or not isinstance(tags_document, dict) \
            or set(tags_document) != {"name", "tags"} \
            or tags_document.get("name") != target["registry_name"] \
            or tags_document.get("tags") != [target["tag"]]:
        raise _refuse("public tag inventory is not exactly v2")

    tag_raw, tag_headers = _http_get(
        opener, manifest_base + target["tag"],
        accept=OCI_MANIFEST_MEDIA_TYPE, label="public v2 tag manifest",
        bearer=token)
    _manifest_response(
        tag_raw, tag_headers, source_raw, target,
        "public v2 tag manifest")

    return {
        "manifest_bytes": len(source_raw),
        "manifest_sha256": hashlib.sha256(source_raw).hexdigest(),
        "config_bytes": len(config_raw),
        "config_sha256": hashlib.sha256(config_raw).hexdigest(),
        "tags": list(tags_document["tags"]),
    }


def _preflight_public_registry(*, target: Mapping[str, str], opener) -> dict:
    """Read the v2 manifest anonymously without pulling it into Docker."""
    target = dict(target)
    registry_root = "https://ghcr.io/v2/" + target["registry_name"]
    digest_url = registry_root + "/manifests/" + target["manifest_digest"]
    token = _anonymous_pull_token(opener, digest_url, target)
    manifest_raw, manifest_headers = _http_get(
        opener, digest_url, accept=OCI_MANIFEST_MEDIA_TYPE,
        label="public digest manifest", bearer=token)
    _manifest_response(
        manifest_raw, manifest_headers, manifest_raw, target,
        "public digest manifest")
    _manifest_config(manifest_raw, target, "public digest manifest")
    return {
        "repository": target["repository"],
        "manifest_digest": target["manifest_digest"],
        "config_image_id": target["config_image_id"],
        "manifest_bytes": len(manifest_raw),
    }


def preflight_public_registry() -> dict:
    """Prove that the current consumer image is credential-free readable."""
    return _preflight_public_registry(
        target=_publication_target(), opener=_anonymous_urlopen)


def acquisition_argv_validator(reference: str, config_image_id: str):
    """The closed Docker vocabulary of one acquisition, and nothing else."""
    pull = ("image", "pull", "--platform", "linux/amd64", reference)
    inspect = ("image", "inspect", config_image_id)
    probe = ("run", "--rm", "--network", "none", "--pull=never",
             "--entrypoint", "/bin/sh", config_image_id,
             "-c", oci._QUALIFICATION_SCRIPT)

    def validate(argv: Sequence[str]) -> tuple[str, ...]:
        try:
            value = tuple(argv)
        except TypeError as exc:
            raise _refuse("acquisition Docker argv is not a sequence") from exc
        if value not in (pull, inspect, probe):
            raise _refuse(
                "Docker command is outside the acquisition vocabulary")
        return value

    return validate


class LiveAcquisitionRunner:
    """Authority-bound Docker adapter for one registry-by-digest acquisition."""

    def __init__(self, *, docker_authority_path: str, reference: str,
                 config_image_id: str):
        from ..core import docker_cli
        from .epubcheck_image import LiveDockerRunner
        authority_path = _absolute(docker_authority_path, "Docker authority")
        docker_cli.configure(authority_path=authority_path)
        document, authority_reference = docker_cli.authority_reference(
            live=False)
        daemon = document.get("daemon")
        # The two-identity verification below reads the daemon image `.Id`
        # as the config digest, which is the classic-store meaning; a
        # containerd-store daemon reports the manifest digest there and
        # would fail the check with a misleading message.
        if not isinstance(daemon, dict) \
                or daemon.get("storage_driver") != "overlay2":
            raise _refuse(
                "image acquisition requires the classic overlay2 image store")
        self._runner = LiveDockerRunner(
            authority_reference,
            argv_validator=acquisition_argv_validator(
                reference, config_image_id),
            mutation_predicate=lambda argv: tuple(argv)[:2] in {
                ("image", "pull"), ("run", "--rm")})

    def revalidate_authority(self) -> Mapping[str, object]:
        return self._runner.revalidate_authority()

    def run(self, argv: Sequence[str], *, timeout: int) \
            -> research.CommandResult:
        result = self._runner.run(argv, timeout=timeout)
        return research.CommandResult(
            tuple(result.argv), result.returncode, result.stdout,
            result.stderr, result.timed_out, result.overflowed)


def _write_json_no_clobber(path: str, value: Mapping[str, object], *,
                           label: str = "acquisition receipt") -> None:
    """Commit canonical JSON only after complete staged bytes are durable."""
    parent = os.path.dirname(path)
    if not os.path.isdir(parent) or os.path.lexists(path):
        raise _refuse(f"{label} is not exclusive-new: {path}")
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode()
    fd, stage = tempfile.mkstemp(prefix=".r2t-acquire-stage-", dir=parent)
    try:
        os.fchmod(fd, 0o644)
        os.write(fd, raw)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(stage, path, follow_symlinks=False)
        except OSError as exc:
            raise _refuse(
                f"{label} lost no-clobber commit: {path}") from exc
        parent_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.lexists(stage):
            os.unlink(stage)


def validate_acquisition_receipt(
        value: object, *, installed_bundle: Mapping) -> dict:
    """Join one closed acquisition receipt to its selected bundle."""
    if not isinstance(value, dict) or set(value) != _RECEIPT_KEYS:
        raise _refuse("acquisition receipt is not its closed schema")
    if value["digest"] != authority_evidence.semantic_digest(value):
        raise _refuse("acquisition receipt digest differs from its bytes")
    if value["schema"] != ACQUISITION_SCHEMA \
            or value["path"] != algorand_bundle.IMAGE_PATH \
            or value["project"] != algorand_bundle.PROJECT \
            or value["platform"] != "linux/amd64" \
            or value["distribution_mode"] != "registry_digest":
        raise _refuse("acquisition receipt names another distribution")
    repository = value["repository"]
    try:
        algorand_bundle._repository(repository)
    except algorand_bundle.AlgorandBundleRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    try:
        # V8 reuses the published V2 OCI identity, not a V2 installation.
        version = installed_bundle["version"]
        selected = algorand_bundle.layout("2" if version == "8" else version)
    except (KeyError, TypeError,
            algorand_bundle.AlgorandBundleRefused) as exc:
        raise _refuse("selected installed bundle facts are malformed") from exc
    expected_repository = installed_bundle.get("oci_repository")
    if expected_repository != selected.image_repository:
        raise _refuse("selected installed bundle repository is invalid")
    if repository != expected_repository:
        raise _refuse("acquisition receipt names another installed bundle "
                      "repository")
    manifest_digest = value["manifest_digest"]
    config_image_id = value["config_image_id"]
    if manifest_digest == config_image_id:
        raise _refuse("acquisition manifest and config identities are aliases")
    if manifest_digest != algorand_bundle.IMAGE_MANIFEST_DIGEST \
            or config_image_id != algorand_bundle.IMAGE_CONFIG_ID:
        raise _refuse("acquisition receipt is not the recorded v1 image")
    if value["pull_reference"] != f"{repository}@{manifest_digest}":
        raise _refuse("acquisition pull reference differs from its identities")
    if value["imported_config_id"] != config_image_id:
        raise _refuse("imported config ID differs from the bundle identity")
    _sha256(value["bundle_manifest_sha256"], "bundle manifest SHA-256")
    _sha256(value["oci_image_sha256"], "OCI image role SHA-256")
    if (manifest_digest != installed_bundle.get("oci_manifest_digest")
            or config_image_id != installed_bundle.get("config_image_id")
            or value["bundle_manifest_sha256"]
            != installed_bundle.get("bundle_manifest_sha256")
            or value["oci_image_sha256"]
            != installed_bundle.get("oci_image_sha256")):
        raise _refuse("acquisition receipt differs from the selected "
                      "installed bundle")
    authority = value["docker_authority"]
    if not isinstance(authority, dict) \
            or set(authority) != {"reference", "daemon_fingerprint"} \
            or not isinstance(authority["reference"], dict) \
            or set(authority["reference"]) != _REFERENCE_KEYS:
        raise _refuse("acquisition Docker authority is not its closed shape")
    _sha256(authority["daemon_fingerprint"], "daemon fingerprint")
    _sha256(authority["reference"]["file_sha256"], "authority file SHA-256")
    _sha256(authority["reference"]["digest"], "authority digest")
    _absolute(authority["reference"]["path"], "authority path")
    qualification = value["qualification"]
    if not isinstance(qualification, dict) \
            or set(qualification) != {"probe_stdout", "probe_stderr"} \
            or not isinstance(qualification["probe_stdout"], str) \
            or not isinstance(qualification["probe_stderr"], str) \
            or "R2T-QUALIFIED" not in qualification["probe_stdout"]:
        raise _refuse("acquisition qualification output is absent or failed")
    if value["gold_smoke"] != SMOKE_DEFERRED:
        raise _refuse("acquisition receipt misstates the gold-smoke boundary")
    return value


def _evaluation_image_bundle(data_root: str, release_index_path: Optional[str]):
    """Resolve V8 through S1's complete installed reader and measured index."""
    from ..data import evaluation_bundle
    validated = evaluation_bundle.validate_evaluation_bundle(
        project=algorand_bundle.PROJECT, version="8", root=data_root,
        release_index_path=release_index_path)
    role_path = validated["role_paths"]["oci_image"]
    with open(role_path, "rb") as handle:
        raw = handle.read()
    image = json.loads(raw)
    return {
        "version": "8", "oci_repository": image["repository"],
        "bundle_manifest_sha256": algorand_bundle._hash(validated["manifest_path"]),
        "oci_image_sha256": hashlib.sha256(raw).hexdigest(),
        "oci_manifest_digest": image["manifest_digest"],
        "config_image_id": image["config_image_id"],
    }, role_path


def acquire_image(*, project: str, out: str,
                  docker_authority: Optional[str] = None,
                  data_root: Optional[str] = None,
                  version: str = algorand_bundle.VERSION,
                  release_index_path: Optional[str] = None,
                  runner=None) -> dict:
    """Pull, verify, qualify, and receipt the bundled runtime image."""
    if project != algorand_bundle.PROJECT:
        raise _refuse("image acquisition supports project algorand-sdk only")
    if version == "5":
        raise _refuse(
            "Algorand v5 is reference-only and has no image acquisition route")
    if release_index_path is not None and version != "8":
        raise _refuse("a private evaluation release index requires Algorand v8")
    out = _absolute(out, "acquisition receipt path")
    if os.path.lexists(out):
        raise _refuse("acquisition receipt path already exists")
    if not os.path.isdir(os.path.dirname(out)):
        raise _refuse("acquisition receipt directory does not exist")
    if data_root is None:
        from ..core.paths import data_root as default_data_root
        data_root = default_data_root()
    data_root = _absolute(os.path.abspath(data_root), "data root")

    # The identity source is the complete validated installed bundle, not a
    # lone role file: a tampered or partially installed tree refuses here,
    # before any Docker or registry contact.
    from ..data.bundle import BundleRefused
    try:
        if version == "8":
            report, role_path = _evaluation_image_bundle(data_root, release_index_path)
        else:
            report = algorand_bundle.validate_bundle(data_root, version=version)
            selected = algorand_bundle.layout(version)
            role_path = os.path.join(data_root, selected.file_roles["oci_image"])
    except (algorand_bundle.AlgorandBundleRefused, BundleRefused) as exc:
        raise _refuse("installed bundle failed validation: "
                      + str(exc).removeprefix("REFUSED: ")) from exc
    with open(role_path, "rb") as handle:
        role_raw = handle.read()
    image = json.loads(role_raw)
    repository = image["repository"]
    manifest_digest = image["manifest_digest"]
    config_image_id = image["config_image_id"]
    reference = f"{repository}@{manifest_digest}"

    if runner is None:
        if docker_authority is None:
            raise _refuse("image acquisition requires --docker-authority; "
                          "no Docker command was run")
        runner = LiveAcquisitionRunner(
            docker_authority_path=docker_authority,
            reference=reference, config_image_id=config_image_id)
    authority = dict(runner.revalidate_authority())

    present = runner.run(("image", "inspect", config_image_id), timeout=120)
    if present.returncode == 0:
        raise _refuse("expected config image ID is already present in the "
                      "selected daemon; acquisition starts without it and "
                      "does not relabel prior state as acquired")
    pulled = runner.run(
        ("image", "pull", "--platform", "linux/amd64", reference),
        timeout=7200)
    if pulled.timed_out or pulled.overflowed or pulled.returncode != 0:
        raise _refuse("registry pull by manifest digest failed: "
                      + _pull_condition(pulled))

    inspected_result = runner.run(
        ("image", "inspect", config_image_id), timeout=120)
    if inspected_result.timed_out or inspected_result.overflowed \
            or inspected_result.returncode != 0:
        raise _refuse(
            "pulled image does not resolve by the expected config image ID")
    try:
        inspected = research._inspect(inspected_result.stdout,
                                      config_image_id)
    except research.MinimalJavaRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if inspected.get("Os") != "linux" \
            or inspected.get("Architecture") != "amd64":
        raise _refuse("pulled image platform is not linux/amd64")
    if inspected.get("RepoTags") not in (None, []):
        raise _refuse("acquisition introduced a convenience tag")
    # The daemon committed the pulled manifest under this repository@digest
    # only after verifying its bytes against the digest, and it derived the
    # image `.Id` from the config bytes that manifest's config descriptor
    # named.  Requiring exactly the bundle's reference here and exactly the
    # bundle's config ID above verifies the two identities independently;
    # neither field ever stands in for the other.
    if inspected.get("RepoDigests") != [reference]:
        raise _refuse("pulled manifest digest differs from the bundle "
                      "reference")
    config = inspected.get("Config")
    if not isinstance(config, dict) \
            or config.get("WorkingDir") != "/work" \
            or config.get("Entrypoint") not in (None, []) \
            or config.get("Cmd") != ["tail", "-f", "/dev/null"]:
        raise _refuse("pulled image differs from canonical qualification")
    if not {"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"} \
            <= set(config.get("Env") or []):
        raise _refuse("pulled image UTF-8/UTC environment differs")

    probe = runner.run(
        ("run", "--rm", "--network", "none", "--pull=never",
         "--entrypoint", "/bin/sh", config_image_id,
         "-c", oci._QUALIFICATION_SCRIPT), timeout=600)
    banner = probe.stdout + probe.stderr
    if probe.timed_out or probe.overflowed or probe.returncode != 0 \
            or b"R2T-QUALIFIED\n" not in probe.stdout \
            or b"Apache Maven 3.9.6" not in banner \
            or not research._java_banner_matches(
                banner, research._config(project).jdk_major):
        raise _refuse("pulled image JDK/Maven/source-free qualification "
                      "failed")

    receipt = {
        "schema": ACQUISITION_SCHEMA,
        "path": algorand_bundle.IMAGE_PATH,
        "project": algorand_bundle.PROJECT,
        "platform": "linux/amd64",
        "distribution_mode": "registry_digest",
        "repository": repository,
        "pull_reference": reference,
        "manifest_digest": manifest_digest,
        "config_image_id": config_image_id,
        "imported_config_id": inspected["Id"],
        "bundle_manifest_sha256": report["bundle_manifest_sha256"],
        "oci_image_sha256": hashlib.sha256(role_raw).hexdigest(),
        "docker_authority": authority,
        "qualification": {
            "probe_stdout": _bounded_text(probe.stdout),
            "probe_stderr": _bounded_text(probe.stderr),
        },
        "gold_smoke": SMOKE_DEFERRED,
    }
    receipt["digest"] = authority_evidence.semantic_digest(receipt)
    validate_acquisition_receipt(receipt, installed_bundle=report)
    _write_json_no_clobber(out, receipt)
    return {"project": algorand_bundle.PROJECT, "version": version,
            "pull_reference": reference,
            "manifest_digest": manifest_digest,
            "config_image_id": config_image_id,
            "bundle_manifest_sha256": report["bundle_manifest_sha256"],
            "receipt_path": out,
            "receipt_sha256": algorand_bundle._hash(out),
            "gold_smoke": SMOKE_DEFERRED}


def verify_publication(*, version: str, source_manifest: str, out: str,
                       docker_authority: Optional[str] = None) -> dict:
    """Verify the fixed public v2 package and write its existing receipt."""
    if version != "2":
        raise _refuse("publication verification requires version 2")
    return _verify_publication(
        source_manifest=source_manifest, out=out,
        docker_authority=docker_authority,
        opener=_anonymous_urlopen, runner=None,
        target=_publication_target())


def _verify_publication(*, source_manifest: str, out: str,
                        docker_authority: Optional[str] = None,
                        opener, runner,
                        target: Mapping[str, str]) -> dict:
    """Private fake seams for the fixed public verifier."""
    target = dict(target)
    source_manifest = _absolute(source_manifest, "source manifest path")
    out = _absolute(out, "publication receipt path")
    if os.path.lexists(out):
        raise _refuse("publication receipt path already exists")
    if not os.path.isdir(os.path.dirname(out)):
        raise _refuse("publication receipt directory does not exist")
    try:
        with open(source_manifest, "rb") as handle:
            source_raw = handle.read()
    except OSError as exc:
        raise _refuse("source manifest could not be read") from exc

    reference = f"{target['repository']}@{target['manifest_digest']}"
    pull_argv = (
        "image", "pull", "--platform", "linux/amd64", reference)
    inspect_argv = ("image", "inspect", target["config_image_id"])
    if runner is None:
        if docker_authority is None:
            raise _refuse(
                "publication verification requires --docker-authority")
        runner = LiveAcquisitionRunner(
            docker_authority_path=docker_authority,
            reference=reference,
            config_image_id=target["config_image_id"])
    registry = _anonymous_registry_facts(
        source_raw, target=target, opener=opener)
    runner.revalidate_authority()
    present = runner.run(inspect_argv, timeout=120)
    if present.returncode == 0:
        raise _refuse(
            "expected config image ID is already present; anonymous "
            "publication verification requires a fresh pull")
    if present.timed_out or present.overflowed or present.returncode != 1 \
            or b"No such image" not in present.stdout + present.stderr:
        raise _refuse(
            "could not prove expected config image ID absent before pull")
    pulled = runner.run(pull_argv, timeout=7200)
    if pulled.timed_out or pulled.overflowed or pulled.returncode != 0:
        raise _refuse("anonymous public pull by digest failed: "
                      + _pull_condition(pulled))
    inspected_result = runner.run(inspect_argv, timeout=120)
    if inspected_result.timed_out or inspected_result.overflowed \
            or inspected_result.returncode != 0:
        raise _refuse("publicly pulled image could not be inspected")
    try:
        inspected = research._inspect(
            inspected_result.stdout, target["config_image_id"])
    except research.MinimalJavaRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    # The raw config blob is already pinned by config_image_id, so this leg
    # needs only the independently observed platform and registry attachment.
    # RepoDigests is membership, not equality: the same config may retain the
    # historical organization digest as well as this personal one.
    if inspected.get("Os") != "linux" \
            or inspected.get("Architecture") != "amd64" \
            or reference not in (inspected.get("RepoDigests") or []) \
            or inspected.get("RepoTags") not in (None, []):
        raise _refuse(
            "publicly pulled image differs from the v2 platform/reference")

    receipt = {
        "schema": algorand_bundle.PUBLICATION_SCHEMA,
        "path": algorand_bundle.IMAGE_PATH,
        "project": algorand_bundle.PROJECT,
        "platform": "linux/amd64",
        "distribution_mode": "registry_digest",
        "repository": target["repository"],
        "manifest_digest": target["manifest_digest"],
        "config_image_id": target["config_image_id"],
    }
    _write_json_no_clobber(out, receipt, label="publication receipt")
    return {
        "project": algorand_bundle.PROJECT,
        "version": "2",
        "repository": target["repository"],
        "manifest_digest": target["manifest_digest"],
        "config_image_id": target["config_image_id"],
        **registry,
        "receipt_path": out,
        "receipt_sha256": algorand_bundle._hash(out),
    }


# --------------------------------------------------------------- selftest
_FIXTURE_AUTHORITY = {
    "reference": {"path": "/private/docker-authority.json",
                  "file_sha256": "a" * 64, "digest": "c" * 64},
    "daemon_fingerprint": "b" * 64,
}


class _FakeAcquisitionRunner:
    """One fake daemon/registry pair; every knob is a single defect."""

    def __init__(self, *, repository, present=False, pull_fails=False,
                 resolve_after_pull=True, imported_id=None, repo_digest=None,
                 tag=None, architecture="amd64", workdir="/work",
                 env_complete=True, qualified=True):
        self.reference = \
            f"{repository}@{algorand_bundle.IMAGE_MANIFEST_DIGEST}"
        self.config_image_id = algorand_bundle.IMAGE_CONFIG_ID
        self.present = present
        self.pull_fails = pull_fails
        self.resolve_after_pull = resolve_after_pull
        self.imported_id = imported_id or self.config_image_id
        self.repo_digest = repo_digest or self.reference
        self.tag = tag
        self.architecture = architecture
        self.workdir = workdir
        self.env_complete = env_complete
        self.qualified = qualified
        self._validate = acquisition_argv_validator(
            self.reference, self.config_image_id)
        self.calls = []

    def revalidate_authority(self):
        return json.loads(json.dumps(_FIXTURE_AUTHORITY))

    def run(self, argv, *, timeout):
        assert timeout > 0
        value = self._validate(argv)
        self.calls.append(value)
        if value[:2] == ("image", "inspect"):
            if not self.present:
                return research.CommandResult(
                    value, 1, stderr=b"Error: No such image\n")
            environment = ["LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"] \
                if self.env_complete else ["LANG=C.UTF-8", "LC_ALL=C.UTF-8"]
            document = [{
                "Id": self.imported_id, "Os": "linux",
                "Architecture": self.architecture,
                "RepoTags": [self.tag] if self.tag else [],
                "RepoDigests": [self.repo_digest],
                "Config": {"WorkingDir": self.workdir, "Entrypoint": [],
                           "Cmd": ["tail", "-f", "/dev/null"],
                           "Env": environment},
            }]
            return research.CommandResult(
                value, 0, json.dumps(document).encode())
        if value[:2] == ("image", "pull"):
            if self.pull_fails:
                return research.CommandResult(
                    value, 1, stderr=b"manifest verification failed\n")
            if self.resolve_after_pull:
                self.present = True
            return research.CommandResult(
                value, 0, b"Digest: " + self.reference.split("@")[1].encode()
                + b"\n")
        stdout = b"Apache Maven 3.9.6\n"
        if self.qualified:
            stdout += b"R2T-QUALIFIED\n"
        return research.CommandResult(
            value, 0, stdout, b'openjdk version "11.0.20" 2023-07-18\n')


def _installed_fixture(root: str, *, version: str = "1") -> tuple[str, str]:
    """Build the tiny 117/111 fixture bundle and install it under `root`.

    This reuses `algorand_bundle`'s own fixture world and build path, with
    the same external-evidence seam its selftest patches, so the tree this
    returns passes the real, unpatched `validate_bundle`.
    """
    bundle = algorand_bundle
    selected = bundle.layout(version)
    descriptor = bundle._fixture_inputs(root, version=version)
    fixture = bundle._load_inputs(descriptor, version=version)
    roles = dict(fixture["roles"])
    roles.update({role: os.path.join(root, "inputs", role)
                  for role in bundle.DERIVED_FILE_ROLES})
    source, _raw = bundle._read_json(
        roles["source_approval"], "fixture source approval")

    def fixture_evidence(current, *, selected):
        projection, _projection_raw = bundle._read_json(
            roles["mutation_validation"], "fixture mutation projection")
        projection["packaged"] = {
            "manifest_sha256": bundle._hash(
                current["roles"]["mutation_manifest"]),
            "map_sha256": bundle._hash(current["roles"]["mutation_map"]),
            "released_items_sha256": bundle._hash(
                current["roles"]["released_items"]),
            "boundary_sha256": bundle._hash(current["roles"]["boundary"]),
        }
        projection["digest"] = bundle._document_digest(projection)
        image, _image_raw = bundle._read_json(
            roles["oci_image"], "fixture OCI image reference")
        image["repository"] = selected.image_repository
        image["digest"] = bundle._document_digest(image)
        return {"source_approval": source,
                "mutation_validation": projection,
                "oci_image": image}

    out_dir = os.path.join(root, "bundle-out")
    os.mkdir(out_dir)
    out = os.path.join(out_dir, selected.asset_name)
    real_evidence = bundle._validate_build_evidence
    real_producer = bundle._validate_producer
    bundle._validate_build_evidence = fixture_evidence
    bundle._validate_producer = lambda producer: None
    try:
        bundle.build_bundle(inputs_path=descriptor, out=out, version=version)
    finally:
        bundle._validate_build_evidence = real_evidence
        bundle._validate_producer = real_producer
    data_root = os.path.join(root, "data-root")
    os.mkdir(data_root)
    bundle._inspect_archive(out, data_root, selected=selected)
    image, _image_raw = bundle._read_json(
        roles["oci_image"], "fixture OCI image reference")
    return data_root, image["repository"]


def _evaluation_image_selftest(check, refused) -> None:
    """Exercise V8 forwarding and acquisition with no daemon or registry."""
    from pathlib import Path
    from types import ModuleType
    from unittest.mock import patch
    from .. import data as data_package
    from ..data.bundle import BundleRefused

    with tempfile.TemporaryDirectory(prefix="r2t-acquire-v8-") as root:
        image_path = os.path.join(root, "v8-oci-image.json")
        manifest_path = os.path.join(root, "v8-bundle.json")
        private_index = os.path.join(root, "private-index.json")
        repository = algorand_bundle.layout("2").image_repository
        Path(image_path).write_text(json.dumps({
            "repository": repository,
            "manifest_digest": algorand_bundle.IMAGE_MANIFEST_DIGEST,
            "config_image_id": algorand_bundle.IMAGE_CONFIG_ID,
        }))
        Path(manifest_path).write_text('{"fixture":"V8 shared manifest"}')
        Path(private_index).write_text('{"fixture":"measured private index"}')
        calls = []
        shared = ModuleType("r2t.data.evaluation_bundle")

        def validate(**kwargs):
            calls.append(kwargs)
            return {"role_paths": {"oci_image": image_path},
                    "manifest_path": manifest_path}

        shared.validate_evaluation_bundle = validate
        with patch.dict("sys.modules", {shared.__name__: shared}), \
                patch.object(data_package, "evaluation_bundle", shared, create=True), \
                patch.object(algorand_bundle, "validate_bundle",
                             side_effect=AssertionError("V8 must not load legacy bundles")):
            out = os.path.join(root, "acquired.json")
            runner = _FakeAcquisitionRunner(repository=repository)
            result = acquire_image(
                project=algorand_bundle.PROJECT, version="8", data_root=root,
                release_index_path=private_index, out=out, runner=runner)
            receipt = json.loads(Path(out).read_bytes())
            check("V8 image acquisition uses the complete shared reader and private index",
                  calls == [{"project": algorand_bundle.PROJECT, "version": "8",
                             "root": root, "release_index_path": private_index}]
                  and result["version"] == "8"
                  and receipt["bundle_manifest_sha256"] == algorand_bundle._hash(manifest_path)
                  and receipt["oci_image_sha256"] == algorand_bundle._hash(image_path))
            check("V8 acquisition preserves the published manifest/config identities without V2 installation",
                  receipt["repository"] == repository
                  and receipt["manifest_digest"] == algorand_bundle.IMAGE_MANIFEST_DIGEST
                  and receipt["imported_config_id"] == algorand_bundle.IMAGE_CONFIG_ID)
            _evaluation_image_bundle(root, None)
            check("V8 image reader preserves the default measured release index route",
                  calls[-1]["release_index_path"] is None)

            def reject(**kwargs):
                raise BundleRefused("REFUSED: measured V8 index mismatch")

            shared.validate_evaluation_bundle = reject
            runner = _FakeAcquisitionRunner(repository=repository)
            check("V8 installed validation failure precedes every image operation",
                  refused(lambda: acquire_image(
                      project=algorand_bundle.PROJECT, version="8", data_root=root,
                      release_index_path=private_index,
                      out=os.path.join(root, "rejected.json"), runner=runner),
                          "measured V8 index mismatch")
                  and runner.calls == [])
            check("a private V8 release index cannot select a historical acquisition route",
                  refused(lambda: acquire_image(
                      project=algorand_bundle.PROJECT, version="2", data_root=root,
                      release_index_path=private_index,
                      out=os.path.join(root, "wrong-version.json"), runner=runner),
                          "requires Algorand v8")
                  and runner.calls == [])


def selftest() -> int:
    ok = True

    def check(name, condition, detail=""):
        nonlocal ok
        ok = ok and bool(condition)
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not condition else ""))

    def refused(fn, text=""):
        try:
            fn()
        except ImageAcquisitionRefused as exc:
            return not text or text in str(exc)
        return False

    from pathlib import Path

    _evaluation_image_selftest(check, refused)

    with tempfile.TemporaryDirectory(prefix="r2t-acquire-") as temporary:
        root = str(Path(temporary))
        data_root, repository = _installed_fixture(root)
        installed_bundle = algorand_bundle.validate_bundle(data_root)
        reference = f"{repository}@{algorand_bundle.IMAGE_MANIFEST_DIGEST}"
        receipts = os.path.join(root, "receipts")
        os.mkdir(receipts)
        v5_runner_access = []
        class V5Runner:
            def __getattr__(self, name):
                v5_runner_access.append(name)
                raise AssertionError("v5 image runner was contacted")
        v5_out = os.path.join(receipts, "v5-must-refuse.json")
        check("reference-only v5 refuses image acquisition before bundle or "
              "runner contact",
              refused(lambda: acquire_image(
                  project="algorand-sdk", out=v5_out,
                  data_root=data_root, version="5", runner=V5Runner()),
                  "reference-only")
              and not v5_runner_access and not os.path.lexists(v5_out))

        def acquire(runner, name):
            return acquire_image(
                project="algorand-sdk", out=os.path.join(receipts, name),
                data_root=data_root, runner=runner)

        def validate(value, bundle=installed_bundle):
            return validate_acquisition_receipt(
                value, installed_bundle=bundle)

        happy = _FakeAcquisitionRunner(repository=repository)
        report = acquire(happy, "happy.json")
        receipt_path = os.path.join(receipts, "happy.json")
        receipt = json.loads(Path(receipt_path).read_bytes())
        check("acquisition pulls by digest and writes one validating receipt",
              report["pull_reference"] == reference
              and report["config_image_id"] == algorand_bundle.IMAGE_CONFIG_ID
              and report["gold_smoke"] == SMOKE_DEFERRED
              and validate(receipt) == receipt
              and "R2T-QUALIFIED" in receipt["qualification"]["probe_stdout"])
        check("acquisition speaks only the closed vocabulary, in order",
              [call[:2] for call in happy.calls]
              == [("image", "inspect"), ("image", "pull"),
                  ("image", "inspect"), ("run", "--rm")])
        check("manifest digest and config image ID stay distinct facts",
              receipt["manifest_digest"] != receipt["config_image_id"]
              and receipt["imported_config_id"]
              == receipt["config_image_id"])

        collision = _FakeAcquisitionRunner(repository=repository)
        before = Path(receipt_path).read_bytes()
        check("receipt collision refuses before any Docker command",
              refused(lambda: acquire(collision, "happy.json"),
                      "already exists")
              and not collision.calls
              and Path(receipt_path).read_bytes() == before)

        wrong_project = _FakeAcquisitionRunner(repository=repository)
        check("another project refuses before bundle or Docker work",
              refused(lambda: acquire_image(
                  project="epubcheck",
                  out=os.path.join(receipts, "project.json"),
                  data_root=data_root, runner=wrong_project),
                  "algorand-sdk only")
              and not wrong_project.calls)
        check("a receipt path in a missing directory refuses",
              refused(lambda: acquire_image(
                  project="algorand-sdk",
                  out=os.path.join(receipts, "absent", "receipt.json"),
                  data_root=data_root,
                  runner=_FakeAcquisitionRunner(repository=repository)),
                  "directory does not exist"))
        check("acquisition without a Docker authority refuses",
              refused(lambda: acquire_image(
                  project="algorand-sdk",
                  out=os.path.join(receipts, "no-authority.json"),
                  data_root=data_root),
                  "requires --docker-authority"))

        already = _FakeAcquisitionRunner(repository=repository, present=True)
        check("a pre-existing config image ID refuses, before any pull",
              refused(lambda: acquire(already, "present.json"),
                      "already present")
              and ("image", "pull", "--platform", "linux/amd64", reference)
              not in already.calls)

        check("a failing registry pull refuses, naming docker's condition, "
              "and writes no receipt",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         pull_fails=True), "pull.json"),
                  "pull by manifest digest failed: "
                  "manifest verification failed")
              and not os.path.lexists(os.path.join(receipts, "pull.json")))

        def condition(**fields):
            return _pull_condition(
                research.CommandResult(("image", "pull"), 1, **fields))

        check("the named condition is the last stderr line, or the "
              "exceptional window that replaced it",
              condition(stderr=b"denied\nunauthorized: denied\n")
              == "unauthorized: denied"
              and condition(stderr=b"") == "exit 1 with no diagnostic"
              and condition(timed_out=True) == "timed out"
              and condition(overflowed=True) == "output overflowed"
              and len(condition(stderr=b"x" * 500)) == PULL_DETAIL_LIMIT)
        check("an image that does not resolve by config ID refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         resolve_after_pull=False),
                  "unresolved.json"),
                  "does not resolve"))
        check("a pulled config identity that differs refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         imported_id="sha256:" + "d" * 64),
                  "config.json"),
                  "another/malformed config ID"))
        check("a pulled manifest digest that differs refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(
                      repository=repository,
                      repo_digest=f"{repository}@sha256:{'e' * 64}"),
                  "digest.json"),
                  "manifest digest differs"))
        check("a convenience tag introduced by acquisition refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         tag="r2t:latest"), "tag.json"),
                  "convenience tag"))
        check("a non-amd64 platform refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         architecture="arm64"),
                  "platform.json"),
                  "linux/amd64"))
        check("a drifted container configuration refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         workdir="/"), "workdir.json"),
                  "canonical qualification"))
        check("a missing UTF-8/UTC environment refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         env_complete=False), "env.json"),
                  "UTF-8/UTC"))
        check("a failed qualification probe refuses",
              refused(lambda: acquire(
                  _FakeAcquisitionRunner(repository=repository,
                                         qualified=False),
                  "qualification.json"),
                  "qualification failed"))

        validator = acquisition_argv_validator(
            reference, algorand_bundle.IMAGE_CONFIG_ID)
        check("a tag-bearing pull is outside the closed vocabulary",
              refused(lambda: validator(
                  ("image", "pull", "--platform", "linux/amd64",
                   repository + ":latest")), "outside the acquisition")
              and refused(lambda: validator(
                  ("image", "tag", algorand_bundle.IMAGE_CONFIG_ID,
                   "r2t:latest")), "outside the acquisition"))

        role_path = os.path.join(
            data_root, algorand_bundle.FILE_ROLES["oci_image"])
        role_raw = Path(role_path).read_bytes()
        untouched = _FakeAcquisitionRunner(repository=repository)
        os.unlink(role_path)
        check("a missing oci-image.json role refuses before Docker",
              refused(lambda: acquire(untouched, "missing-role.json"),
                      "installed bundle failed validation")
              and not untouched.calls)
        Path(role_path).write_bytes(role_raw + b"\n")
        check("a tampered oci-image.json role refuses before Docker",
              refused(lambda: acquire(untouched, "tampered-role.json"),
                      "installed bundle failed validation")
              and not untouched.calls)
        Path(role_path).write_bytes(role_raw)

        def redigested(**changes):
            changed = json.loads(json.dumps(receipt))
            changed.update(changes)
            changed["digest"] = authority_evidence.semantic_digest(changed)
            return changed

        tampered = json.loads(json.dumps(receipt))
        tampered["repository"] = "ghcr.test/other/repository"
        check("a byte-tampered receipt refuses on its digest",
              refused(lambda: validate(tampered),
                      "digest differs"))
        check("a re-digested alias of the two identities refuses",
              refused(lambda: validate(redigested(
                  manifest_digest=receipt["config_image_id"],
                  pull_reference=f"{repository}"
                  f"@{receipt['config_image_id']}")), "aliases"))
        check("a re-digested foreign image identity refuses",
              refused(lambda: validate(redigested(
                  manifest_digest="sha256:" + "e" * 64,
                  pull_reference=f"{repository}@sha256:{'e' * 64}")),
                  "recorded v1 image"))
        personal = "ghcr.io/qibinhang/r2t-java-algorand-sdk"
        check("a re-digested v1 receipt cannot name the personal repository",
              refused(lambda: validate(redigested(
                  repository=personal,
                  pull_reference=f"{personal}@{receipt['manifest_digest']}")),
                  "another installed bundle repository"))
        check("a re-digested mismatched pull reference refuses",
              refused(lambda: validate(redigested(
                  pull_reference=f"{repository}@sha256:{'e' * 64}")),
                  "pull reference"))
        check("a re-digested unqualified probe output refuses",
              refused(lambda: validate(redigested(
                  qualification={"probe_stdout": "Apache Maven 3.9.6\n",
                                 "probe_stderr": ""})),
                  "qualification output"))
        check("a re-digested gold-smoke claim refuses",
              refused(lambda: validate(redigested(
                  gold_smoke="complete")), "gold-smoke boundary"))
        check("a re-digested foreign imported config ID refuses",
              refused(lambda: validate(redigested(
                  imported_config_id="sha256:" + "d" * 64)),
                  "imported config ID"))
        check("a same-repository receipt remains joined to the exact bundle "
              "manifest and OCI role",
              refused(lambda: validate(redigested(
                  bundle_manifest_sha256="d" * 64)),
                  "selected installed bundle")
              and refused(lambda: validate(redigested(
                  oci_image_sha256="e" * 64)),
                  "selected installed bundle"))
        check("a re-digested malformed Docker authority refuses",
              refused(lambda: validate(redigested(
                  docker_authority={
                      "reference": _FIXTURE_AUTHORITY["reference"],
                      "daemon_fingerprint": "zz"})),
                  "daemon fingerprint"))

        v2_root = os.path.join(root, "v2-fixture")
        os.mkdir(v2_root)
        v2_data_root, v2_repository = _installed_fixture(
            v2_root, version="2")
        v2_receipts = os.path.join(v2_root, "receipts")
        os.mkdir(v2_receipts)

        def acquire_v2(runner, name):
            return acquire_image(
                project="algorand-sdk", version="2",
                out=os.path.join(v2_receipts, name),
                data_root=v2_data_root, runner=runner)

        v2_happy = _FakeAcquisitionRunner(repository=v2_repository)
        v2_report = acquire_v2(v2_happy, "happy.json")
        v2_receipt = json.loads(Path(
            v2_receipts, "happy.json").read_bytes())
        v1_bundle = algorand_bundle.validate_bundle(data_root)
        v2_bundle = algorand_bundle.validate_bundle(
            v2_data_root, version="2")
        check("explicit v2 acquisition pulls the personal repository by "
              "digest and joins its /1 receipt to only that installed bundle",
              v2_report["version"] == "2"
              and v2_report["pull_reference"]
              == f"{v2_repository}@{algorand_bundle.IMAGE_MANIFEST_DIGEST}"
              and validate_acquisition_receipt(
                  v2_receipt, installed_bundle=v2_bundle) == v2_receipt
              and refused(lambda: validate_acquisition_receipt(
                  receipt, installed_bundle=v2_bundle),
                  "another installed bundle repository")
              and refused(lambda: validate_acquisition_receipt(
                  v2_receipt, installed_bundle=v1_bundle),
                  "another installed bundle repository"))

        v2_failures = (
            ("present.json", _FakeAcquisitionRunner(
                repository=v2_repository, present=True), "already present"),
            ("manifest.json", _FakeAcquisitionRunner(
                repository=v2_repository,
                repo_digest=f"{v2_repository}@sha256:{'e' * 64}"),
             "manifest digest differs"),
            ("config.json", _FakeAcquisitionRunner(
                repository=v2_repository,
                imported_id="sha256:" + "d" * 64),
             "another/malformed config ID"),
            ("tag.json", _FakeAcquisitionRunner(
                repository=v2_repository, tag="r2t:v2"),
             "convenience tag"),
        )
        check("v2 retains the absent-image and exact manifest/config/tag "
              "acquisition gates",
              all(refused(lambda runner=runner, name=name: acquire_v2(
                      runner, name), detail)
                  and not os.path.lexists(os.path.join(v2_receipts, name))
                  for name, runner, detail in v2_failures))

        from ..core import docker_cli
        from . import epubcheck_image
        authority_document = authority_evidence._fixture_authority()
        authority_path = os.path.join(root, "docker-authority.json")
        live_authority_reference = {
            "path": authority_path, "file_sha256": "a" * 64,
            "digest": authority_document["digest"],
        }
        v2_reference = (
            f"{v2_repository}@{algorand_bundle.IMAGE_MANIFEST_DIGEST}")
        v2_pull = (
            "image", "pull", "--platform", "linux/amd64", v2_reference)
        process_calls = []
        real_authority_reference = authority_evidence.authority_reference
        real_bounded_process = epubcheck_image._bounded_process

        def fixture_authority(path, *, live=False):
            del path, live
            return authority_document, live_authority_reference

        def fixture_process(argv, *, timeout, environ, cancel=None):
            outer = list(argv)
            config = outer[outer.index("--config") + 1]
            process_calls.append((
                outer, dict(environ), config,
                os.stat(config).st_mode & 0o777, os.listdir(config)))
            return epubcheck_image.CommandResult(
                tuple(outer), 0, b"", b"")

        authority_evidence.authority_reference = fixture_authority
        epubcheck_image._bounded_process = fixture_process
        previous_docker_config = os.environ.pop("DOCKER_CONFIG", None)
        try:
            live_runner = LiveAcquisitionRunner(
                docker_authority_path=authority_path,
                reference=v2_reference,
                config_image_id=algorand_bundle.IMAGE_CONFIG_ID)
            live_runner.revalidate_authority()
            live_result = live_runner.run(v2_pull, timeout=17)
            successful_call_count = len(process_calls)
            os.environ["DOCKER_CONFIG"] = "credential-shaped-secret"
            try:
                live_runner.run(v2_pull, timeout=17)
            except authority_evidence.DockerAuthorityRefused:
                ambient_refused = True
            else:
                ambient_refused = False
        finally:
            if previous_docker_config is None:
                os.environ.pop("DOCKER_CONFIG", None)
            else:
                os.environ["DOCKER_CONFIG"] = previous_docker_config
            authority_evidence.authority_reference = real_authority_reference
            epubcheck_image._bounded_process = real_bounded_process
            docker_cli.configure()
        live_call = process_calls[0] if process_calls else ([], {}, None, 0, [])
        expected_outer = [
            authority_document["client"]["selected_executable"],
            "--config", live_call[2], "--host",
            authority_document["endpoint"]["address"], *v2_pull]
        check("v2 live acquisition uses one anonymous isolated Docker client",
              live_result.argv == v2_pull
              and live_call[0] == expected_outer
              and live_call[1] == {
                  "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"}
              and live_call[3] == 0o700 and live_call[4] == []
              and ambient_refused
              and len(process_calls) == successful_call_count == 1)

        publication_root = os.path.join(root, "publication-fixtures")
        os.mkdir(publication_root)
        production_publication = _publication_target()
        production_blob_url = (
            "https://ghcr.io/v2/" + production_publication["registry_name"]
            + "/blobs/" + production_publication["config_image_id"])
        redirected = _AnonymousRedirect().redirect_request(
            urllib.request.Request(
                production_blob_url,
                headers={"Authorization": "Bearer anonymous-fixture-token"}),
            None, 307, "Temporary Redirect", {},
            "https://objects.example.invalid/blob")
        check("cross-host blob redirects never receive the registry bearer",
              redirected.full_url == "https://objects.example.invalid/blob"
              and redirected.get_header("Authorization") is None
              and refused(lambda: _AnonymousRedirect().redirect_request(
                  urllib.request.Request(
                      "https://ghcr.io/v2/example/manifests/sha256:00"),
                  None, 307, "Temporary Redirect", {},
                  "https://objects.example.invalid/manifest"),
                  "outside config blob"))

        class PublicationResponse:
            def __init__(self, body, headers=None):
                self.body = body
                self.headers = headers or {}
                self.status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return self.body

        def json_bytes(value):
            return json.dumps(
                value, sort_keys=True, separators=(",", ":")).encode()

        class PublicationRegistry:
            def __init__(self, target, manifest_raw, config_raw):
                self.target = target
                self.manifest_raw = manifest_raw
                self.tag_raw = manifest_raw
                self.config_raw = config_raw
                self.tags = {"name": target["registry_name"],
                             "tags": [target["tag"]]}
                self.challenge = (
                    "Bearer realm=\"https://ghcr.io/token\","
                    "service=\"ghcr.io\",scope=\"repository:"
                    f"{target['registry_name']}:pull\"")
                self.requests = []

            def __call__(self, request):
                self.requests.append(request)
                url = request.full_url
                manifest_headers = {
                    "Content-Type": OCI_MANIFEST_MEDIA_TYPE,
                    "Docker-Content-Digest": self.target["manifest_digest"],
                }
                registry_root = (
                    "https://ghcr.io/v2/" + self.target["registry_name"])
                if url.startswith("https://ghcr.io/token?"):
                    return PublicationResponse(json_bytes({
                        "token": "anonymous-fixture-token"}))
                if url == registry_root + "/manifests/" \
                        + self.target["manifest_digest"]:
                    if _header(dict(request.header_items()),
                               "Authorization") is None:
                        raise urllib.error.HTTPError(
                            url, 401, "Unauthorized",
                            {"WWW-Authenticate": self.challenge}, None)
                    return PublicationResponse(
                        self.manifest_raw, manifest_headers)
                if url == registry_root + "/blobs/" \
                        + self.target["config_image_id"]:
                    return PublicationResponse(self.config_raw)
                if url == registry_root + "/tags/list":
                    return PublicationResponse(json_bytes(self.tags))
                if url == registry_root + "/manifests/" \
                        + self.target["tag"]:
                    return PublicationResponse(self.tag_raw, manifest_headers)
                raise AssertionError(f"unexpected publication URL: {url}")

        class PublicationRunner:
            def __init__(self, target):
                self.target = target
                self.calls = []
                self.revalidations = 0
                self.pull_fails = False
                self.present = False
                self.preinspect_timed_out = False
                self.architecture = "amd64"
                self.repo_tags = []
                self.race_out = None
                self.repo_digests = [
                    f"{target['repository']}@{target['manifest_digest']}"]

            def revalidate_authority(self):
                self.revalidations += 1
                return {}

            def run(self, argv, *, timeout):
                value = tuple(argv)
                self.calls.append(value)
                if value[:2] == ("image", "pull"):
                    if not self.pull_fails:
                        self.present = True
                    return research.CommandResult(
                        value, 1 if self.pull_fails else 0,
                        stderr=b"anonymous pull failed\n"
                        if self.pull_fails else b"")
                if not self.present:
                    return research.CommandResult(
                        value, 1, stderr=b"No such image\n",
                        timed_out=self.preinspect_timed_out)
                document = [{
                    "Id": self.target["config_image_id"],
                    "Os": "linux", "Architecture": self.architecture,
                    "RepoDigests": self.repo_digests,
                    "RepoTags": self.repo_tags,
                }]
                if self.race_out is not None:
                    Path(self.race_out).write_bytes(b"winner\n")
                return research.CommandResult(
                    value, 0, json.dumps(document).encode())

        def publication_fixture(name, *, architecture="amd64",
                                descriptor_digest=None):
            directory = os.path.join(publication_root, name)
            os.mkdir(directory)
            config_raw = json_bytes({
                "architecture": architecture, "os": "linux"})
            config_id = "sha256:" + hashlib.sha256(config_raw).hexdigest()
            descriptor_id = descriptor_digest or config_id
            manifest_raw = json_bytes({
                "schemaVersion": 2,
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "config": {
                    "mediaType": OCI_CONFIG_MEDIA_TYPE,
                    "digest": descriptor_id, "size": len(config_raw),
                },
                "layers": [],
            })
            manifest_id = "sha256:" + hashlib.sha256(
                manifest_raw).hexdigest()
            target = _publication_target(
                manifest_digest=manifest_id, config_image_id=config_id)
            source_path = os.path.join(directory, "source-manifest.json")
            Path(source_path).write_bytes(manifest_raw)
            return {
                "source": source_path,
                "out": os.path.join(directory, "publication.json"),
                "target": target,
                "registry": PublicationRegistry(
                    target, manifest_raw, config_raw),
                "runner": PublicationRunner(target),
            }

        publication = publication_fixture("happy")
        registry_preflight = _preflight_public_registry(
            target=publication["target"], opener=publication["registry"])
        preflight_authorization = [
            _header(dict(request.header_items()), "Authorization")
            for request in publication["registry"].requests]
        check("registry preflight proves credential-free manifest readability "
              "without a Docker pull",
              registry_preflight == {
                  "repository": publication["target"]["repository"],
                  "manifest_digest": publication["target"]["manifest_digest"],
                  "config_image_id": publication["target"]["config_image_id"],
                  "manifest_bytes": len(
                      publication["registry"].manifest_raw),
              }
              and preflight_authorization == [
                  None, None, "Bearer anonymous-fixture-token"])
        publication["registry"].requests.clear()
        publication_report = _verify_publication(
            source_manifest=publication["source"], out=publication["out"],
            opener=publication["registry"], runner=publication["runner"],
            target=publication["target"])
        publication_receipt = json.loads(Path(
            publication["out"]).read_bytes())
        algorand_bundle._publication_record(
            publication["out"], selected=algorand_bundle.layout("2"))
        request_authorization = [
            _header(dict(request.header_items()), "Authorization")
            for request in publication["registry"].requests]
        check("anonymous verification writes only the existing publication "
              "receipt after raw and Docker checks",
              publication_report["receipt_sha256"]
              == algorand_bundle._hash(publication["out"])
              and publication_report["manifest_sha256"]
              == publication["target"]["manifest_digest"].removeprefix(
                  "sha256:")
              and publication_report["tags"]
              == publication["registry"].tags["tags"]
              and publication_receipt == {
                  "schema": algorand_bundle.PUBLICATION_SCHEMA,
                  "path": algorand_bundle.IMAGE_PATH,
                  "project": algorand_bundle.PROJECT,
                  "platform": "linux/amd64",
                  "distribution_mode": "registry_digest",
                  "repository": publication["target"]["repository"],
                  "manifest_digest": publication["target"][
                      "manifest_digest"],
                  "config_image_id": publication["target"][
                      "config_image_id"],
              }
              and publication["runner"].revalidations == 1
              and publication["runner"].calls == [
                  ("image", "inspect",
                   publication["target"]["config_image_id"]),
                  ("image", "pull", "--platform", "linux/amd64",
                   f"{publication['target']['repository']}@"
                   f"{publication['target']['manifest_digest']}"),
                  ("image", "inspect",
                   publication["target"]["config_image_id"]),
              ]
              and request_authorization[:2] == [None, None]
              and request_authorization[2:]
              == ["Bearer anonymous-fixture-token"] * 4
              and b"anonymous-fixture-token" not in Path(
                  publication["out"]).read_bytes())

        collision = publication_fixture("collision")
        Path(collision["out"]).write_bytes(b"winner\n")
        check("publication output collision refuses before HTTP or Docker",
              refused(lambda: _verify_publication(
                  source_manifest=collision["source"], out=collision["out"],
                  opener=collision["registry"], runner=collision["runner"],
                  target=collision["target"]), "already exists")
              and Path(collision["out"]).read_bytes() == b"winner\n"
              and not collision["registry"].requests
              and not collision["runner"].calls)

        raw_failures = []
        changed_source = publication_fixture("changed-source")
        Path(changed_source["source"]).write_bytes(
            Path(changed_source["source"]).read_bytes() + b" ")
        raw_failures.append(changed_source)
        changed_challenge = publication_fixture("changed-challenge")
        changed_challenge["registry"].challenge = (
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\","
            "scope=\"repository:other/repository:pull\"")
        raw_failures.append(changed_challenge)
        changed_manifest = publication_fixture("changed-manifest")
        changed_manifest["registry"].manifest_raw += b" "
        raw_failures.append(changed_manifest)
        changed_descriptor = publication_fixture(
            "changed-descriptor", descriptor_digest="sha256:" + "d" * 64)
        raw_failures.append(changed_descriptor)
        changed_config = publication_fixture("changed-config")
        changed_config["registry"].config_raw += b" "
        raw_failures.append(changed_config)
        changed_platform = publication_fixture(
            "changed-platform", architecture="arm64")
        raw_failures.append(changed_platform)
        changed_repository = publication_fixture("changed-repository")
        changed_repository["registry"].tags["name"] = "other/repository"
        raw_failures.append(changed_repository)
        changed_tags = publication_fixture("changed-tags")
        changed_tags["registry"].tags["tags"].append("latest")
        raw_failures.append(changed_tags)
        changed_tag_manifest = publication_fixture("changed-tag-manifest")
        changed_tag_manifest["registry"].tag_raw += b" "
        raw_failures.append(changed_tag_manifest)
        def raw_refused(world):
            return refused(lambda: _verify_publication(
                source_manifest=world["source"], out=world["out"],
                opener=world["registry"], runner=world["runner"],
                target=world["target"])) \
                and not os.path.lexists(world["out"]) \
                and not world["runner"].calls

        check("every raw manifest/config/platform/repository/tag "
              "failure writes no receipt and reaches no Docker command",
              all(raw_refused(world) for world in raw_failures)
              and not changed_source["registry"].requests)

        pull_failure = publication_fixture("pull-failure")
        pull_failure["runner"].pull_fails = True
        inspect_failure = publication_fixture("inspect-failure")
        inspect_failure["runner"].architecture = "arm64"
        pull_reference = (
            f"{pull_failure['target']['repository']}@"
            f"{pull_failure['target']['manifest_digest']}")
        inspect_reference = (
            f"{inspect_failure['target']['repository']}@"
            f"{inspect_failure['target']['manifest_digest']}")
        check("public pull or inspect failure writes no publication receipt",
              refused(lambda: _verify_publication(
                  source_manifest=pull_failure["source"],
                  out=pull_failure["out"],
                  opener=pull_failure["registry"],
                  runner=pull_failure["runner"],
                  target=pull_failure["target"]), "public pull")
              and not os.path.lexists(pull_failure["out"])
              and pull_failure["runner"].calls == [
                  ("image", "inspect",
                   pull_failure["target"]["config_image_id"]),
                  ("image", "pull", "--platform", "linux/amd64",
                   pull_reference)]
              and refused(lambda: _verify_publication(
                  source_manifest=inspect_failure["source"],
                  out=inspect_failure["out"],
                  opener=inspect_failure["registry"],
                  runner=inspect_failure["runner"],
                  target=inspect_failure["target"]), "platform/reference")
              and not os.path.lexists(inspect_failure["out"])
              and inspect_failure["runner"].calls == [
                  ("image", "inspect",
                   inspect_failure["target"]["config_image_id"]),
                  ("image", "pull", "--platform", "linux/amd64",
                   inspect_reference),
                  ("image", "inspect",
                   inspect_failure["target"]["config_image_id"]),
              ])

        preexisting_image = publication_fixture("preexisting-image")
        preexisting_image["runner"].present = True
        unknown_absence = publication_fixture("unknown-absence")
        unknown_absence["runner"].preinspect_timed_out = True
        tagged_image = publication_fixture("tagged-image")
        tagged_image["runner"].repo_tags = ["local:v2"]
        check("publication verification requires an absent, tag-free image",
              refused(lambda: _verify_publication(
                  source_manifest=preexisting_image["source"],
                  out=preexisting_image["out"],
                  opener=preexisting_image["registry"],
                  runner=preexisting_image["runner"],
                  target=preexisting_image["target"]), "already present")
              and not os.path.lexists(preexisting_image["out"])
              and preexisting_image["runner"].calls == [
                  ("image", "inspect",
                   preexisting_image["target"]["config_image_id"])]
              and refused(lambda: _verify_publication(
                  source_manifest=unknown_absence["source"],
                  out=unknown_absence["out"],
                  opener=unknown_absence["registry"],
                  runner=unknown_absence["runner"],
                  target=unknown_absence["target"]), "could not prove")
              and not os.path.lexists(unknown_absence["out"])
              and unknown_absence["runner"].calls == [
                  ("image", "inspect",
                   unknown_absence["target"]["config_image_id"])]
              and refused(lambda: _verify_publication(
                  source_manifest=tagged_image["source"],
                  out=tagged_image["out"],
                  opener=tagged_image["registry"],
                  runner=tagged_image["runner"],
                  target=tagged_image["target"]), "platform/reference")
              and not os.path.lexists(tagged_image["out"]))

        commit_race = publication_fixture("commit-race")
        commit_race["runner"].race_out = commit_race["out"]
        check("publication receipt commit never overwrites a late winner",
              refused(lambda: _verify_publication(
                  source_manifest=commit_race["source"],
                  out=commit_race["out"],
                  opener=commit_race["registry"],
                  runner=commit_race["runner"],
                  target=commit_race["target"]), "exclusive-new")
              and Path(commit_race["out"]).read_bytes() == b"winner\n")

        default_root = os.path.join(publication_root, "default-live")
        os.mkdir(default_root)
        default_source = os.path.join(default_root, "source.json")
        Path(default_source).write_bytes(b"fixture source")
        default_out = os.path.join(default_root, "publication.json")
        default_target = _publication_target()
        default_runner = PublicationRunner(default_target)
        live_factory_kwargs = []
        anonymous_calls = []
        real_live_runner = globals()["LiveAcquisitionRunner"]
        real_registry_facts = globals()["_anonymous_registry_facts"]
        globals()["LiveAcquisitionRunner"] = lambda **kwargs: (
            live_factory_kwargs.append(kwargs) or default_runner)
        globals()["_anonymous_registry_facts"] = (
            lambda source_raw, **_kwargs: anonymous_calls.append(source_raw)
            or {"manifest_bytes": len(source_raw),
                "manifest_sha256": "0" * 64,
                "config_bytes": 1, "config_sha256": "1" * 64,
                "tags": [PUBLICATION_TAG]})
        try:
            missing_authority_refused = refused(lambda: verify_publication(
                version="2", source_manifest=default_source,
                out=default_out, docker_authority=None),
                "requires --docker-authority")
            default_report = verify_publication(
                version="2", source_manifest=default_source, out=default_out,
                docker_authority="/private/authority.json")
            wrong_version_refused = refused(lambda: verify_publication(
                version="1", source_manifest=default_source,
                out=os.path.join(default_root, "wrong-version.json"),
                docker_authority="/private/authority.json"), "version 2")
        finally:
            globals()["LiveAcquisitionRunner"] = real_live_runner
            globals()["_anonymous_registry_facts"] = real_registry_facts
        check("the public verifier fixes v2 and constructs its live runner "
              "before anonymous HTTP",
              missing_authority_refused and wrong_version_refused
              and len(anonymous_calls) == 1
              and live_factory_kwargs == [{
                  "docker_authority_path": "/private/authority.json",
                  "reference": f"{default_target['repository']}@"
                  f"{default_target['manifest_digest']}",
                  "config_image_id": default_target["config_image_id"],
              }]
              and default_report["version"] == "2"
              and os.path.isfile(default_out))

        from .. import cli
        # Under `python3 -m r2t.toolkit.algorand_image` this file runs as
        # `__main__`; patch the canonical `r2t.toolkit.algorand_image` module the
        # CLI imports, not this execution's globals.
        from . import algorand_image as installed
        captured = []
        captured_publication = []
        real_acquire = installed.acquire_image
        real_verify_publication = installed.verify_publication
        installed.acquire_image = \
            lambda **kwargs: captured.append(kwargs) or {"fixture": True}
        installed.verify_publication = lambda **kwargs: (
            captured_publication.append(kwargs) or {"fixture": True})
        try:
            import contextlib
            import io
            with contextlib.redirect_stdout(io.StringIO()):
                cli_rc = cli.main([
                    "bundle", "acquire-image", "--project", "algorand-sdk",
                    "--out", os.path.join(receipts, "cli.json")])
                cli_v2_rc = cli.main([
                    "bundle", "acquire-image", "--project", "algorand-sdk",
                    "--version", "2", "--out",
                    os.path.join(receipts, "cli-v2.json")])
                cli_v3_rc = cli.main([
                    "bundle", "acquire-image", "--project", "algorand-sdk",
                    "--version", "3", "--out",
                    os.path.join(receipts, "cli-v3.json")])
                cli_v4_rc = cli.main([
                    "bundle", "acquire-image", "--project", "algorand-sdk",
                    "--version", "4", "--out",
                    os.path.join(receipts, "cli-v4.json")])
                cli_publication_rc = cli.main([
                    "--docker-authority", "/private/authority.json",
                    "bundle", "verify-algorand-publication",
                    "--version", "2",
                    "--source-manifest", publication["source"],
                    "--out", os.path.join(receipts, "publication.json")])

            def publication_cli_refused(version):
                try:
                    with contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(io.StringIO()):
                        cli.main([
                            "--docker-authority", "/private/authority.json",
                            "bundle", "verify-algorand-publication",
                            "--version", version,
                            "--source-manifest", publication["source"],
                            "--out", os.path.join(
                                receipts, "must-refuse-publication.json")])
                except SystemExit as exc:
                    return exc.code == 2
                return False

            wrong_publication_version_refused = \
                publication_cli_refused("1")
        finally:
            installed.acquire_image = real_acquire
            installed.verify_publication = real_verify_publication
        check("the CLI wires bundle acquire-image to this module",
              cli_rc == 0 and cli_v2_rc == 0 and cli_v3_rc == 0
              and cli_v4_rc == 0
              and captured == [{
                  "project": "algorand-sdk", "version": "1",
                  "docker_authority": None,
                  "out": os.path.join(receipts, "cli.json")}, {
                  "project": "algorand-sdk", "version": "2",
                  "docker_authority": None,
                  "out": os.path.join(receipts, "cli-v2.json")}, {
                  "project": "algorand-sdk", "version": "3",
                  "docker_authority": None,
                  "out": os.path.join(receipts, "cli-v3.json")}, {
                  "project": "algorand-sdk", "version": "4",
                  "docker_authority": None,
                  "out": os.path.join(receipts, "cli-v4.json")}])
        check("the CLI exposes only source/output plus Docker authority for "
              "publication verification",
              cli_publication_rc == 0 and captured_publication == [{
                  "version": "2",
                  "source_manifest": publication["source"],
                  "docker_authority": "/private/authority.json",
                  "out": os.path.join(receipts, "publication.json"),
              }]
              and wrong_publication_version_refused)

    print("\n" + ("ALL PASS (algorand_image)" if ok
                  else "FAILURES (algorand_image)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
