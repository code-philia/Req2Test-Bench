"""Deterministic OCI distribution for ``java-research-minimal/v1`` images.

The useful live path is deliberately small: save one immutable Docker config
image ID, project its exact config and uncompressed layers to one OCI layout,
and package that layout as canonical USTAR. Validation and Docker-load archive
reconstruction are pure filesystem operations.

This implementation is archive-only and uses the classic ``overlay2`` image
store whose immutable Docker ID is the config digest named by the accepted
specification. Live registry transport, containerd-store identity, and the
public bundle-driven acquisition command remain closed; none is guessed here.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import BinaryIO, Mapping, Optional, Protocol, Sequence

from .. import docker_authority
from ..bench import campaign
from . import research_minimal as research


PATH = "java-research-minimal-oci/v1"
AUTHORITY_SCHEMA = "r2t.java-research-minimal-oci-authority/1"
RECEIPT_SCHEMA = "r2t.java-research-minimal-oci-receipt/1"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar"
PLATFORM = {"architecture": "amd64", "os": "linux"}
MEDIA_TYPES = {"manifest": OCI_MANIFEST, "config": OCI_CONFIG,
               "layer": OCI_LAYER}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_LAYOUT_FILES = research.MAX_M2_FILES + 4
_EXPORT_LOG_PATHS = {
    "inspect": "inspect.json",
    "qualification_stdout": "qualification.stdout",
    "qualification_stderr": "qualification.stderr",
    "save_stderr": "save.stderr",
}

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_BLOB_PATH = re.compile(r"blobs/sha256/([0-9a-f]{64})\Z")


class OCIDistributionRefused(ValueError):
    """The requested OCI operation is outside the reviewed contract."""


def _refuse(message: str) -> OCIDistributionRefused:
    return OCIDistributionRefused("REFUSED: " + message)


def _exact(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise _refuse(f"{label} is not its closed schema")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise _refuse(f"{label} is empty or malformed")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _refuse(f"{label} is not lower-case SHA-256")
    return value


def _image_id(value: object, label: str = "config image ID") -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise _refuse(f"{label} is not one immutable sha256 ID")
    return value


def _absolute(value: object, label: str) -> str:
    if not isinstance(value, str) or not os.path.isabs(value) \
            or os.path.normpath(value) != value:
        raise _refuse(f"{label} is not one normalized absolute path")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise _refuse(f"document is not canonical JSON: {exc}") from exc


def _json(raw: bytes, label: str) -> object:
    if len(raw) > MAX_JSON_BYTES:
        raise _refuse(f"{label} exceeds its byte ceiling")
    try:
        return docker_authority.loads_exact_json(raw, label=label)
    except docker_authority.DockerAuthorityRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc


def _hash_file(path: str) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _regular(path: str, label: str, *, maximum: Optional[int] = None) -> bytes:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise _refuse(f"{label} is absent") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise _refuse(f"{label} is linked or special")
    if maximum is not None and info.st_size > maximum:
        raise _refuse(f"{label} exceeds its byte ceiling")
    return Path(path).read_bytes()


def _mkdir_new(path: str) -> str:
    target = _absolute(path, "output directory")
    try:
        os.mkdir(target, 0o700)
    except FileExistsError as exc:
        raise _refuse(f"output already exists: {target}") from exc
    return target


def _write_new(path: str, raw: bytes, *, mode: int = 0o600) -> None:
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        raise _refuse(f"output parent does not exist: {parent}")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NOFOLLOW", 0), mode)
    except OSError as exc:
        raise _refuse(f"output is not exclusive-new: {path}") from exc
    try:
        _write_all(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_all(fd: int, raw: bytes | memoryview) -> None:
    view = memoryview(raw)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _write_json_no_clobber(path: str, value: Mapping[str, object]) -> None:
    """Commit compact JSON only after complete staged bytes are durable."""
    parent = os.path.dirname(path)
    if not os.path.isdir(parent) or os.path.lexists(path):
        raise _refuse(f"JSON output is not exclusive-new: {path}")
    fd, stage = tempfile.mkstemp(prefix=".r2t-oci-stage-", dir=parent)
    try:
        os.fchmod(fd, 0o600)
        _write_all(fd, _canonical_json(value))
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(stage, path, follow_symlinks=False)
        except OSError as exc:
            raise _refuse(f"JSON output lost no-clobber commit: {path}") from exc
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


def _copy_stream(source: BinaryIO, target: str, *, maximum: int) \
        -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise _refuse("image member exceeds its byte ceiling")
            digest.update(chunk)
            _write_all(fd, chunk)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        # The attempt is terminal and uses a fresh path. Keep partial bytes as
        # diagnostics; another attempt must select another output root.
        raise
    else:
        os.close(fd)
    return digest.hexdigest(), size


def _blob_path(root: str, digest: str) -> str:
    return os.path.join(root, "blobs", "sha256", _sha256(digest, "blob digest"))


def _safe_tar_name(name: object, label: str) -> str:
    value = _text(name, label)
    if value.startswith("/") or posixpath.normpath(value) != value \
            or value.startswith("../") or "//" in value:
        raise _refuse(f"{label} is not a normalized relative path")
    return value


def _tar_members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    result = {}
    for member in archive.getmembers():
        name = _safe_tar_name(member.name.rstrip("/"), "Docker-save member")
        if name in result:
            raise _refuse("Docker-save archive repeats a member")
        if member.issym() or member.islnk() or not (member.isfile()
                                                    or member.isdir()):
            raise _refuse("Docker-save archive contains a link or special member")
        result[name] = member
    return result


def _tar_body(archive: tarfile.TarFile, member: tarfile.TarInfo,
              label: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    if not member.isfile() or member.size > maximum:
        raise _refuse(f"{label} is missing, special, or oversized")
    handle = archive.extractfile(member)
    if handle is None:
        raise _refuse(f"{label} has no body")
    raw = handle.read(maximum + 1)
    if len(raw) != member.size or len(raw) > maximum:
        raise _refuse(f"{label} changed or exceeds its byte ceiling")
    return raw


def docker_save_to_layout(docker_archive: str, *, layout: str,
                          expected_config_id: str) -> dict:
    """Project current Moby classic-overlay2 save bytes into canonical OCI."""
    source = _absolute(docker_archive, "Docker-save archive")
    config_id = _image_id(expected_config_id)
    root = _mkdir_new(layout)
    blobs = os.path.join(root, "blobs", "sha256")
    os.makedirs(blobs, mode=0o700)

    def source_descriptor(value, label, media_types):
        doc = _exact(value, {"digest", "mediaType", "size"}, label)
        _image_id(doc["digest"], f"{label} digest")
        if doc["mediaType"] not in media_types \
                or isinstance(doc["size"], bool) \
                or not isinstance(doc["size"], int) or doc["size"] < 0:
            raise _refuse(f"{label} is malformed")
        return doc

    with tarfile.open(source, mode="r:*") as archive:
        members = _tar_members(archive)
        if "repositories" in members:
            raise _refuse("Docker-save archive carries repository tags")
        layout_member = members.get("oci-layout")
        index_member = members.get("index.json")
        if layout_member is None or index_member is None:
            raise _refuse("Docker save is not the reviewed hybrid OCI projection")
        layout_doc = _exact(_json(_tar_body(
            archive, layout_member, "Docker OCI layout"),
            "Docker OCI layout"), {"imageLayoutVersion"}, "Docker OCI layout")
        if layout_doc != {"imageLayoutVersion": "1.0.0"}:
            raise _refuse("Docker OCI layout version differs")
        index = _exact(_json(_tar_body(
            archive, index_member, "Docker OCI index"), "Docker OCI index"),
            {"schemaVersion", "mediaType", "manifests"}, "Docker OCI index")
        if index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX \
                or not isinstance(index["manifests"], list) \
                or len(index["manifests"]) != 1:
            raise _refuse("Docker OCI index does not select one image")
        selected = index["manifests"][0]
        if not isinstance(selected, dict) \
                or not {"digest", "mediaType", "size"} <= set(selected) \
                or not set(selected) <= {
                    "digest", "mediaType", "size", "platform", "annotations"} \
                or selected.get("platform", PLATFORM) != PLATFORM:
            raise _refuse("Docker OCI manifest selection differs")
        manifest_descriptor = source_descriptor(
            {key: selected[key] for key in ("digest", "mediaType", "size")},
            "Docker OCI manifest descriptor",
            {OCI_MANIFEST, "application/vnd.docker.distribution.manifest.v2+json"})
        manifest_name = "blobs/sha256/" + manifest_descriptor["digest"][7:]
        manifest_member = members.get(manifest_name)
        if manifest_member is None:
            raise _refuse("Docker OCI manifest blob is absent")
        manifest_raw = _tar_body(
            archive, manifest_member, "Docker OCI manifest")
        if len(manifest_raw) != manifest_descriptor["size"] \
                or hashlib.sha256(manifest_raw).hexdigest() \
                != manifest_descriptor["digest"][7:]:
            raise _refuse("Docker OCI manifest size/digest differs")
        manifest = _exact(_json(manifest_raw, "Docker OCI manifest"),
                          {"schemaVersion", "mediaType", "config", "layers"},
                          "Docker OCI manifest")
        if manifest["schemaVersion"] != 2 \
                or manifest["mediaType"] != manifest_descriptor["mediaType"] \
                or not isinstance(manifest["layers"], list) \
                or not manifest["layers"]:
            raise _refuse("Docker OCI manifest has another shape")
        config_descriptor = source_descriptor(
            manifest["config"], "Docker OCI config descriptor",
            {OCI_CONFIG, "application/vnd.docker.container.image.v1+json"})
        if config_descriptor["digest"] != config_id:
            raise _refuse("Docker OCI config differs from config image ID")
        config_name = "blobs/sha256/" + config_id[7:]
        config_member = members.get(config_name)
        if config_member is None:
            raise _refuse("Docker OCI config blob is absent")
        config_raw = _tar_body(
            archive, config_member, "Docker OCI config",
            maximum=MAX_JSON_BYTES)
        if len(config_raw) != config_descriptor["size"] \
                or hashlib.sha256(config_raw).hexdigest() != config_id[7:]:
            raise _refuse("Docker OCI config size/digest differs")
        config = _json(config_raw, "Docker OCI config")
        if not isinstance(config, dict) or config.get("os") != "linux" \
                or config.get("architecture") != "amd64" \
                or config.get("variant") not in (None, ""):
            raise _refuse("Docker OCI config is not plain linux/amd64")
        rootfs = config.get("rootfs")
        if not isinstance(rootfs, dict) or rootfs.get("type") != "layers" \
                or not isinstance(rootfs.get("diff_ids"), list) \
                or len(rootfs["diff_ids"]) != len(manifest["layers"]) \
                or len(set(rootfs["diff_ids"])) != len(rootfs["diff_ids"]):
            raise _refuse("Docker OCI layers differ from config")

        _write_new(_blob_path(root, config_id[7:]), config_raw)
        layer_descriptors = []
        source_files = {"oci-layout", "index.json", manifest_name, config_name}
        for index_number, (value, diff_value) in enumerate(
                zip(manifest["layers"], rootfs["diff_ids"])):
            descriptor = source_descriptor(
                value, f"Docker OCI layer {index_number}", {OCI_LAYER})
            diff_id = _image_id(
                diff_value, f"Docker OCI layer {index_number} diff ID")
            if descriptor["digest"] != diff_id:
                raise _refuse("Docker OCI layer differs from config diff ID")
            source_name = "blobs/sha256/" + descriptor["digest"][7:]
            source_files.add(source_name)
            member = members.get(source_name)
            if member is None or not member.isfile() \
                    or member.size != descriptor["size"]:
                raise _refuse("Docker OCI layer blob is absent or changed")
            handle = archive.extractfile(member)
            if handle is None:
                raise _refuse("Docker OCI layer has no body")
            temporary = os.path.join(blobs, f"layer-{index_number}.tmp")
            digest, size = _copy_stream(
                handle, temporary, maximum=MAX_ARCHIVE_BYTES)
            if digest != descriptor["digest"][7:] \
                    or size != descriptor["size"]:
                raise _refuse("Docker OCI layer bytes differ")
            os.rename(temporary, _blob_path(root, digest))
            layer_descriptors.append(
                {"digest": "sha256:" + digest,
                 "mediaType": OCI_LAYER, "size": size})
        if len({row["digest"] for row in layer_descriptors}) \
                != len(layer_descriptors):
            raise _refuse("Docker OCI manifest repeats a layer blob")

        compatibility = set()
        if "manifest.json" in members:
            compatibility.add("manifest.json")
            rows = _json(_tar_body(
                archive, members["manifest.json"],
                "Docker compatibility manifest"),
                "Docker compatibility manifest")
            if not isinstance(rows, list) or len(rows) != 1 \
                    or not isinstance(rows[0], dict) \
                    or rows[0].get("RepoTags") not in (None, []):
                raise _refuse("Docker compatibility manifest carries a tag")
        admitted_dirs = {"blobs", "blobs/sha256"}
        for name, member in members.items():
            if member.isdir() and name not in admitted_dirs:
                raise _refuse("Docker-save archive has an extra directory")
            if member.isfile() and name not in source_files | compatibility:
                match = _BLOB_PATH.fullmatch(name)
                if match is None:
                    raise _refuse("Docker-save archive has an extra file")
                metadata = _tar_body(
                    archive, member, "Docker legacy layer metadata")
                if hashlib.sha256(metadata).hexdigest() != match.group(1):
                    raise _refuse("Docker legacy layer metadata digest differs")

    output_manifest = {
        "config": {"digest": config_id, "mediaType": OCI_CONFIG,
                   "size": len(config_raw)},
        "layers": layer_descriptors,
        "mediaType": OCI_MANIFEST,
        "schemaVersion": 2}
    output_raw = _canonical_json(output_manifest)
    output_hex = hashlib.sha256(output_raw).hexdigest()
    _write_new(_blob_path(root, output_hex), output_raw)
    _write_new(os.path.join(root, "index.json"), _canonical_json({
        "manifests": [{"digest": "sha256:" + output_hex,
                       "mediaType": OCI_MANIFEST,
                       "platform": dict(PLATFORM),
                       "size": len(output_raw)}],
        "mediaType": OCI_INDEX,
        "schemaVersion": 2}))
    _write_new(os.path.join(root, "oci-layout"), _canonical_json(
        {"imageLayoutVersion": "1.0.0"}))
    return validate_layout(
        root, expected_config_id=config_id,
        expected_manifest_digest="sha256:" + output_hex)


def _descriptor(value: object, *, media_type: str, label: str) -> dict:
    doc = _exact(value, {"digest", "mediaType", "size"}, label)
    if doc["mediaType"] != media_type:
        raise _refuse(f"{label} has another media type")
    _image_id(doc["digest"], f"{label} digest")
    if isinstance(doc["size"], bool) or not isinstance(doc["size"], int) \
            or doc["size"] < 0:
        raise _refuse(f"{label} size is invalid")
    return doc


def _layout_files(root: str) -> set[str]:
    files = set()
    directories = set()
    for base, dirs, names in os.walk(root, followlinks=False):
        if any(Path(base, name).is_symlink() for name in dirs):
            raise _refuse("OCI layout contains a linked directory")
        for name in dirs:
            directories.add(os.path.relpath(
                os.path.join(base, name), root).replace(os.sep, "/"))
        for name in names:
            path = os.path.join(base, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise _refuse("OCI layout contains a linked or special file")
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if rel in files:
                raise _refuse("OCI layout repeats a path")
            files.add(rel)
    if len(files) > MAX_LAYOUT_FILES:
        raise _refuse("OCI layout exceeds its file ceiling")
    if directories != {"blobs", "blobs/sha256"}:
        raise _refuse("OCI layout has a missing or extra directory")
    return files


def _read_blob(root: str, digest: str, size: int, label: str) -> bytes:
    value = _image_id(digest, f"{label} digest")
    path = _blob_path(root, value.removeprefix("sha256:"))
    raw = _regular(path, label, maximum=MAX_JSON_BYTES)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() \
            != value.removeprefix("sha256:"):
        raise _refuse(f"{label} size/digest differs")
    return raw


def validate_layout(layout: str, *, expected_config_id: Optional[str] = None,
                    expected_manifest_digest: Optional[str] = None) -> dict:
    """Validate the complete one-platform OCI descriptor closure."""
    root = _absolute(layout, "OCI layout")
    if not os.path.isdir(root) or os.path.islink(root):
        raise _refuse("OCI layout is not one real directory")
    layout_raw = _regular(os.path.join(root, "oci-layout"), "oci-layout",
                          maximum=MAX_JSON_BYTES)
    layout_doc = _exact(_json(layout_raw, "oci-layout"),
                        {"imageLayoutVersion"}, "oci-layout")
    if layout_doc != {"imageLayoutVersion": "1.0.0"} \
            or layout_raw != _canonical_json(layout_doc):
        raise _refuse("oci-layout bytes are not canonical v1")
    index_raw = _regular(os.path.join(root, "index.json"), "OCI index",
                         maximum=MAX_JSON_BYTES)
    index = _exact(_json(index_raw, "OCI index"),
                   {"schemaVersion", "mediaType", "manifests"}, "OCI index")
    if index["schemaVersion"] != 2 or index["mediaType"] != OCI_INDEX \
            or not isinstance(index["manifests"], list) \
            or len(index["manifests"]) != 1 \
            or index_raw != _canonical_json(index):
        raise _refuse("OCI index is not one canonical manifest selection")
    selected = _exact(index["manifests"][0],
                      {"digest", "mediaType", "platform", "size"},
                      "OCI index descriptor")
    if selected["platform"] != PLATFORM:
        raise _refuse("OCI index platform is not linux/amd64")
    manifest_descriptor = _descriptor(
        {key: selected[key] for key in ("digest", "mediaType", "size")},
        media_type=OCI_MANIFEST, label="OCI manifest descriptor")
    manifest_digest = manifest_descriptor["digest"]
    if expected_manifest_digest is not None \
            and manifest_digest != _image_id(
                expected_manifest_digest, "expected OCI manifest digest"):
        raise _refuse("OCI manifest digest differs from expected identity")
    manifest_raw = _read_blob(
        root, manifest_digest, manifest_descriptor["size"], "OCI manifest")
    manifest = _exact(_json(manifest_raw, "OCI manifest"),
                      {"schemaVersion", "mediaType", "config", "layers"},
                      "OCI manifest")
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_MANIFEST \
            or manifest_raw != _canonical_json(manifest):
        raise _refuse("OCI manifest bytes are not canonical schema 2")
    config = _descriptor(manifest["config"], media_type=OCI_CONFIG,
                         label="OCI config descriptor")
    config_id = config["digest"]
    if expected_config_id is not None \
            and config_id != _image_id(expected_config_id):
        raise _refuse("OCI config descriptor differs from config image ID")
    config_raw = _read_blob(root, config_id, config["size"], "OCI config")
    config_doc = _json(config_raw, "OCI config")
    if not isinstance(config_doc, dict) or config_doc.get("os") != "linux" \
            or config_doc.get("architecture") != "amd64" \
            or config_doc.get("variant") not in (None, ""):
        raise _refuse("OCI config is not linux/amd64")
    rootfs = config_doc.get("rootfs")
    if not isinstance(rootfs, dict) or rootfs.get("type") != "layers" \
            or not isinstance(rootfs.get("diff_ids"), list):
        raise _refuse("OCI config has no ordered layer diff IDs")
    layers = manifest["layers"]
    if not isinstance(layers, list) or not layers \
            or len(layers) != len(rootfs["diff_ids"]):
        raise _refuse("OCI layer descriptors differ from config")
    if len({value.get("digest") for value in layers
            if isinstance(value, dict)}) != len(layers):
        raise _refuse("OCI manifest repeats a layer blob")
    closure = {"oci-layout", "index.json",
               "blobs/sha256/" + manifest_digest.removeprefix("sha256:"),
               "blobs/sha256/" + config_id.removeprefix("sha256:")}
    layer_facts = []
    for index_number, (value, diff_id) in enumerate(
            zip(layers, rootfs["diff_ids"])):
        descriptor = _descriptor(value, media_type=OCI_LAYER,
                                 label=f"OCI layer {index_number}")
        digest = descriptor["digest"]
        if digest != _image_id(diff_id, f"OCI diff ID {index_number}"):
            raise _refuse("OCI layer digest differs from config diff ID")
        path = _blob_path(root, digest.removeprefix("sha256:"))
        actual_digest, actual_size = _hash_file(path)
        if actual_digest != digest.removeprefix("sha256:") \
                or actual_size != descriptor["size"]:
            raise _refuse("OCI layer blob size/digest differs")
        closure.add("blobs/sha256/" + actual_digest)
        layer_facts.append(dict(descriptor))
    if _layout_files(root) != closure:
        raise _refuse("OCI layout has a missing, extra, or unreferenced blob")
    return {"canonical_config_image_id": config_id,
            "oci_manifest_digest": manifest_digest,
            "manifest_descriptor": {
                "digest": manifest_digest, "mediaType": OCI_MANIFEST,
                "size": len(manifest_raw)},
            "config_descriptor": dict(config),
            "manifest_size": len(manifest_raw),
            "config_size": len(config_raw),
            "layers": layer_facts,
            "platform": "linux/amd64"}


def _ustar_header(name: str, size: int) -> bytes:
    info = tarfile.TarInfo(name)
    info.type = tarfile.REGTYPE
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    info.size = size
    try:
        return info.tobuf(format=tarfile.USTAR_FORMAT,
                          encoding="utf-8", errors="strict")
    except (ValueError, UnicodeError) as exc:
        raise _refuse(f"OCI archive path cannot be represented by ustar: {name}") \
            from exc


def _archive_layout_paths(root: str) -> list[str]:
    paths = sorted(_layout_files(root), key=lambda value: value.encode("utf-8"))
    if any(path not in {"oci-layout", "index.json"}
           and _BLOB_PATH.fullmatch(path) is None for path in paths):
        raise _refuse("OCI layout has a non-archive path")
    return paths


def write_oci_archive(layout: str, out: str) -> dict:
    """Write one exact regular-file-only USTAR stream."""
    root = _absolute(layout, "OCI layout")
    facts = validate_layout(root)
    target = _absolute(out, "OCI archive output")
    if os.path.lexists(target):
        raise _refuse("OCI archive output already exists")
    parent = os.path.dirname(target)
    if not os.path.isdir(parent):
        raise _refuse("OCI archive output parent does not exist")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        for rel in _archive_layout_paths(root):
            path = os.path.join(root, *rel.split("/"))
            size = os.path.getsize(path)
            _write_all(fd, _ustar_header(rel, size))
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    _write_all(fd, chunk)
            padding = (-size) % 512
            if padding:
                _write_all(fd, b"\0" * padding)
        _write_all(fd, b"\0" * 1024)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        # Preserve partial bytes inside this terminal attempt for diagnosis.
        raise
    else:
        os.close(fd)
    parent_fd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    digest, size = _hash_file(target)
    return {**facts, "archive_path": target, "archive_sha256": digest,
            "archive_bytes": size}


def unpack_oci_archive(archive: str, *, out: str) -> dict:
    """Strictly parse canonical USTAR into a fresh layout directory."""
    source_path = _absolute(archive, "OCI archive")
    root = _mkdir_new(out)
    previous = None
    seen = set()
    total = 0
    zeros = b"\0" * 512
    try:
        with open(source_path, "rb") as source:
            while True:
                header = source.read(512)
                if len(header) != 512:
                    raise _refuse("OCI archive is truncated before its terminator")
                total += 512
                if header == zeros:
                    if source.read(512) != zeros or source.read(1) != b"":
                        raise _refuse("OCI archive has another terminator/trailing bytes")
                    total += 512
                    break
                try:
                    info = tarfile.TarInfo.frombuf(
                        header, encoding="utf-8", errors="strict")
                except (tarfile.TarError, ValueError, UnicodeError) as exc:
                    raise _refuse("OCI archive has a malformed ustar header") from exc
                name = _safe_tar_name(info.name, "OCI archive member")
                if not info.isreg() or header != _ustar_header(name, info.size):
                    raise _refuse("OCI archive member metadata is not canonical")
                if name not in {"oci-layout", "index.json"} \
                        and _BLOB_PATH.fullmatch(name) is None:
                    raise _refuse("OCI archive member path is not admitted")
                encoded = name.encode("utf-8")
                if name in seen or previous is not None and encoded <= previous:
                    raise _refuse("OCI archive members repeat or are out of order")
                seen.add(name)
                previous = encoded
                if info.size > MAX_ARCHIVE_BYTES or total + info.size \
                        > MAX_ARCHIVE_BYTES:
                    raise _refuse("OCI archive exceeds its byte ceiling")
                target = os.path.join(root, *name.split("/"))
                os.makedirs(os.path.dirname(target), mode=0o700, exist_ok=True)
                remaining = info.size
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_CLOEXEC", 0)
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise _refuse("OCI archive member is truncated")
                        _write_all(fd, chunk)
                        remaining -= len(chunk)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                padding = (-info.size) % 512
                if padding and source.read(padding) != b"\0" * padding:
                    raise _refuse("OCI archive member padding is nonzero")
                total += info.size + padding
        if len(seen) > MAX_LAYOUT_FILES:
            raise _refuse("OCI archive exceeds its file ceiling")
        return validate_layout(root)
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def write_docker_load_archive(layout: str, out: str) -> dict:
    """Reconstruct the minimal tagless Docker-load projection."""
    root = _absolute(layout, "OCI layout")
    facts = validate_layout(root)
    manifest_hex = facts["oci_manifest_digest"].removeprefix("sha256:")
    manifest = _json(_regular(_blob_path(root, manifest_hex), "OCI manifest",
                              maximum=MAX_JSON_BYTES), "OCI manifest")
    assert isinstance(manifest, dict)
    config_hex = facts["canonical_config_image_id"].removeprefix("sha256:")
    members = {config_hex + ".json": _blob_path(root, config_hex)}
    layers = []
    for descriptor in manifest["layers"]:
        layer_hex = descriptor["digest"].removeprefix("sha256:")
        name = layer_hex + "/layer.tar"
        members[name] = _blob_path(root, layer_hex)
        layers.append(name)
    docker_manifest = _canonical_json([{
        "Config": config_hex + ".json", "Layers": layers, "RepoTags": []}])
    target = _absolute(out, "Docker-load archive output")
    if os.path.lexists(target):
        raise _refuse("Docker-load archive output already exists")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        for name in sorted((*members, "manifest.json"),
                           key=lambda value: value.encode("utf-8")):
            if name == "manifest.json":
                size = len(docker_manifest)
                _write_all(fd, _ustar_header(name, size))
                _write_all(fd, docker_manifest)
            else:
                path = members[name]
                size = os.path.getsize(path)
                _write_all(fd, _ustar_header(name, size))
                with open(path, "rb") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        _write_all(fd, chunk)
            padding = (-size) % 512
            if padding:
                _write_all(fd, b"\0" * padding)
        _write_all(fd, b"\0" * 1024)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        if os.path.isfile(target):
            os.unlink(target)
        raise
    else:
        os.close(fd)
    digest, size = _hash_file(target)
    return {**facts, "docker_archive_path": target,
            "docker_archive_sha256": digest, "docker_archive_bytes": size}


def implementation_identity() -> dict:
    source = Path(__file__).read_bytes()
    commit = campaign.harness_commit_identity()
    if commit is None:
        raise _refuse("implementation checkout has no full Git commit identity")
    return {"commit": commit, "source_sha256": hashlib.sha256(source).hexdigest()}


_AUTHORITY_KEYS = {
    "schema", "path", "project", "canonical_transcript",
    "canonical_transcript_sha256", "canonical_config_image_id",
    "implementation", "distribution", "platform", "media_types",
    "credential_channels", "image_store", "export_output", "digest",
}


def validate_authority(value: object, *, check_implementation: bool = True) \
        -> dict:
    """Validate one reviewed OCI distribution authority document."""
    doc = _exact(value, _AUTHORITY_KEYS, "OCI distribution authority")
    if doc["schema"] != AUTHORITY_SCHEMA or doc["path"] != PATH \
            or doc["project"] not in research.PROJECTS:
        raise _refuse("OCI distribution authority has another identity")
    _absolute(doc["canonical_transcript"], "canonical transcript")
    _sha256(doc["canonical_transcript_sha256"],
            "canonical transcript SHA-256")
    _image_id(doc["canonical_config_image_id"])
    implementation = _exact(
        doc["implementation"],
        {"commit", "exporter_source_sha256", "importer_source_sha256"},
        "OCI implementation identity")
    if not isinstance(implementation["commit"], str) \
            or re.fullmatch(r"[0-9a-f]{40}", implementation["commit"]) is None:
        raise _refuse("OCI implementation commit is not full lower-case Git")
    exporter_sha = _sha256(implementation["exporter_source_sha256"],
                           "OCI exporter source SHA-256")
    importer_sha = _sha256(implementation["importer_source_sha256"],
                           "OCI importer source SHA-256")
    if exporter_sha != importer_sha:
        raise _refuse("OCI exporter/importer do not name their shared source")
    if check_implementation:
        current = implementation_identity()
        if implementation != {
                "commit": current["commit"],
                "exporter_source_sha256": current["source_sha256"],
                "importer_source_sha256": current["source_sha256"]}:
            raise _refuse("OCI implementation identity differs from this tree")
    if doc["platform"] != "linux/amd64" or doc["media_types"] != MEDIA_TYPES:
        raise _refuse("OCI platform/media types differ from v1")
    if doc["image_store"] != "classic-overlay2":
        raise _refuse("OCI authority does not select classic overlay2")
    channels = doc["credential_channels"]
    if not isinstance(channels, list) or len(channels) != len(set(channels)) \
            or any(not isinstance(item, str)
                   or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", item) is None
                   for item in channels):
        raise _refuse("OCI credential channel names are malformed")
    distribution = doc["distribution"]
    if isinstance(distribution, dict) and distribution.get("mode") \
            == "oci_archive":
        block = _exact(distribution,
                       {"mode", "asset_name", "storage_namespace"},
                       "OCI archive distribution")
        asset = _text(block["asset_name"], "OCI archive asset name")
        namespace = _text(
            block["storage_namespace"], "OCI archive storage namespace")
        if "/" in asset or asset in {".", ".."} \
                or len(namespace) > 256 \
                or any(character.isspace() for character in namespace) \
                or any(token in namespace for token in ("@", "?", "#", "\\")):
            raise _refuse("OCI archive distribution has an unsafe name")
    else:
        raise _refuse("this implementation admits only oci_archive mode")
    _absolute(doc["export_output"], "OCI export output")
    try:
        expected = docker_authority.semantic_digest(doc)
    except docker_authority.DockerAuthorityRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    if doc["digest"] != expected:
        raise _refuse("OCI distribution authority digest does not rederive")
    return dict(doc)


def authority_document(fields: Mapping[str, object]) -> dict:
    """Add the semantic digest to exact operator-reviewed authority fields."""
    document = dict(fields)
    if set(document) != _AUTHORITY_KEYS - {"digest"}:
        raise _refuse("OCI authority fields are not the closed draft shape")
    document["digest"] = docker_authority.semantic_digest(document)
    return validate_authority(document)


def load_authority(path: str, *, approved_digest: str) -> dict:
    from ..bench import result_ledger
    source = _absolute(path, "OCI authority path")
    raw = result_ledger.read_trusted_bytes(source, label="OCI authority")
    try:
        document = docker_authority.loads_exact_json(raw, label="OCI authority")
    except docker_authority.DockerAuthorityRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    validated = validate_authority(document)
    if validated["digest"] != _sha256(
            approved_digest, "approved OCI authority digest"):
        raise _refuse("OCI authority does not have the approved digest")
    return validated


def write_authority_draft(*, fields_path: str, out: str) -> dict:
    from ..bench import result_ledger
    fields = _json(result_ledger.read_trusted_bytes(
        _absolute(fields_path, "OCI authority fields"),
        label="OCI authority fields"), "OCI authority fields")
    if not isinstance(fields, dict):
        raise _refuse("OCI authority fields are not an object")
    document = authority_document(fields)
    _write_json_no_clobber(
        _absolute(out, "OCI authority draft output"), document)
    return document


@dataclass(frozen=True)
class CanonicalImage:
    project: str
    transcript_path: str
    transcript_sha256: str
    config_image_id: str
    m2_manifest_sha256: str
    m2_tree_sha256: str
    authority: Mapping[str, object]


def canonical_image(authority: Mapping[str, object]) -> CanonicalImage:
    doc = validate_authority(authority)
    from ..bench import result_ledger
    transcript_path = doc["canonical_transcript"]
    raw = result_ledger.read_trusted_bytes(
        transcript_path, label="canonical Java image transcript")
    if hashlib.sha256(raw).hexdigest() \
            != doc["canonical_transcript_sha256"]:
        raise _refuse("canonical transcript differs from reviewed bytes")
    transcript = _json(raw, "canonical Java image transcript")
    if not isinstance(transcript, dict) \
            or transcript.get("schema") != research.IMAGE_SCHEMA \
            or transcript.get("path") != research.PATH \
            or transcript.get("project") != doc["project"] \
            or transcript.get("phase") != "canonical" \
            or transcript.get("status") != "complete":
        raise _refuse("canonical transcript is not one complete image")
    result = transcript.get("result")
    if not isinstance(result, dict):
        raise _refuse("canonical transcript has no result")
    image_id = _image_id(result.get("candidate_image_id"))
    if image_id != doc["canonical_config_image_id"]:
        raise _refuse("canonical transcript image differs from OCI authority")
    m2_manifest = _sha256(result.get("m2_manifest_sha256"),
                          "canonical M2 manifest SHA-256")
    m2_tree = _sha256(result.get("m2_tree_sha256"),
                      "canonical M2 tree SHA-256")
    transcript_authority = transcript.get("authority")
    if not isinstance(transcript_authority, dict):
        raise _refuse("canonical transcript has no Docker authority")
    return CanonicalImage(
        doc["project"], doc["canonical_transcript"],
        doc["canonical_transcript_sha256"], image_id,
        m2_manifest, m2_tree, dict(transcript_authority))


_QUALIFICATION_SCRIPT = (
    "set -eu; test -z \"$(find /work -mindepth 1 -print -quit)\"; "
    "test ! -e /pom.xml; test ! -e /src; test ! -e /.git; "
    "grep -q '<offline>true</offline>' /root/.m2/settings.xml; "
    "java -version; mvn --version; printf 'R2T-QUALIFIED\\n'")


def validate_oci_docker_argv(argv: Sequence[str]) -> tuple[str, ...]:
    try:
        value = tuple(argv)
    except TypeError as exc:
        raise _refuse("OCI Docker argv is not a sequence") from exc
    if not value or any(not isinstance(token, str) or not token
                        or "\x00" in token for token in value):
        raise _refuse("OCI Docker argv is malformed")
    if value[:2] == ("image", "inspect") and len(value) == 3 \
            and _IMAGE_ID.fullmatch(value[2]):
        return value
    if value[:2] == ("image", "save") and len(value) == 5 \
            and value[2:4] == ("--platform", "linux/amd64") \
            and _IMAGE_ID.fullmatch(value[4]):
        return value
    if value[:7] == ("run", "--rm", "--network", "none", "--pull=never",
                     "--entrypoint", "/bin/sh") \
            and len(value) == 10 and _IMAGE_ID.fullmatch(value[7]) \
            and value[8:] == ("-c", _QUALIFICATION_SCRIPT):
        return value
    if value[:7] == ("run", "--rm", "--network", "none", "--pull=never",
                     "--entrypoint", "/bin/tar") \
            and len(value) == 13 and _IMAGE_ID.fullmatch(value[7]) \
            and value[8:] == ("-C", "/opt", "-cf", "-", "m2"):
        return value
    raise _refuse("Docker command is outside the OCI distribution vocabulary")


class ArchiveRunner(Protocol):
    def revalidate_authority(self) -> Mapping[str, object]: ...
    def run(self, argv: Sequence[str], *, timeout: int,
            build: bool = False) -> research.CommandResult: ...
    def save(self, image_id: str, *, target: str) -> Mapping[str, object]: ...
    def capture_files(self, image_id: str, path: str, *, timeout: int) \
            -> Mapping[str, bytes]: ...


class LiveArchiveRunner:
    """Small authority-bound Docker adapter for save/load qualification."""

    def __init__(self, *, docker_authority_path: str, scratch_root: str):
        from ..core import docker_cli
        from ..toolkit.epubcheck_image import LiveDockerRunner
        authority_path = _absolute(docker_authority_path, "Docker authority")
        self._scratch_root = _absolute(scratch_root, "OCI scratch root")
        docker_cli.configure(authority_path=authority_path)
        document, reference = docker_cli.authority_reference(live=False)
        daemon = document.get("daemon")
        if not isinstance(daemon, dict) \
                or daemon.get("storage_driver") != "overlay2":
            raise _refuse("OCI export requires the classic overlay2 image store")
        self._runner = LiveDockerRunner(
            reference, argv_validator=validate_oci_docker_argv,
            mutation_predicate=lambda argv: tuple(argv)[:2] in {
                ("image", "inspect"), ("image", "save"),
                ("run", "--rm")})

    def revalidate_authority(self) -> Mapping[str, object]:
        return self._runner.revalidate_authority()

    def run(self, argv: Sequence[str], *, timeout: int,
            build: bool = False) -> research.CommandResult:
        result = self._runner.run(argv, timeout=timeout, build=build)
        return research.CommandResult(
            tuple(result.argv), result.returncode, result.stdout, result.stderr,
            result.timed_out, result.overflowed)

    def save(self, image_id: str, *, target: str) -> Mapping[str, object]:
        result = self._runner.stream_to(
            ("image", "save", "--platform", "linux/amd64", image_id),
            timeout=7200, target=target, maximum=MAX_ARCHIVE_BYTES)
        return {"argv": list(result.argv), "returncode": result.returncode,
                "stderr": result.stderr, "bytes": result.size,
                "sha256": result.sha256, "timed_out": result.timed_out,
                "overflowed": result.overflowed}

    def capture_files(self, image_id: str, path: str, *, timeout: int) \
            -> Mapping[str, bytes]:
        return self._runner.capture_files(
            image_id, path, timeout=timeout,
            maximum_files=research.MAX_M2_FILES,
            maximum_bytes=research.MAX_M2_BYTES,
            scratch_root=self._scratch_root)


def _checked(runner: ArchiveRunner, argv: Sequence[str], *, timeout: int) \
        -> research.CommandResult:
    result = runner.run(argv, timeout=timeout)
    if result.timed_out or result.overflowed or result.returncode != 0:
        raise _refuse("OCI Docker command failed")
    return result


def qualify_image(runner: ArchiveRunner, image: CanonicalImage) -> dict:
    authority = runner.revalidate_authority()
    if authority != image.authority:
        raise _refuse("export Docker authority differs from canonical image")
    inspected_result = _checked(
        runner, ("image", "inspect", image.config_image_id), timeout=120)
    try:
        inspected = research._inspect(
            inspected_result.stdout, image.config_image_id)
    except research.MinimalJavaRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    config = inspected.get("Config")
    if inspected.get("Os") != "linux" or inspected.get("Architecture") != "amd64" \
            or not isinstance(config, dict) \
            or config.get("WorkingDir") != "/work" \
            or config.get("Entrypoint") not in (None, []) \
            or config.get("Cmd") != ["tail", "-f", "/dev/null"] \
            or inspected.get("RepoTags") not in (None, []):
        raise _refuse("OCI image inspect differs from canonical qualification")
    environment = set(config.get("Env") or [])
    if not {"LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"} <= environment:
        raise _refuse("OCI image UTF-8/UTC environment differs")
    probe = _checked(
        runner, ("run", "--rm", "--network", "none", "--pull=never",
                 "--entrypoint", "/bin/sh", image.config_image_id,
                 "-c", _QUALIFICATION_SCRIPT), timeout=300)
    banner = probe.stdout + probe.stderr
    cfg = research._config(image.project)
    if b"R2T-QUALIFIED\n" not in probe.stdout \
            or b"Apache Maven 3.9.6" not in banner \
            or not research._java_banner_matches(banner, cfg.jdk_major):
        raise _refuse("OCI image JDK/Maven/source-free qualification failed")
    captured_manifest, captured_tree = research._manifest(dict(
        runner.capture_files(image.config_image_id, "/opt/m2", timeout=7200)))
    if hashlib.sha256(research._canonical_json(captured_manifest)).hexdigest() \
            != image.m2_manifest_sha256 or captured_tree != image.m2_tree_sha256:
        raise _refuse("OCI image /opt/m2 differs from canonical transcript")
    return {"authority": dict(authority),
            "inspect": inspected_result.stdout,
            "probe_stdout": probe.stdout, "probe_stderr": probe.stderr,
            "m2_manifest_sha256": image.m2_manifest_sha256,
            "m2_tree_sha256": image.m2_tree_sha256}


def _log_record(path: str, raw: bytes) -> dict:
    _write_new(path, raw)
    return {"path": os.path.basename(path), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def _receipt(document: dict) -> dict:
    result = dict(document)
    result["digest"] = docker_authority.semantic_digest(result)
    return result


def _write_failure(root: str, *, operation: str, project: str,
                   message: str) -> None:
    path = os.path.join(root, "failure.json")
    if os.path.lexists(path):
        return
    value = _receipt({"schema": RECEIPT_SCHEMA, "path": PATH,
                      "operation": operation, "status": "failed",
                      "project": project, "reason": message[:1024]})
    try:
        validate_failure_receipt(value)
        _write_json_no_clobber(path, value)
    except Exception:
        return


def export_archive(authority: Mapping[str, object], *,
                   runner: ArchiveRunner) -> dict:
    """Export and qualify one canonical daemon-local image as OCI USTAR."""
    approved = validate_authority(authority)
    image = canonical_image(approved)
    root = _mkdir_new(approved["export_output"])
    try:
        qualification = qualify_image(runner, image)
        work = os.path.join(root, "work")
        os.mkdir(work, 0o700)
        docker_save = os.path.join(work, "docker-save.tar")
        saved = runner.save(image.config_image_id, target=docker_save)
        if saved.get("returncode") != 0 or saved.get("timed_out") \
                or saved.get("overflowed"):
            raise _refuse("immutable Docker image save failed")
        layout = os.path.join(work, "layout")
        layout_facts = docker_save_to_layout(
            docker_save, layout=layout,
            expected_config_id=image.config_image_id)
        asset_name = approved["distribution"]["asset_name"]
        archive_path = os.path.join(root, asset_name)
        archive_facts = write_oci_archive(layout, archive_path)
        logs = {
            "inspect": _log_record(
                os.path.join(root, "inspect.json"), qualification["inspect"]),
            "qualification_stdout": _log_record(
                os.path.join(root, "qualification.stdout"),
                qualification["probe_stdout"]),
            "qualification_stderr": _log_record(
                os.path.join(root, "qualification.stderr"),
                qualification["probe_stderr"]),
            "save_stderr": _log_record(
                os.path.join(root, "save.stderr"), saved.get("stderr", b"")),
        }
        shutil.rmtree(work)
        identity = implementation_identity()
        receipt = _receipt({
            "schema": RECEIPT_SCHEMA, "path": PATH, "operation": "export",
            "status": "complete", "project": image.project,
            "mode": "oci_archive",
            "canonical_transcript": {
                "path": image.transcript_path,
                "sha256": image.transcript_sha256},
            "authority": qualification["authority"],
            "implementation": identity, "platform": "linux/amd64",
            "canonical_config_image_id":
                layout_facts["canonical_config_image_id"],
            "oci_manifest_digest": layout_facts["oci_manifest_digest"],
            "distribution_object": {
                "path": archive_path, "asset_name": asset_name,
                "storage_namespace":
                    approved["distribution"]["storage_namespace"],
                "bytes": archive_facts["archive_bytes"],
                "sha256": archive_facts["archive_sha256"]},
            "descriptor_closure": {
                "manifest": layout_facts["manifest_descriptor"],
                "config": layout_facts["config_descriptor"],
                "layers": layout_facts["layers"]},
            "logs": logs,
            "authority_digest": approved["digest"],
        })
        validate_export_receipt(receipt)
        _write_json_no_clobber(os.path.join(root, "receipt.json"), receipt)
        return receipt
    except Exception as exc:
        _write_failure(root, operation="export", project=approved["project"],
                       message=str(exc))
        raise


def validate_export_receipt(value: object) -> dict:
    keys = {"schema", "path", "operation", "status", "project", "mode",
            "canonical_transcript", "authority", "implementation", "platform",
            "canonical_config_image_id", "oci_manifest_digest",
            "distribution_object", "descriptor_closure", "logs",
            "authority_digest",
            "digest"}
    doc = _exact(value, keys, "OCI export receipt")
    if doc["schema"] != RECEIPT_SCHEMA or doc["path"] != PATH \
            or doc["operation"] != "export" or doc["status"] != "complete" \
            or doc["project"] not in research.PROJECTS \
            or doc["mode"] != "oci_archive" or doc["platform"] != "linux/amd64":
        raise _refuse("OCI export receipt has another identity")
    transcript = _exact(doc["canonical_transcript"], {"path", "sha256"},
                        "OCI receipt canonical transcript")
    _absolute(transcript["path"], "OCI receipt canonical transcript")
    _sha256(transcript["sha256"], "OCI receipt canonical transcript SHA-256")
    _image_id(doc["canonical_config_image_id"])
    _image_id(doc["oci_manifest_digest"], "OCI receipt manifest digest")
    distribution = _exact(doc["distribution_object"],
                          {"path", "asset_name", "storage_namespace",
                           "bytes", "sha256"},
                          "OCI distribution object")
    _absolute(distribution["path"], "OCI distribution object")
    asset_name = _text(distribution["asset_name"], "OCI asset name")
    if os.path.basename(distribution["path"]) != asset_name:
        raise _refuse("OCI distribution path does not end in its asset name")
    _text(distribution["storage_namespace"], "OCI storage namespace")
    if isinstance(distribution["bytes"], bool) \
            or not isinstance(distribution["bytes"], int) \
            or distribution["bytes"] <= 0:
        raise _refuse("OCI distribution object byte count is invalid")
    _sha256(distribution["sha256"], "OCI archive SHA-256")
    _sha256(doc["authority_digest"], "OCI authority digest")
    closure = _exact(doc["descriptor_closure"],
                     {"manifest", "config", "layers"},
                     "OCI receipt descriptor closure")
    manifest = _descriptor(closure["manifest"], media_type=OCI_MANIFEST,
                           label="OCI receipt manifest descriptor")
    config = _descriptor(closure["config"], media_type=OCI_CONFIG,
                         label="OCI receipt config descriptor")
    if manifest["digest"] != doc["oci_manifest_digest"] \
            or config["digest"] != doc["canonical_config_image_id"] \
            or not isinstance(closure["layers"], list) \
            or not closure["layers"]:
        raise _refuse("OCI receipt descriptor identities differ")
    for index, layer in enumerate(closure["layers"]):
        _descriptor(layer, media_type=OCI_LAYER,
                    label=f"OCI receipt layer {index}")
    if len({layer["digest"] for layer in closure["layers"]}) \
            != len(closure["layers"]):
        raise _refuse("OCI receipt repeats a layer descriptor")
    authority = _exact(doc["authority"],
                       {"reference", "daemon_fingerprint"},
                       "OCI receipt Docker authority")
    try:
        docker_authority._validate_reference(
            authority["reference"], "OCI receipt Docker authority")
    except docker_authority.DockerAuthorityRefused as exc:
        raise _refuse(str(exc).removeprefix("REFUSED: ")) from exc
    _sha256(authority["daemon_fingerprint"],
            "OCI receipt daemon fingerprint")
    implementation = _exact(doc["implementation"],
                            {"commit", "source_sha256"},
                            "OCI receipt implementation")
    if not isinstance(implementation["commit"], str) \
            or re.fullmatch(r"[0-9a-f]{40}", implementation["commit"]) is None:
        raise _refuse("OCI receipt implementation commit is malformed")
    _sha256(implementation["source_sha256"],
            "OCI receipt implementation source SHA-256")
    if not isinstance(doc["logs"], dict) \
            or set(doc["logs"]) != set(_EXPORT_LOG_PATHS):
        raise _refuse("OCI export receipt log set differs")
    for name, value in doc["logs"].items():
        record = _exact(value, {"path", "bytes", "sha256"},
                        f"OCI receipt log {name}")
        if record["path"] != _EXPORT_LOG_PATHS[name]:
            raise _refuse("OCI receipt log path differs")
        if isinstance(record["bytes"], bool) \
                or not isinstance(record["bytes"], int) \
                or record["bytes"] < 0:
            raise _refuse("OCI receipt log byte count is invalid")
        _sha256(record["sha256"], f"OCI receipt log {name} SHA-256")
    if doc["digest"] != docker_authority.semantic_digest(doc):
        raise _refuse("OCI export receipt digest does not rederive")
    return dict(doc)


def validate_failure_receipt(value: object) -> dict:
    doc = _exact(value, {"schema", "path", "operation", "status", "project",
                         "reason", "digest"}, "OCI failure receipt")
    if doc["schema"] != RECEIPT_SCHEMA or doc["path"] != PATH \
            or doc["operation"] != "export" or doc["status"] != "failed" \
            or doc["project"] not in research.PROJECTS \
            or not isinstance(doc["reason"], str) or not doc["reason"] \
            or len(doc["reason"]) > 1024:
        raise _refuse("OCI failure receipt has another identity")
    if doc["digest"] != docker_authority.semantic_digest(doc):
        raise _refuse("OCI failure receipt digest does not rederive")
    return dict(doc)


def _main(argv: Optional[Sequence[str]] = None) -> int:
    from ..bench import result_ledger
    from ..toolkit.epubcheck_image import EPUBCheckImageRefused
    parser = argparse.ArgumentParser(
        prog="python -m r2t.java.research_minimal_oci")
    sub = parser.add_subparsers(dest="command", required=True)
    draft = sub.add_parser("authority-draft")
    draft.add_argument("--fields", required=True)
    draft.add_argument("--out", required=True)
    export = sub.add_parser("export")
    export.add_argument("--authority", required=True)
    export.add_argument("--approved-digest", required=True)
    export.add_argument("--docker-authority", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--archive", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "authority-draft":
            result = write_authority_draft(fields_path=args.fields, out=args.out)
        elif args.command == "export":
            authority = load_authority(
                args.authority, approved_digest=args.approved_digest)
            runner = LiveArchiveRunner(
                docker_authority_path=args.docker_authority,
                scratch_root=authority["export_output"])
            result = export_archive(authority, runner=runner)
        else:
            with tempfile.TemporaryDirectory(prefix="r2t-oci-verify-") as root:
                result = unpack_oci_archive(
                    _absolute(args.archive, "OCI verification archive"),
                    out=os.path.join(root, "layout"))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OCIDistributionRefused, research.MinimalJavaRefused,
            docker_authority.DockerAuthorityRefused,
            result_ledger.ResultLedgerRefused, EPUBCheckImageRefused,
            OSError) as exc:
        message = str(exc)
        if not message.startswith("REFUSED: "):
            message = "REFUSED: " + message
        parser.exit(2, message + "\n")


if __name__ == "__main__":
    raise SystemExit(_main())
