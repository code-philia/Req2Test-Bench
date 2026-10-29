"""THE reviewed Git blob authority: one repository, one commit, one blob.

There is deliberately one implementation of this in the tree.  It is not a
new model; it is the two reviewed ones lifted into a place both callers can
reach:

  * `test_quality.validate_compute_cap_review_authority` supplied the
    repository-relative path grammar, the repository root two directories
    above this package, and the exact `ls-tree -z --full-tree` entry check
    (mode `100644`/`100755`, type `blob`, 40-hex object, exact name); and
  * the C5 provenance reads in `benchmark/scripts/preflight_docx_c5.py`
    supplied the offline invocation controls -- no replacement objects, no
    lazy fetch, no terminal prompt, no optional locks -- and
    `java/j0.py::_closed_process_environment` supplied the rest of them, plus
    the one thing neither resolver had.

THE ONE THING NEITHER HAD.  Both of those callers built Git's environment by
copying the caller's own (`dict(os.environ)`) and overlaying a handful of
`GIT_*` names.  Everything they did not name survived, and several of the
survivors outrank the `-C <repository>` argument outright: `GIT_DIR`,
`GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_INDEX_FILE`,
`GIT_CEILING_DIRECTORIES`, and the `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
`GIT_CONFIG_VALUE_n` triple.  A caller who exported `GIT_DIR` could therefore
answer a question about the reviewed repository out of a repository it
supplied itself -- which is exactly what the pinning is for.  So the
environment here is BUILT from `CLOSED_ENVIRONMENT` rather than inherited:
an unnamed variable is absent, not merely overridden.

THE THING NONE OF THEM PINNED.  Closing the environment removes one channel
and leaves the other open, because `-C <repository>` is where Git STARTS
looking for a repository, not where it stops.  When the named directory is
not itself a repository, Git walks its parents and the first ancestor that
is one answers -- so a `git archive` export, or a copy of this tree placed
inside any other checkout, is read out of that other checkout with nobody
attacking anything, and it fails OPEN, with plausible bytes for a commit
that is not this repository's.  Two things close it here, and both are
repository-derived rather than inherited: every read carries
`GIT_CEILING_DIRECTORIES` set to the repository's PARENT, so the upward walk
considers exactly the named directory; and `require_repository` asks Git
which working tree answered and refuses unless it is that same directory.
The first makes discovery unable to leave, the second asserts where it
landed.

Refusals are raised as `ReviewedGitRefused` carrying a stable `code`.  The
code, not the wording, is the interface: each caller maps it onto its own
already reviewed diagnostic text, so extracting this module changed no
producer's messages.
"""
from __future__ import annotations

import os
import re
import subprocess


#: The reviewed compute-cap path grammar, shared so there is one spelling of
#: it.  983 ASCII characters keeps `path@40hex` within the reviewed 1024.
PATH_MAX_LENGTH = 983
PATH_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._/-]*"
COMMIT_PATTERN = r"[0-9a-f]{40}"
_PATH_RE = re.compile(PATH_PATTERN + r"\Z")
_COMMIT_RE = re.compile(COMMIT_PATTERN + r"\Z")
#: A reviewed blob is a regular file.  A symlink (`120000`), a directory
#: (`040000`), a gitlink/submodule (`160000`) and a non-`blob` object are not
#: substitutes, so the admitted pair is exact.
TREE_MODES = (b"100644", b"100755")
_OBJECT_RE = re.compile(rb"[0-9a-f]{40}\Z")

#: The absolute interpreter the reviewed J0 producer already pins.  Resolving
#: `git` through `PATH` would put the choice of binary back in the caller's
#: hands, which is the same class of hole as `GIT_DIR`.
GIT_EXECUTABLE = "/usr/bin/git"
DEFAULT_TIMEOUT = 30

#: The COMPLETE environment a reviewed read runs under.  Anything not named
#: here is absent from the child, so nothing the caller exported can move the
#: read.  It is deliberately repository-INDEPENDENT: the one name that has to
#: be derived from the repository, `GIT_CEILING_DIRECTORIES`, is added by
#: `closed_environment(repository)` and never inherited.
CLOSED_ENVIRONMENT = {
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_ASKPASS": "/bin/false",
    "GIT_ATTR_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SSH_ASKPASS": "/bin/false",
    "TZ": "UTC",
    "XDG_CONFIG_HOME": "/nonexistent",
}
#: Named for the probes: the environment variables that would redirect a read
#: away from `-C <repository>` if the child inherited them.
REDIRECTING_ENVIRONMENT_NAMES = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "GIT_DIR",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)


class ReviewedGitRefused(RuntimeError):
    """One reviewed-authority refusal, with the code its caller maps."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def repository_root() -> str:
    """The real source-derived repository two directories above this package."""
    return os.path.dirname(os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), os.pardir, os.pardir)))


def validate_path(value: object, *, max_length: int = PATH_MAX_LENGTH) -> str:
    """The reviewed repository-relative POSIX authority path grammar."""
    if not isinstance(value, str) or not value:
        raise ReviewedGitRefused("path", "is not a nonempty string")
    if len(value) > max_length:
        raise ReviewedGitRefused(
            "path", f"exceeds {max_length} ASCII characters")
    if not value.isascii() or _PATH_RE.fullmatch(value) is None:
        raise ReviewedGitRefused(
            "path", "is not the reviewed authority path grammar")
    if any(part in ("", ".", "..") for part in value.split("/")):
        raise ReviewedGitRefused(
            "path", "has an empty, dot, or dot-dot component")
    return value


def validate_commit(value: object) -> str:
    """One full 40-lowercase-hex commit; a ref or abbreviation is not one."""
    if not isinstance(value, str) or _COMMIT_RE.fullmatch(value) is None:
        raise ReviewedGitRefused(
            "commit", "is not one full 40-lowercase-hex commit")
    return value


def repository_ceiling(repository: str) -> str:
    """The one directory Git's upward repository discovery may not leave.

    Git resolves `-C <repository>` by looking for `.git` there and then in
    each parent in turn; with no ceiling the walk runs to `/`.  Naming the
    repository's parent as the ceiling makes the walk consider exactly the
    named directory, so a directory that is not itself a repository produces
    a refusal instead of an ancestor's answer.  Omitting the variable is the
    PERMISSIVE setting, which is why it is set per read rather than left out
    of `CLOSED_ENVIRONMENT`.
    """
    if not isinstance(repository, str) or not os.path.isabs(repository) \
            or repository != os.path.normpath(repository):
        raise ReviewedGitRefused(
            "repository", "is not one normalized absolute directory")
    parent = os.path.dirname(repository)
    if parent == repository:
        raise ReviewedGitRefused(
            "repository", "is the filesystem root, which pins nothing")
    return parent


def closed_environment(repository: str | None = None) -> dict:
    """A fresh copy of the complete environment a reviewed read runs under.

    Without a repository this is the repository-independent set, which is
    what a caller reusing the controls (rather than the reads) wants.  With
    one it also carries that repository's own discovery ceiling.
    """
    environment = dict(CLOSED_ENVIRONMENT)
    if repository is not None:
        environment["GIT_CEILING_DIRECTORIES"] = repository_ceiling(repository)
    return environment


def run(repository: str, arguments: tuple,
        *, timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess:
    """One local Git read, closed against replacement, fetch, config and env.

    The caller inspects `returncode` itself: the two reviewed callers draw
    different diagnostics from a failed `cat-file -t` and a failed `ls-tree`,
    and collapsing them here would have changed one of their messages.
    """
    if not os.path.isfile(GIT_EXECUTABLE):
        raise ReviewedGitRefused(
            "git_exec", f"no Git interpreter at {GIT_EXECUTABLE}")
    environment = closed_environment(repository)
    try:
        return subprocess.run(
            [GIT_EXECUTABLE, "--no-replace-objects", "--no-optional-locks",
             "-c", "credential.helper=",
             "-c", "core.hooksPath=" + os.devnull,
             "-c", "core.fsmonitor=false",
             "-c", "protocol.allow=never",
             "-C", repository, *arguments],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            timeout=timeout, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewedGitRefused("git_exec", str(exc)) from exc


def require_repository(repository: str,
                       *, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Refuse unless the repository that answers IS this exact directory.

    The ceiling in `run` already stops discovery from leaving `repository`;
    this asks Git which working tree it actually resolved and compares it,
    so the invariant is asserted rather than inferred from an environment
    variable's semantics.  Realpath on both sides because the answer comes
    back physical: a symlinked spelling of the same directory is the same
    repository, and a different directory is not.
    """
    toplevel = run(repository, ("rev-parse", "--show-toplevel"),
                   timeout=timeout)
    if toplevel.returncode != 0 or not toplevel.stdout.endswith(b"\n"):
        raise ReviewedGitRefused(
            "repository",
            "is not itself a locally readable Git working tree")
    answered = os.path.realpath(os.fsdecode(toplevel.stdout[:-1]))
    if answered != os.path.realpath(repository):
        raise ReviewedGitRefused(
            "repository",
            f"is answered by the repository at {answered!r} instead")
    return repository


def blob_object(commit: str, path: str, *, repository: str,
                timeout: int = DEFAULT_TIMEOUT) -> str:
    """The one regular-file blob object a commit/path pair selects.

    Refusal codes: `repository` (the answering repository is not the named
    directory), `commit` (the 40-hex object is missing locally or is not a
    commit), `entry` (the path selects no entry, or more than one), `mode`
    (the entry is not a regular-file blob).

    The repository is pinned FIRST, on every read rather than once per
    process: a commit that exists, a path that resolves and bytes that hash
    are all worthless if another repository supplied them.
    """
    require_repository(repository, timeout=timeout)
    commit_type = run(repository, ("cat-file", "-t", commit), timeout=timeout)
    if commit_type.returncode != 0 or commit_type.stdout != b"commit\n":
        raise ReviewedGitRefused(
            "commit", "does not name a locally recoverable full Git commit")
    listing = run(
        repository, ("ls-tree", "-z", "--full-tree", commit, "--", path),
        timeout=timeout)
    records = listing.stdout[:-1].split(b"\0") \
        if listing.returncode == 0 and listing.stdout.endswith(b"\0") else []
    if len(records) != 1 or b"\t" not in records[0]:
        raise ReviewedGitRefused(
            "entry", "selects no single entry in that exact commit")
    metadata, name = records[0].split(b"\t", 1)
    fields = metadata.split()
    if name != path.encode("ascii") or len(fields) != 3 \
            or fields[0] not in TREE_MODES \
            or fields[1] != b"blob" \
            or _OBJECT_RE.fullmatch(fields[2]) is None:
        raise ReviewedGitRefused(
            "mode", "is not one regular-file blob at that exact commit")
    return fields[2].decode("ascii")


def blob_bytes(commit: str, path: str, *, repository: str,
               timeout: int = DEFAULT_TIMEOUT) -> bytes:
    """The exact local bytes of that one reviewed regular-file blob."""
    object_id = blob_object(commit, path, repository=repository,
                            timeout=timeout)
    content = run(repository, ("cat-file", "blob", object_id), timeout=timeout)
    if content.returncode != 0:
        raise ReviewedGitRefused(
            "blob", "names a blob object that is not locally readable")
    return content.stdout
