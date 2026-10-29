"""What an image definition and the harness must agree about.

A Dockerfile and the code that execs into it are two files nobody edits in
the same commit.  They share four facts, and every one of them fails QUIETLY
when they drift:

* **where the offline Maven repository is.**  The harness passes
  `-Dmaven.repo.local=/opt/m2` on every invocation
  (`stacks.cucumber.MAVEN_LOCAL_REPO`).  An image that baked its repository
  anywhere else answers `mvn -o` with "The repository system is offline" for
  every item — which the stack classifies as `container_error`, so the run
  is not scored wrong, it is not scored at all, once per item, for as long
  as nobody reads a log.
* **which JDK compiles the submission.**  epubcheck's pom sets
  `<source>/<target>` 1.8 and `ProjectQuirks.jdk_major` records 8.  A
  temurin-11 base still compiles that pom, so the disagreement does not
  announce itself: it changes which `javac` judged the generated test, which
  is the compile gate's entire claim.
* **which base image the allowlist approved.**  `docker build` accepts any
  reference; only a reader notices that the one in the file is not the one
  in `E1_REGISTRY_MAVEN_ALLOWLIST_SPEC.md` §4.2.
* **which plugins the STRIP adds to the pom the image must resolve.**  The
  retained E1 seed tables, completed-census projection and canonical capture
  require the transported `/opt/m2` payload to contain JaCoCo as well as the
  pinned project's closure.  The offline compile and JaCoCo qualification
  probes check that payload before publication.

So this module reads the Dockerfile as bytes and states the disagreements.  It
also closes proposal-only record semantics for the authority-bound D-6 capture
and canonical exact-path/SHA-256 check.  Those validators authenticate no live
fact: the separate stopped producer in `r2t.toolkit.epubcheck_image` must observe and
stable-read/recompute facts under revalidated authority once every live gate
is exact-approved.  There is intentionally no subprocess or CLI build path in
this legacy validator module.  It needs no daemon, image or network, which is
the property that lets it run in `r2t.selftest` beside the harness.

What it deliberately does NOT do is validate Dockerfile syntax or lint the
build.  Docker does that, loudly, at build time.  Everything checked here is
something a successful build would hide.
"""
from __future__ import annotations

import copy
import hashlib
import os
import posixpath
import re
from typing import Iterable, Mapping, Optional

from .. import docker_authority as _AUTHORITY
from ..stacks.cucumber import JACOCO_PLUGIN, MAVEN_LOCAL_REPO, quirks_for


class ImageDisagreement(RuntimeError):
    pass


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The image definitions, one directory per stack.
DOCKER_ROOT = os.path.join(os.path.dirname(HERE), "docker")
EPUBCHECK_DOCKERFILE = os.path.join(DOCKER_ROOT, "epubcheck", "Dockerfile")
ALGORAND_DOCKERFILE = os.path.join(DOCKER_ROOT, "algorand", "Dockerfile")
EPUBCHECK_OFFLINE_SETTINGS = os.path.join(
    DOCKER_ROOT, "epubcheck", "offline-settings.xml")

#: The base reference `E1_REGISTRY_MAVEN_ALLOWLIST_SPEC.md` §4.2 approves for
#: epubcheck, carried here as a constant rather than read out of that file:
#: the allowlist is not in this branch's tree, and a check that silently
#: skipped itself when its authority was missing would be worse than one
#: whose authority is a commit hash a reviewer can resolve.
ALLOWLIST_COMMIT = "fae0502cf68a835cfcd005311e0153bb9e0f5eef"
ALLOWLIST_SHA256 = \
    "50877f10df8e51997dc261502247468fe98422ca735f642fed6364743653943e"
ALLOWLIST_BASE = {
    "epubcheck": "docker.io/library/maven:3.9.6-eclipse-temurin-8",
    "algorand-sdk": "docker.io/library/maven:3.9.6-eclipse-temurin-11",
}

#: The two hosts an image definition may name.  `docker.io` is the registry
#: of §4.1 (`auth.docker.io` and `registry-1.docker.io` are what a pull of a
#: `docker.io/...` reference contacts); `repo.maven.apache.org` is the single
#: repository of §5.  `repo1.maven.org` serves the same bytes and is
#: deliberately NOT an endpoint, which is why this is a list of two rather
#: than a rule about Maven Central.
ALLOWED_HOSTS = ("docker.io", "repo.maven.apache.org")

#: What stands in the digest position until §4.3 closes it.  Not a digest, so
#: the reference is invalid and the build stops; the marker is here so that
#: "no digest yet" is a state this module can recognise rather than one it
#: has to infer from a missing `@`.
DIGEST_PENDING = "DIGEST-PENDING"
CANONICAL_BUILD_REFUSAL = \
    "R2T-CANONICAL-IMAGE-BUILD-REFUSED-PENDING-E1"


def _harness_jacoco_coordinate() -> str:
    """`group:artifact:version`, read out of the harness's own plugin block.

    Parsed rather than restated: `stacks.cucumber.JACOCO_PLUGIN` is the only
    place that decides which coordinate an item's patched pom asks for, and
    a second literal `0.8.11` in this file would be a thing to forget on the
    day somebody bumps the first one.
    """
    fields = [re.search(rf"<{tag}>([^<]+)</{tag}>", JACOCO_PLUGIN)
              for tag in ("groupId", "artifactId", "version")]
    if any(field is None for field in fields):
        raise ImageDisagreement(
            "REFUSED: `stacks.cucumber.JACOCO_PLUGIN` no longer spells a "
            "groupId, an artifactId and a version, so nothing here can say "
            "which coordinate the image is required to bake.")
    return ":".join(field.group(1) for field in fields)


#: The coverage plugin the strip patches into EVERY workspace pom, and thus
#: the one plugin the image must hold that the pinned pom never mentions.
JACOCO_COORDINATE = _harness_jacoco_coordinate()
JACOCO_GROUP_ARTIFACT = JACOCO_COORDINATE.rsplit(":", 1)[0]
JACOCO_VERSION = JACOCO_COORDINATE.rsplit(":", 1)[1]

#: The document that proposes those coordinates.  Its bytes are complete and
#: reviewed, and the owner has now approved its exact commit.  Proposal identity
#: and approval state remain separate constants so the former can never
#: self-approve the latter.
JACOCO_AMENDMENT = "E1_ALLOWLIST_JACOCO_AMENDMENT.md"
JACOCO_AMENDMENT_COMMIT = "2d0a068132e814b638a4c13d700cce351e6da4e2"
JACOCO_AMENDMENT_PROPOSAL_SHA256 = \
    "65520019784f9acd57ef2434badcdb0939f6202f4363e9ec6a6be642d9be3b46"
JACOCO_CENSUS_IDENTITY = \
    "934684b6a43812b44ee5e6d4388448bdee9609276d64c66483f9c5cf4714aa2e"

#: These are source-projected approval slots.  Only the exact JaCoCo decision
#: exists here; every ``None`` remains intentionally closed until a later
#: reviewed source commit carries its corresponding owner decision.  No
#: command-line value can fill a slot, so a well-formed invented digest cannot
#: turn a proposal into execution authority.
APPROVED_BASE_IMAGE_DIGEST: Optional[str] = None
APPROVED_JACOCO_AMENDMENT_SHA256: Optional[str] = \
    "65520019784f9acd57ef2434badcdb0939f6202f4363e9ec6a6be642d9be3b46"
APPROVED_D6_MODIFICATION_IDENTITY: Optional[str] = None
APPROVED_DOCKER_REDIRECT_HOST: Optional[str] = None
APPROVED_DISCOVERY_MAVEN_ARGV: Optional[tuple[str, ...]] = None
APPROVED_COMPLETED_CENSUS_SHA256: Optional[str] = None
APPROVED_CANONICAL_M2_MANIFEST_SHA256: Optional[str] = None
#: The authority-bound controller, transcript validator, and source-only red
#: tests exist in ``r2t.toolkit.epubcheck_image``.  Live image execution does not:
#: the required lossless pull and shared-daemon helper-topology observers are
#: still deliberately unimplemented.  Keep this false independently of every
#: contact/generated-byte approval slot.
IMAGE_BUILD_EXECUTION_IMPLEMENTED = False

#: D-6's exact per-project ceilings.  Decimal "2 GiB" here is the binary GiB
#: used everywhere else in the benchmark's resource envelopes.
DISCOVERY_MAX_FILES = 4096
DISCOVERY_MAX_BYTES = 2 * 1024 * 1024 * 1024
DISCOVERY_REQUIRED_HOSTS = (
    "auth.docker.io",
    "registry-1.docker.io",
    "repo.maven.apache.org",
)
DISCOVERY_FAMILIES = (
    "org.apache.maven.plugins",
    "org.apache.maven",
    "org.apache.maven.shared",
    "org.apache.maven.resolver",
    "org.apache.maven.surefire",
    "org.apache.maven.doxia",
    "org.apache.maven.reporting",
    "org.codehaus.plexus",
    "org.codehaus.mojo",
    "org.sonatype.plexus",
    "org.eclipse.sisu",
    "org.eclipse.aether",
    "org.apache.felix",
    "org.sonatype.central",
    "net.sf.saxon",
)
REFUSED_DISCOVERY_CLASSIFIERS = (
    "sources", "javadoc", "tests", "test-sources",
)
DISCOVERY_CAPTURE_SCHEMA = "r2t.image-discovery-capture/proposal-v1"
CANONICAL_MANIFEST_SCHEMA = "r2t.image-m2-manifest/proposal-v1"

_FROM = re.compile(r"^\s*FROM\s+(?P<ref>\S+)", re.I | re.M)
_REPO_LOCAL = re.compile(r"-Dmaven\.repo\.local=(?P<path>\S+)")
_TEMURIN = re.compile(r"temurin-(?P<major>\d+)\b")
_URL_HOST = re.compile(r"https?://(?P<host>[A-Za-z0-9.\-]+)")
_CLASSIFIER = re.compile(r"-(?:sources|javadoc|tests|test-sources)\b")
#: The same leakage by a name that is not a classifier: a goal or a flag that
#: makes Maven fetch the sources/javadoc artifact of every coordinate it
#: already resolved.  `dependency:sources` puts exactly the bytes
#: `_CLASSIFIER` refuses into `/opt/m2` without the token `-sources` ever
#: appearing in the file.
_CLASSIFIER_FETCH = re.compile(
    r"dependency:(?:sources|resolve-sources)\b|-Ddownload(?:Sources|Javadocs)",
    re.I)
#: A `\` line continuation, which joins one shell command across lines.
_CONTINUATION = re.compile(r"\\[ \t]*\n")
_RUN_PREFIX = re.compile(r"^RUN\s+", re.I)
#: A digest as the only thing that may follow `@`: the pending marker, or an
#: exact sha256.  `@sha256:short` and `@sha512:...` are both refusals.
_DIGEST = re.compile(r"^(?:sha256:[0-9a-f]{64}|"
                     + re.escape(DIGEST_PENDING) + r")$")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DNS_HOST = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_MAVEN_TOKEN = re.compile(r"[A-Za-z0-9_.+\-]+\Z")
_M2_PATH = re.compile(r"[A-Za-z0-9_.+\-/]+\Z")
_MANIFEST_LINE = re.compile(
    r"(?P<sha256>[0-9a-f]{64})  (?P<path>[^\x00\r\n]+)\Z")


def instructions(text: str) -> str:
    """The Dockerfile with comment lines removed.

    Every check below except the digest one reads THIS rather than the file:
    a comment that quotes the harness's `mvn -o -B …` line, or names a host
    in prose, is documentation and not an instruction, and a checker that
    could not tell them apart would make the file's own explanation of
    itself into a failure.
    """
    return "\n".join(line for line in text.split("\n")
                     if not line.lstrip().startswith("#"))


def commands(text: str) -> list[str]:
    """One string per shell command: continuations joined, `RUN` stripped.

    `mvn` reaches a Dockerfile in three shapes that a reader does not
    distinguish and a per-line split does: the FIRST invocation of a chain
    carries the `RUN`, the later ones follow an `&&`, and a `\\` can put the
    goal on a different line from the flags.  A check that only recognised
    the second shape would read `RUN mvn ...` as no invocation at all --
    which is the invocation that populates the repository.
    """
    joined = _CONTINUATION.sub(" ", instructions(text))
    out = []
    for command in re.split(r"&&|\n|;", joined):
        command = command.strip().lstrip("|&").strip()
        out.append(_RUN_PREFIX.sub("", command).strip())
    return out


def stages(text: str) -> list[str]:
    """One string per build stage, in file order, comments already stripped.

    The split matters for the confinement claim: what the FINAL stage copies
    is what the image contains, and a `COPY` in an earlier stage says
    nothing about it.
    """
    body = instructions(text)
    cuts = [m.start() for m in _FROM.finditer(body)]
    return [body[start:end] for start, end
            in zip(cuts, cuts[1:] + [len(body)])]


def base_findings(text: str, *, project: str = "epubcheck",
                  expected_base: str | None = None) -> list[str]:
    """Base identity and JDK findings shared by Java image definitions."""
    body = instructions(text)
    refs = [m.group("ref") for m in _FROM.finditer(body)]
    found = []
    if len(set(refs)) != 1:
        return [f"base_reference: the FROM lines name {sorted(set(refs))}, "
                f"and every stage of one image must be built on the same "
                f"base -- a resolve stage on another JDK resolves another "
                f"closure."]
    reference, _, digest = refs[0].partition("@")
    expected = expected_base or ALLOWLIST_BASE[project]
    if reference != expected:
        found.append(
            f"base_reference: the Dockerfile is FROM {reference!r} and the "
            f"allowlist (commit {ALLOWLIST_COMMIT[:8]}, sha256 "
            f"{ALLOWLIST_SHA256[:8]}) approves {expected!r}. A base outside "
            f"the allowlist is a refusal, never a widening.")
    if not _DIGEST.match(digest):
        found.append(
            f"base_digest: the base is pinned as {digest!r}. It must be an "
            f"exact `sha256:` of 64 hex digits once the allowlist's staged "
            f"resolution has closed it, and until then the literal "
            f"{DIGEST_PENDING} marker -- a tag is not "
            f"an identity and a build that pulls one is unrepeatable.")
    major = _TEMURIN.search(reference)
    wanted = quirks_for(project).jdk_major
    if major is None:
        found.append(
            f"jdk_major: {reference!r} does not name a temurin JDK major, so "
            f"nothing in this file states which javac the compile gate runs.")
    elif int(major.group("major")) != wanted:
        found.append(
            f"jdk_major: the base carries JDK {major.group('major')} and "
            f"`stacks.cucumber.quirks_for({project!r}).jdk_major` is "
            f"{wanted}. This disagreement changes which compiler judged "
            f"the submission without necessarily failing the build.")
    return found


def _repository_findings(text: str) -> list[str]:
    body = instructions(text)
    found = []
    paths = {m.group("path") for m in _REPO_LOCAL.finditer(body)}
    if not paths:
        found.append(
            f"maven_repo_local: no `-Dmaven.repo.local=` appears, so the "
            f"build resolves into Maven's default `~/.m2/repository` and the "
            f"image has no {MAVEN_LOCAL_REPO} for the harness to run "
            f"against.")
    for path in sorted(paths - {MAVEN_LOCAL_REPO}):
        found.append(
            f"maven_repo_local: the Dockerfile bakes {path!r} and the "
            f"harness passes `-Dmaven.repo.local={MAVEN_LOCAL_REPO}` on every "
            f"invocation (`stacks.cucumber.MAVEN_LOCAL_REPO`). Every item "
            f"would fail offline resolution and be charged to the container.")
    for command in commands(text):
        if command.startswith("mvn ") and "-Dmaven.repo.local=" not in command:
            found.append(
                f"mvn_invocation: `{' '.join(command.split()[:4])} ...` "
                f"carries no `-Dmaven.repo.local=`, so it resolves somewhere "
                f"the image does not keep.")
    settings = re.search(r"<localRepository>(?P<path>[^<]*)</localRepository>",
                         body)
    if settings is None or settings.group("path") != MAVEN_LOCAL_REPO:
        found.append(
            f"settings_offline: the baked settings.xml does not set "
            f"<localRepository>{MAVEN_LOCAL_REPO}</localRepository>, so a "
            f"container started by hand resolves differently from one the "
            f"worker plan started.")
    if "<offline>true</offline>" not in body:
        found.append(
            "settings_offline: the baked settings.xml does not set "
            "<offline>true</offline>. The harness passes `-o` itself, but a "
            "step definition that shells out to `mvn` inherits the "
            "settings, and on a no-egress network its download is a timeout "
            "rather than a refusal.")
    return found


def _confinement_findings(text: str) -> list[str]:
    body = instructions(text)
    found = []
    workdirs = re.findall(r"^\s*WORKDIR\s+(\S+)", stages(text)[-1], re.I | re.M)
    if not workdirs:
        found.append(
            "workspace_confinement: the final stage sets no WORKDIR, so "
            "where the workspace is bind-mounted is a property of whoever "
            "runs the container.")
    else:
        workspace = workdirs[-1].rstrip("/") + "/"
        if MAVEN_LOCAL_REPO.startswith(workspace):
            found.append(
                f"workspace_confinement: {MAVEN_LOCAL_REPO} is INSIDE the "
                f"workspace {workdirs[-1]!r}, so the agent's tree contains "
                f"the offline repository -- the seed confinement "
                f"`J0_MAVEN_ANSWER_SOURCE_DECISION.md` makes a gate.")
    copied = re.findall(r"^\s*COPY\s+(?P<rest>.+)$", stages(text)[-1],
                        re.I | re.M)
    for line in copied:
        parts = line.split()
        # Flags may precede the operands in any order and any number
        # (`COPY --chown=root:root --from=resolve …`), so `--from=` is
        # looked for among ALL of them rather than at parts[0]: a `--chown`
        # in front of it would otherwise make a stage copy read as a copy
        # from the build context.
        flags = [part for part in parts if part.startswith("--")]
        operands = [part for part in parts if not part.startswith("--")]
        if not any(flag.startswith("--from=") for flag in flags):
            found.append(
                f"final_stage_contents: the final stage copies `{line}` "
                f"from the build CONTEXT, which is the pinned checkout: its "
                f"retained step definitions and feature files are the answer "
                f"surface the strip removes, and an image carrying them "
                f"answers the item it is scoring.")
            continue
        sources, destination = operands[:-1], operands[-1]
        if sources != [MAVEN_LOCAL_REPO]:
            found.append(
                f"final_stage_contents: the final stage copies "
                f"{sources} out of an earlier stage and the only path "
                f"that may cross that boundary is {MAVEN_LOCAL_REPO}.")
        # The DESTINATION, which is the half that decides what the image
        # actually holds.  `COPY --from=resolve /opt/m2 /opt/m2-extra` copies
        # the right bytes to the wrong path: nothing about the source says
        # so, `mvn -o -Dmaven.repo.local=/opt/m2` finds an empty directory,
        # and every item is a `container_error`.  A trailing slash names the
        # same directory to Docker and is not a finding.
        if destination.rstrip("/") != MAVEN_LOCAL_REPO:
            found.append(
                f"final_stage_contents: the final stage lands the repository "
                f"at {destination!r} and the harness resolves against "
                f"`-Dmaven.repo.local={MAVEN_LOCAL_REPO}` on every "
                f"invocation. The bytes are right and the path is not, which "
                f"is offline-resolution failure once per item.")
    if _CLASSIFIER.search(body):
        found.append(
            "classifier: a `-sources`/`-javadoc`/`-tests` classifier is "
            "named. The allowlist refuses every one of them for every "
            "coordinate: python-docx's sdist proved a language package can "
            "be an answer source, and a sources JAR inside the image is "
            "exactly that shape.")
    if _CLASSIFIER_FETCH.search(body):
        found.append(
            "classifier: a goal or flag that FETCHES the sources/javadoc "
            "artifact of an already-resolved coordinate is named. It writes "
            "the same bytes into the repository as a `-sources` coordinate "
            "would, without the token appearing anywhere, and §8.2 refuses "
            "them 'on any coordinate, including the new families'.")
    hosts = {m.group("host") for m in _URL_HOST.finditer(body)}
    hosts |= {ref.split("/")[0] for ref in
              (m.group("ref") for m in _FROM.finditer(body))
              if "." in ref.split("/")[0]}
    for host in sorted(hosts - set(ALLOWED_HOSTS)):
        found.append(
            f"host: {host!r} is named, and the allowlist's closed vocabulary "
            f"is {list(ALLOWED_HOSTS)}. Anything else is a refusal, never a "
            f"widening -- including `repo1.maven.org`, which serves Central's "
            f"bytes under a name nobody approved.")
    return found


def _coverage_findings(text: str) -> list[str]:
    """The plugin the pinned pom does not declare and every item resolves.

    This is the one check whose absence costs EVERY item rather than the
    coverage ones.  `strip_repo_cucumber` patches `JACOCO_PLUGIN` into the
    workspace pom once, unconditionally; Maven resolves a declared plugin's
    realm before instantiating any mojo of it; and `-Djacoco.skip=true` is
    read inside the mojo, so it skips the goal and not the resolution.  An
    image resolved from the UNPATCHED pom therefore answers `mvn -o` with
    "could not be resolved" for every item on the plan.  That exact real
    wording is now an error marker, so the loss is the `container_error` it
    always was; every item is still excluded until the image is complete.
    """
    body = instructions(text)
    found = []
    versions = set(re.findall(
        re.escape(JACOCO_GROUP_ARTIFACT) + r":([0-9A-Za-z._\-]+)", body))
    if not versions:
        found.append(
            f"jacoco_closure: no instruction resolves "
            f"{JACOCO_GROUP_ARTIFACT}, so the image's {MAVEN_LOCAL_REPO} "
            f"holds no jacoco. `stacks.cucumber` patches it into EVERY "
            f"workspace pom at strip time and Maven resolves a declared "
            f"plugin's realm before any mojo of it runs, so "
            f"`-Djacoco.skip=true` -- which skips the GOAL -- does not save "
            f"the non-coverage items either: offline resolution fails once "
            f"per item, for every item on the plan. Maven's real lower-case "
            f"wording is now in `CUCUMBER_ERROR_MARKERS`, so it is excluded "
            f"as `container_error` rather than charged to the submission.")
    for version in sorted(versions - {JACOCO_VERSION}):
        found.append(
            f"jacoco_closure: the Dockerfile resolves "
            f"{JACOCO_GROUP_ARTIFACT}:{version} and "
            f"`stacks.cucumber.JACOCO_PLUGIN` puts "
            f"{JACOCO_GROUP_ARTIFACT}:{JACOCO_VERSION} in the pom. A realm "
            f"baked at one version is not the realm the patched pom asks "
            f"for, and the item's symptom is again offline resolution "
            f"rather than a version warning.")
    # Read on the RAW text, comments included, and deliberately: the citation
    # is not an instruction, it records the exact approved amendment admitting
    # these bytes, and a jacoco coordinate cannot enter this Dockerfile without
    # naming it.
    if versions and JACOCO_AMENDMENT not in text:
        found.append(
            f"jacoco_amendment: a jacoco coordinate is resolved and this "
            f"file does not name {JACOCO_AMENDMENT}. The approved allowlist "
            f"(commit {ALLOWLIST_COMMIT[:8]}, sha256 {ALLOWLIST_SHA256[:8]}) "
            f"names no jacoco anywhere -- not in its census and not in its "
            f"discovery-build families, which is why even the discovery "
            f"build stops on one -- so the exact approved amendment is the "
            f"only thing admitting these bytes and the file has to say which "
            f"document does so.")
    return found


def _execution_gate_findings(text: str) -> list[str]:
    """Keep the proposal Dockerfile inert while its owner inputs are absent."""
    body = instructions(text)
    expected = f"sh -c 'exit 64' {CANONICAL_BUILD_REFUSAL}"
    gate_commands = [command for command in commands(text)
                     if CANONICAL_BUILD_REFUSAL in command]
    run_payloads = [" ".join(match.group(1).split()) for match in
                    re.finditer(r"^\s*RUN\s+([^\n]+)$", body, re.I | re.M)]
    has_shell_instruction = re.search(
        r"^\s*SHELL(?:\s|$)", body, re.I | re.M) is not None
    canonical_gate_open = (
        not IMAGE_BUILD_EXECUTION_IMPLEMENTED
        or APPROVED_BASE_IMAGE_DIGEST is None
        or APPROVED_JACOCO_AMENDMENT_SHA256 is None
        or APPROVED_COMPLETED_CENSUS_SHA256 is None
        or APPROVED_CANONICAL_M2_MANIFEST_SHA256 is None)
    if canonical_gate_open and (
            gate_commands != [expected] or not run_payloads
            or run_payloads[0] != expected or has_shell_instruction):
        return [
            "execution_gate: image approvals/manifest are still open, but "
            "the Dockerfile's first RUN is not the one exact exit-64 "
            "pending-E1 command, or a SHELL instruction can reinterpret it."]
    return []


def _lean_definition_findings(text: str) -> list[str]:
    """Require the producer's one pending payload-only source shape."""
    from .epubcheck_image import canonical_definition_for_reference

    reference = ALLOWLIST_BASE["epubcheck"] + "@" + DIGEST_PENDING
    expected = canonical_definition_for_reference(reference)
    if text.encode("utf-8") != expected:
        return [
            "canonical_shape: the committed Dockerfile differs from the "
            "producer's two-FROM payload-only pending definition"]
    return []


def offline_settings_findings(raw: bytes) -> list[str]:
    """Require the exact settings bytes the canonical producer pins."""
    from .epubcheck_image import OFFLINE_SETTINGS_SHA256

    if not isinstance(raw, bytes) \
            or hashlib.sha256(raw).hexdigest() != OFFLINE_SETTINGS_SHA256:
        return [
            "offline_settings: committed settings differ from the exact "
            "offline/local-/opt/m2 bytes the producer pins"]
    return []


def disagreements(text: str) -> list[str]:
    """Every source-shape disagreement in the pending canonical image."""
    return base_findings(text) + _lean_definition_findings(text)


def verify(text: str, settings: Optional[bytes] = None) -> None:
    """Raise naming ALL of them, or return.

    All rather than the first: these are facts about one file that a human
    is about to edit, and stopping at the first one turns a single reading
    into as many rounds as there are mistakes.
    """
    if settings is None:
        with open(EPUBCHECK_OFFLINE_SETTINGS, "rb") as handle:
            settings = handle.read()
    found = disagreements(text) + offline_settings_findings(settings)
    if found:
        raise ImageDisagreement(
            "REFUSED: the image definition and the harness disagree.\n  - "
            + "\n  - ".join(found))


def read(path: str = EPUBCHECK_DOCKERFILE) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def read_settings(path: str = EPUBCHECK_OFFLINE_SETTINGS) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _proposal_refuse(message: str) -> ImageDisagreement:
    return ImageDisagreement("REFUSED: " + message)


def _exact_object(value: object, fields: Iterable[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise _proposal_refuse(f"{label} is not an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        raise _proposal_refuse(
            f"{label} fields differ; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _proposal_refuse(f"{label} is not one lower-case full SHA-256")
    return value


def _relative_m2_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") \
            or _M2_PATH.fullmatch(value) is None \
            or "\x00" in value or "\r" in value or "\n" in value:
        raise _proposal_refuse(f"{label} is not a nonempty relative path")
    normal = posixpath.normpath(value)
    if normal != value or value == "." or value.startswith("../") \
            or "//" in value:
        raise _proposal_refuse(f"{label} is not a normalized relative path")
    return value


def authority_build_binding(document: object, reference: object) -> dict:
    """Project exact rootless endpoint/client facts out of one authority.

    This is deliberately a projection, not a selector.  A build request gets
    one authority reference and these facts are derived from its authenticated
    document; it never gets independent ``--docker-host`` or ``--docker-cli``
    overrides that could disagree with the artifact.  The function performs no
    Docker contact.  ``authority_build_binding_from_path`` additionally joins
    the reference to the file bytes, still offline.
    """
    try:
        authority = _AUTHORITY.validate_authority_document(
            document, current_source=False)
    except _AUTHORITY.DockerAuthorityRefused as exc:
        raise _proposal_refuse(
            f"image-build Docker authority is ineligible: {exc}") from exc
    ref = _exact_object(reference, ("path", "file_sha256", "digest"),
                        "image-build authority reference")
    try:
        path = _AUTHORITY.canonical_absolute_path(
            ref["path"], "image-build authority reference path")
    except _AUTHORITY.DockerAuthorityRefused as exc:
        raise _proposal_refuse(str(exc)) from exc
    file_sha256 = _sha256(ref["file_sha256"],
                          "image-build authority file SHA-256")
    digest = _sha256(ref["digest"], "image-build authority semantic digest")
    if digest != authority["digest"]:
        raise _proposal_refuse(
            "image-build authority reference does not name the supplied "
            "authority semantic digest")
    endpoint = authority["endpoint"]
    client = authority["client"]
    adapter = authority["adapter"]
    return {
        "schema": "r2t.image-build-authority-binding/proposal-v1",
        "authority": {
            "path": path,
            "file_sha256": file_sha256,
            "digest": digest,
        },
        "endpoint": {
            "address": endpoint["address"],
            "address_sha256": endpoint["address_sha256"],
            "selected_socket_path": adapter["selected_socket_path"],
            "resolved_socket_path": adapter["resolved_socket_path"],
        },
        "client": {
            "selected_executable": client["selected_executable"],
            "resolved_executable": client["resolved_executable"],
            "executable_sha256": client["executable_sha256"],
        },
    }


def authority_build_binding_from_path(path: str) -> dict:
    """Read and authenticate an authority artifact without live revalidation."""
    try:
        document, reference = _AUTHORITY.authority_reference(path, live=False)
    except _AUTHORITY.DockerAuthorityRefused as exc:
        raise _proposal_refuse(
            f"image-build Docker authority cannot be loaded: {exc}") from exc
    return authority_build_binding(document, reference)


def image_build_gate_findings(*, mode: str, base_digest: Optional[str],
                              jacoco_amendment_sha256: Optional[str]) -> list[str]:
    """Name every owner-controlled input still closed for an image path.

    The approved values are source constants, not caller-supplied expected
    values.  Consequently a caller cannot make an invented but well-formed
    digest pass.  This branch intentionally returns findings for both modes.
    """
    found = []
    if mode not in {"discovery", "canonical"}:
        return ["mode: image build mode must be `discovery` or `canonical`"]
    if not IMAGE_BUILD_EXECUTION_IMPLEMENTED:
        found.append(
            "implementation: controller source exists, but live image "
            "execution and its required lossless observers are not implemented")
    if not isinstance(base_digest, str) \
            or re.fullmatch(r"sha256:[0-9a-f]{64}", base_digest) is None:
        found.append("base_digest: no full lower-case sha256 base digest was "
                     "supplied")
    if APPROVED_BASE_IMAGE_DIGEST is None:
        found.append("base_approval: the owner-approved base-image digest is "
                     "still absent")
    elif base_digest != APPROVED_BASE_IMAGE_DIGEST:
        found.append("base_approval: the supplied base digest is not the "
                     "owner-approved digest")

    if jacoco_amendment_sha256 != JACOCO_AMENDMENT_PROPOSAL_SHA256:
        found.append("jacoco_identity: the supplied JaCoCo amendment digest "
                     "does not name the reviewed proposal bytes")
    if APPROVED_JACOCO_AMENDMENT_SHA256 is None:
        found.append("jacoco_approval: no exact owner-approved JaCoCo "
                     "amendment digest is recorded in source")
    elif jacoco_amendment_sha256 != APPROVED_JACOCO_AMENDMENT_SHA256:
        found.append("jacoco_approval: the supplied JaCoCo amendment is not "
                     "the owner-approved amendment")

    if mode == "discovery":
        if APPROVED_D6_MODIFICATION_IDENTITY is None:
            found.append("d6_approval: D-6 is a modification request refused "
                         "by default and has no exact approval identity")
        if APPROVED_DOCKER_REDIRECT_HOST is None:
            found.append("redirect_host: R-1's Docker blob-redirect host is "
                         "still open")
        if APPROVED_DISCOVERY_MAVEN_ARGV is None:
            found.append("discovery_argv: no exact approved transformation "
                         "of the offline J0 `mvn test` argv exists; the four "
                         "Dockerfile Maven invocations cannot substitute")
    else:
        if APPROVED_COMPLETED_CENSUS_SHA256 is None:
            found.append("completed_census: discovery has produced no "
                         "owner-approved completed plugin/provider census")
        if APPROVED_CANONICAL_M2_MANIFEST_SHA256 is None:
            found.append("canonical_manifest: no approved exact EPUBCheck "
                         "/opt/m2 path-and-SHA-256 manifest exists")
    return found


def require_image_build_gate(*, mode: str, base_digest: Optional[str],
                             jacoco_amendment_sha256: Optional[str]) -> None:
    found = image_build_gate_findings(
        mode=mode, base_digest=base_digest,
        jacoco_amendment_sha256=jacoco_amendment_sha256)
    if found:
        raise _proposal_refuse(
            "image-build authority is closed.\n  - " + "\n  - ".join(found))


def _family_group(group_id: str) -> bool:
    # E1 §8.2 writes each row as one exact Maven ``groupId:*`` family.  It
    # names ``org.apache.maven`` and several of its sub-groups separately;
    # interpreting a row as a dotted-prefix rule would make those rows
    # redundant and silently admit e.g. ``org.apache.maven.unreviewed``.
    return group_id in DISCOVERY_FAMILIES


def _coordinate_id(group_id: str, artifact_id: str, version: str,
                   classifier: Optional[str]) -> str:
    return ":".join((group_id, artifact_id, version, classifier or "-"))


def _coordinate_payload_path(coordinate: Mapping[str, object],
                             extension: str) -> str:
    classifier = coordinate["classifier"]
    filename = (f"{coordinate['artifact_id']}-{coordinate['version']}"
                + (f"-{classifier}" if classifier is not None else "")
                + extension)
    return "/".join((str(coordinate["group_id"]).replace(".", "/"),
                     str(coordinate["artifact_id"]),
                     str(coordinate["version"]), filename))


def validate_discovery_capture_proposal(
        value: object, *, authority_binding: Mapping[str, object],
        approved_redirect_host: str,
        approved_coordinates: Iterable[str],
        approved_maven_argv: Iterable[str]) -> dict:
    """Validate one *proposal* D-6 capture without authorizing a build.

    The caller-supplied redirect, coordinate set and argv are test-vector
    inputs, not live authority.  The executable wrapper remains absent and the
    public build gate above remains closed.  This closes the proposed wire
    semantics so a later owner decision cannot be implemented by silently
    widening a host, family, classifier, command, or ceiling.

    Passing this function proves only that the supplied record is internally
    well-formed.  It does not authenticate that a host was contacted, a file
    existed, a byte count was complete, or an image was discarded.  The later
    authority-bound producer must observe those facts itself, stable-read every
    file, recompute size/SHA-256, detect replacement during capture, and bind
    the resulting record to the revalidated authority.  Self-report from a
    caller is never execution evidence.
    """
    doc = _exact_object(value, (
        "schema", "project", "attempt", "authority_binding",
        "permitted_hosts", "observed_hosts", "maven_argvs",
        "resolution_logging", "coordinates", "files", "limits", "image"),
        "discovery capture")
    if doc["schema"] != DISCOVERY_CAPTURE_SCHEMA \
            or doc["project"] != "epubcheck" or doc["attempt"] != 1:
        raise _proposal_refuse(
            "discovery capture is not EPUBCheck's one admitted attempt")
    if not isinstance(authority_binding, Mapping) \
            or doc["authority_binding"] != dict(authority_binding):
        raise _proposal_refuse(
            "discovery capture does not bind the exact authority-derived "
            "endpoint and client")

    if not isinstance(approved_redirect_host, str) \
            or _DNS_HOST.fullmatch(approved_redirect_host) is None \
            or approved_redirect_host.lower() != approved_redirect_host \
            or approved_redirect_host in DISCOVERY_REQUIRED_HOSTS \
            or approved_redirect_host == "repo1.maven.org":
        raise _proposal_refuse(
            "approved R-1 redirect is not one distinct exact DNS host; "
            "repo1.maven.org is explicitly forbidden")
    allowed = tuple(sorted((*DISCOVERY_REQUIRED_HOSTS,
                            approved_redirect_host)))
    if doc["permitted_hosts"] != list(allowed):
        raise _proposal_refuse(
            "discovery permitted_hosts differs from the exact approved set")
    observed = doc["observed_hosts"]
    if not isinstance(observed, list) or not observed \
            or any(not isinstance(host, str) for host in observed) \
            or len(observed) != len(set(observed)) \
            or any(host not in allowed for host in observed):
        raise _proposal_refuse(
            "discovery observed_hosts is empty, duplicated, or outside the "
            "approved set")

    try:
        argv = tuple(approved_maven_argv)
    except TypeError as exc:
        raise _proposal_refuse(
            "approved discovery Maven argv is not iterable") from exc
    if not argv or any(not isinstance(part, str) or not part or "\x00" in part
                       for part in argv):
        raise _proposal_refuse("approved discovery Maven argv is invalid")
    if doc["maven_argvs"] != [list(argv)]:
        raise _proposal_refuse(
            "discovery must run exactly one approved D-6 Maven argv")
    lowered_argv = tuple(part.lower() for part in argv)
    logging_suppressed = any(
        part in {"--offline", "-o", "--no-transfer-progress", "-ntp",
                 "--quiet", "-q", "--log-file", "-l"}
        or part.startswith("--log-file=")
        or (part.startswith("-l") and part != "-l")
        or part.startswith("-dorg.slf4j.simplelogger")
        for part in lowered_argv)
    if argv[0] != "mvn" or argv[-1] != "test" or logging_suppressed:
        raise _proposal_refuse(
            "approved discovery argv is not an online, resolution-logging "
            "`mvn test` shape")
    if doc["resolution_logging"] is not True:
        raise _proposal_refuse("discovery resolution logging is not true")

    limits = _exact_object(doc["limits"], ("max_files", "max_bytes"),
                           "discovery limits")
    if limits != {"max_files": DISCOVERY_MAX_FILES,
                  "max_bytes": DISCOVERY_MAX_BYTES}:
        raise _proposal_refuse(
            "discovery limits differ from D-6's 4096-file/2-GiB ceiling")

    coordinates = doc["coordinates"]
    if not isinstance(coordinates, list) or not coordinates:
        raise _proposal_refuse("discovery coordinates is empty/not a list")
    try:
        approved_input = list(approved_coordinates)
    except TypeError as exc:
        raise _proposal_refuse(
            "approved coordinate set is not iterable") from exc
    if any(not isinstance(identity, str) or not identity
           for identity in approved_input) \
            or len(approved_input) != len(set(approved_input)):
        raise _proposal_refuse(
            "approved coordinate set is invalid or duplicated")
    approved = set(approved_input)
    by_id = {}
    for index, item in enumerate(coordinates):
        coordinate = _exact_object(item, (
            "id", "group_id", "artifact_id", "version", "classifier",
            "admission", "parent"), f"discovery coordinate {index}")
        group_id = coordinate["group_id"]
        artifact_id = coordinate["artifact_id"]
        version = coordinate["version"]
        classifier = coordinate["classifier"]
        if any(not isinstance(token, str)
               or _MAVEN_TOKEN.fullmatch(token) is None
               for token in (group_id, artifact_id, version)):
            raise _proposal_refuse(
                f"discovery coordinate {index} has an invalid Maven token")
        if classifier is not None and (
                not isinstance(classifier, str)
                or _MAVEN_TOKEN.fullmatch(classifier) is None):
            raise _proposal_refuse(
                f"discovery coordinate {index} has an invalid classifier")
        if classifier is not None \
                and classifier.lower() in REFUSED_DISCOVERY_CLASSIFIERS:
            raise _proposal_refuse(
                f"discovery coordinate {index} uses refused classifier "
                f"{classifier!r}")
        if "SNAPSHOT" in version.upper():
            raise _proposal_refuse(
                f"discovery coordinate {index} is a snapshot")
        identity = _coordinate_id(group_id, artifact_id, version, classifier)
        if coordinate["id"] != identity or identity in by_id:
            raise _proposal_refuse(
                f"discovery coordinate {index} identity is noncanonical or "
                "duplicated")
        admission = coordinate["admission"]
        parent = coordinate["parent"]
        if admission == "approved":
            if identity not in approved or parent is not None:
                raise _proposal_refuse(
                    f"discovery coordinate {identity} falsely claims an "
                    "approved-row admission")
        elif admission == "family":
            if not _family_group(group_id) or parent is not None:
                raise _proposal_refuse(
                    f"discovery coordinate {identity} is outside the named "
                    "D-6 families")
        elif admission == "transitive":
            if not isinstance(parent, str) or not parent or parent == identity:
                raise _proposal_refuse(
                    f"discovery coordinate {identity} has no transitive "
                    "parent")
        else:
            raise _proposal_refuse(
                f"discovery coordinate {identity} has unknown admission")
        by_id[identity] = coordinate

    state = {}

    def reaches_admitted_root(identity: str) -> bool:
        if state.get(identity) == "done":
            return True
        if state.get(identity) == "visiting" or identity not in by_id:
            return False
        state[identity] = "visiting"
        coordinate = by_id[identity]
        if coordinate["admission"] in {"approved", "family"}:
            answer = True
        else:
            answer = reaches_admitted_root(coordinate["parent"])
        state[identity] = "done" if answer else "failed"
        return answer

    if any(not reaches_admitted_root(identity) for identity in by_id):
        raise _proposal_refuse(
            "discovery transitive graph is cyclic, missing a parent, or not "
            "rooted in an approved row/named family")

    files = doc["files"]
    if not isinstance(files, list) or not files \
            or len(files) > DISCOVERY_MAX_FILES:
        raise _proposal_refuse(
            "discovery file capture is empty or exceeds D-6's 4096-file "
            "ceiling")
    paths = set()
    payload_coordinates = set()
    total_bytes = 0
    for index, item in enumerate(files):
        record = _exact_object(item, ("path", "sha256", "size", "coordinate"),
                               f"discovery file {index}")
        path = _relative_m2_path(record["path"],
                                 f"discovery file {index}.path")
        if path in paths:
            raise _proposal_refuse(f"discovery file path repeats: {path}")
        paths.add(path)
        _sha256(record["sha256"], f"discovery file {index}.sha256")
        size = record["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise _proposal_refuse(
                f"discovery file {index}.size is not a nonnegative integer")
        total_bytes += size
        if total_bytes > DISCOVERY_MAX_BYTES:
            raise _proposal_refuse(
                "discovery file capture exceeds D-6's 2-GiB ceiling")
        if "SNAPSHOT" in path.upper():
            raise _proposal_refuse(f"discovery file is a snapshot path: {path}")
        coordinate_id = record["coordinate"]
        is_payload = path.endswith((".jar", ".pom"))
        if coordinate_id is not None and coordinate_id not in by_id:
            raise _proposal_refuse(
                f"discovery file {path} names an unknown coordinate")
        if is_payload and coordinate_id is None:
            raise _proposal_refuse(
                f"discovery payload {path} has no admitted coordinate")
        if is_payload:
            expected_path = _coordinate_payload_path(
                by_id[coordinate_id], ".jar" if path.endswith(".jar")
                else ".pom")
            if path != expected_path:
                raise _proposal_refuse(
                    f"discovery payload {path} does not match coordinate "
                    f"{coordinate_id}")
            payload_coordinates.add(coordinate_id)
    if set(by_id) - payload_coordinates:
        raise _proposal_refuse(
            "discovery coordinate graph contains a coordinate with no "
            "captured JAR/POM payload")

    image = _exact_object(doc["image"], (
        "image_id", "tagged", "reusable", "discarded"), "discovery image")
    if not isinstance(image["image_id"], str) \
            or _IMAGE_ID.fullmatch(image["image_id"]) is None \
            or image["tagged"] is not False \
            or image["reusable"] is not False \
            or image["discarded"] is not True:
        raise _proposal_refuse(
            "discovery image is not recorded as untagged, nonreusable, and "
            "discarded")
    return doc


def parse_canonical_m2_manifest(raw: bytes | str) -> dict[str, str]:
    """Parse the proposed exact final ``/opt/m2`` path/SHA-256 format."""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _proposal_refuse("canonical Maven manifest is not UTF-8") \
                from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise _proposal_refuse("canonical Maven manifest is not bytes/text")
    if not text.endswith("\n") or "\r" in text:
        raise _proposal_refuse(
            "canonical Maven manifest must end in one LF-only record")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != CANONICAL_MANIFEST_SCHEMA:
        raise _proposal_refuse(
            "canonical Maven manifest has the wrong schema header")
    if len(lines) == 1:
        raise _proposal_refuse("canonical Maven manifest contains no files")
    entries = {}
    ordered = []
    for index, line in enumerate(lines[1:], 1):
        match = _MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise _proposal_refuse(
                f"canonical Maven manifest line {index + 1} is malformed")
        path = _relative_m2_path(match.group("path"),
                                 f"canonical manifest line {index + 1}.path")
        if not path.endswith((".jar", ".pom")):
            raise _proposal_refuse(
                f"canonical manifest path is not a JAR/POM payload: {path}")
        if "SNAPSHOT" in path.upper() or re.search(
                r"-(?:sources|javadoc|tests|test-sources)\.(?:jar|pom)\Z",
                path, re.I):
            raise _proposal_refuse(
                f"canonical manifest contains a refused payload: {path}")
        if path in entries:
            raise _proposal_refuse(
                f"canonical Maven manifest repeats path {path}")
        entries[path] = match.group("sha256")
        ordered.append(path)
    if ordered != sorted(ordered):
        raise _proposal_refuse(
            "canonical Maven manifest paths are not bytewise sorted")
    return entries


def validate_canonical_repository_capture_proposal(
        manifest_raw: bytes | str, files: object, *,
        approved_manifest_sha256: str) -> dict[str, str]:
    """Require a supplied final-repository record to equal one exact set.

    This is structural proposal validation, not a filesystem witness.  A later
    authority-bound producer must enumerate the final image itself, reject
    symlinks/non-regular entries, stable-read and hash each file, and re-read
    the image/authority identities around capture before this record can be
    evidence.
    """
    expected_digest = _sha256(
        approved_manifest_sha256, "approved canonical manifest SHA-256")
    encoded = manifest_raw if isinstance(manifest_raw, bytes) \
        else manifest_raw.encode("utf-8") if isinstance(manifest_raw, str) \
        else b""
    if hashlib.sha256(encoded).hexdigest() != expected_digest:
        raise _proposal_refuse(
            "canonical Maven manifest bytes do not match the approved digest")
    expected = parse_canonical_m2_manifest(manifest_raw)
    if not isinstance(files, list):
        raise _proposal_refuse("canonical repository capture is not a list")
    actual = {}
    for index, item in enumerate(files):
        record = _exact_object(item, (
            "path", "sha256", "size", "kind", "mode"),
            f"canonical repository file {index}")
        path = _relative_m2_path(record["path"],
                                 f"canonical repository file {index}.path")
        if path in actual:
            raise _proposal_refuse(
                f"canonical repository repeats path {path}")
        digest = _sha256(record["sha256"],
                         f"canonical repository file {index}.sha256")
        size = record["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 \
                or record["kind"] != "regular" or record["mode"] != "0644":
            raise _proposal_refuse(
                f"canonical repository file {path} is not a normalized "
                "regular file")
        actual[path] = digest
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    mismatched = sorted(path for path in set(expected) & set(actual)
                        if expected[path] != actual[path])
    if missing or extra or mismatched:
        raise _proposal_refuse(
            "canonical repository differs from the exact approved set; "
            f"missing={missing}, extra={extra}, sha256_mismatch={mismatched}")
    return expected


def verify_authorized_canonical_repository(
        manifest_raw: bytes | str, files: object) -> dict[str, str]:
    """Production-facing gate; deliberately closed pending owner approval."""
    if APPROVED_CANONICAL_M2_MANIFEST_SHA256 is None:
        raise _proposal_refuse(
            "no owner-approved canonical Maven manifest digest is recorded")
    return validate_canonical_repository_capture_proposal(
        manifest_raw, files,
        approved_manifest_sha256=APPROVED_CANONICAL_M2_MANIFEST_SHA256)


def selftest() -> int:
    failures = []

    def check(name, condition, detail=""):
        print(f"  [{'PASS' if condition else 'FAIL'}] {name}"
              + (f"  ({detail})" if detail and not condition else ""))
        if not condition:
            failures.append(name)

    def refused(fn) -> bool:
        try:
            fn()
        except ImageDisagreement:
            return True
        return False

    real = read()

    def mutant(old, new):
        # EVERY occurrence, and the comments are why: this file explains its
        # own base reference in prose above the `FROM` that carries it, so a
        # first-occurrence edit lands in the explanation and leaves the
        # instruction — and the check — untouched.  Each `old` below is
        # therefore either instruction-only or wanted everywhere.
        assert old in real, old
        return real.replace(old, new)

    def codes(text):
        return sorted({finding.split(":", 1)[0]
                       for finding in disagreements(text)})

    # ------------------------------------------------- the committed file
    settings = read_settings()
    check("the committed Dockerfile is the producer's one lean pending "
          "payload-only definition",
          disagreements(real) == [], "\n".join(disagreements(real)))
    check("...and the source verifier joins the exact offline settings",
          verify(real, settings) is None)
    check("the pending digest is literal in both equal FROM references, "
          "with no caller-overridable ARG and no RUN instruction",
          instructions(real).count("@" + DIGEST_PENDING) == 2
          and "ARG " not in instructions(real)
          and "RUN " not in instructions(real))
    check("the payload stage receives only approved-m2 and the final stage "
          "receives only that repository plus offline settings",
          "COPY approved-m2/ /opt/m2/" in real
          and "COPY --from=payloads /opt/m2/ /opt/m2/" in real
          and "COPY offline-settings.xml /root/.m2/settings.xml" in real
          and "pom.xml" not in real and "COPY src" not in real)
    check("the fixed runtime posture is part of the exact source shape",
          "ENV LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC" in real
          and "WORKDIR /work" in real
          and "ENTRYPOINT []" in real
          and 'CMD ["tail","-f","/dev/null"]' in real)

    # A handful of source mutations exercise the contract without
    # re-implementing Dockerfile parsing beside the producer.
    check("a tag-only base cannot replace the pending digest",
          "base_digest" in codes(mutant("@" + DIGEST_PENDING, "")))
    check("a different JDK/base is rejected",
          {"base_reference", "jdk_major"} <=
          set(codes(mutant("temurin-8", "temurin-11"))))
    algorand = read(ALGORAND_DOCKERFILE)
    algorand_codes = {
        finding.split(":", 1)[0]
        for finding in base_findings(algorand, project="algorand-sdk")}
    wrong_algorand_codes = {
        finding.split(":", 1)[0]
        for finding in base_findings(
            algorand.replace("temurin-11", "temurin-8"),
            project="algorand-sdk")}
    check("the Algorand definition agrees on its allowlisted JDK 11 base "
          "and remains closed only on the pending digest",
          algorand_codes == {"base_digest"}
          and {"base_reference", "base_digest", "jdk_major"}
          <= wrong_algorand_codes
          and base_findings(
              algorand.replace("${BASE_DIGEST}", DIGEST_PENDING),
              project="algorand-sdk") == [])
    check("a syntactically plausible invented digest does not self-approve",
          "canonical_shape" in codes(
              mutant(DIGEST_PENDING, "sha256:" + "0" * 64)))
    check("source, an extra final-stage path, or an online RUN cannot enter "
          "the lean definition",
          all("canonical_shape" in codes(real + addition) for addition in (
              "COPY src/ /work/src/\n",
              "RUN mvn dependency:go-offline\n",
              "COPY --from=payloads /opt/m2/ /opt/m2-extra/\n")))
    check("the exact offline settings bytes are accepted and a one-byte "
          "change is rejected",
          offline_settings_findings(settings) == []
          and offline_settings_findings(settings + b"\n"))

    # ------------------------------------- the still-closed build boundary
    # The exact JaCoCo approval is now projected into source.  It clears only
    # its own finding; implementation and every unrelated owner input remain
    # closed.
    discovery_gate = image_build_gate_findings(
        mode="discovery", base_digest="sha256:" + "0" * 64,
        jacoco_amendment_sha256=JACOCO_AMENDMENT_PROPOSAL_SHA256)
    discovery_gate_codes = {
        finding.split(":", 1)[0] for finding in discovery_gate}
    canonical_gate = image_build_gate_findings(
        mode="canonical", base_digest="sha256:" + "0" * 64,
        jacoco_amendment_sha256=JACOCO_AMENDMENT_PROPOSAL_SHA256)
    canonical_gate_codes = {
        finding.split(":", 1)[0] for finding in canonical_gate}
    check("the exact approved amendment digest clears only the discovery "
          "JaCoCo finding",
          discovery_gate_codes == {
              "implementation", "base_approval", "d6_approval",
              "redirect_host", "discovery_argv"},
          str(sorted(discovery_gate_codes)))
    check("the exact approved amendment digest clears only the canonical "
          "JaCoCo finding",
          canonical_gate_codes == {
              "implementation", "base_approval", "completed_census",
              "canonical_manifest"},
          str(sorted(canonical_gate_codes)))
    wrong_jacoco_gate = image_build_gate_findings(
        mode="discovery", base_digest="sha256:" + "0" * 64,
        jacoco_amendment_sha256="0" * 64)
    wrong_jacoco_gate_codes = {
        finding.split(":", 1)[0] for finding in wrong_jacoco_gate}
    check("a wrong JaCoCo digest fails both proposal identity and exact "
          "approval",
          {"jacoco_identity", "jacoco_approval"}.issubset(
              wrong_jacoco_gate_codes),
          str(sorted(wrong_jacoco_gate_codes)))
    check("a wrong JaCoCo digest is refused by the production-facing gate",
          refused(lambda: require_image_build_gate(
              mode="discovery", base_digest="sha256:" + "0" * 64,
              jacoco_amendment_sha256="0" * 64)))
    check("recording JaCoCo approval leaves live implementation and every "
          "unrelated source gate closed",
          APPROVED_BASE_IMAGE_DIGEST is None
          and APPROVED_D6_MODIFICATION_IDENTITY is None
          and APPROVED_DOCKER_REDIRECT_HOST is None
          and APPROVED_DISCOVERY_MAVEN_ARGV is None
          and APPROVED_COMPLETED_CENSUS_SHA256 is None
          and APPROVED_CANONICAL_M2_MANIFEST_SHA256 is None
          and not IMAGE_BUILD_EXECUTION_IMPLEMENTED)
    check("the exact approved JaCoCo digest does not open the production-facing "
          "build gate",
          refused(lambda: require_image_build_gate(
              mode="discovery", base_digest="sha256:" + "0" * 64,
              jacoco_amendment_sha256=JACOCO_AMENDMENT_PROPOSAL_SHA256)))

    authority_document = _AUTHORITY._fixture_authority()
    authority_reference = {
        "path": "/private/authority.json",
        "file_sha256": "a" * 64,
        "digest": authority_document["digest"],
    }
    binding = authority_build_binding(authority_document, authority_reference)
    check("one authority reference derives the exact rootless endpoint and "
          "client; neither is an independent build input",
          binding["authority"] == authority_reference
          and binding["endpoint"]["address"]
          == authority_document["endpoint"]["address"]
          and binding["client"]["selected_executable"]
          == authority_document["client"]["selected_executable"]
          and binding["client"]["executable_sha256"]
          == authority_document["client"]["executable_sha256"])
    check("an authority reference/document digest mismatch is refused",
          refused(lambda: authority_build_binding(
              authority_document,
              {**authority_reference, "digest": "0" * 64})))

    # ----------------------------------------- D-6 capture proposal vectors
    approved_argv = (
        "mvn", "-B", "-Dmaven.repo.local=/opt/m2",
        "-DreuseForks=false", "test")
    approved_redirect_host = "approved-cdn.example.net"
    approved_hosts = tuple(sorted((*DISCOVERY_REQUIRED_HOSTS,
                                   approved_redirect_host)))
    approved_coordinate = "com.example:base:1:-"
    family_coordinate = "org.apache.maven.plugins:maven-x:1:-"
    transitive_coordinate = "org.example.transitive:helper:2:-"
    discovery = {
        "schema": DISCOVERY_CAPTURE_SCHEMA,
        "project": "epubcheck",
        "attempt": 1,
        "authority_binding": binding,
        "permitted_hosts": list(approved_hosts),
        "observed_hosts": ["repo.maven.apache.org"],
        "maven_argvs": [list(approved_argv)],
        "resolution_logging": True,
        "coordinates": [
            {"id": approved_coordinate, "group_id": "com.example",
             "artifact_id": "base", "version": "1", "classifier": None,
             "admission": "approved", "parent": None},
            {"id": family_coordinate,
             "group_id": "org.apache.maven.plugins",
             "artifact_id": "maven-x", "version": "1",
             "classifier": None, "admission": "family", "parent": None},
            {"id": transitive_coordinate,
             "group_id": "org.example.transitive",
             "artifact_id": "helper", "version": "2",
             "classifier": None, "admission": "transitive",
             "parent": family_coordinate},
        ],
        "files": [
            {"path": "com/example/base/1/base-1.jar", "sha256": "1" * 64,
             "size": 10, "coordinate": approved_coordinate},
            {"path": "org/apache/maven/plugins/maven-x/1/maven-x-1.jar",
             "sha256": "2" * 64, "size": 20,
             "coordinate": family_coordinate},
            {"path": "org/example/transitive/helper/2/helper-2.pom",
             "sha256": "3" * 64, "size": 30,
             "coordinate": transitive_coordinate},
        ],
        "limits": {"max_files": DISCOVERY_MAX_FILES,
                   "max_bytes": DISCOVERY_MAX_BYTES},
        "image": {"image_id": "sha256:" + "4" * 64, "tagged": False,
                  "reusable": False, "discarded": True},
    }

    def discovery_refused(mutator) -> bool:
        candidate = copy.deepcopy(discovery)
        mutator(candidate)
        return refused(lambda: validate_discovery_capture_proposal(
            candidate, authority_binding=binding,
            approved_redirect_host=approved_redirect_host,
            approved_coordinates=(approved_coordinate,),
            approved_maven_argv=approved_argv))

    check("the proposal capture admits an approved row, a named D-6 family, "
          "and a structurally rooted transitive dependency",
          validate_discovery_capture_proposal(
              discovery, authority_binding=binding,
              approved_redirect_host=approved_redirect_host,
              approved_coordinates=(approved_coordinate,),
              approved_maven_argv=approved_argv) is discovery)
    check("a host outside the exact E1-plus-R-1 set is refused",
          discovery_refused(lambda candidate: candidate["observed_hosts"]
                            .append("repo1.maven.org")))
    forbidden_redirect = copy.deepcopy(discovery)
    forbidden_redirect["permitted_hosts"] = list(sorted(
        (*DISCOVERY_REQUIRED_HOSTS, "repo1.maven.org")))
    check("the R-1 slot cannot be filled with explicitly forbidden "
          "repo1.maven.org",
          refused(lambda: validate_discovery_capture_proposal(
              forbidden_redirect, authority_binding=binding,
              approved_redirect_host="repo1.maven.org",
              approved_coordinates=(approved_coordinate,),
              approved_maven_argv=approved_argv)))
    check("a second Maven invocation silently broadens D-6 and is refused",
          discovery_refused(lambda candidate: candidate["maven_argvs"]
                            .append(list(approved_argv))))
    quiet_discovery = copy.deepcopy(discovery)
    quiet_discovery["maven_argvs"] = [["mvn", "-q", "test"]]
    check("a quiet Maven argv cannot contradict the claimed resolution log",
          refused(lambda: validate_discovery_capture_proposal(
              quiet_discovery, authority_binding=binding,
              approved_redirect_host=approved_redirect_host,
              approved_coordinates=(approved_coordinate,),
              approved_maven_argv=("mvn", "-q", "test"))))
    redirected_log_discovery = copy.deepcopy(discovery)
    redirected_log_discovery["maven_argvs"] = [
        ["mvn", "--log-file=hidden.log", "test"]]
    check("redirecting Maven's log cannot satisfy the capture's logging bit",
          refused(lambda: validate_discovery_capture_proposal(
              redirected_log_discovery, authority_binding=binding,
              approved_redirect_host=approved_redirect_host,
              approved_coordinates=(approved_coordinate,),
              approved_maven_argv=(
                  "mvn", "--log-file=hidden.log", "test"))))

    def outside_family(candidate):
        coordinate = candidate["coordinates"][1]
        coordinate["group_id"] = "org.unlisted"
        coordinate["id"] = "org.unlisted:maven-x:1:-"

    check("a direct coordinate outside both approved rows and named families "
          "is refused",
          discovery_refused(outside_family))

    def prefixed_but_unlisted_family(candidate):
        coordinate = candidate["coordinates"][1]
        coordinate["group_id"] = "org.apache.maven.unreviewed"
        coordinate["id"] = "org.apache.maven.unreviewed:maven-x:1:-"

    check("a dotted subgroup of a named D-6 family is not that exact groupId",
          discovery_refused(prefixed_but_unlisted_family))

    def sources_classifier(candidate):
        coordinate = candidate["coordinates"][1]
        coordinate["classifier"] = "sources"
        coordinate["id"] = "org.apache.maven.plugins:maven-x:1:sources"

    check("D-6 does not waive the sources/javadoc/tests classifier refusal",
          discovery_refused(sources_classifier))

    def snapshot(candidate):
        coordinate = candidate["coordinates"][1]
        coordinate["version"] = "1-SNAPSHOT"
        coordinate["id"] = (
            "org.apache.maven.plugins:maven-x:1-SNAPSHOT:-")

    check("D-6 admits no snapshot",
          discovery_refused(snapshot))
    check("the 4,096-file ceiling is enforced before duplicate/path details",
          discovery_refused(lambda candidate: candidate.__setitem__(
              "files", [candidate["files"][0]] * (DISCOVERY_MAX_FILES + 1))))
    check("the 2-GiB ceiling is enforced over captured file sizes",
          discovery_refused(lambda candidate: candidate["files"][0]
                            .__setitem__("size", DISCOVERY_MAX_BYTES + 1)))
    check("discovery evidence is inadmissible until its image is discarded",
          discovery_refused(lambda candidate: candidate["image"]
                            .__setitem__("discarded", False)))
    check("the capture cannot substitute an endpoint/client binding beside "
          "the authority reference",
          discovery_refused(lambda candidate: candidate["authority_binding"]
                            ["client"].__setitem__(
                                "selected_executable", "/tmp/docker")))

    # ---------------------------------- canonical exact-set proposal vectors
    manifest = (
        CANONICAL_MANIFEST_SCHEMA + "\n"
        + "5" * 64 + "  com/example/a/1/a-1.jar\n"
        + "6" * 64 + "  com/example/a/1/a-1.pom\n")
    manifest_sha256 = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    canonical_files = [
        {"path": "com/example/a/1/a-1.jar", "sha256": "5" * 64,
         "size": 100, "kind": "regular", "mode": "0644"},
        {"path": "com/example/a/1/a-1.pom", "sha256": "6" * 64,
         "size": 50, "kind": "regular", "mode": "0644"},
    ]
    check("canonical repository acceptance is exact path-set plus SHA-256",
          validate_canonical_repository_capture_proposal(
              manifest, canonical_files,
              approved_manifest_sha256=manifest_sha256)
          == {"com/example/a/1/a-1.jar": "5" * 64,
              "com/example/a/1/a-1.pom": "6" * 64})
    check("one extra Maven metadata/sidecar file prevents final acceptance",
          refused(lambda: validate_canonical_repository_capture_proposal(
              manifest,
              canonical_files + [{"path": "com/example/a/1/_remote.repositories",
                                  "sha256": "7" * 64, "size": 1,
                                  "kind": "regular", "mode": "0644"}],
              approved_manifest_sha256=manifest_sha256)))
    check("a missing approved path prevents final acceptance",
          refused(lambda: validate_canonical_repository_capture_proposal(
              manifest, canonical_files[:1],
              approved_manifest_sha256=manifest_sha256)))
    check("a byte mismatch at the right path prevents final acceptance",
          refused(lambda: validate_canonical_repository_capture_proposal(
              manifest,
              [{**canonical_files[0], "sha256": "8" * 64},
               canonical_files[1]],
              approved_manifest_sha256=manifest_sha256)))
    check("a caller cannot bless arbitrary manifest bytes with their own "
          "digest through the production-facing gate",
          refused(lambda: verify_authorized_canonical_repository(
              manifest, canonical_files)))

    print()
    if failures:
        print(f"FAILED: {len(failures)}")
        return 1
    print("images: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(selftest())
