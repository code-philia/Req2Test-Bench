# Preserved native Then-strip fixture

These source and native event/plan/stdout bytes come from the independently
reviewed synthetic native probe, operator SHA-256
59bba139ecfbff0e8104bcc81b05f444371ba137d888163667bcec8903862ec6,
manifest b002213a262da588fde6e0ec198b144e696ae26cba2cc5e3a0367c24e6781ac5.
The preserved run used Go 1.25.0 and Godog v0.15.1 in image
sha256:3a83a33993d4f63b132831d3ec211182fd29f05151ec23b227abe4c1b29c65c9,
with seam source commit 4b797b425a84912b938b7a5945bd4d5e287d7a72.
Original native statuses: passed, passed, passed, deliberately failed. Stripped
statuses: all four passed. Two Then bodies and three blank imports preserved the
nine import-init/wrapper/hook/Given/helper/When/cleanup markers. No subject source,
benchmark measurement, or provider call was involved.

Self-tests replay these exact records and source edits. Additional local Go
compiler fixtures exercise the production planner; replay is not a new native
framework run. The fixture's helper filenames are synthetic. Adapter composition
tests explicitly rename those paths to the BDD-only answer-path convention.
