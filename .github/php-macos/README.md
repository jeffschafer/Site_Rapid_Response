# Native Mac rerun — ready for review

Candidate includes all three approved review corrections where applicable.
Tests run the exact extracted Mac payload with real PHP 8.5.11 and 8.5.12 on
disposable Intel and Apple Silicon runners. Added cases cover oversized data,
the unchanged 512 MiB runtime limit, explicit file-root exclusions and bounded
diagnostics. Python is only a CI test driver, never a scanner dependency.

This branch contains validation tooling only and is not a contribution PR.
Collect both native results before publishing the tested scanner corrections.
Managed BigFix execution and older macOS versions require separate validation.

The existing workflow reuses pinned fixtures from run 39863269612; verify artifact
availability before dispatch. If expired, build them from the pinned source inputs
using the existing harness and remove the reuse-fixtures workflow step.
