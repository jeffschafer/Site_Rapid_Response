# Native Mac validation awaiting upload approval

Tests the exact Mac candidate on disposable Intel and Apple Silicon runners.
Checks real affected/patched PHP, renamed runtimes, all 189 excluded suffixes,
PHP build evidence and the unchanged 512 MiB boundary. Compares speed with the
exact earlier scanner on an identical document corpus at 10% YARA CPU.
No Deep scans. Python drives CI only; endpoints need stock Mac tools.
This bundle is local only. No branch, workflow, review PR or site was updated.
