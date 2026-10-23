# PHP preset validation on Mac

Tests the exact Mac scanner on disposable Intel and Apple Silicon runners with
real affected and patched PHP. Quick, Normal and Deep use their complete preset
values; every mode retains 512 MiB and the 10% YARA CPU setting. Renamed files,
the 512 MiB boundary and the 10-million-file validation ceiling are checked.
Python drives CI only; the scanner uses stock Mac shells and tools.
Managed BigFix Mac execution and older macOS versions require team validation.
