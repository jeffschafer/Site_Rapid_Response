# PHP scanner v3 native Mac test bundle

Prepared locally for the existing temporary test branch. No PR or BIGFIX SOC update.
Tests Intel and Apple Silicon using pinned real affected/patched PHP fixtures, the exact v3 BES payload, helper safety, expected find errors, API-only extensions, Unicode paths, and controlled before/after timing. No Deep scans or full-volume scans.
Python is used only by the CI test driver; endpoint scanning has no Python dependency.
