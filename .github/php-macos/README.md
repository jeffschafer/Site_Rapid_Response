# Background PHP scanner native Mac tests

Temporary test bundle only. PRs #6/#7 and BIGFIX SOC remain unchanged.

Runs the existing detection and safety checks on disposable Intel and Apple
Silicon Mac runners, then tests background launch, real affected/patched PHP,
overlap protection, heartbeat, another process running during a scan, retained
summary.txt/scan.log after cleanup, worker failure and descendant termination.
No Deep or full-volume scan. Python is only the test driver, never an endpoint
scanner dependency. No services, installations or security-policy changes.
