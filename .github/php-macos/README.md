# Native PHP Mac tests

This temporary branch tests Mac PHP discovery for CVE-2026-109618 and CVE-2026-109619. It is separate from the released Windows/Linux content and is not a proposed change to that release.

The workflow runs only when the `PHP-macOS-Native-Tests-20261022` branch is updated. Do not merge these test tools into the Rapid Response contribution.

The two disposable GitHub runners use `macos-15-intel` and `macos-15` for Intel and Apple Silicon. The workflow has read-only repository permissions, no persisted checkout credentials and pinned action commits. It installs no packages and uses no secrets, sudo or BigFix credentials. Workflow and artifact actions were resolved from their official repositories on 2026-10-22.

Tests extract the exact Bash/zsh payloads from the candidate BES, use stock Mac tools and the pinned native YARA-X engine, compile official hash-verified PHP 8.5.11 and 8.5.12 in temporary folders, and scan CLI/CGI/FPM/phpdbg files without executing PHP. They cover standard/renamed filenames, Unicode, directory exclusions, the 512 MiB boundary, overlap locks and timeouts. Failure reports and build output are retained for review; only the test's temporary fixture tree is removed.

The controlled speed comparison uses the original forum Mac Bash script and both new name modes against the same corpus. Both sides extract and verify a cached archive on each run. Three runs per mode rotate ordering. The current draft uses its normal CPU target, so the report compares operating policies and overall scan workflows rather than isolating one algorithm. It does not measure a full machine or an installed BigFix action.

Passing these tests would qualify the native payload on those two runner images only. macOS 10.12 Intel, macOS 11 Apple Silicon, TCC/Full Disk Access, other local/remote mounts, the native Console and an installed Mac BESClient still need appropriate endpoint validation. No runner result should be presented as proof of those environments.

Sources: [GitHub runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [YARA-X release](https://github.com/VirusTotal/yara-x/releases/tag/v1.22.0), [PHP security release](https://news-web.php.net/php.announce/513), [original Mac content](https://github.com/bigfix/Site_Rapid_Response/blob/main/Fixlets/Mac/4%20Scan_for_PHP_Installs_with_YARA-X_-_macOS.bes).
