"""No-dependency regression checks shared with the disposable Mac runner."""
from pathlib import Path


def function(source, name):
    start = source.index(name+"() {")
    return source[start:source.index("\n}\n", start)+3]


def workspace_checks(root, work, run, record, shell="/bin/bash"):
    """Test exact production helpers only within the supplied private fixture."""
    source = (work/"scan-macos.sh").read_text()
    folder = root/"workspace-checks"
    folder.mkdir(mode=0o700)
    output = folder/"YARA_PHP"
    output.mkdir(mode=0o700)
    current = output/"work-1-2-3"
    current.mkdir(mode=0o700)
    removed = output/"work-2-3-4"
    removed.mkdir(mode=0o700)
    (removed/"attempt.started").write_text("PHP_YARA_WORKSPACE_V3\n")
    (removed/"attempt.started").chmod(0o600)
    pending = output/"work-3-4-5"
    pending.mkdir(mode=0o700)
    unsafe = output/"work-4-5-6"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    (unsafe/"attempt.started").write_text("PHP_YARA_WORKSPACE_V3\n")
    (unsafe/"attempt.started").chmod(0o600)
    wrong = output/"work-5-6-7"
    wrong.mkdir(mode=0o700)
    (wrong/"attempt.started").write_text("NOT-A-SCANNER-WORKSPACE\n")
    outside = folder/"outside"
    outside.mkdir(mode=0o700)
    (outside/"keep").write_text("preserve")
    (output/"work-6-7-8").symlink_to(outside, target_is_directory=True)
    script = folder/"cleanup.sh"
    script.write_text("set -eo pipefail\numask 077\nexport LC_ALL=C\noutput=$1;work=$2\n"
                      +function(source,"cleanup_abandoned_work")+"\ncleanup_abandoned_work\n")
    run([shell,script,output,current])
    assert not removed.exists()
    assert all(p.exists() for p in [current,pending,unsafe,wrong,outside/"keep"])
    assert (output/"work-6-7-8").is_symlink()
    assert (current/"attempt.started").read_text()=="PHP_YARA_WORKSPACE_V3\n"
    record("guarded abandoned-work cleanup; pending/unsafe/unmarked/symlink/current paths preserved")
    # Test exact path validator and staging helper with a deliberately low-space
    # df adapter. No disk is filled and no production mount is modified.
    script = folder/"paths.sh"
    script.write_text("set -eo pipefail\numask 077\nexport LC_ALL=C\nwork=$1;deadline=$((SECONDS+10));size=10;read_errors=0;reasons=()\n"
        +function(source,"valid_utf8")+function(source,"scan_list_path_safe")+function(source,"stage_candidate")+r'''
scan_list_path_safe 'café/php'
scan_list_path_safe '/ordinary/php'
if scan_list_path_safe $'bad-\377/php'; then exit 30; fi
if scan_list_path_safe $'tab\tphp'; then exit 31; fi
if scan_list_path_safe $'line\nphp'; then exit 32; fi
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfixture 100 99 1 99%% /\n'; }
path=$work/input;scan_path=$work/copy
printf '1234567890' >"$path"
if stage_candidate; then exit 33; fi
[[ ! -e $scan_path && ${reasons[0]} = 'insufficient free space for unusual-path staging' ]]
df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\nfixture 1000000 0 1000000 0%% /\n'; }
timeout() { shift 2; shift; "$@"; }
stage_candidate
[[ -f $scan_path && $(cat "$scan_path") = 1234567890 ]]
rm -f -- "$scan_path"
# A source that grows after discovery must not consume unbounded disk.
printf '%20000s' oversized >"$path"
if stage_candidate; then exit 34; fi
[[ ! -e $scan_path && $read_errors -gt 0 ]]
''')
    run([shell,script,current])
    record("UTF-8 direct paths; invalid/control paths; low-space guard; growing-copy limit and immediate cleanup")
    package = folder/"package.sh"
    package.write_text("set -eo pipefail\nexport LC_ALL=C\npackage_paths=();package_states=();\n"
        +function(source,"package_status")+r'''
for path in /opt/homebrew/Cellar/php/8.5.11/bin/php /opt/homebrew/Cellar/php@8.3/8.3.20/bin/php /usr/local/Cellar/php/8.5.11/bin/php /opt/local/bin/php83 /opt/local/sbin/php-fpm83 /opt/local/lib/php83/libphp.so; do
    package_status "$path"
    [[ $package_state = upstream ]]
done
for path in /usr/bin/php /System/Library/php; do
    package_status "$path"
    [[ $package_state = vendor ]]
done
''')
    run([shell,package])
    record("Homebrew/MacPorts upstream assessment; Apple vendor qualification preserved")
