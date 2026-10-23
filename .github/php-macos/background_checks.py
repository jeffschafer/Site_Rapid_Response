"""Dependency-free Unix lifecycle checks, also used on disposable Mac runners."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def wait_for(predicate, seconds=35):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=predicate()
        if value: return value
        time.sleep(.1)
    raise AssertionError('Lifecycle check timed out')


def fields(path):
    try: return dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line)
    except FileNotFoundError: return {}


def check(root, sources, engine, bins, platform='Linux', shell='/bin/bash'):
    root.mkdir(mode=0o700)
    results=[]
    engine_hash=hashlib.sha256(engine.read_bytes()).hexdigest()

    def attempt(output, number):
        work=output/('work-'+str(number)+'-2-3')
        work.mkdir(mode=0o700)
        for leaf in ['scan-linux.sh','linux-read-header.sh','scan-macos.sh','mac-lock.zsh','mac-find.sh','mac-read-header.sh','mac-run-bounded.zsh','php-detect.yar','php-header-filter.yar','background-unix.sh']:
            if (sources/leaf).is_file(): shutil.copyfile(sources/leaf,work/leaf)
        shutil.copyfile(engine,work/'yr');(work/'yr').chmod(0o700)
        return work

    def launch(output, work, extra, timeout=35):
        worker=[shell,work/'scan-linux.sh'] if platform=='Linux' else ['/bin/zsh','-f',work/'mac-lock.zsh',output/'scan.lock',work/'scan-macos.sh']
        command=[shell,work/'background-unix.sh','launch',platform,output,work,*worker,
            '--engine',work/'yr','--engine-sha256',engine_hash,'--rules',work/'php-detect.yar','--output',output,
            '--max-file-mb','512','--cpu-limit','10',*extra]
        start=time.monotonic()
        result=subprocess.run([str(value) for value in command],capture_output=True,timeout=timeout)
        return result,time.monotonic()-start

    for version, expected in [('8.5.11','TRUE'),('8.5.12','FALSE')]:
        output=root/('results-'+version);output.mkdir(mode=0o700)
        scope=root/('scope-'+version);scope.mkdir(mode=0o700)
        shutil.copyfile(bins[version],scope/'php')
        work=attempt(output,1)
        result,elapsed=launch(output,work,['--root',str(scope)])
        assert result.returncode==0,(result.returncode,result.stderr)
        wait_for(lambda: fields(output/'scan-state.txt').get('STATE') in ['COMPLETED','PARTIAL','FAILED'])
        state=fields(output/'scan-state.txt');summary=fields(output/'summary.txt')
        assert state['STATE']=='COMPLETED',(state,(output/'scan.log').read_text())
        assert summary['DETECTED']==expected,summary
        wait_for(lambda: not work.exists())
        assert (output/'scan.log').is_file() and (output/'scan-state.txt').is_file() and (output/'summary.txt').is_file()
        results.append({'case':'real-'+version,'detected':expected,'launch_seconds':elapsed,'preserved_results':True})
    output=root/'slow';output.mkdir(mode=0o700)
    work=attempt(output,10)
    old=b'RESULT_FORMAT=2\nDETECTED=TRUE\nLAST_SCAN=prior completed scan\nDURATION=1 second\n'
    (output/'summary.txt').write_bytes(old)
    # A bounded lifecycle fixture deliberately does no discovery.
    script='''#!/bin/bash
set -eu
work=$(cd "$(dirname "$0")" && pwd)
printf 'admitted\n' >"$work/attempt.admitted"
sleep 15
exit 0
'''
    (work/('scan-linux.sh' if platform=='Linux' else 'scan-macos.sh')).write_text(script)
    result,elapsed=launch(output,work,[])
    assert result.returncode==0 and elapsed<8,(elapsed,result.returncode,result.stderr)
    assert fields(output/'scan-state.txt')['STATE']=='RUNNING'
    assert (output/'summary.txt').read_bytes()==old
    assert subprocess.run(['/bin/sh','-c','exit 0'],capture_output=True,timeout=2).returncode==0
    before=fields(output/'scan-state.txt')['UPDATED']
    competing=attempt(output,11)
    result,_=launch(output,competing,[])
    assert result.returncode==75,(result.returncode,result.stderr)
    assert fields(output/'scan-state.txt')['RUN_ID']==work.name and not competing.exists()
    wait_for(lambda: fields(output/'scan-state.txt').get('UPDATED')!=before,20)
    wait_for(lambda: not work.exists(),25)
    assert (output/'summary.txt').read_bytes()==old
    results.append({'case':'overlap-heartbeat-and-independent-process','passed':True,'launch_seconds':elapsed,'summary_unchanged':True})
    work=attempt(output,12)
    (work/('scan-linux.sh' if platform=='Linux' else 'scan-macos.sh')).write_text(script.replace('sleep 15','sleep 1').replace('exit 0','exit 7'))
    result,_=launch(output,work,[])
    assert result.returncode==0,(result.returncode,result.stderr)
    wait_for(lambda: fields(output/'scan-state.txt').get('STATE')=='FAILED')
    wait_for(lambda: not work.exists())
    assert (output/'summary.txt').read_bytes()==old
    results.append({'case':'post-launch-failure-preserves-previous-summary','passed':True})
    work=attempt(output,13)
    crashing='''#!/bin/bash
set -eu
work=$(cd "$(dirname "$0")" && pwd)
sleep 60 &
printf '%s\n' "$!" >"$work/descendant.pid"
printf 'admitted\n' >"$work/attempt.admitted"
sleep 1
kill -KILL $$
'''
    (work/('scan-linux.sh' if platform=='Linux' else 'scan-macos.sh')).write_text(crashing)
    result,_=launch(output,work,[])
    assert result.returncode==0,(result.returncode,result.stderr)
    descendant=int((work/'descendant.pid').read_text())
    wait_for(lambda: fields(output/'scan-state.txt').get('STATE')=='FAILED')
    wait_for(lambda: not work.exists())
    probe=subprocess.run(['/bin/ps','-o','stat=','-p',str(descendant)],capture_output=True,timeout=3)
    assert not probe.stdout.strip() or probe.stdout.strip().startswith(b'Z'),probe.stdout
    assert (output/'summary.txt').read_bytes()==old
    results.append({'case':'killed-worker-descendant-stopped-before-cleanup','passed':True})
    return results

