"""Native Mac payload validation, for a disposable Intel/ARM GitHub runner.

Python is a CI test driver only, never an endpoint scanner dependency. All scans
are confined to private fixtures. The scanner does not execute PHP. There is no
installation, sudo, security-policy change, service operation or BigFix action.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import statistics
import struct
import subprocess
import tarfile
import tempfile
import time
from urllib.request import urlopen
from xml.etree import ElementTree as ET


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle,'sha256').hexdigest()


def run(args, *, cwd=None, timeout=60, allowed=(0,), env=None, log_path=None):
    result=subprocess.run([str(arg) for arg in args],shell=False,cwd=cwd,
                          capture_output=True,timeout=timeout,env=env)
    if log_path:log_path.write_bytes(result.stdout+result.stderr)
    if result.returncode not in allowed:
        raise RuntimeError(str(args[0])+' exit '+str(result.returncode)+'\n'+(result.stdout+result.stderr)[-5000:].decode(errors='replace'))
    return result


def fetch(row, target):
    with urlopen(row['url'], timeout=60) as response, target.open('xb') as handle:
        shutil.copyfileobj(response,handle)
    assert sha(target)==row['sha256'],target.name+' digest mismatch'
    if 'size' in row:assert target.stat().st_size==row['size']


def extract_payloads(candidate, work):
    action=ET.parse(candidate).findtext('.//ActionScript')
    lines=action.splitlines(); index=0; count=0
    while index<len(lines):
        if lines[index].startswith('createfile until '):
            marker=lines[index].split(' ',2)[2]; end=lines.index(marker,index+1)
            source='\n'.join(lines[index+1:end]).replace('{{','{')+'\n'
            name=re.search(r'work"}/([^"/]+)',lines[end+1])[1]
            assert name in ['scan-macos.sh','mac-find.sh','mac-lock.zsh','mac-run-bounded.zsh','php-detect.yar','mac-read-header.sh']
            (work/name).write_text(source,encoding='utf-8',newline='\n')
            count+=1;index=end+1
        else:index+=1
    assert count==6


def check_process_helpers(root,work):
    """Native kernel locks and watchdogs, confined to test-created processes."""
    watch=['/bin/zsh','-f',work/'mac-run-bounded.zsh']
    for code in [0,7]:run([*watch,'2','1','/bin/sh','-c','exit '+str(code)],allowed=(code,))
    pidfile=root/'child.pid'
    child=root/'stubborn.sh'
    child.write_text('trap "" TERM; echo $$ > "$1"; zmodload zsh/zselect; while :; do zselect -t 100; done\n')
    started=time.monotonic()
    run([*watch,'1','1','/bin/zsh','-f',child,pidfile],timeout=5,allowed=(137,))
    assert 1.8 < time.monotonic()-started < 4
    try:os.kill(int(pidfile.read_text()),0)
    except ProcessLookupError:pass
    else:raise AssertionError('Timed out child survived')
    scanner=root/'hold-lock.sh';scanner.write_text('echo $$ > "$1"; exec /bin/sleep "$2"\n')
    args=['/bin/zsh','-f',work/'mac-lock.zsh',root/'test.lock',scanner,root/'owner.pid']
    owner=subprocess.Popen([str(x) for x in [*args,'30']],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if (root/'owner.pid').exists():break
            time.sleep(.01)
        assert (root/'owner.pid').exists()
        run([*args,'0'],allowed=(75,))
    finally:
        if owner.poll() is None:owner.kill()
        owner.communicate(timeout=5)
    run([*args,'0'])
    root.chmod(0o755);run([*args,'0'])
    root.chmod(0o777);run([*args,'0'],allowed=(2,))
    root.chmod(0o700)
    (root/'test.lock').unlink();(root/'test.lock').symlink_to(scanner)
    before=scanner.read_bytes();run([*args,'0'],allowed=(2,));assert scanner.read_bytes()==before


def check_header_worker(root,work):
    """Test the exact embedded client functions with every possible byte value."""
    source=(work/'scan-macos.sh').read_text()
    client='header_pid=\n'+source.split('header_pid=\n',1)[1].split('finished=0 find_pid=',1)[0]
    folder=root/'header-worker-test';folder.mkdir();folder.chmod(0o700)
    shutil.copyfile(work/'mac-read-header.sh',folder/'mac-read-header.sh')
    requests=bytearray()
    for index in range(256):
        data=bytes((index+offset)%256 for offset in range(32))
        file=folder/('case-'+str(index));file.write_bytes(data)
        requests+=os.fsencode(file)+b'\0'+b'32\0'+data[:20].hex().encode()+b'\0'
    (folder/'requests').write_bytes(requests)
    (folder/'link').symlink_to(folder/'case-0')
    script='set -eo pipefail\nexport LC_ALL=C\nwork=$1\n'+client+'''
trap stop_header_worker EXIT
while IFS= read -r -d '' file && IFS= read -r -d '' size && IFS= read -r -d '' expected; do
    read_header "$file" "$size"
    [[ $header = "$expected" ]]
done <"$work/requests"
blocked=$header_pid
kill -STOP "$blocked"
if read_header "$work/case-0" 32; then exit 20; fi
if kill -0 "$blocked" 2>/dev/null; then exit 21; fi
read_header "$work/case-0" 32
if read_header "$work/link" 32; then exit 22; fi
read_header "$work/case-255" 32
last=$header_pid
stop_header_worker
if kill -0 "$last" 2>/dev/null; then exit 23; fi
'''
    (folder/'client.sh').write_text(script)
    run(['/bin/bash',folder/'client.sh',folder],timeout=15)


def check_mount_inventory(root,work,artifacts):
    """Exercise actual Mac root selection without traversing the whole runner."""
    source=(work/'scan-macos.sh').read_text()
    functions=source[source.index('timeout() {'):source.index('package_status() {')]
    folder=root/'mount-probe';folder.mkdir();folder.chmod(0o700)
    script=folder/'probe.sh'
    script.write_text('set -eo pipefail\nexport LC_ALL=C PATH=/usr/bin:/bin:/usr/sbin:/sbin\n'+functions+'''
work=$1; output=$2; include_broader_locations=0; roots=(); reasons=()
mac_roots
printf '%s\\0' "${roots[@]}"
''')
    result=run(['/bin/bash',script,work,folder],timeout=15)
    roots=[os.fsdecode(value) for value in result.stdout.split(b'\0') if value]
    assert roots
    if Path('/System/Volumes/Data').is_dir():
        assert '/System/Volumes/Data' in roots and '/' not in roots,roots
    shutil.copyfile(folder/'scan.log',artifacts/'native-mount-inventory.txt')
    return roots


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--artifacts',type=Path,required=True)
    parser.add_argument('--reuse-fixtures',type=Path)
    args=parser.parse_args()
    assert platform.system()=='Darwin','This test must run on native macOS'
    architecture=platform.machine()
    assert architecture==os.environ['EXPECTED_ARCHITECTURE']
    base=Path(__file__).resolve().parent
    artifacts=args.artifacts.resolve();artifacts.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((base/'manifest.json').read_text())
    assert sha(base/'candidate.bes')==manifest['candidate_sha256']
    assert sha(base/'forum-macos.sh')==manifest['forum_script_sha256']
    root=Path(tempfile.mkdtemp(prefix='php-mac-native-',dir=Path(os.environ['RUNNER_TEMP']).resolve()))
    root.chmod(0o700)
    report={'architecture':architecture,'os':platform.mac_ver()[0],'native_payload_test':True,
            'bigfix_action_test':False,'checks':[],'timings':[],'candidate_sha256':manifest['candidate_sha256']}
    def record(name, **data):
        report['checks'].append({'name':name,**data})
        (artifacts/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(name,flush=True)
    try:
        bash=run(['/bin/bash','--version']).stdout.decode().splitlines()[0]
        assert '3.2.' in bash,bash
        run(['/bin/zsh','-f','-c','zmodload zsh/system; zmodload zsh/stat; zmodload zsh/zselect'])
        work=root/'work';work.mkdir();work.chmod(0o700)
        extract_payloads(base/'candidate.bes',work)
        for script in ['scan-macos.sh','mac-find.sh','mac-read-header.sh']:
            run(['/bin/bash','-n',work/script])
        for script in ['mac-lock.zsh','mac-run-bounded.zsh']:
            run(['/bin/zsh','-fn',work/script])
        record('stock shells, modules and exact packaged payload syntax',bash=bash)
        check_process_helpers(root,work)
        record('native lock, overlap, killed-owner recovery, 0755/0777 permissions, symlink rejection and watchdog')
        check_header_worker(root,work)
        record('native header worker:256 byte cases, timeout recovery, symlink rejection and cleanup')
        record('native local-volume/APFS root selection',roots=check_mount_inventory(root,work,artifacts))
        asset=next(row for row in manifest['engine_assets'] if ('aarch64' in row['name'])==(architecture=='arm64'))
        archive=root/asset['name'];fetch(asset,archive)
        with tarfile.open(archive) as packed:
            entry=packed.getmember('yr');assert entry.isfile() and entry.size<80_000_000
            (work/'yr').write_bytes(packed.extractfile(entry).read())
        (work/'yr').chmod(0o700);assert sha(work/'yr')==asset['engine_sha256']
        record('pinned native YARA-X starts',version=run([work/'yr','--version']).stdout.decode().strip())
        def scan(name,folder,expected,options=()):
            output=root/('output-'+name);output.mkdir();output.chmod(0o700)
            # Match the forum's per-run cached-archive extraction boundary.
            # A prepared-engine-only timing would unfairly favour this draft.
            if (work/'yr').exists():(work/'yr').unlink()
            command=['/bin/zsh','-f',work/'mac-lock.zsh',output/'scan.lock',work/'scan-macos.sh',
                     '--engine',work/'yr','--engine-sha256',asset['engine_sha256'],
                     '--archive',archive,'--archive-sha256',asset['sha256'],
                     '--rules',work/'php-detect.yar','--output',output,'--root',folder,*options]
            started=time.monotonic()
            try:
                result=run(command,timeout=150,allowed=(0,10),log_path=artifacts/(name+'-process.txt'))
            finally:
                # Failure diagnostics must survive the private fixture cleanup.
                for leaf in ['summary.txt','scan.log']:
                    if (output/leaf).is_file():shutil.copyfile(output/leaf,artifacts/(name+'-'+leaf))
            elapsed=time.monotonic()-started
            summary=(output/'summary.txt').read_text();log=(output/'scan.log').read_text()
            shutil.copyfile(output/'summary.txt',artifacts/(name+'-summary.txt'))
            shutil.copyfile(output/'scan.log',artifacts/(name+'-log.txt'))
            state=re.search(r'^DETECTED=(.*)$',summary,re.M)[1]
            assert state==expected,(name,expected,summary,log[-3000:])
            record(name,state=state,exit=result.returncode,seconds=elapsed)
            return summary,elapsed
        smoke=root/'transport-smoke';smoke.mkdir()
        header=struct.pack('<IIIIIIII',0xfeedfacf,0x100000c if architecture=='arm64' else 0x1000007,3,2,0,0,0,0)
        (smoke/'php').write_bytes(header+b'\0'*96+b'X-Powered-By: PHP/8.5.11\0Zend Engine v4.5\0')
        scan('transport-smoke',smoke,'TRUE')
        shutil.rmtree(smoke)
        bins={}
        if args.reuse_fixtures:
            pins=json.loads((base/'fixture-pins.json').read_text())
            assert pins['run_id']==39863269612
            report['fixture_source_run']=pins['run_id']
            for version,files in pins['architectures'][architecture].items():
                bins[version]={}
                for name,digest in files.items():
                    file=args.reuse_fixtures/'fixtures'/version/(name+'.bin')
                    assert file.is_file() and not file.is_symlink() and sha(file)==digest
                    bins[version][name]=file
                record('verified real PHP '+version+' native build reused',files=files)
        else:
            for version,source in manifest['php_sources'].items():
                packed=root/source['filename'];fetch(source,packed)
                with tarfile.open(packed) as bundle:bundle.extractall(root,filter='data')
                project=root/('php-'+version)
                env={**os.environ,'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LC_ALL':'C'}
                result=run(['/bin/sh','./configure','--disable-all','--enable-cli','--enable-cgi','--enable-fpm','--enable-phpdbg','--without-pear'],
                           cwd=project,timeout=300,env=env,log_path=artifacts/('configure-'+version+'.txt'))
                print('Building PHP '+version,flush=True)
                result=run(['/usr/bin/make','-j'+str(min(4,os.cpu_count() or 2))],cwd=project,timeout=1500,env=env,
                           log_path=artifacts/('build-'+version+'.txt'))
                bins[version]={name:project/relative for name,relative in {
                    'php':'sapi/cli/php','php-cgi':'sapi/cgi/php-cgi','php-fpm':'sapi/fpm/php-fpm','phpdbg':'sapi/phpdbg/phpdbg'}.items()}
                for file in bins[version].values():assert file.is_file()
                retained=artifacts/'fixtures'/version;retained.mkdir(parents=True)
                for name,file in bins[version].items():shutil.copyfile(file,retained/(name+'.bin'))
                record('real PHP '+version+' native build',files={name:sha(file) for name,file in bins[version].items()})
        scopes={}
        def scope(name, files):
            folder=root/name;folder.mkdir()
            for relative,source in files.items():
                file=folder/relative;file.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,file)
            scopes[name]=folder
            return folder
        affected=scope('affected',bins['8.5.11'])
        patched=scope('patched',bins['8.5.12'])
        renamed=scope('renamed',{'business-service':bins['8.5.11']['php']})
        unicode=scope('unicode',{'café/php':bins['8.5.11']['php']})
        excluded=scope('excluded',{'data/php':bins['8.5.11']['php'],'data/child/php':bins['8.5.11']['php']})
        for name,folder,state in [('affected',affected,'TRUE'),('patched',patched,'FALSE')]:
            summary,_=scan(name,folder,state)
            if state=='TRUE':
                assert sum(line.startswith('VULNERABLE=') for line in summary.splitlines())==4,summary
        scan('renamed-default',renamed,'FALSE')
        scan('renamed-enabled',renamed,'TRUE',['--include-nonstandard-names','1'])
        summary,_=scan('unicode',unicode,'TRUE');assert 'café/php | PHP 8.5.11' in summary
        encoded='x'+(str(excluded/'data')+'/*').encode().hex()
        scan('tree-exclusion',excluded,'FALSE',['--exclude-directories-hex',encoded])
        encoded='x'+(str(excluded/'data')+'/').encode().hex()
        scan('direct-exclusion',excluded,'TRUE',['--exclude-directories-hex',encoded])
        # A sparse candidate hits the unchanged 512 MiB ceiling without writing
        # 512 MiB of data, and must never become a clean FALSE or failed action.
        limited=scope('limited',{'php':bins['8.5.11']['php']})
        with (limited/'php').open('r+b') as handle:handle.truncate(512*1024*1024)
        scan('size-limit',limited,'UNKNOWN')
        # Controlled corpus: exact original forum Bash script and both new modes.
        # Balanced warm runs; this is not a full-machine scan or BigFix timing.
        corpus=scope('corpus',{'php':bins['8.5.11']['php'],'php-cgi':bins['8.5.12']['php-cgi']})
        for number in range(10000):
            folder=corpus/str(number//250);folder.mkdir(exist_ok=True)
            (folder/('business-'+str(number)+'.bin')).write_bytes(b'not a PHP runtime\0'*8)
        samples={mode:[] for mode in ['forum','default','nonstandard']}
        for iteration in range(3):
            modes=list(samples);modes=modes[iteration:]+modes[:iteration]
            for mode in modes:
                name='speed-'+str(iteration)+'-'+mode
                if mode=='forum':
                    output=root/name
                    started=time.monotonic()
                    result=run(['/bin/bash',base/'forum-macos.sh','-t',corpus,'-o',output,'-a',archive,'-m','512'],
                               timeout=300,allowed=(0,1))
                    elapsed=time.monotonic()-started
                    (artifacts/(name+'-stdout.txt')).write_bytes(result.stdout+result.stderr)
                    rows=[file for file in output.rglob('*.text') if not file.name.endswith('.raw.text')]
                    assert rows and any('8.5.11' in file.read_text() and '8.5.12' in file.read_text() for file in rows)
                else:
                    _,elapsed=scan(name,corpus,'TRUE',['--include-nonstandard-names',str(int(mode=='nonstandard'))])
                samples[mode].append(elapsed)
        report['timings']={mode:{'runs_seconds':values,'median_seconds':statistics.median(values)} for mode,values in samples.items()}
        report['timing_scope']='Cached archive through scan completion; extraction and verification in both. Default policies differ: new CPU target10%, standard names by default, 512MiB both. No full-machine speed claim.'
        record('controlled corpus timing and detection comparison',files=10002)
        report['passed']=True
    except Exception as error:
        report['passed']=False;report['error']=str(error);raise
    finally:
        (artifacts/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        assert root.parent==Path(os.environ['RUNNER_TEMP']).resolve() and root.name.startswith('php-mac-native-') and not root.is_symlink()
        shutil.rmtree(root)


if __name__=='__main__':main()
