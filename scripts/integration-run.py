#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Released-binary integration: execute examples and deterministic loopback tests.

Missing assets/unsupported prerequisites are BLOCKED and fail the job. No skipped
or compile-only example is counted as a successful end-to-end run.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.util.spec_from_file_location('released_hosts', ROOT/'scripts/released-hosts.py')
hosts = importlib.util.module_from_spec(loader); loader.loader.exec_module(hosts)

def run(argv, cwd, env, timeout=180):
    result = subprocess.run(hosts.command(argv[0], *argv[1:]), cwd=cwd, env=env,
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    if result.returncode:
        raise RuntimeError('command failed ('+str(result.returncode)+'): '+str(argv)+'\n'+result.stdout[-6000:]+result.stderr[-6000:])
    return result.stdout

def export_examples(ref, stage):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./-]*', ref):
        raise ValueError('invalid examples git ref')
    commit = subprocess.check_output(['git', 'rev-parse', '--verify', '--end-of-options', ref+'^{commit}'], cwd=ROOT, text=True).strip()
    data = subprocess.check_output(['git', 'archive', commit], cwd=ROOT)
    stage.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or ':' in member.name or not (member.isfile() or member.isdir()):
                raise ValueError('unsafe source archive entry: '+member.name)
            destination = stage.joinpath(*path.parts)
            if member.isdir(): destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
    (stage/'build').mkdir(exist_ok=True)
    return commit

def deferred_programs(text):
    """Legacy chapter scripts save one program without executing it themselves."""
    code = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*', ' ', text)
    if re.search(r'\bsystem\b', code):
        return []
    declarations = {}
    for variable, header in re.findall(r'\b(\w+)\s*=\s*_(?:lmcode|dsl)_\s+([^;]+);', text):
        cli = re.search(r'\bcli\s*=\s*"([^"]+)"', header)
        if cli: declarations[variable] = cli.group(1).split()
    programs = []
    for variable, filename in re.findall(r'\bsavedsl\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', text):
        if variable not in declarations:
            raise ValueError('cannot identify saved program host: '+variable)
        programs.append((declarations[variable], filename))
    if not programs:
        raise ValueError('example has neither a system execution nor a literal saved program')
    return programs

def execute_example(example, stage, compiler, binaries, env, timeout):
    text = example.read_text(encoding='utf-8')
    started = time.monotonic()
    output = run([compiler, example], stage, env, timeout)
    executed = []
    for cli, filename in deferred_programs(text):
        if cli[0] not in binaries: raise ValueError('uninstalled host: '+cli[0])
        program = (stage/filename).resolve(strict=True)
        if not program.is_relative_to(stage): raise ValueError('program escapes example workspace')
        output += run([binaries[cli[0]], *cli[1:], '--dsl', program], stage, env, timeout)
        executed.append(filename)
    # Host stdout uses a JSON result line, so inspect its decoded strings too.
    evidence = output
    for line in output.splitlines():
        try:
            value=json.loads(line)
            if isinstance(value,dict) and isinstance(value.get('output'),list):
                evidence += '\n'+'\n'.join(str(item) for item in value['output'])
        except (json.JSONDecodeError, TypeError): pass
    expected = re.findall(r'^\s*#\|([^\n]*)', text, re.M)
    missing = [value.strip() for value in expected if value.strip() not in evidence]
    if missing: raise RuntimeError('missing expected execution output: '+repr(missing)+'\n'+output[-3000:])
    return {'status':'PASS', 'seconds':round(time.monotonic()-started, 3), 'deferred_programs_executed':executed,
            'output_tail':output[-1200:]}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lmdebug-tag', default='v0.1.36')
    parser.add_argument('--examples-ref', default='v0.1.36')
    parser.add_argument('--compiler', type=Path, default=Path(shutil.which('lmscript') or 'lmscript'), help='released lmdebug v5 compiler (0.2.426)')
    parser.add_argument('--mock-compiler', type=Path, required=True, help='lmmock v6 installer/compiler (0.2.448)')
    parser.add_argument('--work', type=Path, default=Path('out/integration'))
    parser.add_argument('--report', type=Path, default=Path('out/integration-report.json'))
    parser.add_argument('--summary', type=Path)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--only', help='development-only example substring filter')
    parser.add_argument('--sudo-capture', action='store_true')
    parser.add_argument('--skip-traffic', action='store_true', help='development only; reports BLOCKED, never a green complete run')
    args=parser.parse_args()
    target=hosts.native_platform(); work=args.work.resolve(); report_path=args.report.resolve()
    report={'status':'FAIL','platform':target,'examples':[],'tools':{},'traffic':{'status':'NOT_RUN'}}
    code=1
    try:
        work.mkdir(parents=True, exist_ok=False)
        compiler=args.compiler.resolve(strict=True); mock_compiler=args.mock_compiler.resolve(strict=True)
        env=dict(os.environ, LMSCRIPT_TOOL_CACHE=str(work/'cache'))
        report['compiler']=run([compiler,'--version'], ROOT, env).strip()
        report['mock_compiler']=run([mock_compiler,'--version'],ROOT,env).strip()
        if report['compiler'] != 'lmscript 0.2.426' or report['mock_compiler'] != 'lmscript 0.2.448':
            raise ValueError('released v5/v6 fixtures require lmscript 0.2.426 and 0.2.448 respectively')
        stage=work/'examples'; report['examples_commit']=export_examples(args.examples_ref, stage)
        examples=sorted(p for p in (stage/'examples').rglob('*.lms') if not args.only or args.only in p.relative_to(stage).as_posix())
        if not examples: raise ValueError('no examples selected')
        report['selected_examples']=len(examples); report['development_filter']=args.only
        # Historical public scan example names an implementation-only input
        # file. Supply public test data, not private YARA rule implementation.
        fixture=ROOT/'integration/fixtures/detection-marker.txt'
        target_fixture=stage/'rules/builtin.yar'
        if not target_fixture.exists():
            target_fixture.parent.mkdir(parents=True,exist_ok=True)
            target_fixture.write_bytes(fixture.read_bytes())
            report['fixtures']=[{'source':'integration/fixtures/detection-marker.txt','target':'rules/builtin.yar',
                                 'sha256':hashlib.sha256(fixture.read_bytes()).hexdigest()}]

        lock=json.loads((ROOT/'scripts/integration-hosts.json').read_text()); lock['lmdebug']['tag']=args.lmdebug_tag
        directory=work/'bin'; directory.mkdir(); binaries={}
        needed={'lmdebug','lmconn'}
        for example in examples:
            needed.update(re.findall(r'\bcli\s*=\s*"(\w+)', example.read_text(encoding='utf-8')))
        for name in sorted(needed, key=lambda n: (n!='lmdebug', n)):
            if name not in lock: raise ValueError('unregistered example host: '+name)
            binaries[name], report['tools'][name]=hosts.install(name,lock[name],target,directory)
            report['tools'][name]['version']=run([binaries[name],'--version'],ROOT,env).strip()
            if name=='lmdebug' and report['tools'][name]['version'] != 'lmdebug '+args.lmdebug_tag.lstrip('v'):
                raise ValueError('released lmdebug version does not match requested tag')
        report['capabilities']=json.loads(run([binaries['lmdebug'],'caps'],ROOT,env))
        env['PATH']=str(directory)+os.pathsep+env.get('PATH','')
        binaries['lmmock'],report['tools']['lmmock']=hosts.install_mock(mock_compiler,lock['lmmock'],target,directory,work,env)
        report['tools']['lmmock']['version']=run([binaries['lmmock'],'--version'],ROOT,env).strip()
        for example in examples:
            record={'example':example.relative_to(stage).as_posix()}
            try: record.update(execute_example(example,stage,compiler,binaries,env,args.timeout))
            except Exception as error: record.update(status='FAIL',detail=str(error)[-8000:])
            report['examples'].append(record); print(record['status'],record['example'],flush=True)
        traffic=work/'traffic-report.json'
        if args.skip_traffic:
            report['traffic']={'status':'BLOCKED','reason':'development invocation omitted real traffic'}
        else:
            command=[sys.executable,ROOT/'scripts/traffic-check.py','--lmdebug',binaries['lmdebug'],'--lmmock',binaries['lmmock'],
                     '--lmconn',binaries['lmconn'],'--compiler',mock_compiler,'--lmdebug-compiler',compiler,
                     '--work',work/'traffic','--report',traffic]
            if args.sudo_capture: command.append('--sudo')
            result=subprocess.run(hosts.command(command[0],*command[1:]),env=env,cwd=ROOT,text=True,capture_output=True,timeout=180)
            report['traffic']=json.loads(traffic.read_text()) if traffic.is_file() else {'status':'FAIL','detail':result.stdout+result.stderr}
            if result.returncode and report['traffic']['status']=='PASS': raise RuntimeError('traffic process failed despite PASS report')
        report['status']='PASS' if all(r['status']=='PASS' for r in report['examples']) and report['traffic']['status']=='PASS' else 'FAIL'
        code=0 if report['status']=='PASS' else 1
    except hosts.Unavailable as error:
        report.update(status='BLOCKED',reason=str(error)); code=2
        if not report['examples'] and 'examples' in locals():
            report['examples']=[{'example':p.relative_to(stage).as_posix(),'status':'BLOCKED','detail':str(error)} for p in examples]
    except Exception as error:
        report.update(status='FAIL',reason=str(error)); code=1
    finally:
        counts={s:sum(r['status']==s for r in report['examples']) for s in ('PASS','FAIL','BLOCKED')}
        report['counts']=counts
        report_path.parent.mkdir(parents=True,exist_ok=True); report_path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
        summary='### '+target+': '+report['status']+'\n\n'+str(counts)+'\n\n'+report.get('reason','')+'\n'
        summary += 'Traffic: '+report['traffic']['status']+' '+str(report['traffic'].get('error') or report['traffic'].get('reason') or report['traffic'].get('detail') or '')[-1000:]+'\n'
        for failure in (r for r in report['examples'] if r['status']!='PASS'):
            summary += '- '+failure['example']+': '+failure.get('detail','')[-400:]+'\n'
        if args.summary:
            with args.summary.open('a',encoding='utf-8') as stream: stream.write(summary)
        print(summary)
    return code
if __name__=='__main__': raise SystemExit(main())
