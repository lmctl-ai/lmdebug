#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path); module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
hosts=load('hosts','scripts/released-hosts.py'); integration=load('integration','scripts/integration-run.py'); traffic=load('traffic','scripts/traffic-check.py')
def fixture_plan(ref, stage, target):
    return {'examples':{p.relative_to(stage).as_posix():{'platforms':[target]} for p in (stage/'examples').rglob('*.lms')},
            'helper_overlays':[]}, 'fixture-sha'
class IntegrationContracts(unittest.TestCase):
    def test_all_five_native_assets_and_missing_mac_fail_closed(self):
        for target in ('linux-x64','linux-arm64','macos-x64','macos-arm64','windows-x64'):
            suffix='.exe' if target.startswith('windows') else ''
            metadata={'tag_name':'v1.0.0','assets':[{'name':'lmdebug-'+target+suffix}]}
            self.assertEqual(hosts.select_asset(metadata,'lmdebug',target),metadata['assets'][0])
        with self.assertRaisesRegex(hosts.Unavailable,'macos-arm64'):
            hosts.select_asset({'tag_name':'v0.1.36','assets':[]},'lmdebug','macos-arm64')
    def test_windows_npm_compiler_uses_command_wrapper(self):
        with patch.object(hosts.os,'name','nt'):
            # Patch Path too: a Linux test must not instantiate a WindowsPath.
            with patch.object(hosts,'Path',return_value=type('Suffix',(),{'suffix':'.cmd'})()):
                self.assertEqual(hosts.command('C:/Program Files/lmscript.cmd','case.lms'),
                                 ['cmd.exe','/d','/c','C:/Program Files/lmscript.cmd','case.lms'])
        text=(ROOT/'scripts/traffic-check.py').read_text()
        for variable in ('a.compiler','a.lmdebug_compiler'):
            self.assertIn('hosts.command('+variable,text)
            self.assertNotIn('[str('+variable+')',text)
    def test_platform_manifest_exact_set_and_documented_windows_skips(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory)/'stage'
            integration.export_examples('v0.1.36',stage)
            manifest,digest=integration.platform_plan('v0.1.36',stage,'windows-x64')
            self.assertEqual(len(digest),64)
            self.assertEqual(len(manifest['examples']),50)
            supported=[n for n,e in manifest['examples'].items() if 'windows-x64' in e['platforms']]
            self.assertEqual(len(supported),29)
            for n,e in manifest['examples'].items():
                if n not in supported:
                    self.assertTrue(e['unsupported']['windows-x64']['reason'])
            records=integration.overlay_helpers(stage,manifest)
            self.assertEqual(len(records),2)
            for record in records:
                self.assertEqual(record['sha256'],hashlib.sha256((stage/record['path']).read_bytes()).hexdigest())
                self.assertNotIn('"--lmcode"',(stage/record['path']).read_text())
                self.assertNotIn("'--lmcode'",(stage/record['path']).read_text())
            (stage/'examples/unreviewed.lms').write_text('fixture')
            with self.assertRaisesRegex(ValueError,'manifest/example set differs'):
                integration.platform_plan('v0.1.36',stage,'windows-x64')
            with self.assertRaisesRegex(ValueError,'no reviewed platform manifest'):
                integration.platform_plan('main',stage,'windows-x64')
    def test_capture_expectations_do_not_silently_skip_linux(self):
        for target in ('linux-x64','linux-arm64'):
            self.assertTrue(traffic.capture_policy(target)['capture'])
        policy=traffic.capture_policy('windows-x64')
        self.assertFalse(policy['capture']); self.assertIn('header-only',policy['reason'])
    def test_checksum_rejection_before_install(self):
        hosts.verify(b'release',hashlib.sha256(b'release').hexdigest())
        with self.assertRaises(ValueError): hosts.verify(b'tamper',hashlib.sha256(b'release').hexdigest())
    def test_archive_writes_only_selected_platform_executable(self):
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w:gz') as out:
            member=tarfile.TarInfo('lmconn-linux-x64'); member.size=4; out.addfile(member,io.BytesIO(b'host'))
            member=tarfile.TarInfo('../../ignored'); member.size=3; out.addfile(member,io.BytesIO(b'bad'))
        self.assertEqual(hosts.executable_bytes(data.getvalue(),'lmconn-linux-x64.tar.gz','lmconn','linux-x64'),b'host')
    def test_saved_program_is_executed_not_just_compiled(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory); (stage/'build').mkdir(); (stage/'build/case.dslb').write_bytes(b'fixture')
            example=stage/'case.lms'; example.write_text('p=_dsl_ cli="lmdebug";\nprintln("system in a string");\nend _dsl_\nsavedsl(p,"build/case.dslb");\n#|witness\n')
            calls=[]
            def run(argv,*args):
                calls.append(argv); return '' if len(calls)==1 else '{"output":["witness"]}\n'
            with patch.object(integration,'run',side_effect=run):
                result=integration.execute_example(example,stage,'compiler',{'lmdebug':'released-lmdebug'},{},10)
            self.assertEqual(result['deferred_programs_executed'],['build/case.dslb'])
            self.assertEqual(calls[1][0:2],['released-lmdebug','--dsl'])
    def test_workspace_alias_is_normalized_but_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); stage=root/'stage'; stage.mkdir()
            # A lexical alias exercises the same asymmetry as macOS /var -> /private/var
            # and Windows temporary-directory junctions, without requiring symlink privileges.
            (stage/'nested').mkdir(); alias=stage/'nested/..'
            (stage/'case.dslb').write_bytes(b'fixture')
            example=stage/'case.lms'
            example.write_text('p=_dsl_ cli="lmdebug"; end _dsl_ savedsl(p,"case.dslb");')
            with patch.object(integration,'run',return_value=''):
                self.assertEqual(integration.execute_example(example,alias,'compiler',{'lmdebug':'host'},{},10)['status'],'PASS')
                (root/'outside.dslb').write_bytes(b'fixture')
                example.write_text('p=_dsl_ cli="lmdebug"; end _dsl_ savedsl(p,"../outside.dslb");')
                with self.assertRaisesRegex(ValueError,'escapes'):
                    integration.execute_example(example,alias,'compiler',{'lmdebug':'host'},{},10)
    def test_only_absent_primary_macos_asset_can_skip(self):
        cases=[('macos-arm64','lmdebug',True,'SKIP',0),
               ('macos-x64','lmdebug',True,'SKIP',0),
               ('macos-arm64','lmdebug',False,'BLOCKED',2),
               ('windows-x64','lmdebug',True,'BLOCKED',2),
               ('macos-arm64','lmconn',True,'BLOCKED',2),
               ('macos-arm64',None,True,'BLOCKED',2)]
        for target,product,enabled,status,code in cases:
            with self.subTest(target=target,product=product,enabled=enabled), tempfile.TemporaryDirectory() as directory:
                root=Path(directory); compiler=root/'compiler'; compiler.write_text('fixture')
                def export(ref,stage):
                    (stage/'examples').mkdir(parents=True)
                    (stage/'examples/a.lms').write_text('fixture')
                    return 'fixture-commit'
                error=(integration.hosts.MissingAsset({'tag_name':'v0.1.36'},product,target,'absent')
                       if product else integration.hosts.Unavailable('checksum absent'))
                argv=['integration-run.py','--compiler',str(compiler),'--mock-compiler',str(compiler),
                      '--work',str(root/'work'),'--report',str(root/'report.json')]
                if enabled: argv.append('--skip-unsupported-macos')
                with patch('sys.argv',argv), patch.object(integration,'export_examples',side_effect=export), \
                 patch.object(integration,'platform_plan',side_effect=fixture_plan), \
                     patch.object(integration,'run',side_effect=['lmscript 0.2.426','lmscript 0.2.448']), \
                     patch.object(integration.hosts,'native_platform',return_value=target), \
                     patch.object(integration.hosts,'install',side_effect=error), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(integration.main(),code)
                report=json.loads((root/'report.json').read_text())
                self.assertEqual(report['status'],status)
                self.assertEqual(report['counts']['PASS'],0)
                self.assertEqual(report['counts'][status],1)
    def test_host_failure_and_missing_expected_output_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            stage=Path(directory); example=stage/'case.lms'; example.write_text('r=system ["host"];\n#|required observation\n')
            with patch.object(integration,'run',return_value='nothing'):
                with self.assertRaisesRegex(RuntimeError,'missing expected'): integration.execute_example(example,stage,'compiler',{}, {},10)
            with patch.object(integration,'run',side_effect=RuntimeError('real failure')):
                with self.assertRaisesRegex(RuntimeError,'real failure'): integration.execute_example(example,stage,'compiler',{}, {},10)
    def test_empty_example_does_not_count_as_execution(self):
        with self.assertRaises(ValueError): integration.deferred_programs('println("only compilation");')
    def test_pktmon_session_is_bounded_on_exclusive_empty_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            capture=traffic.WindowsCapture('pktmon',Path(directory),34567)
            with patch.dict(os.environ,LMDEBUG_PKTMON_EXCLUSIVE='1'), patch.object(capture,'call',return_value=subprocess.CompletedProcess([],0,stdout='',stderr='')) as call:
                capture.start(); capture.finish(Path(directory)/'out.pcapng'); capture.close()
            commands=[x.args for x in call.call_args_list]
            self.assertEqual(commands[0],('filter','list'))
            self.assertIn(('filter','remove'),commands)
            start=next(x for x in commands if x[0]=='start')
            self.assertIn('--capture',start); self.assertIn('--file-name',start)
            self.assertTrue(any(x[0]=='etl2pcap' and '--out' in x for x in commands))
    def test_missing_release_cannot_be_reported_as_green_or_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); compiler=root/'compiler'; compiler.write_text('fixture')
            def export(ref,stage):
                (stage/'examples').mkdir(parents=True)
                (stage/'examples/a.lms').write_text('fixture')
                (stage/'examples/b.lms').write_text('fixture')
                return 'fixture-commit'
            argv=['integration-run.py','--compiler',str(compiler),'--mock-compiler',str(compiler),
                  '--work',str(root/'work'),'--report',str(root/'report.json')]
            with patch('sys.argv',argv), patch.object(integration,'export_examples',side_effect=export), \
                 patch.object(integration,'platform_plan',side_effect=fixture_plan), \
                 patch.object(integration,'run',side_effect=['lmscript 0.2.426','lmscript 0.2.448']), \
                 patch.object(integration.hosts,'native_platform',return_value='macos-arm64'), \
                 patch.object(integration.hosts,'install',side_effect=integration.hosts.Unavailable('missing macOS asset')):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(integration.main(),2)
            report=json.loads((root/'report.json').read_text())
            self.assertEqual(report['status'],'BLOCKED')
            self.assertEqual(report['counts'],{'PASS':0,'FAIL':0,'BLOCKED':2,'SKIP':0})
    def test_wrong_native_architecture_fails_before_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            argv=['integration-run.py','--mock-compiler','unused','--expected-platform','linux-arm64',
                  '--work',str(root/'work'),'--report',str(root/'report.json')]
            with patch('sys.argv',argv), patch.object(integration.hosts,'native_platform',return_value='linux-x64'), \
                 patch.object(integration.hosts,'install') as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(integration.main(),1)
                install.assert_not_called()
            self.assertIn('native runner mismatch',json.loads((root/'report.json').read_text())['reason'])
    def test_failed_pktmon_start_does_not_stop_a_foreign_session(self):
        with tempfile.TemporaryDirectory() as directory:
            capture=traffic.WindowsCapture('pktmon',Path(directory),34567)
            def command(*args):
                if args[0]=='start': raise RuntimeError('capture already active')
                return subprocess.CompletedProcess([],0,stdout='',stderr='')
            with patch.dict(os.environ,LMDEBUG_PKTMON_EXCLUSIVE='1'), patch.object(capture,'call',side_effect=command) as call:
                with self.assertRaises(RuntimeError): capture.start()
                capture.close()
            self.assertNotIn(('stop',),[x.args for x in call.call_args_list])
            self.assertIn(('filter','remove'),[x.args for x in call.call_args_list])
    def test_pktmon_refuses_foreign_filters_or_nonexclusive_host(self):
        with tempfile.TemporaryDirectory() as directory:
            capture=traffic.WindowsCapture('pktmon',Path(directory),34567)
            with patch.dict(os.environ,LMDEBUG_PKTMON_EXCLUSIVE='0'), patch.object(capture,'call') as call:
                with self.assertRaisesRegex(RuntimeError,'exclusive'): capture.start()
                call.assert_not_called()
            with patch.dict(os.environ,LMDEBUG_PKTMON_EXCLUSIVE='1'), patch.object(capture,'call',return_value=subprocess.CompletedProcess([],0,stdout='1 foreign TCP 443',stderr='')) as call:
                with self.assertRaisesRegex(RuntimeError,'foreign'): capture.start()
                capture.close()
                self.assertEqual([x.args for x in call.call_args_list],[('filter','list')])
    def test_workflow_is_manual_and_contains_every_native_runner(self):
        text=(ROOT/'.github/workflows/integration.yml').read_text()
        trigger=text.split('on:\n',1)[1].split('permissions:',1)[0]
        self.assertIn('workflow_dispatch:',trigger)
        for forbidden in ('\n  push:','\n  pull_request:','\n  schedule:'): self.assertNotIn(forbidden,trigger)
        for runner in ('ubuntu-24.04','ubuntu-24.04-arm','macos-15-intel','macos-15','windows-2022'): self.assertIn(runner,text)
        self.assertNotIn('--allow-skips',text)
if __name__=='__main__': unittest.main()
