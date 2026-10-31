#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real lmmock/lmconn loopback HTTP traffic captured and analyzed by lmdebug."""
import argparse, importlib.util, json, os, platform, re, shutil, signal, socket, subprocess, sys, tempfile, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
loader = importlib.util.spec_from_file_location('traffic_hosts', ROOT/'scripts/released-hosts.py')
hosts = importlib.util.module_from_spec(loader); loader.loader.exec_module(hosts)
def free_port():
    sock=socket.socket(); sock.bind(("127.0.0.1",0)); port=sock.getsockname()[1]; sock.close(); return port
def report(path, value): path.parent.mkdir(parents=True, exist_ok=True); path.write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
def blocked(path, reason): report(path, {"status":"BLOCKED", "reason":reason, "platform":platform.system(), "arch":platform.machine()}); print("BLOCKED: "+reason, file=sys.stderr); return 2
class WindowsCapture:
    """Use pktmon only on an explicitly exclusive disposable runner."""
    def __init__(self, executable, work, port):
        self.executable=executable; self.work=work; self.port=port
        self.name='lmdebug-integration-'+str(os.getpid()); self.started=False; self.filtered=False
        self.etl=work/'loopback.etl'
    def call(self, *args):
        result=subprocess.run([self.executable,*map(str,args)],cwd=self.work,capture_output=True,text=True,timeout=25)
        if result.returncode: raise RuntimeError('pktmon '+str(args)+': '+result.stdout+result.stderr)
        return result
    def start(self):
        if os.environ.get('LMDEBUG_PKTMON_EXCLUSIVE') != '1':
            raise RuntimeError('pktmon capture requires an explicitly exclusive disposable runner')
        existing=self.call('filter','list').stdout
        if re.search(r'^\s*\d+\s+',existing,re.M):
            raise RuntimeError('pktmon already has filters; refusing to replace foreign state')
        self.call('filter','add',self.name,'-t','TCP','-i','127.0.0.1','-p',self.port); self.filtered=True
        self.call('start','--capture','--pkt-size','0','--file-name',self.etl,'--file-size','32','--log-mode','circular')
        self.started=True
    def finish(self, destination):
        self.call('stop'); self.started=False
        self.call('etl2pcap',self.etl,'--out',destination)
    def close(self):
        try:
            if self.started: self.call('stop'); self.started=False
        finally:
            if self.filtered: self.call('filter','remove'); self.filtered=False

def run_iperf(binary, work):
    port = free_port(); server = subprocess.Popen([str(binary), "iperf3", "-s", "-B", "127.0.0.1", "-p", str(port)], cwd=work, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(.2)
        client = subprocess.run([str(binary), "iperf3", "-c", "127.0.0.1", "-p", str(port), "-t", "1", "-b", "10M", "-J"], cwd=work, capture_output=True, text=True, timeout=20)
        if client.returncode: raise RuntimeError("lmdebug iperf3 client failed: "+client.stdout+client.stderr)
        data=json.loads(client.stdout); assert data.get("end",{}).get("sum_sent",{}).get("bytes",0)>0
        return {"port":port,"bytes":data["end"]["sum_sent"]["bytes"]}
    finally:
        server.terminate()
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired: server.kill(); server.wait(timeout=5)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--lmdebug",type=Path,required=True); ap.add_argument("--lmmock",type=Path,required=True); ap.add_argument("--lmconn",type=Path,required=True); ap.add_argument("--compiler",type=Path,required=True,help="compiler for lmmock v6"); ap.add_argument("--lmdebug-compiler",type=Path,help="compiler for released lmdebug v5 (0.2.426)"); ap.add_argument("--report",type=Path,required=True); ap.add_argument("--work",type=Path,required=True); ap.add_argument("--tcpdump",type=Path,default=Path(shutil.which("tcpdump") or "")); ap.add_argument("--interface"); ap.add_argument("--sudo",action="store_true"); a=ap.parse_args()
    a.lmdebug=a.lmdebug.resolve(); a.lmmock=a.lmmock.resolve(); a.lmconn=a.lmconn.resolve(); a.compiler=a.compiler.resolve(); a.lmdebug_compiler=(a.lmdebug_compiler or a.compiler).resolve(); a.tcpdump=a.tcpdump.resolve(); a.work=a.work.resolve(); a.report=a.report.resolve()
    system=platform.system().lower()
    if system == "darwin" and not a.tcpdump.is_file(): return blocked(a.report, "tcpdump is required for real loopback capture")
    a.work.mkdir(parents=True, exist_ok=False); ready=a.work/"ready.json"; pcap=a.work/"loopback.pcap"; analysis=a.work/"analysis.json"; bytecode=a.work/"analyze.dslb"; mockcode=a.work/"mock.dslb"; mock_schema=a.work/"lmmock-schema.json"
    schema_proc=subprocess.run([str(a.lmmock),"schema"],cwd=a.work,capture_output=True,check=True); mock_schema.write_bytes(schema_proc.stdout)
    mock_source=a.work/"traffic-mock.lms"; mock_source.write_text((ROOT/"integration/traffic-mock.lms").read_text(),encoding="utf-8")
    subprocess.run(hosts.command(a.compiler,mock_source,mockcode),cwd=a.work,check=True)
    debug_schema=a.work/"lmdebug-schema.json"; debug_schema.write_bytes(subprocess.check_output([str(a.lmdebug),"pcap","--dsl-schema","--json"]))
    iface=a.interface or ("lo0" if system == "darwin" else None if system == "windows" else "lo")
    class Upstream(BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'{"sentinel":"LMDEBUG_LOOPBACK_HEALTH_V1"}'
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            size=int(self.headers.get("Content-Length", "0")); body=self.rfile.read(size); self.send_response(200); self.send_header("Content-Type","text/plain"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    upstream=ThreadingHTTPServer(("127.0.0.1",0), Upstream); threading.Thread(target=upstream.serve_forever, daemon=True).start()
    mock=subprocess.Popen([str(a.lmmock),"serve","--lmcode",str(mockcode),"--upstream",f"http://127.0.0.1:{upstream.server_port}/","--listen","127.0.0.1:0","--ready-file",str(ready)],cwd=a.work,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); capture=None; windows=None; sampler=None; evidence={}; native_capture=False
    try:
        for _ in range(400):
            if ready.is_file(): break
            if mock.poll() is not None: raise RuntimeError("lmmock exited: "+mock.stderr.read())
            time.sleep(.05)
        if not ready.is_file(): raise RuntimeError("lmmock did not become ready")
        base=json.loads(ready.read_text())["url"]; env=dict(os.environ,LMMOCK_URL=base,LMCONN_BIN=str(a.lmconn)); port=int(base.rsplit(":",1)[1])
        capture_reason=None
        if system == "windows":
            pktmon=shutil.which("pktmon")
            if not pktmon: capture_reason="pktmon is required on Windows for native loopback capture"
            else:
                windows=WindowsCapture(pktmon,a.work,port)
                try: windows.start()
                except Exception as error: capture_reason=str(error)
        elif system == "linux":
            native_capture=True
            capture_source=a.work/"capture.lms"; capture_code=a.work/"capture.dslb"
            q=lambda value:json.dumps(str(value),ensure_ascii=False)
            capture_source.write_text('p=_lmcode_ schema='+q(debug_schema)+';\nlet c=shark.live('+q(iface)+',10000,3.0,65535,false,true,'+q('tcp and host 127.0.0.1 and port '+str(port))+');c.save_pcap('+q(pcap)+');\nend _lmcode_\nsavedsl(p,'+q(capture_code)+');\n',encoding='utf-8')
            subprocess.run(hosts.command(a.lmdebug_compiler,capture_source),cwd=a.work,check=True)
            cmd=[str(a.lmdebug),'pcap','--dsl',str(capture_code)]
            if a.sudo: cmd=['sudo','-E',*cmd]
            capture=subprocess.Popen(cmd,cwd=a.work,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        else:
            cmd=[str(a.tcpdump),"-i",iface,"-U","-w",str(pcap),"tcp", "and", "host", "127.0.0.1", "and", "port", str(port)]; cmd=["sudo","-E",*cmd] if a.sudo else cmd; capture=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        time.sleep(.5)
        sampler=subprocess.Popen([str(a.lmdebug),"sys","sample","--duration","2s","--interval","100ms","--fields","net","--format","json"],cwd=a.work,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        client=subprocess.run([sys.executable,str(ROOT/"integration/traffic-client.py")],cwd=a.work,env=env,capture_output=True,text=True,timeout=30)
        if client.returncode: raise RuntimeError("traffic client failed: "+client.stdout+client.stderr)
        evidence['http_client']=client.stdout
        iperf=run_iperf(a.lmdebug, a.work); evidence['iperf']=iperf
        sample_out,sample_error=sampler.communicate(timeout=15)
        if sampler.returncode: raise RuntimeError('network sampler failed: '+sample_error)
        sampling=json.loads(sample_out)
        if sampling.get('error') or sampling.get('samples_kept',0)<2 or not any(m.get('n',0)>0 and not m.get('error') for m in sampling.get('metrics',[])): raise RuntimeError('network sampling lacks valid observations: '+sample_out)
        evidence['sampling']=sampling
        if system == "windows" and windows and windows.started:
            windows.finish(pcap)
        elif capture and not native_capture:
            capture.send_signal(signal.SIGINT)
        if capture:
            try: capture.wait(timeout=10)
            except subprocess.TimeoutExpired: capture.kill(); capture.wait(timeout=5)
        if native_capture and capture.returncode:
            raise RuntimeError('lmdebug live acquisition failed: '+capture.stdout.read()+capture.stderr.read())
        if capture_reason:
            report(a.report,{"status":"BLOCKED","reason":capture_reason,"platform":platform.system(),**evidence}); print("BLOCKED: "+capture_reason,file=sys.stderr); return 2
        if not pcap.is_file() or pcap.stat().st_size < 64:
            detail=capture.stderr.read()[-4000:] if capture and capture.poll() is not None else ""
            raise RuntimeError("packet capture produced no pcap: "+detail)
        source=a.work/"traffic-analyze.lms"; source.write_text((ROOT/"integration/traffic-analyze.lms").read_text().replace('p = _lmcode_ cli="lmdebug pcap" install="github:lmctl-ai/lmdebug@v0.1.36";', 'p = _lmcode_ schema='+json.dumps(str(debug_schema),ensure_ascii=False)+';').replace("ARGV[0]",json.dumps(str(pcap),ensure_ascii=False)).replace("ARGV[1]",json.dumps(str(analysis),ensure_ascii=False)).replace("ARGV[2]",json.dumps(str(bytecode),ensure_ascii=False)),encoding="utf-8")
        subprocess.run(hosts.command(a.lmdebug_compiler,source),cwd=a.work,check=True)
        analyzed=subprocess.run([str(a.lmdebug),"pcap","--dsl",str(bytecode)],cwd=a.work,capture_output=True,text=True,timeout=60)
        if analyzed.returncode: raise RuntimeError("lmdebug offline analysis failed: "+analyzed.stdout+analyzed.stderr)
        report(a.report,{"status":"PASS","platform":platform.system(),"interface":iface,"capture_privilege":"sudo" if a.sudo and system!="windows" else "current token","backend":"lmdebug-live+offline" if native_capture else "pktmon+offline" if system=="windows" else "tcpdump+offline","url":base,"sentinel":"LMDEBUG_LOOPBACK_SENTINEL_V1","pcap_bytes":pcap.stat().st_size,"analysis":json.loads(analysis.read_text()),**evidence}); print("PASS real lmmock/lmconn HTTP + lmdebug iperf loopback traffic captured and analyzed by lmdebug"); return 0
    except Exception as exc: report(a.report,{"status":"FAIL","error":str(exc),"platform":platform.system(),**evidence}); print(str(exc),file=sys.stderr); return 1
    finally:
        if capture and capture.poll() is None:
            capture.terminate()
            try: capture.wait(timeout=5)
            except subprocess.TimeoutExpired: capture.kill(); capture.wait(timeout=5)
        cleanup_error=None
        if windows:
            try: windows.close()
            except Exception as error: cleanup_error=error
        if sampler and sampler.poll() is None: sampler.kill(); sampler.wait(timeout=5)
        if mock.poll() is None:
            mock.terminate()
            try: mock.wait(timeout=5)
            except subprocess.TimeoutExpired: mock.kill(); mock.wait(timeout=5)
        upstream.shutdown(); upstream.server_close()
        if cleanup_error:
            value=json.loads(a.report.read_text()) if a.report.is_file() else {}
            value.update(status="FAIL",cleanup_error=str(cleanup_error)); report(a.report,value)
            raise RuntimeError("capture cleanup failed: "+str(cleanup_error))
if __name__ == "__main__": raise SystemExit(main())
