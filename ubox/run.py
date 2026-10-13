#!/usr/bin/env python3
"""UBox Camera add-on supervisor (on-demand live stream).

Pipeline: qemu-aarch64-static -L /app/rootfs /app/bin/rehost
  -> v_*.bin (Annex-B H.265 NALs) -> ffmpeg hevc pipe -> MJPEG.

Lifecycle: qemu spawns on the first /video.mjpg subscriber, killed after
`idle_timeout` seconds with zero subscribers. Credentials come only from
/data/options.json (never baked into the image).

Endpoints: / (page), /video.mjpg, /snap.jpg, /stats, /api/transport
Transport: auto|relay|direct enforced via iptables (needs NET_ADMIN).
  auto = no rules, lib picks; relay = drop LAN discovery (udp/32762);
  direct = drop P4P relays (udp/20001). Effective path is lib-internal;
  /stats reports the requested mode plus whether rules applied.
"""
import glob
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP = "/app"
ROOTFS = os.path.join(APP, "rootfs")
BINDIR = os.path.join(APP, "bin")
QEMU = os.path.join(BINDIR, "qemu-aarch64-static")
REHOST = os.path.join(BINDIR, "rehost")
FFMPEG = shutil.which("ffmpeg") or "/usr/bin/ffmpeg"
OPTFILE = "/data/options.json"
TRANSPORT_FILE = "/data/transport"
TRANSPORT_MODES = ("auto", "relay", "direct")
# P4P relay port (every hardcoded relay) vs LAN discovery port
# (broadcast + direct unicast signalling to the camera).
RELAY_PORT = 20001
LANDISC_PORT = 32762
IPTABLES = shutil.which("iptables")

NAL_RE = re.compile(rb"\x00\x00\x00\x01(.)", re.DOTALL)


def load_options():
    opt = {"uid": "", "username": "admin", "password": "",
           "stream": 1, "fps": 8, "port": 8089, "idle_timeout": 60,
           "transport": "auto"}
    try:
        with open(OPTFILE, encoding="utf-8") as fh:
            opt.update(json.load(fh))
    except OSError:
        pass
    # Runtime choice from the web button survives restarts; it wins over
    # the supervisor-managed options.json until the user changes config.
    try:
        with open(TRANSPORT_FILE, encoding="utf-8") as fh:
            saved = fh.read().strip().lower()
        if saved in TRANSPORT_MODES:
            opt["transport"] = saved
    except OSError:
        pass
    for k in ("stream", "fps", "port", "idle_timeout"):
        try:
            opt[k] = int(os.environ.get("UBOX_" + k.upper(), opt[k]))
        except ValueError:
            pass
    for k in ("uid", "username", "password", "transport"):
        opt[k] = os.environ.get("UBOX_" + k.upper(), opt[k])
    if opt["transport"] not in TRANSPORT_MODES:
        opt["transport"] = "auto"
    return opt


OPT = load_options()

TR = {"mode": OPT["transport"], "applied": False,
      "detail": "not applied yet"}


def _ipt(*args):
    try:
        p = subprocess.run(["iptables"] + list(args), capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)[-200:]
    out = ((p.stderr or "") + " " + (p.stdout or "")).strip()
    return p.returncode, (out[-200:] if out else "ok")


def _ipt_has(rule):
    rc, _ = _ipt("-C", "OUTPUT", *rule)
    return rc == 0


def transport_rule(mode):
    if mode == "relay":
        # kill LAN discovery -> lib can only use public relays
        return ["-p", "udp", "--dport", str(LANDISC_PORT),
                "-m", "comment", "--comment", "ubox-transport"]
    if mode == "direct":
        # kill every P4P relay -> lib can only use the LAN path
        return ["-p", "udp", "--dport", str(RELAY_PORT),
                "-m", "comment", "--comment", "ubox-transport"]
    return None


def apply_transport(mode):
    """Enforce relay/direct at the network layer. Returns applied bool."""
    if mode not in TRANSPORT_MODES:
        mode = "auto"
    with LOCK:
        TR["mode"] = mode
    if not IPTABLES:
        with LOCK:
            TR["applied"] = False
            TR["detail"] = "iptables missing: mode recorded, nothing enforced"
        print("transport %s requested but iptables missing" % mode,
              flush=True)
        return False
    for m in ("relay", "direct"):
        _ipt("-D", "OUTPUT", *transport_rule(m))
    rule = transport_rule(mode)
    if rule is None:
        with LOCK:
            TR["applied"] = True
            TR["detail"] = "auto: no firewall rules, lib picks path"
        return True
    rc, out = _ipt("-A", "OUTPUT", *rule)
    ok = rc == 0 and _ipt_has(rule)
    detail = ("drop udp/%s (%s-only)" % (rule[3], mode)) if ok \
        else ("iptables failed: %s" % out)
    with LOCK:
        TR["applied"] = ok
        TR["detail"] = detail
    print("transport %s: %s" % (mode, detail), flush=True)
    return ok

ST = {"t0": time.time(), "decoded": 0, "nals": 0, "restarts": 0,
      "spawns": 0, "running": False, "served": 0, "subs": 0,
      "last_sub_t": 0.0}
LATEST = {"jpg": None, "seq": 0, "t": 0.0}
LOCK = threading.Lock()
PIPE = {"cap": None, "ff": None, "rundir": ""}
WAKE = threading.Event()


def has_params(b):
    types = set((m[0] >> 1) & 0x3F for m in NAL_RE.findall(b))
    return 32 in types and 33 in types and 34 in types


def stable_read(path, tries=5, gap=0.05):
    last = -1
    for _ in range(tries):
        try:
            sz = os.path.getsize(path)
        except OSError:
            return None
        if sz == last and sz > 0:
            with open(path, "rb") as fh:
                return fh.read()
        last = sz
        time.sleep(gap)
    return None


def split_jpegs(proc):
    buf = bytearray()
    while True:
        try:
            chunk = proc.stdout.read(65536)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
        while True:
            s = bytes(buf).find(b"\xff\xd8")
            if s < 0:
                del buf[:max(0, len(buf) - 1)]
                break
            e = bytes(buf).find(b"\xff\xd9", s + 2)
            if e < 0:
                del buf[:s]
                break
            jpg = bytes(buf[s:e + 2])
            del buf[:e + 2]
            with LOCK:
                LATEST["jpg"] = jpg
                LATEST["seq"] += 1
                LATEST["t"] = time.time()
                ST["decoded"] += 1


def client_gone(conn):
    """Peer closed while we were only sleeping (no writes yet)."""
    try:
        r, _, _ = select.select([conn], [], [], 0)
    except (OSError, ValueError):
        return True
    if not r:
        return False
    try:
        return conn.recv(1, socket.MSG_PEEK) == b""
    except OSError:
        return True


def stop_pipeline():
    cap, ff = PIPE["cap"], PIPE["ff"]
    PIPE["cap"], PIPE["ff"] = None, None
    for p in (ff, cap):
        if p is None:
            continue
        try:
            if p.stdin:
                p.stdin.close()
        except Exception:
            pass
        try:
            p.terminate()
        except Exception:
            pass
    for p in (ff, cap):
        if p is None:
            continue
        try:
            p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    with LOCK:
        ST["running"] = False


def run_pipeline():
    rundir = "/tmp/ubox_run"
    os.makedirs(rundir, exist_ok=True)
    for f in glob.glob(os.path.join(rundir, "*")):
        try:
            os.remove(f)
        except OSError:
            pass
    PIPE["rundir"] = rundir
    if not OPT["uid"] or not OPT["password"]:
        print("no uid/password in options, pipeline not started",
              flush=True)
        return
    for need in (QEMU, REHOST):
        if not (os.path.isfile(need) and os.access(need, os.X_OK)):
            print("missing executable: %s" % need, flush=True)
            return
    cap = subprocess.Popen(
        [QEMU, "-L", ROOTFS, REHOST, OPT["uid"], OPT["username"],
         OPT["password"], "1", str(OPT["stream"]), "86400"],
        cwd=rundir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "LD_LIBRARY_PATH": BINDIR})
    ff = subprocess.Popen(
        [FFMPEG, "-hide_banner", "-loglevel", "error",
         "-probesize", "32", "-f", "hevc", "-i", "pipe:0",
         "-vf", "fps=%d" % OPT["fps"], "-q:v", "4",
         "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    PIPE["cap"], PIPE["ff"] = cap, ff
    threading.Thread(target=split_jpegs, args=(ff,), daemon=True).start()
    with LOCK:
        ST["running"] = True
        ST["spawns"] += 1
    print("pipeline spawned", flush=True)
    nxt, primed = 0, False
    try:
        while True:
            if PIPE["cap"] is None:
                break
            path = os.path.join(rundir, "v_%d.bin" % nxt)
            if not os.path.isfile(path):
                if cap.poll() is not None:
                    print("rehost exited rc=%s" % cap.returncode,
                          flush=True)
                    break
                time.sleep(0.15)
                continue
            b = stable_read(path)
            if b is None:
                time.sleep(0.1)
                continue
            if not primed:
                if not has_params(b):
                    nxt += 1
                    continue
                primed = True
            try:
                ff.stdin.write(b)
                with LOCK:
                    ST["nals"] += 1
            except (BrokenPipeError, ValueError):
                with LOCK:
                    ST["restarts"] += 1
                break
            nxt += 1
    finally:
        stop_pipeline()
        print("pipeline stopped", flush=True)


def supervisor():
    while True:
        WAKE.wait(timeout=5)
        WAKE.clear()
        with LOCK:
            subs = ST["subs"]
            running = ST["running"]
            idle_for = time.time() - ST["last_sub_t"]
        if subs > 0 and not running:
            threading.Thread(target=run_pipeline, daemon=True).start()
        elif subs == 0 and running and idle_for > OPT["idle_timeout"]:
            print("idle %.0fs, stopping pipeline" % idle_for, flush=True)
            stop_pipeline()


PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UBox Camera</title>
<style>
  body { background:#111; color:#eee; font-family:system-ui,sans-serif; margin:0; padding:16px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:#888; font-size:13px; margin-bottom:12px; }
  #stage img { display:block; width:960px; max-width:96vw; background:#000; }
  #stats { margin-top:10px; font-size:13px; color:#9d9; font-family:monospace; }
  button { margin-top:10px; padding:8px 18px; font-size:14px; cursor:pointer; }
  .row { margin-top:10px; font-size:13px; color:#aaa; }
  .row button.on { border:2px solid #9d9; }
  .warn { color:#f96; }
</style>
</head>
<body>
<h1>UBox Camera</h1>
<div class="sub">on-demand &middot; qemu runs only while viewing</div>
<div id="stage"><img id="v" src="/video.mjpg" alt="live"></div>
<div id="stats">connecting...</div>
<button onclick="var a=document.createElement('a');a.href='/snap.jpg?ts='+Date.now();a.download='ubox.jpg';document.body.appendChild(a);a.click();a.remove();">抓拍</button>
<div class="row">传输：
<button data-m="auto" onclick="setTr('auto')">自动</button><button data-m="relay" onclick="setTr('relay')">中继</button><button data-m="direct" onclick="setTr('direct')">直连</button>
<span id="tr"></span></div>
<div class="row">直连=封relay(:20001)只留局域网（同LAN才有画面）；中继=封局域网发现(:32762)走公网relay；自动=不封路lib自选。切换会重启取流约10秒。</div>
<script>
function setTr(m){
  fetch('/api/transport?mode='+m,{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    alert('传输='+d.mode+' 生效='+d.applied+' '+d.detail);
  }).catch(function(){ alert('切换失败'); });
}
setInterval(function(){
  fetch('/stats').then(function(r){return r.json();}).then(function(s){
    document.getElementById('stats').textContent =
      (s.running?'LIVE':'idle')+' decoded='+s.decoded+' nals='+s.nals+
      ' subs='+s.subs+' spawns='+s.spawns+' uptime='+s.uptime_s+'s';
    var t=document.getElementById('tr');
    t.textContent='当前='+s.transport+' ('+s.transport_detail+')';
    if(!s.transport_applied){ t.className='warn'; } else { t.className=''; }
    var bs=document.querySelectorAll('button[data-m]');
    for(var i=0;i<bs.length;i++){
      if(bs[i].getAttribute('data-m')===s.transport){ bs[i].classList.add('on'); }
      else { bs[i].classList.remove('on'); }
    }
  }).catch(function(){});
},2000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "ubox-addon"

    def log_message(self, *a):
        pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8",
                       PAGE.encode("utf-8"))
        elif path == "/stats":
            with LOCK:
                snap = dict(ST)
                snap["last_age_ms"] = (
                    int((time.time() - LATEST["t"]) * 1000)
                    if LATEST["t"] else None)
                tr = dict(TR)
            snap["uptime_s"] = int(time.time() - snap.pop("t0"))
            snap.pop("last_sub_t", None)
            snap["fps"] = OPT["fps"]
            snap["transport"] = tr["mode"]
            snap["transport_applied"] = tr["applied"]
            snap["transport_detail"] = tr["detail"]
            self._send(200, "application/json",
                       json.dumps(snap).encode())
        elif path == "/snap.jpg":
            with LOCK:
                jpg = LATEST["jpg"]
            if not jpg:
                self._send(404, "text/plain", b"no frame yet")
                return
            self._send(200, "image/jpeg", jpg)
        elif path == "/video.mjpg":
            with LOCK:
                ST["subs"] += 1
                ST["last_sub_t"] = time.time()
            WAKE.set()
            try:
                bnd = "uboxlive"
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "multipart/x-mixed-replace; boundary=" + bnd)
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                last = -1
                while True:
                    if client_gone(self.connection):
                        break
                    with LOCK:
                        seq, jpg = LATEST["seq"], LATEST["jpg"]
                        ST["last_sub_t"] = time.time()
                    if jpg is not None and seq != last:
                        head = ("--%s\r\nContent-Type: image/jpeg\r\n"
                                "Content-Length: %d\r\n\r\n"
                                % (bnd, len(jpg))).encode()
                        self.wfile.write(head + jpg + b"\r\n")
                        last = seq
                        with LOCK:
                            ST["served"] += 1
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError,
                    ConnectionAbortedError):
                pass
            finally:
                with LOCK:
                    ST["subs"] = max(0, ST["subs"] - 1)
                    ST["last_sub_t"] = time.time()
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        path, _, qs = self.path.partition("?")
        q = {}
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                q[k] = v
        if path == "/api/transport":
            mode = (q.get("mode", "") or "").lower()
            if mode not in TRANSPORT_MODES:
                self._send(400, "application/json",
                           json.dumps(
                               {"error": "mode must be auto|relay|direct"}
                           ).encode())
                return
            try:
                with open(TRANSPORT_FILE, "w", encoding="utf-8") as fh:
                    fh.write(mode)
                persisted, perr = True, ""
            except OSError as e:
                # /data always exists in the add-on container; if not,
                # still switch for this run and say so honestly.
                persisted, perr = False, str(e)
            OPT["transport"] = mode
            ok = apply_transport(mode)
            stop_pipeline()
            WAKE.set()
            with LOCK:
                tr = dict(TR)
            self._send(200, "application/json",
                       json.dumps({"mode": mode, "applied": tr["applied"],
                                   "detail": tr["detail"],
                                   "persisted": persisted,
                                   "persist_error": perr,
                                   "restarted": True}).encode())
        else:
            self._send(404, "text/plain", b"not found")


def main():
    print("options: uid=%s.. stream=%d fps=%d idle=%ds transport=%s" % (
        (OPT["uid"][:4] + "…") if OPT["uid"] else "(empty)",
        OPT["stream"], OPT["fps"], OPT["idle_timeout"],
        OPT["transport"]), flush=True)
    apply_transport(OPT["transport"])
    threading.Thread(target=supervisor, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", OPT["port"]), Handler)
    print("serving on :%d" % OPT["port"], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
