#!/usr/bin/env python3
"""UBox Camera add-on supervisor (on-demand live stream).

Pipeline: qemu-aarch64-static -L /app/rootfs /app/bin/rehost
  -> v_*.bin (Annex-B H.265 NALs) -> ffmpeg hevc pipe -> MJPEG.

Lifecycle: qemu spawns on the first /video.mjpg subscriber, killed after
`idle_timeout` seconds with zero subscribers. Device uid/password and cloud
account are entered on the web page and kept in /data (never in options).

Endpoints: / (page), /video.mjpg, /snap.jpg, /stats, /api/transport,
  /api/login, /api/logout, /api/session, /api/devices (cloud passthrough),
  /api/device, /api/device-login (device credentials in /data).
Transport: auto|relay|direct enforced via iptables (needs NET_ADMIN).
  auto = no rules, lib picks; relay = drop LAN discovery (udp/32762);
  direct = drop P4P relays (udp/20001). Effective path is lib-internal;
  /stats reports the requested mode plus whether rules applied.
HTTP auth: options http_username/http_password; empty password = open
  (backwards compatible), non-empty = every endpoint requires Basic auth.
"""
import base64
import glob
import hashlib
import hmac
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
import urllib.error
import urllib.request
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
    # Only non-secret runtime knobs live in Add-on options. Device uid /
    # password and cloud account are entered on the web page and persisted
    # under /data (never in options.json / the image).
    opt = {"username": "admin",
           "stream": 1, "fps": 8, "port": 8089, "idle_timeout": 60,
           "transport": "auto", "http_username": "ubox", "http_password": ""}
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
    for k in ("username", "transport",
                "http_username", "http_password"):
        opt[k] = os.environ.get("UBOX_" + k.upper(), opt[k])
    if opt["transport"] not in TRANSPORT_MODES:
        opt["transport"] = "auto"
    return opt


OPT = load_options()

TR = {"mode": OPT["transport"], "applied": False,
      "detail": "not applied yet"}


# ---- Cloud account (portal.ubianet.com passthrough, layout ported from
# local :8080; stdlib only). Token persists in /data, never in the image.
REGIONS = {
    "cn": "https://portal-cn.ubianet.com",
    "us": "https://portal-us.ubianet.com",
    "uni": "https://portal-uni.ubianet.com",
}
CLOUD_SESSION_FILE = os.environ.get("UBOX_SESSION_FILE", "/data/session.json")
_cloud_token = None
_cloud_region = "us"
_cloud_account = ""


def _save_cloud_session():
    try:
        with open(CLOUD_SESSION_FILE, "w", encoding="utf-8") as fh:
            json.dump({"token": _cloud_token, "region": _cloud_region,
                       "account": _cloud_account,
                       "saved_at": int(time.time())}, fh)
        try:
            os.chmod(CLOUD_SESSION_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _load_cloud_session():
    global _cloud_token, _cloud_region, _cloud_account
    try:
        with open(CLOUD_SESSION_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
        if d.get("token"):
            _cloud_token = d["token"]
            if d.get("region") in REGIONS:
                _cloud_region = d["region"]
            _cloud_account = d.get("account", "")
    except (OSError, ValueError):
        pass


def _clear_cloud_session():
    global _cloud_token, _cloud_account
    _cloud_token = None
    _cloud_account = ""
    try:
        os.remove(CLOUD_SESSION_FILE)
    except OSError:
        pass


def _app_password(pwd):
    mac = hmac.new(b"", pwd.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(mac).decode("ascii").replace(
        "+", "-").replace("/", "_").replace("=", ",")


def _cloud_call(path, body, token, base=None):
    req = urllib.request.Request(
        (base or REGIONS.get(_cloud_region, REGIONS["us"])) + path,
        data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("X-Ubia-Auth-UserToken", token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        try:
            text = e.read().decode("utf-8", errors="replace")
        except Exception:
            text = ""
        return None, "HTTP %d: %s" % (e.code, text[:300])
    except Exception as e:
        return None, str(e)


def _cloud_login(account, password, region):
    global _cloud_token, _cloud_region, _cloud_account
    if region in REGIONS:
        _cloud_region = region
    if not account or not password:
        return None, "need account and password"
    data = {"account": account, "password": _app_password(password),
            "app": "ubox", "app_version": "1.1.370",
            "brand": "android", "lang": "zh_CN", "device_type": 1}
    resp, err = _cloud_call("/api/pub/account/login/v3", data, "",
                            base=REGIONS[_cloud_region])
    if err:
        return None, err
    token = (resp.get("data") or {}).get("Token")
    if not token:
        return None, "login failed: " + json.dumps(resp)[:300]
    _cloud_token = token
    _cloud_account = account
    _save_cloud_session()
    return token, None


# ---- Device credentials (entered on the web page, persisted under /data).
DEVICE_FILE = os.environ.get("UBOX_DEVICE_FILE", "/data/device.json")
DEV = {"uid": os.environ.get("UBOX_UID", ""),
       "username": os.environ.get("UBOX_USERNAME", ""),
       "password": os.environ.get("UBOX_PASSWORD", "")}


def _save_device():
    try:
        with open(DEVICE_FILE, "w", encoding="utf-8") as fh:
            json.dump({"uid": DEV["uid"], "username": DEV["username"],
                       "password": DEV["password"],
                       "saved_at": int(time.time())}, fh)
        try:
            os.chmod(DEVICE_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _load_device():
    try:
        with open(DEVICE_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
        for k in ("uid", "username", "password"):
            if d.get(k):
                DEV[k] = d[k]
    except (OSError, ValueError):
        pass


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
    _load_device()
    username = DEV["username"] or OPT.get("username") or "admin"
    if not DEV["uid"] or not DEV["password"]:
        print("no device uid/password (enter on web page), "
              "pipeline not started", flush=True)
        return
    for need in (QEMU, REHOST):
        if not (os.path.isfile(need) and os.access(need, os.X_OK)):
            print("missing executable: %s" % need, flush=True)
            return
    cap = subprocess.Popen(
        [QEMU, "-L", ROOTFS, REHOST, DEV["uid"], username,
         DEV["password"], "1", str(OPT["stream"]), "86400"],
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
  *{box-sizing:border-box}
  body { background:#141414; color:#eee; font-family:system-ui,sans-serif; margin:0; padding:16px; }
  h1 { font-size:20px; margin:0 0 4px; }
  .sub { color:#888; font-size:13px; margin-bottom:12px; }
  .card{background:#1e1e1e;border:1px solid #333;border-radius:8px;padding:12px;margin-bottom:12px}
  button{margin:4px 6px 4px 0;padding:7px 16px;font-size:14px;cursor:pointer;background:#2a6;color:#fff;border:none;border-radius:4px}
  button:hover{background:#3b7}
  button.danger{background:#a33}
  input,select{padding:6px 10px;font-size:14px;background:#2a2a2a;color:#eee;border:1px solid #444;border-radius:4px}
  .navtabs{display:flex;gap:0;background:#1e1e1e;border:1px solid #333;border-radius:8px;overflow:hidden;margin-bottom:12px}
  .navtabs button{flex:1;margin:0;padding:10px 0;font-size:15px;border:none;border-radius:0;background:transparent;color:#aaa}
  .navtabs button.on{background:#2a6;color:#fff}
  .tabpage{display:none}
  .tabpage.on{display:block}
  .dev-layout{display:flex;gap:12px;align-items:flex-start}
  .dev-side{width:270px;flex:0 0 270px;display:flex;flex-direction:column;gap:12px}
  .dev-side .card{margin-bottom:0}
  .dev-main{flex:1;min-width:0;display:flex;flex-direction:column;gap:0}
  .dev-main .card{margin-bottom:12px}
  @media (max-width:900px){.dev-layout{flex-direction:column}.dev-side{width:100%;flex:auto}}
  #stage img { display:block; width:100%; max-width:960px; background:#000; border-radius:4px; }
  #stats { margin-top:10px; font-size:13px; color:#9d9; font-family:monospace; }
  .row { margin-top:10px; font-size:13px; color:#aaa; }
  .row button.on { outline:2px solid #9d9; }
  .warn { color:#f96; }
  .muted{color:#666}
</style>
</head>
<body>
<h1>UBox Camera</h1>
<div class="sub">on-demand &middot; qemu runs only while viewing</div>
<div class="navtabs" id="navtabs">
  <button data-tab="live" class="on" onclick="switchTab('live')">直播</button>
  <button data-tab="status" onclick="switchTab('status')">状态</button>
  <button data-tab="cloud" onclick="switchTab('cloud')">云账户</button>
</div>
<div class="tabpage on" id="tab-live">
<div class="dev-layout">
<div class="dev-side">
<div class="card">
<div style="margin-bottom:8px"><input id="d-uid" placeholder="设备UID" style="width:100%;padding:8px"></div>
<div style="margin-bottom:8px"><input id="d-user" placeholder="用户名（默认admin）" style="width:100%;padding:8px"></div>
<div style="margin-bottom:8px"><input id="d-pass" type="password" placeholder="设备密码" style="width:100%;padding:8px"></div>
<button onclick="saveDevice()" style="width:100%">保存设备并重启取流</button>
<div id="dev-msg" class="muted" style="margin-top:6px"></div>
</div>
<div class="card">
<button onclick="var a=document.createElement('a');a.href='/snap.jpg?ts='+Date.now();a.download='ubox.jpg';document.body.appendChild(a);a.click();a.remove();">抓拍</button>
<div class="row">传输：
<button data-m="auto" onclick="setTr('auto')">自动</button><button data-m="relay" onclick="setTr('relay')">中继</button><button data-m="direct" onclick="setTr('direct')">直连</button>
<span id="tr"></span></div>
<div class="row muted">直连=封relay(:20001)只留局域网（同LAN才有画面）；中继=封局域网发现(:32762)走公网relay；自动=不封路lib自选。切换会重启取流约10秒。</div>
</div>
</div>
<div class="dev-main">
<div class="card">
<div id="stage"><img id="v" src="/video.mjpg" alt="live"></div>
<div id="stats">connecting...</div>
</div>
</div>
</div>
</div>
<div class="tabpage" id="tab-status">
<div class="card"><div id="stats2" class="muted">connecting...</div></div>
</div>
<div class="tabpage" id="tab-cloud">
<div class="card" style="max-width:360px">
<div style="margin-bottom:8px"><input id="c-account" type="email" placeholder="云账号" style="width:100%;padding:8px"></div>
<div style="margin-bottom:8px"><input id="c-password" type="password" placeholder="密码" style="width:100%;padding:8px"></div>
<div style="margin-bottom:8px"><select id="c-region" style="width:100%;padding:8px"><option value="us" selected>美国</option><option value="cn">中国</option><option value="uni">联通</option></select></div>
<button onclick="doCloudLogin()" style="width:100%">登录</button>
<button onclick="doCloudLogout()" class="danger" style="width:100%">退出登录</button>
<div id="cloud-msg" class="muted" style="margin-top:6px"></div>
</div>
<div class="card"><div id="cloud-devs" class="muted">未登录</div></div>
</div>
<script>
function switchTab(t){
  var pages=document.querySelectorAll('.tabpage');
  for(var i=0;i<pages.length;i++){ pages[i].classList.remove('on'); }
  document.getElementById('tab-'+t).classList.add('on');
  var bs=document.querySelectorAll('#navtabs button');
  for(var j=0;j<bs.length;j++){
    if(bs[j].getAttribute('data-tab')===t){ bs[j].classList.add('on'); }
    else { bs[j].classList.remove('on'); }
  }
}
function setTr(m){
  fetch('/api/transport?mode='+m,{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    alert('传输='+d.mode+' 生效='+d.applied+' '+d.detail);
  }).catch(function(){ alert('切换失败'); });
}
function saveDevice(){
  var b={uid:document.getElementById('d-uid').value,
    username:document.getElementById('d-user').value||'admin',
    password:document.getElementById('d-pass').value};
  fetch('/api/device-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});}).then(function(x){
    document.getElementById('dev-msg').textContent=x.ok?('已保存 '+(x.d.uid||'')):(x.d.error||'保存失败');
  }).catch(function(){ document.getElementById('dev-msg').textContent='保存失败'; });
}
function refreshDevice(){
  fetch('/api/device').then(function(r){return r.json();}).then(function(d){
    if(d.uid){ document.getElementById('d-uid').value=d.uid; }
    if(d.username){ document.getElementById('d-user').value=d.username; }
    document.getElementById('dev-msg').textContent=d.uid?('设备 '+(d.has_password?'已配密码':'未配密码')):'未配置设备';
  }).catch(function(){});
}
refreshDevice();
function doCloudLogin(){
  var b={account:document.getElementById('c-account').value,
    password:document.getElementById('c-password').value,
    region:document.getElementById('c-region').value};
  fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});}).then(function(x){
    document.getElementById('cloud-msg').textContent=x.ok?('已登录 '+(x.d.account||'')):(x.d.error||'登录失败');
    refreshCloud();
  }).catch(function(){ document.getElementById('cloud-msg').textContent='登录失败'; });
}
function doCloudLogout(){
  fetch('/api/logout',{method:'POST'}).then(function(){ document.getElementById('cloud-msg').textContent='已退出'; refreshCloud(); });
}
function refreshCloud(){
  fetch('/api/session').then(function(r){return r.json();}).then(function(s){
    if(!s.logged_in){ document.getElementById('cloud-devs').textContent='未登录'; return; }
    document.getElementById('cloud-msg').textContent='已登录 '+(s.account||'')+' · '+s.region;
    fetch('/api/devices').then(function(r){return r.json();}).then(function(d){
      var items=(d.data&&d.data.items)||[];
      document.getElementById('cloud-devs').textContent='共 '+items.length+' 台设备';
    }).catch(function(){});
  }).catch(function(){});
}
refreshCloud();
setInterval(function(){
  fetch('/stats').then(function(r){return r.json();}).then(function(s){
    document.getElementById('stats').textContent =
      (s.running?'LIVE':'idle')+' decoded='+s.decoded+' nals='+s.nals+
      ' subs='+s.subs+' spawns='+s.spawns+' uptime='+s.uptime_s+'s';
    document.getElementById('stats2').textContent =
      document.getElementById('stats').textContent;
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

    def _auth_ok(self):
        want_u, want_p = OPT.get("http_username", ""), OPT.get("http_password", "")
        if not want_p:
            return True
        got = self.headers.get("Authorization", "")
        if not got.startswith("Basic "):
            return False
        try:
            cred = base64.b64decode(got[6:].strip(), validate=True)
        except (ValueError, base64.binascii.Error):
            return False
        expect = ("%s:%s" % (want_u, want_p)).encode("utf-8")
        return hmac.compare_digest(cred, expect)

    def _deny_auth(self):
        body = b"auth required"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ubox"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth_ok():
            self._deny_auth()
            return
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8",
                       PAGE.encode("utf-8"))
        elif path == "/api/session":
            self._send(200, "application/json",
                       json.dumps(
                           {"logged_in": bool(_cloud_token),
                            "account": _cloud_account,
                            "region": _cloud_region}).encode())
        elif path == "/api/devices":
            if not _cloud_token:
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call("/api/v2/user/device_list", {},
                                    _cloud_token)
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
        elif path == "/api/device":
            self._send(200, "application/json",
                       json.dumps(
                           {"uid": DEV["uid"],
                            "username": DEV["username"]
                            or OPT.get("username") or "admin",
                            "has_password": bool(DEV["password"])}).encode())
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

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8")) or {}
        except Exception:
            return {}

    def do_POST(self):
        if not self._auth_ok():
            self._deny_auth()
            return
        path, _, qs = self.path.partition("?")
        q = {}
        for kv in qs.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                q[k] = v
        if path == "/api/login":
            body = self._read_json()
            account = body.get("account") or ""
            password = body.get("password") or ""
            region = body.get("region") or "us"
            _, err = _cloud_login(account, password, region)
            if err:
                self._send(401, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps({"ok": True, "account": _cloud_account,
                                   "region": _cloud_region}).encode())
            return
        if path == "/api/device-login":
            body = self._read_json()
            uid = (body.get("uid") or "").strip()
            username = (body.get("username") or "admin").strip() or "admin"
            password = body.get("password") or ""
            if not uid or not password:
                self._send(400, "application/json",
                           json.dumps(
                               {"error": "need uid and password"}).encode())
                return
            DEV["uid"] = uid
            DEV["username"] = username
            DEV["password"] = password
            _save_device()
            stop_pipeline()
            WAKE.set()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "uid": uid,
                                   "username": username,
                                   "restarted": True}).encode())
            return
        if path == "/api/logout":
            _clear_cloud_session()
            self._send(200, "application/json",
                       json.dumps({"ok": True}).encode())
            return
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
    _load_cloud_session()
    _load_device()
    print("options: stream=%d fps=%d idle=%ds transport=%s http_auth=%s cloud=%s device=%s" % (
        OPT["stream"], OPT["fps"], OPT["idle_timeout"],
        OPT["transport"], "on" if OPT.get("http_password") else "off",
        ("logged_in" if _cloud_token else "logged_out"),
        ("set" if (DEV["uid"] and DEV["password"]) else "empty")),
        flush=True)
    apply_transport(OPT["transport"])
    threading.Thread(target=supervisor, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", OPT["port"]), Handler)
    print("serving on :%d" % OPT["port"], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
