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


# ---- Runtime settings (page-driven, persisted under /data).
SETTINGS_FILE = os.environ.get("UBOX_SETTINGS_FILE", "/data/settings.json")
SETTING_KEYS = ("username", "stream", "fps", "idle_timeout",
                "http_username", "http_password")


def _save_settings():
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
            json.dump({k: OPT.get(k) for k in SETTING_KEYS
                       } | {"saved_at": int(time.time())}, fh)
        try:
            os.chmod(SETTINGS_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return
    if d.get("username"):
        OPT["username"] = d["username"]
    for k, lo, hi in (("stream", 0, 99), ("fps", 1, 15),
                      ("idle_timeout", 15, 600)):
        try:
            v = int(d.get(k, OPT[k]))
        except (TypeError, ValueError):
            continue
        OPT[k] = max(lo, min(hi, v))
    for k in ("http_username", "http_password"):
        if isinstance(d.get(k), str):
            OPT[k] = d[k]


_load_settings()


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
SD_LOCK = threading.Lock()
SD_RUN = {"running": False, "t0": 0}
SD_RUNDIR = "/tmp/ubox_sd"
VOD_LOCK = threading.Lock()
VOD_RUN = {"running": False, "start": None, "log": [], "mp4": None}
VODDIR = "/tmp/ubox_vod"


def parse_sdlist(path):
    """Parse one 0x101 SD list response (same layout as sd_parse.py).

    [0:4] channel LE32, [4] IO, [5] index, [7] count int8, [8:10] total
    LE16, [10] DbInitFlag (1=empty/not-ready, 2=retry, else entries
    follow). [12:] entries of 8B: start unix LE32, len LE16, type, flag.
    """
    import struct as _st
    info = {"ok": False, "channel": None, "io": None, "index": None,
            "count": None, "total": None, "dbflag": None, "note": "",
            "events": []}
    try:
        with open(path, "rb") as fh:
            d = fh.read()
    except OSError as e:
        info["note"] = "read fail: %s" % e
        return info
    info["bytes"] = len(d)
    if len(d) < 12:
        info["note"] = "too short"
        return info
    info["channel"] = _st.unpack("<I", d[0:4])[0]
    info["io"] = d[4]
    info["index"] = d[5]
    info["count"] = _st.unpack("b", d[7:8])[0]
    info["total"] = _st.unpack("<H", d[8:10])[0]
    info["dbflag"] = d[10]
    if d[10] == 1:
        info["ok"] = True
        info["note"] = "DbInitFlag=1: camera DB empty/not-ready"
        return info
    if d[10] == 2:
        info["note"] = "DbInitFlag=2: camera asked 1s retry"
        return info
    n = (len(d) - 12) // 8
    for i in range(n):
        s = _st.unpack("<I", d[12 + i * 8:16 + i * 8])[0]
        ln = _st.unpack("<H", d[16 + i * 8:18 + i * 8])[0]
        info["events"].append({
            "i": i, "start": s, "end": s + ln, "len_s": ln,
            "type": d[18 + i * 8], "flag": d[19 + i * 8],
            "start_h": time.strftime("%Y-%m-%d %H:%M:%SZ",
                                     time.gmtime(s))})
    info["ok"] = True
    return info


def read_sd_live():
    """Peek at 0x101 replies landed so far (no lock, no qemu).

    Merges every ioctl_257_*.bin in SD_RUNDIR, dedupes by start.
    For progressive display while a query is still running.
    """
    evs, seen, files = [], set(), 0
    try:
        paths = sorted(glob.glob(os.path.join(SD_RUNDIR,
                                              "ioctl_257_*.bin")))
    except Exception:
        paths = []
    for p in paths:
        try:
            if os.path.getsize(p) <= 0:
                continue
        except OSError:
            continue
        files += 1
        for e in parse_sdlist(p).get("events", []):
            if e["start"] in seen:
                continue
            seen.add(e["start"])
            e["i"] = len(evs)
            evs.append(e)
    return {"running": SD_RUN["running"],
            "elapsed": (int(time.time() - SD_RUN["t0"])
                        if SD_RUN["running"] and SD_RUN["t0"] else 0),
            "files": files, "events": evs}


def run_sdlist(uid, username, password, hours, secs=40):
    """Run rehost_sdlist via qemu and parse the 0x101 response.

    secs = max wait after the 0x100 request (15~90s, default 40). The
    0x101 reply usually lands seconds after the request, so the qemu
    run is polled every 2s and cut short once ioctl_257_*.bin appears
    and stays stable (~4s); slow cameras still get the full wait.
    Returns (payload_dict, http_code). Callers must hold SD_LOCK
    semantics (one query at a time).
    """
    now = int(time.time())
    hours = max(1, min(168, int(hours or 24)))
    try:
        secs = int(secs or 40)
    except (TypeError, ValueError):
        secs = 40
    secs = max(15, min(90, secs))
    t0 = now
    start, end = now - hours * 3600, now
    sdbin = os.path.join(BINDIR, "rehost_sdlist")
    rundir = SD_RUNDIR
    try:
        os.makedirs(rundir, exist_ok=True)
        for f in glob.glob(os.path.join(rundir, "*")):
            try:
                os.remove(f)
            except OSError:
                pass
    except OSError as e:
        return {"error": "rundir fail: %s" % e}, 500
    if not (os.path.isfile(QEMU) and os.access(QEMU, os.X_OK)):
        return {"error": "missing executable: %s" % QEMU}, 500
    if not (os.path.isfile(sdbin) and os.access(sdbin, os.X_OK)):
        return {"error": "SD P2P 0x101未接入（镜像缺rehost_sdlist）",
                "events": []}, 501
    if not password:
        return {"error": "device password not configured "
                         "(enter on web page)"}, 503
    log = ""
    early = False
    try:
        p = subprocess.Popen(
            [QEMU, "-L", ROOTFS, sdbin, uid, username, password,
             "1", "1", str(secs), str(start), str(end)],
            cwd=rundir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "LD_LIBRARY_PATH": BINDIR})
        deadline = time.time() + 25 + secs
        last_sz, stable = -1, 0
        while True:
            if p.poll() is not None:
                break
            cands = glob.glob(os.path.join(rundir, "ioctl_257_*.bin"))
            if cands:
                try:
                    sz = os.path.getsize(sorted(cands)[0])
                except OSError:
                    sz = -1
                if sz == last_sz and sz > 0:
                    stable += 1
                    if stable >= 2:
                        early = True
                        break
                else:
                    stable = 0
                last_sz = sz
            if time.time() > deadline:
                break
            time.sleep(2)
        if p.poll() is None:
            try:
                p.terminate()
            except Exception:
                pass
            try:
                out, _ = p.communicate(timeout=8)
            except subprocess.TimeoutExpired:
                try:
                    p.kill()
                except Exception:
                    pass
                out, _ = p.communicate()
        else:
            out, _ = p.communicate()
        log = (out or b"").decode("utf-8", errors="replace")[-800:]
    except Exception as e:
        return {"error": "SD查询启动失败：%s" % str(e)[:160],
                "events": []}, 500
    cands = sorted(glob.glob(os.path.join(rundir, "ioctl_257_*.bin")))
    if not cands:
        return {"error": "camera无0x101回包（SD卡可能未插/离线）",
                "uid": uid, "window": [start, end],
                "log_tail": log, "events": []}, 502
    info = parse_sdlist(cands[0])
    with LOCK:
        trmode = TR["mode"]
    info.update({
        "uid": uid, "window": [start, end], "hours": hours,
        "secs": secs, "early": early,
        "elapsed": int(time.time()) - t0,
        "source": {"relay": "p2p-relay", "direct": "p2p-lan"}.get(
            trmode, "p2p-auto"),
        "log_tail": log[-300:] if log else "",
    })
    return info, 200


def vod_extract(src, dst):
    """stream.bin ([len:4][magic 0x0DF0EEBE][data]) -> Annex-B H.265.

    Only keeps 00 00 00 01 payloads (video NALs). Returns (nv, na, bytes).
    """
    import struct as _st
    try:
        with open(src, "rb") as fh:
            d = fh.read()
    except OSError:
        return 0, 0, 0
    off, nv, na = 0, 0, 0
    out = bytearray()
    while off + 8 <= len(d):
        (ln,) = _st.unpack("<I", d[off:off + 4])
        if ln <= 0 or ln > 2000000 or off + 8 + ln > len(d):
            break
        payload = d[off + 8:off + 8 + ln]
        if payload[:4] == b"\x00\x00\x00\x01":
            out += payload
            nv += 1
        else:
            na += 1
        off += 8 + ln
    try:
        with open(dst, "wb") as fh:
            fh.write(bytes(out))
    except OSError:
        return nv, na, 0
    return nv, na, len(out)


def run_sd_vod(uid, username, password, start, length, reqseq=3):
    """Blocking VOD job: rehost_sdlist vod-stream -> mp4.

    Runs qemu (secs=45+len*2, capped 400s), extracts stream.bin to H.265,
    ffmpeg -c copy to VODDIR/回放_<start>.mp4. Updates VOD_RUN log/mp4.
    Returns mp4 path or None.
    """
    length = max(1, min(600, int(length or 60)))
    secs = min(45 + length * 2, 400)
    try:
        reqseq = int(reqseq or 3) & 0xFFFF
    except (TypeError, ValueError):
        reqseq = 3
    sdbin = os.path.join(BINDIR, "rehost_sdlist")
    os.makedirs(VODDIR, exist_ok=True)
    stream = os.path.join(VODDIR, "stream.bin")
    for f in (stream,):
        try:
            os.remove(f)
        except OSError:
            pass
    mp4 = os.path.join(VODDIR, "回放_%s.mp4" % start)
    h265 = os.path.join(VODDIR, "回放_%s.h265" % start)
    if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
        with VOD_LOCK:
            VOD_RUN["log"].append("cache hit: " + os.path.basename(mp4))
            VOD_RUN["mp4"] = mp4
        return mp4
    if not (os.path.isfile(QEMU) and os.access(QEMU, os.X_OK)):
        with VOD_LOCK:
            VOD_RUN["log"].append("missing executable: %s" % QEMU)
        return None
    if not (os.path.isfile(sdbin) and os.access(sdbin, os.X_OK)):
        with VOD_LOCK:
            VOD_RUN["log"].append("SD VOD未接入（镜像缺rehost_sdlist）")
        return None
    with VOD_LOCK:
        VOD_RUN["log"].append("+ vod start=%s len=%d secs=%d" % (
            start, length, secs))
    try:
        p = subprocess.run(
            [QEMU, "-L", ROOTFS, sdbin, uid, username, password,
             "1", "1", str(secs), str(start), "--play", str(reqseq)],
            cwd=VODDIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "LD_LIBRARY_PATH": BINDIR},
            timeout=secs + 60)
        tail = (p.stdout or b"").decode("utf-8", errors="replace")[-300:]
        with VOD_LOCK:
            VOD_RUN["log"].append("qemu exit=%s %s" % (p.returncode, tail))
    except subprocess.TimeoutExpired:
        with VOD_LOCK:
            VOD_RUN["log"].append("VOD超时（%ds无退出）" % (secs + 60))
        return None
    except Exception as e:
        with VOD_LOCK:
            VOD_RUN["log"].append("VOD启动失败：%s" % str(e)[:120])
        return None
    if not (os.path.isfile(stream) and os.path.getsize(stream) > 0):
        with VOD_LOCK:
            VOD_RUN["log"].append("no stream produced")
        return None
    nv, na, nb = vod_extract(stream, h265)
    with VOD_LOCK:
        VOD_RUN["log"].append("extract: video=%d other=%d bytes=%d" % (
            nv, na, nb))
    if nb == 0:
        with VOD_LOCK:
            VOD_RUN["log"].append("无视频帧")
        return None
    try:
        r = subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
             "-r", "30", "-f", "hevc", "-i", h265, "-c", "copy", mp4],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=300)
        with VOD_LOCK:
            VOD_RUN["log"].append("mp4: %s rc=%d" % (
                os.path.basename(mp4), r.returncode))
        if r.returncode == 0 and os.path.isfile(mp4):
            with VOD_LOCK:
                VOD_RUN["mp4"] = mp4
            return mp4
    except Exception as e:
        with VOD_LOCK:
            VOD_RUN["log"].append("ffmpeg失败：%s" % str(e)[:120])
    return None


def _vod_worker(uid, username, password, start, length, reqseq):
    try:
        run_sd_vod(uid, username, password, start, length, reqseq)
    finally:
        with VOD_LOCK:
            VOD_RUN["running"] = False


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


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UBox Camera</title>
<style>
*{box-sizing:border-box}
body{background:#f2f2f2;color:#222;font-family:system-ui,sans-serif;margin:0;padding:16px}
h1{font-size:20px;margin:0 0 12px}
h2{font-size:16px;color:#1a5fb4;margin:22px 0 8px}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px}
input,select{padding:6px 10px;font-size:14px;background:#fff;color:#222;border:1px solid #bbb;border-radius:4px}
button{margin:4px 6px 4px 0;padding:7px 16px;font-size:14px;cursor:pointer;background:#2a6;color:#fff;border:none;border-radius:4px}
button:hover{background:#3b7}
button.danger{background:#a33}button.danger:hover{background:#c44}
button.on{outline:2px solid #2a6}
#grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px}
.ev{background:#fafafa;border:1px solid #ddd;border-radius:6px;padding:6px;font-size:12px}
.ev img{width:100%;display:block;border-radius:4px}
.ev .t{color:#555;margin:4px 0}
.ev .meta{color:#999;font-size:11px;margin:2px 0}
.ev a{color:#1a5fb4;text-decoration:none;margin-right:8px}
.ev a:hover{text-decoration:underline}
.err{color:#c00}.ok{color:#1a7f1a}.muted{color:#888}.warn{color:#d60}
.logout{background:#111;color:#9d9;font-size:12px;font-family:monospace;border-radius:4px;padding:8px;max-height:200px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.navtabs{display:flex;gap:0;background:#fff;border:1px solid #ddd;border-radius:8px;overflow:hidden;margin-bottom:12px}
.navtabs button{flex:1;margin:0;padding:10px 0;font-size:15px;border:none;border-radius:0;background:transparent;color:#666}
.navtabs button.on{background:#2a6;color:#fff}
.tabpage{display:none}
.tabpage.on{display:block}
#dev-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin-top:10px}
.dev-card{background:#fafafa;border:1px solid #ddd;border-radius:8px;padding:10px 12px;font-size:13px;cursor:pointer}
.dev-card:hover{border-color:#4a90d9}
.dev-card.sel{border-color:#2a6;box-shadow:0 0 0 1px #2a6}
.dev-card .nm{font-size:15px;margin-bottom:4px}
.dev-card .st{font-size:12px;color:#555;margin:2px 0}
.dev-card .ft{font-size:13px;margin-top:6px}
.dev-card .enter{color:#1a5fb4;text-decoration:none}
.dev-card .enter:hover{text-decoration:underline}
#stats{margin-top:6px;font-size:13px;color:#1a7f1a;font-family:monospace}
.row{margin-top:10px;font-size:13px;color:#666}
.dev-row{display:flex;gap:12px;align-items:stretch}
.dev-left{flex:1;min-width:0;display:flex;flex-direction:column}
.dev-left #dev-cards{margin-top:10px}
#side-player{flex:1;min-width:0;margin-bottom:0;display:flex;flex-direction:column}
#side-player video{width:100%;flex:1;min-height:0;object-fit:contain;background:#000;border-radius:4px}
@media (max-width:900px){.dev-row{flex-direction:column}#side-player{width:100%;flex:auto}}
</style>
</head>
<body>
<div class="navtabs" id="navtabs" style="display:none">
  <button data-tab="live" onclick="switchTab('live')">内网直播</button>
  <button data-tab="relaylive" onclick="switchTab('relaylive')">中继直播</button>
  <button data-tab="user" onclick="switchTab('user')">用户</button>
  <button data-tab="doc" onclick="switchTab('doc')">接口</button>
</div>

<div id="login-page">
  <div class="card" style="max-width:360px;margin:40px auto" id="login-manual">
    <h2 style="margin-top:0">登录</h2>
    <div style="margin-bottom:8px"><input id="account" type="email" placeholder="云账号" style="width:100%;padding:8px"></div>
    <div style="margin-bottom:8px"><input id="password" type="password" placeholder="密码" style="width:100%;padding:8px"></div>
    <div style="margin-bottom:8px"><select id="region" style="width:100%;padding:8px"><option value="us" selected>美国</option><option value="cn">中国</option><option value="uni">国际</option></select></div>
    <button onclick="doLogin()" style="width:100%">登录</button>
    <div id="login-msg" class="muted" style="margin-top:6px"></div>
  </div>
</div>

<div id="app-page" style="display:none">
<div class="tabpage on" id="tab-dev">
<div class="dev-row">
<div class="dev-left">
<div class="card">
  <div id="dev-detail" class="muted" style="font-size:13px;display:none">待加载</div>
  <div style="margin-top:8px;display:none">
    <select id="dev-list" onchange="renderDevDetail()"><option value="">— 无设备 —</option></select>
  </div>
  <div style="margin-top:4px"><span id="dev-msg" class="muted"></span></div>
  <div id="dev-cards"></div>
</div>
<div class="card" style="min-height:320px">
<h2 style="margin-top:0">功能</h2>
  <div id="func-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px"></div>
</div>
</div>
<div class="card" id="side-player">
  <b>播放器</b>
  <video id="side-vid" controls playsinline style="margin-top:6px"></video>
    <div style="margin-top:6px"><a id="side-dl" href="#" download>下载</a> <span id="side-info" class="muted">未在播</span></div>
  </div>
</div>
<div id="func-inline" style="margin-top:12px"></div>
</div><!-- /tab-dev -->

<div class="tabpage" id="tab-live">
<div class="card">
<div class="dev-row">
<div class="dev-left" style="flex:3">
<b>直播</b>
<div style="margin:8px 0"><button onclick="startLan(1)" style="width:100%">内网直播主</button></div>
<div style="margin:8px 0"><button onclick="startLan(0)" style="width:100%">内网直播辅</button></div>
<div style="margin:8px 0"><button onclick="stopLan()" class="danger" style="width:100%">停止</button></div>
<div id="live-msg" class="muted">idle</div>
<div id="live-stats" class="muted">idle</div>
<pre id="live-log" class="logout">等待启动…</pre>
<div class="muted" style="margin-top:4px">主=1080p / 辅=360p，设备凭证自动取云端，强制局域网直连。切走本页即停看（60秒后管线停）。</div>
<div class="card" style="margin-top:12px;border-color:#2a6">
<b>SD卡录像（局域网直连）</b>
<div style="margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
<label>近 <select id="lan-sd-hours"><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="168">7天</option></select></label>
<label>等待 <select id="lan-sd-secs"><option value="20">20秒</option><option value="40" selected>40秒</option><option value="60">60秒</option><option value="90">90秒</option></select></label>
<button onclick="sdLanList()" style="white-space:nowrap">查询SD列表</button>
<span id="lan-sd-status" class="muted">与直播同走局域网直连P2P（0x101），有回包即提前返回（一般20~40秒），点播前请先确认直播能出画面</span>
</div>
<pre id="lan-sd-log" class="logout">SD就绪（P2P直连查0x101，有回包即提前返回）</pre>
<div id="lan-sd-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-top:8px"></div>
<video id="lan-sd-vid" controls playsinline style="width:100%;margin-top:8px;background:#000;border-radius:4px;display:none"></video>
<div id="lan-sd-playinfo" class="muted" style="margin-top:4px"></div>
<div class="muted" style="margin-top:4px">SD列表/回放走P2P直连设备（非云端）；等待时长可调，有回包即提前返回（一般20~40秒）。同一时间只查一个。</div>
</div>
</div>
<div style="flex:7;min-width:0">
<img id="live-img" alt="live" style="width:100%;display:block;background:#000;border-radius:4px">
</div>
</div>
</div>
</div><!-- /tab-live -->

<div class="tabpage" id="tab-relaylive">
<div class="card">
<div class="dev-row">
<div class="dev-left" style="flex:3">
<b>中继直播</b>
<div style="margin:8px 0"><button onclick="startRelay(1)" style="width:100%">中继直播主</button></div>
<div style="margin:8px 0"><button onclick="startRelay(0)" style="width:100%">中继直播辅</button></div>
<div style="margin:8px 0"><button onclick="stopRelay()" class="danger" style="width:100%">停止</button></div>
<div id="relay-msg" class="muted">idle</div>
<div id="relay-stats" class="muted">idle</div>
<pre id="relay-log" class="logout">等待启动…</pre>
<div class="muted" style="margin-top:4px">主=1080p / 辅=360p，设备凭证自动取云端，强制走公网中继（封局域网发现），异地/跨网段用它。切走本页即停看。</div>
</div>
<div style="flex:7;min-width:0">
<img id="relay-img" alt="live" style="width:100%;display:block;background:#000;border-radius:4px">
</div>
</div>
</div>
</div><!-- /tab-relaylive -->

<div class="tabpage" id="tab-user">
<h2 style="margin-top:0">用户</h2>
<div class="card" style="display:flex;align-items:center;gap:8px">
  <span id="login-user" class="muted"></span>
  <span style="flex:1"></span>
  <button onclick="doLogout()" class="danger" style="margin:0">退出登录</button>
</div>
<div class="card">
  <b>设备统计</b>
  <div id="user-devstats" class="muted" style="margin-top:6px">待加载</div>
</div>
<div class="card">
  <b>会话</b>
  <div id="user-session" class="muted" style="margin-top:6px">待加载</div>
</div>
</div><!-- /tab-user -->

<div class="tabpage" id="tab-doc">
<h2 style="margin-top:0">接口</h2>
<div class="card">
   <div>本机接口：/api/login /api/logout /api/session /api/devices（含sd透传） /api/device /api/device-login /api/device/webrtc_token /api/cloud/list /api/cloud/url /api/sd/list（P2P直连0x101查SD，secs最多等待15~90s、有回包提前返回） /api/sd/list_live（查询中途看已到条目，动态显示用） /api/sd/vod /api/sd/vod_status /api/sd/vod_file（AVCMD command=9点播转mp4） /api/settings /api/transport /stats /snap.jpg /video.mjpg</div>
  <div class="muted" style="margin-top:6px">设备密码与云密码只进容器 /data，不进配置不进仓库。直播推流暂未接入，页面先行。</div>
</div>
</div><!-- /tab-doc -->

</div>
<script>
function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json();});}
function get(u){return fetch(u).then(function(r){return r.json();});}
function curUid(){var s=document.getElementById('dev-list');return s?s.value:'';}
function show(id,msg,ok){document.getElementById(id).innerHTML='<span class="'+(ok?'ok':'muted')+'">'+msg+'</span>';}
function fmsg(msg,ok){var el=document.getElementById('dev-msg2');show(el?'dev-msg2':'dev-msg',msg,ok);var rm=document.getElementById('relay-msg');if(rm)rm.innerHTML='<span class="'+(ok?'ok':'muted')+'">'+msg+'</span>';var lm=document.getElementById('live-msg');if(lm)lm.innerHTML='<span class="'+(ok?'ok':'muted')+'">'+msg+'</span>';}

var _devs=[];
function fmtTime(utc){
  if(!utc)return '—';
  try{return new Date(utc*1000).toLocaleString('zh-CN');}catch(e){return String(utc);}
}
function devLabel(i){
  var parts=[i.name||'?'];
  parts.push(i.online?('[在线]'):('[离线'+(i.online_state?' '+i.online_state:'')+']'));
  if(i.battery!=null)parts.push('电量'+i.battery+'%'+(i.charging?'⚡':''));
  if(i.signal!=null)parts.push('信号'+i.signal);
  parts.push('活跃'+fmtTime(i.last_active_utc));
  return parts.join(' ');
}
function loadDevices(quiet){
  fetch('/api/devices').then(function(r){
    if(r.status===401){showLogin();return null;}
    return r.json();
  }).then(function(d){
    if(!d)return;
    if(d.error){if(!quiet)show('dev-msg',d.error);return;}
    var sel=document.getElementById('dev-list');
    var keep=curUid();
    sel.innerHTML='';
    _devs=d.items||[];
    if(!_devs.length){sel.innerHTML='<option value="">— 无设备 —</option>';renderDevDetail();return;}
    _devs.forEach(function(i){
      var o=document.createElement('option');
      o.value=i.uid;
      o.textContent=devLabel(i);
      o.title=i.uid||'';
      sel.appendChild(o);
    });
    if(keep){try{sel.value=keep;}catch(e){}}
    if(!quiet)show('dev-msg','共 '+_devs.length+' 台设备',true);
    renderDevTabs();
    renderDevDetail();
    renderFuncGrid();
  }).catch(function(e){if(!quiet)show('dev-msg','请求失败：'+e);});
}
function curDev(){
  var uid=curUid();
  for(var k=0;k<_devs.length;k++)if(_devs[k].uid===uid)return _devs[k];
  return null;
}
function renderDevDetail(){
  var i=curDev();
  var el=document.getElementById('dev-detail');
  if(!i){el.textContent='';renderDevCards();return;}
  el.innerHTML=
    '<span class="'+(i.online?'ok':'err')+'">'+(i.online?'●在线':'○离线')+'</span>'+
    ' state='+i.online_state+
    ' · 电量 '+(i.battery!=null?i.battery+'%'+(i.charging?'⚡充电中':''):'—')+
    (i.low_power?' <span class="err">(低电量)</span>':'')+
    ' · 信号 '+(i.signal!=null?i.signal:'—')+
    ' · 最后活跃 '+fmtTime(i.last_active_utc)+
    '<br>型号 '+(i.model||'—')+' · 固件 '+(i.firmware||'—')+
    ' · 云存储 '+(i.has_cloud_storage?'已开通':'未开通')+'/'+(i.cloud_opened?'已开启':'未开启')+
    '<br><span class="muted">'+i.uid+'</span>';
  renderDevCards();
  try{if(document.getElementById('sd-card'))renderSdCard();}catch(e){}
}
function escHtml(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function yn(v){return v?'是':'否';}
function fmtDate(utc){
  if(!utc)return '—';
  try{
    var d=new Date(utc*1000);
    return d.getFullYear()+'-'+('0'+(d.getMonth()+1)).slice(-2)+'-'+('0'+d.getDate()).slice(-2);
  }catch(e){return String(utc);}
}
function tzLabel(td){
  if(td===''||td==null)return '—';
  var h=Number(td)/3600;
  return 'UTC'+(h>=0?'+':'')+h;
}
function modeLabel(m){
  if(m===''||m==null)return '—';
  return {0:'0（常电/默认）',1:'1',2:'2'}[String(m)]||String(m);
}
function renderDevCards(){
  var box=document.getElementById('dev-cards');
  if(!box)return;
  var h='';
  _devs.forEach(function(i){
    var selCls=(i.uid===curUid())?' sel':'';
    var uidq=String(i.uid).replace(/'/g,'');
    var uidc=String(i.uid).replace(/[^A-Za-z0-9]/g,'');
    var open='onclick="selectDev(\''+uidq+'\')"';
    h+='<div class="dev-card'+selCls+'" '+open+'>';
    h+='<div class="nm">'+escHtml(i.name||'?')+' '+(i.online?'<span class="ok">●在线</span>':'<span class="err">○离线</span>')+'</div>';
    h+='<div class="st">电量 '+(i.battery!=null?i.battery+'%'+(i.charging?'⚡充电中':''):'—')+
      (i.low_power?' <span class="err">(低电量)</span>':'')+
      ' · 信号 '+(i.signal!=null?i.signal:'—')+
      ' · 活跃 '+fmtTime(i.last_active_utc)+'</div>';
    h+='<div class="st">型号 '+escHtml(i.model||'—')+' · 固件 '+escHtml(i.firmware||'—')+
      ' · 绑定 '+fmtDate(i.bind_utc)+'</div>';
    h+='<div class="st">归属 '+(i.is_owner?'本人':'他人')+' · 区 '+escHtml(i.ps_name||'—')+
      '/zone'+escHtml(i.zone_id||'—')+' · 时区 '+tzLabel(i.time_diff)+'</div>';
    h+='<div class="st">云存储 '+(i.has_cloud_storage?'已开通':'未开通')+'/'+(i.cloud_opened?'已开启':'未开启')+
      ' · dev_func '+escHtml(i.dev_func||'—')+'</div>';
    h+='<div class="st">设备账号 '+escHtml(i.device_user||'—')+
      (i.has_pwd?' · 已配密码':'')+'</div>';
    h+='<div class="st muted">'+escHtml(i.uid||'')+'</div>';
    h+='</div>';
    h+='<div class="dev-card'+selCls+'" '+open+'>';
    h+='<div class="nm">'+escHtml(i.name||'?')+' <span class="muted">实时流凭证</span></div>';
    h+='<div class="st muted">get_webrtc_token · 云端</div>';
    h+='<div class="st">UID '+escHtml(i.uid||'—')+'</div>';
    h+='<div class="st">账号 '+escHtml(i.device_user||'admin')+'</div>';
    h+='<div class="st">密码 '+(i.device_pwd?escHtml(i.device_pwd):'—')+'</div>';
    h+='<div class="st"><a href="#" onclick="event.stopPropagation();getWebrtc(\''+uidq+'\');return false;">取凭证</a>'+
      '<span id="rtc-'+uidc+'" class="muted"></span></div>';
    h+='</div>';
  });
  box.innerHTML=h||'<span class="muted">无设备</span>';
}
function togglePwd(a){
  var s=a.nextSibling;
  if(s&&s.className==='pwd')s.style.display=(s.style.display==='none')?'inline':'none';
}
var _items=[];
function renderCloudCard(){
  var box=document.getElementById('cloud-card');
  var uid=curUid();
  if(!box||!uid)return;
  var now=Math.floor(Date.now()/1000);
  post('/api/cloud/list',{begin:now-7*86400,end:now,device_uids:[uid]}).then(function(d){
    var el=document.getElementById('cloud-card');
    if(!el)return;
    if(d.error){el.innerHTML='<div class="nm">云录像</div><div class="st err">'+d.error+'</div>';return;}
    var items=((d.data||{}).items)||[];
    if(!items.length){el.innerHTML='<div class="nm">云录像</div><div class="st muted">近7天无录像</div>';return;}
    var first=items[0];
    var img=first.img_url||'';
    el.innerHTML='<div class="nm">云录像 <span class="muted">近7天 '+items.length+' 条</span></div>'+
      (img?'<img src="'+img+'" style="width:100%;display:block;border-radius:4px" onerror="this.style.display=\'none\'">':'')+
      '<div class="st">'+new Date((first.et_utc||0)*1000).toLocaleString('zh-CN')+'</div>';
  }).catch(function(e){
    var el=document.getElementById('cloud-card');
    if(el)el.innerHTML='<div class="nm">云录像</div><div class="st err">加载失败</div>';
  });
}
function renderSdCard(){
  var box=document.getElementById('sd-card');
  var dev=curDev();
  if(!box)return;
  if(!dev){box.innerHTML='<div class="nm">SD卡录像</div><div class="st muted">无设备</div>';return;}
  var sd=dev.sd||{};
  var keys=Object.keys(sd);
  if(!keys.length){box.innerHTML='<div class="nm">SD卡录像</div><div class="st muted">云端未返回SD字段</div>';return;}
  var pick=function(){
    for(var i=0;i<arguments.length;i++){var v=sd[arguments[i]];if(v!==undefined&&v!==null&&v!=='')return v;}
    return null;
  };
  var st=pick('sd_status','sd_state','sdcard_status','sd_card_status','tf_status','sdcard_state');
  var cap=pick('sd_capacity','sd_total','sd_size','storage_total','total_size');
  var free=pick('sd_free','sd_available','storage_free','free_size');
  var mode=pick('record_mode','record_status','sd_record_mode','sd_mode');
  var line=(st!==null?('状态 '+st):'SD字段 '+keys.length+' 项')+
    (cap!==null?(' · 总 '+cap):'')+(free!==null?(' · 剩 '+free):'')+(mode!==null?(' · '+mode):'');
  box.innerHTML='<div class="nm">SD卡录像</div><div class="st">'+escHtml(line)+'</div>'+
    '<div class="st muted">点开看全部SD字段</div>';
}
function queryEvents(){
  var uid=curUid();
  if(!uid){fmsg('请先选择设备');return;}
  var days=parseInt(document.getElementById('days').value,10);
  var now=Math.floor(Date.now()/1000);
  show('list-msg','加载中…');
  post('/api/cloud/list',{begin:now-days*86400,end:now,device_uids:[uid]}).then(function(d){
    if(d.error){show('list-msg',d.error);return;}
    var items=((d.data||{}).items)||[];
    _items=items;
    show('list-msg','共 '+items.length+' 条',true);
    var groups={};
    items.forEach(function(it,i){
      var k=dateKey(it.et_utc||0);
      (groups[k]=groups[k]||[]).push(i);
    });
    var keys=Object.keys(groups).sort().reverse();
    var h='';
    keys.forEach(function(k){
      h+='<div class="tl-hour" style="grid-column:1/-1">'+k+'（'+groups[k].length+'）</div>';
      groups[k].forEach(function(i){
        var it=_items[i];
        var t=new Date((it.et_utc||0)*1000).toLocaleTimeString('zh-CN',{hour12:false});
        var img=it.img_url||'';
        h+='<div class="ev">';
        if(img)h+='<img loading="lazy" src="'+img+'" style="cursor:pointer" title="点击播放" onclick="playUrl('+i+',false)" onerror="this.style.display=\'none\'">';
        h+='<div class="t">'+t+'</div></div>';
      });
    });
    document.getElementById('grid').innerHTML=h||'<span class="muted">无录像</span>';
  });
}
function dateKey(utc){
  var d=new Date(utc*1000);
  var p=function(n){return (n<10?'0':'')+n;};
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate());
}
function playUrl(i,win){
  var it=_items[i];
  if(!it)return;
  show('list-msg','获取播放地址…');
  post('/api/cloud/url',{
    bucket_name:it.bucket,
    cloud_provider:it.cloud_provider||(function(c){return c===1?'1_amazon':(c===2?'2_tencent':'0_aliyun');})((it.cp!=null?it.cp:it.cloud)),
    cloud_provider_int:(it.cp!=null?it.cp:it.cloud),endpoint:it.end_point,
    guid:it.guid||it.itemid,image:it.img,uid:curUid()
  }).then(function(r){
    if(r.error){show('list-msg',r.error);return;}
    var url=r.data&&r.data.video_url;
    if(!url){show('list-msg',JSON.stringify(r).slice(0,200),false);return;}
    show('list-msg','已获取链接 ('+(r.data.expired_second||'?')+'s 有效)',true);
    if(win){window.open(url,'_blank');return;}
    playSide(url,'guid='+(r.data.guid||''));
  });
}
function playSide(url,info){
  var v=document.getElementById('side-vid');
  var box=document.getElementById('side-player');
  if(!v||!box)return;
  try{v.pause();}catch(e){}
  v.src=url;
  try{v.load();var _pr=v.play();if(_pr&&_pr.catch)_pr.catch(function(){});}catch(e){}
  var dl=document.getElementById('side-dl');
  if(dl)dl.href=url;
  var vi=document.getElementById('side-info');
  if(vi)vi.textContent=info||'正在播';
  box.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function probeLanIp(){
  show('dev-msg','addon暂不支持局域网探测');
}
function rtcSpan(uid){
  return document.getElementById('rtc-'+String(uid).replace(/[^A-Za-z0-9]/g,''));
}
function getWebrtc(uid){
  var sp=rtcSpan(uid);
  if(sp)sp.textContent='获取中…';
  post('/api/device/webrtc_token',{uid:uid}).then(function(r){
    if(!sp)return;
    if(r.error){sp.textContent=r.error;return;}
    var d=r.data||{};
    if(!d.temp_account){sp.textContent='raw='+JSON.stringify(r).slice(0,120);return;}
    sp.innerHTML='凭证ok · '+escHtml(d.temp_account)+' · vpg'+escHtml(d.vpg_index);
  }).catch(function(e){if(sp)sp.textContent='请求失败：'+e;});
}
function selectDev(uid){
  var sel=document.getElementById('dev-list');
  if(sel)sel.value=uid;
  renderDevDetail();
  markDevTab();
}

var FUNCS=[
];
function renderFuncGrid(){
  var box=document.getElementById('func-grid');
  if(!box)return;
  var h='';
  FUNCS.forEach(function(f){
    h+='<div class="dev-card" onclick="openFunc(\''+f.id+'\')">';
    h+='<div class="nm">'+f.name+'</div>';
    h+='<div class="st">'+f.desc+'</div></div>';
  });
  box.innerHTML=h;
  if(curUid()){
    box.innerHTML+='<div class="dev-card" id="cloud-card" onclick="openFunc(\'events\')">'+
      '<div class="nm">云录像</div><div class="st muted">加载中…</div></div>';
    renderCloudCard();
    box.innerHTML+='<div class="dev-card" id="sd-card" onclick="openFunc(\'sd\')">'+
      '<div class="nm">SD卡录像</div><div class="st muted">加载中…</div></div>';
    renderSdCard();
  }
}
var _openFunc=null;
function openFunc(id){
  if(_openFunc===id){
    closeFunc();
    _openFunc=null;
    return;
  }
  _openFunc=id;
  buildFuncPage(id);
  var el=document.getElementById('func-inline');
  if(el)el.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function closeFunc(){
  document.getElementById('func-inline').innerHTML='';
  _openFunc=null;
}
function backToDev(){
  closeFunc();
  markDevTab();
}
function funcShell(title, inner){
  document.getElementById('func-inline').innerHTML=
    '<div id="func-body">'+inner+'</div>';
}
function buildFuncPage(id){
  if(id==='lanlive'){
    funcShell('内网直播','<div class="card">'+
      '<button onclick="startLan(1)">内网直播主</button> '+
      '<button onclick="startLan(0)">内网直播辅</button> '+
      '<button onclick="stopLan()" class="danger">停止</button>'+
      '<div id="dev-msg2" class="muted" style="margin-top:6px"></div>'+
      '<div id="stats" style="margin-top:6px">idle</div>'+
      '<div class="muted" style="margin-top:4px">主=1080p / 辅=360p，设备UID/账号/密码自动取云端，强制走局域网直连，画面进右侧播放器。</div></div>');
    return;
  }
  if(id==='events'){
    var d=curDev()||{};
    document.getElementById('func-inline').innerHTML=
      '<div class="card" style="border-color:#2a6"><div style="display:flex;align-items:center;gap:8px;overflow-x:auto;white-space:nowrap">'+
      '<label>时间范围: <select id="days">'+
      '<option value="1">1天</option><option value="3">3天</option>'+
      '<option value="7" selected>7天</option><option value="14">14天</option>'+
      '<option value="30">30天</option></select></label>'+
      '<button onclick="queryEvents()" style="white-space:nowrap">加载</button>'+
      '<span id="list-msg" class="muted"></span></div>'+
      '<div id="grid" style="margin-top:8px"></div></div>';
    queryEvents();
    return;
  }
  if(id==='sd'){
    document.getElementById('func-inline').innerHTML=
      '<div class="card" style="border-color:#2a6"><div class="nm">SD卡录像 <span class="muted">'+escHtml((curDev()||{}).name||'')+'</span></div>'+
      '<div style="display:flex;align-items:center;gap:8px;margin-top:6px;flex-wrap:wrap">'+
      '<label>近 <select id="sd-hours"><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="168">7天</option></select></label>'+
      '<label>等待 <select id="sd-secs"><option value="20">20秒</option><option value="40" selected>40秒</option><option value="60">60秒</option><option value="90">90秒</option></select></label>'+
      '<button onclick="sdList()" style="white-space:nowrap">查询SD列表</button>'+
      '<span id="sd-status" class="muted">P2P直连查0x101，有回包即提前返回（一般20~40秒）；点条目即播右侧播放器</span></div>'+
      '<div id="sd-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-top:8px"></div>'+
      '<div class="muted" style="margin-top:4px">点播走AVCMD command=9（约1~4分钟转mp4），同一时间只跑一个点播。</div>'+
      '<span id="dev-msg2" class="muted"></span></div>';
    sdList();
    return;
  }
  if(id==='snap'){
    funcShell('抓拍','<div class="card"><button onclick="snapNow()">抓拍并下载</button> '+
      '<span id="dev-msg2" class="muted"></span><div id="snap-view" style="margin-top:8px"></div></div>');
    return;
  }
  if(id==='transport'){
    funcShell('传输切换','<div class="card"><div class="row" style="margin-top:0">传输： '+
      '<button data-m="auto" onclick="setTr(\'auto\')">自动</button>'+
      '<button data-m="relay" onclick="setTr(\'relay\')">中继</button>'+
      '<button data-m="direct" onclick="setTr(\'direct\')">直连</button> '+
      '<span id="tr"></span></div>'+
      '<div class="row muted">直连=封relay(:20001)只留局域网；中继=封局域网发现(:32762)走公网relay；自动=lib自选。切换重启取流约10秒。</div>'+
      '<span id="dev-msg2" class="muted"></span></div>');
    return;
  }
  if(id==='device'){
    funcShell('设备凭证','<div class="card">'+
      '<div style="margin-bottom:8px"><input id="d-uid" placeholder="设备UID" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="d-user" placeholder="用户名（默认admin）" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="d-pass" type="password" placeholder="设备密码" style="width:100%;padding:8px"></div>'+
      '<button onclick="saveDevice()" style="width:100%">保存设备并重启取流</button>'+
      '<div id="dev-msg2" class="muted" style="margin-top:6px"></div></div>');
    refreshDevice();
    return;
  }
  if(id==='settings'){
    funcShell('运行参数','<div class="card">'+
      '<div style="margin-bottom:8px"><input id="s-username" placeholder="设备用户名（默认admin）" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="s-stream" type="number" placeholder="码流（0子/1主）" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="s-fps" type="number" min="1" max="15" placeholder="帧率fps" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="s-idle" type="number" placeholder="无人看多久停（秒）" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="s-huser" placeholder="页面账号（空=开放）" style="width:100%;padding:8px"></div>'+
      '<div style="margin-bottom:8px"><input id="s-hpass" type="password" placeholder="页面密码（空=开放）" style="width:100%;padding:8px"></div>'+
      '<button onclick="saveSettings()" style="width:100%">保存参数并重启取流</button>'+
      '<div id="dev-msg2" class="muted" style="margin-top:6px"></div></div>');
    refreshSettings();
    return;
  }
  if(id==='status'){
    funcShell('状态','<div class="card"><div id="stats">connecting...</div><div style="margin-top:6px"><span id="tr"></span></div></div>');
    return;
  }
}
var _directWanted=false;
var _relayWanted=false;
function llog(kind,msg){
  var el=document.getElementById(kind==='relay'?'relay-log':'live-log');
  if(!el)return;
  var t=new Date().toLocaleTimeString('zh-CN',{hour12:false});
  var lines=el.textContent.split('\n');
  lines.push(t+' '+msg);
  if(lines.length>40)lines=lines.slice(-40);
  el.textContent=lines.join('\n');
  el.scrollTop=el.scrollHeight;
}
function startLan(n){startStream('direct',n);}
function startRelay(n){startStream('relay',n);}
function startStream(kind,n){
  var isDirect=(kind==='direct');
  var tab=isDirect?'live':'relaylive';
  var imgId=isDirect?'live-img':'relay-img';
  var modeName=isDirect?'直连':'中继';
  fmsg('取云端设备凭证…');
  llog(kind,'取云端设备凭证…');
  get('/api/devices').then(function(d){
    if(d.error){fmsg(d.error);llog(kind,'devices失败: '+d.error);return null;}
    var items=d.items||[];
    var it=null;
    for(var k=0;k<items.length;k++){if(items[k].uid===curUid()){it=items[k];break;}}
    if(!it)it=items[0];
    if(!it){fmsg('无设备');llog(kind,'无设备');return null;}
    if(!it.device_pwd){fmsg('该设备云端无密码');llog(kind,'云端无密码');return null;}
    fmsg('用 '+(it.name||it.uid)+' 取流…');
    llog(kind,'用 '+(it.name||it.uid)+' 登录，码流'+n);
    return post('/api/device-login',{uid:it.uid,username:it.device_user||'admin',password:it.device_pwd});
  }).then(function(r){
    if(!r)return;
    if(r.error){fmsg(r.error);llog(kind,'device-login失败: '+r.error);return null;}
    llog(kind,'device-login ok');
    return fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stream:n})});
  }).then(function(r){
    if(!r)return null;
    return fetch('/api/transport?mode='+kind,{method:'POST'});
  }).then(function(r){
    if(!r)return;
    return r.json();
  }).then(function(d){
    if(!d)return;
    fmsg(modeName+(n===1?'主':'辅')+'取流中…',true);
    llog(kind,'transport='+d.mode+' 生效='+d.applied+' '+d.detail);
    llog(kind,modeName+(n===1?'主':'辅')+'取流中，等待首帧（约10~30秒）…');
    if(isDirect){_directWanted=true;}else{_relayWanted=true;}
    switchTab(tab);
    var v=document.getElementById(imgId);
    if(v)v.src='/video.mjpg?ts='+Date.now();
  }).catch(function(e){fmsg('启动失败');llog(kind,'启动失败: '+e);});
}
function stopLan(){stopStream('direct');}
function stopRelay(){stopStream('relay');}
function stopStream(kind){
  var isDirect=(kind==='direct');
  if(isDirect){_directWanted=false;}else{_relayWanted=false;}
  fetch('/api/pipeline-stop',{method:'POST'}).then(function(){}).catch(function(){});
  llog(kind,'已停止（管线已掐断）');
  var v=document.getElementById('live-img');
  if(v)v.src='about:blank';
  var g=document.getElementById('relay-img');
  if(g)g.src='about:blank';
  var s=document.getElementById('side-vid');
  if(s)s.src='about:blank';
  fmsg('已停止（管线已掐断）');
}
function snapNow(){
  var v=document.getElementById('snap-view');
  if(v)v.innerHTML='<img src="/snap.jpg?ts='+Date.now()+'" style="width:100%;max-width:480px;display:block;border-radius:4px" onerror="fmsg(\'暂无帧（取流未起）\')">';
  fmsg('已抓拍',true);
}
function sdLanLog(msg){
  var el=document.getElementById('lan-sd-log');
  if(!el)return;
  var t=new Date().toLocaleTimeString('zh-CN',{hour12:false});
  var lines=el.textContent.split('\n');
  lines.push(t+' '+msg);
  if(lines.length>40)lines=lines.slice(-40);
  el.textContent=lines.join('\n');
  el.scrollTop=el.scrollHeight;
}
var _sdEvs=[];
var _sdLiveTimer=null;
function sdEvHtml(e,i,where){
  return '<div class="ev" style="cursor:pointer" title="点击播放" onclick="sdVodPlay('+i+',\''+where+'\')"><div class="t">'+escHtml(e.start_h||String(e.start||''))+'</div>'+
    '<div class="meta">'+escHtml(e.len_s||0)+'s · type '+escHtml(e.type||'')+'</div></div>';
}
function renderSdGrid(gridId,evs,where){
  var g=document.getElementById(gridId);
  if(!g)return;
  var h='';
  evs.forEach(function(e,i){h+=sdEvHtml(e,i,where);});
  g.innerHTML=h||'<span class="muted">空</span>';
}
function sdLivePoll(gridId,stId,where,tail){
  get('/api/sd/list_live').then(function(l){
    if(!l||!l.running)return;
    if((l.events||[]).length){
      _sdEvs=l.events;
      renderSdGrid(gridId,_sdEvs,where);
      var st=document.getElementById(stId);
      if(st)st.textContent='查询中…已收'+_sdEvs.length+'段（'+(l.elapsed||0)+'s）'+tail;
    }
  }).catch(function(){});
}
function sdLiveStart(gridId,stId,where,tail){
  sdLiveStop();
  _sdLiveTimer=setInterval(function(){sdLivePoll(gridId,stId,where,tail);},3000);
}
function sdLiveStop(){
  if(_sdLiveTimer){clearInterval(_sdLiveTimer);_sdLiveTimer=null;}
}
function sdLanList(){
  var st=document.getElementById('lan-sd-status');
  var hours=parseInt((document.getElementById('lan-sd-hours')||{}).value||'24',10)||24;
  var secs=parseInt((document.getElementById('lan-sd-secs')||{}).value||'40',10)||40;
  var uid=curUid();
  if(!uid){if(st)st.textContent='请先选择设备';sdLanLog('无设备');return;}
  if(st)st.textContent='查询中（局域网直连P2P，最多等'+secs+'s）…';
  sdLanLog('查询SD列表 uid='+uid+' 近'+hours+'h 等'+secs+'s');
  sdLiveStart('lan-sd-grid','lan-sd-status','lan','，点条目即播下方播放器');
  post('/api/sd/list',{uid:uid,hours:hours,secs:secs,via:'direct'}).then(function(r){
    sdLiveStop();
    if(r.error){if(st)st.textContent=r.error;sdLanLog('失败: '+r.error);
      document.getElementById('lan-sd-grid').innerHTML='<span class="muted">'+escHtml(r.error)+'</span>';return;}
    var evs=r.events||[];
    _sdEvs=evs;
    if(st)st.textContent='共 '+evs.length+' 段（'+(r.source||'?')+'，用时'+(r.elapsed||'?')+'s'+(r.early?'·提前返回':'')+'），点条目即播下方播放器';
    sdLanLog('返回 '+evs.length+' 段');
    renderSdGrid('lan-sd-grid',evs,'lan');
  }).catch(function(e){sdLiveStop();if(st)st.textContent='请求失败：'+e;sdLanLog('请求失败: '+e);});
}
function sdList(){
  var st=document.getElementById('sd-status');
  var hours=parseInt((document.getElementById('sd-hours')||{}).value||'24',10)||24;
  var secs=parseInt((document.getElementById('sd-secs')||{}).value||'40',10)||40;
  var uid=curUid();
  if(!uid){if(st)st.textContent='请先选择设备';return;}
  if(st)st.textContent='查询中（局域网直连P2P，最多等'+secs+'s）…';
  sdLiveStart('sd-grid','sd-status','side','，点条目即播右侧播放器');
  post('/api/sd/list',{uid:uid,hours:hours,secs:secs,via:'direct'}).then(function(r){
    sdLiveStop();
    var g=document.getElementById('sd-grid');
    if(r.error){if(st)st.textContent=r.error;if(g)g.innerHTML='<span class="muted">'+escHtml(r.error)+'</span>';return;}
    var evs=r.events||[];
    _sdEvs=evs;
    if(st)st.textContent='共 '+evs.length+' 段（'+(r.source||'?')+'，用时'+(r.elapsed||'?')+'s'+(r.early?'·提前返回':'')+'），点条目即播右侧播放器';
    renderSdGrid('sd-grid',evs,'side');
  }).catch(function(e){sdLiveStop();if(st)st.textContent='请求失败：'+e;});
}
var _vodTimer=null;
function sdVodPlay(i,where){
  var e=_sdEvs[i];
  if(!e||!e.start)return;
  var uid=curUid();
  if(!uid)return;
  var info=(e.start_h||e.start)+' · '+(e.len_s||'?')+'s';
  if(where==='lan'){
    var pi=document.getElementById('lan-sd-playinfo');
    if(pi)pi.textContent='点播中 '+info+' …';
    var v=document.getElementById('lan-sd-vid');
    if(v)v.style.display='none';
  }else{
    playSide('about:blank','点播中 '+info+' …');
  }
  sdLanLog('点播 start='+e.start+' len='+(e.len_s||60));
  post('/api/sd/vod',{uid:uid,start:e.start,len:e.len_s||60}).then(function(r){
    if(r.error){
      if(where==='lan'){var p2=document.getElementById('lan-sd-playinfo');if(p2)p2.textContent=r.error;}
      else{playSide('about:blank',r.error);}
      sdLanLog('点播失败: '+r.error);
      return;
    }
    if(r.cached){
      sdVodDone(e.start,where);
      return;
    }
    if(_vodTimer)clearInterval(_vodTimer);
    _vodTimer=setInterval(function(){sdVodPoll(e.start,where);},5000);
    sdVodPoll(e.start,where);
  }).catch(function(ex){
    sdLanLog('点播请求失败: '+ex);
  });
}
function sdVodPoll(start,where){
  get('/api/sd/vod_status').then(function(s){
    var log=(s.log||[]).join(' | ').slice(-160);
    if(where==='lan'){var pi=document.getElementById('lan-sd-playinfo');if(pi)pi.textContent='转码中 '+start+' … '+log;}
    sdLanLog('vod '+start+' running='+s.running+' '+(s.mp4||log));
    if(s.mp4&&(!s.running||s.start===start)){
      if(_vodTimer){clearInterval(_vodTimer);_vodTimer=null;}
      sdVodDone(start,where);
    }else if(!s.running&&!s.mp4){
      if(_vodTimer){clearInterval(_vodTimer);_vodTimer=null;}
      if(where==='lan'){var p3=document.getElementById('lan-sd-playinfo');if(p3)p3.textContent='点播失败 '+log;}
      else{playSide('about:blank','点播失败 '+log);}
    }
  }).catch(function(){});
}
function sdVodDone(start,where){
  var url='/api/sd/vod_file?start='+start;
  if(where==='lan'){
    var v=document.getElementById('lan-sd-vid');
    if(v){v.style.display='block';try{v.pause();}catch(e){}v.src=url;try{v.load();var _p=v.play();if(_p&&_p.catch)_p.catch(function(){});}catch(e){}}
    var pi=document.getElementById('lan-sd-playinfo');
    if(pi)pi.innerHTML='正在播 <a href="'+url+'" download>下载</a>';
    if(v)v.scrollIntoView({behavior:'smooth',block:'nearest'});
  }else{
    playSide(url,'SD回放 start='+start);
  }
}
function setTr(m){
  fetch('/api/transport?mode='+m,{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    fmsg('传输='+d.mode+' 生效='+d.applied+' '+d.detail,true);
  }).catch(function(){ fmsg('切换失败'); });
}
function saveDevice(){
  var b={uid:document.getElementById('d-uid').value,
    username:document.getElementById('d-user').value||'admin',
    password:document.getElementById('d-pass').value};
  fetch('/api/device-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});}).then(function(x){
    fmsg(x.ok?('已保存 '+(x.d.uid||'')):(x.d.error||'保存失败'),x.ok);
  }).catch(function(){ fmsg('保存失败'); });
}
function refreshDevice(){
  fetch('/api/device').then(function(r){return r.json();}).then(function(d){
    var u=document.getElementById('d-uid');
    var n=document.getElementById('d-user');
    if(u&&d.uid)u.value=d.uid;
    if(n&&d.username)n.value=d.username;
    fmsg(d.uid?('设备 '+(d.has_password?'已配密码':'未配密码')):'未配置设备');
  }).catch(function(){});
}
function saveSettings(){
  var b={username:document.getElementById('s-username').value,
    stream:parseInt(document.getElementById('s-stream').value,10),
    fps:parseInt(document.getElementById('s-fps').value,10),
    idle_timeout:parseInt(document.getElementById('s-idle').value,10),
    http_username:document.getElementById('s-huser').value,
    http_password:document.getElementById('s-hpass').value};
  fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});}).then(function(x){
    fmsg(x.ok?'已保存（取流已重启）':(x.d.error||'保存失败'),x.ok);
    refreshSettings();
  }).catch(function(){ fmsg('保存失败'); });
}
function refreshSettings(){
  fetch('/api/settings').then(function(r){return r.json();}).then(function(s){
    var m={username:'s-username',stream:'s-stream',fps:'s-fps',idle_timeout:'s-idle',http_username:'s-huser'};
    for(var k in m){var el=document.getElementById(m[k]);if(el)el.value=s[k]||'';}
    fmsg('页面保护'+(s.has_http_password?'已设密码':'未设（开放）'));
  }).catch(function(){});
}
function doLogin(){
  var acc=document.getElementById('account').value.trim();
  var pwd=document.getElementById('password').value;
  if(!acc||!pwd.trim()){document.getElementById('login-msg').innerHTML='<span class="err">请输入账号密码</span>';return;}
  document.getElementById('login-msg').textContent='登录中…';
  post('/api/login',{account:acc,password:pwd.trim(),region:document.getElementById('region').value}).then(function(r){
    if(r.error){document.getElementById('login-msg').innerHTML='<span class="err">'+r.error+'</span>';return;}
    enterApp();
  });
}
function doLogout(){
  post('/api/logout',{}).then(function(){});
  if(_autoTimer){clearInterval(_autoTimer);_autoTimer=null;}
  showLogin();
  document.getElementById('login-msg').textContent='已退出登录';
}
function enterApp(){
  document.getElementById('login-page').style.display='none';
  document.getElementById('app-page').style.display='block';
  document.getElementById('navtabs').style.display='flex';
  refreshSessionInfo();
  loadDevices();
}
function switchTab(name){
  var pages={live:'tab-live',relaylive:'tab-relaylive',user:'tab-user',doc:'tab-doc'};
  for(var k in pages){
    document.getElementById(pages[k]).className='tabpage'+(k===name?' on':'');
  }
  var devPage=document.getElementById('tab-dev');
  if(devPage)devPage.className='tabpage'+((name==='dev'||name.indexOf('dev:')===0)?' on':'');
  var btns=document.querySelectorAll('#navtabs button');
  for(var i=0;i<btns.length;i++){
    var t=btns[i].getAttribute('data-tab');
    btns[i].className=(t===name||(name.indexOf('dev:')===0&&t===name))?'on':'';
  }
  if(name==='user')refreshSessionInfo();
  var lv=document.getElementById('live-img');
  if(lv){
    if(name==='live'){
      if(_directWanted&&!lv.getAttribute('src'))lv.src='/video.mjpg';
    }else{
      lv.src='about:blank';
    }
  }
  var ri=document.getElementById('relay-img');
  if(ri){
    if(name==='relaylive'){
      if(_relayWanted&&!ri.getAttribute('src'))ri.src='/video.mjpg';
    }else{
      ri.src='about:blank';
    }
  }
}
function renderDevTabs(){
  var bar=document.getElementById('navtabs');
  if(!bar)return;
  var old=bar.querySelectorAll('button[data-tab^="dev:"]');
  for(var i=old.length-1;i>=0;i--)old[i].parentNode.removeChild(old[i]);
  var userBtn=bar.querySelector('button[data-tab="user"]');
  var anchor=bar.querySelector('button[data-tab="live"]')||userBtn;
  _devs.forEach(function(d){
    var b=document.createElement('button');
    b.setAttribute('data-tab','dev:'+d.uid);
    b.textContent=d.name||d.uid||'未知设备';
    b.onclick=(function(uid){return function(){switchDevTab(uid);};})(d.uid);
    bar.insertBefore(b,anchor);
  });
  markDevTab();
}
function markDevTab(){
  var bar=document.getElementById('navtabs');
  if(!bar)return;
  var uid=curUid();
  var btns=bar.querySelectorAll('button');
  for(var i=0;i<btns.length;i++){
    var t=btns[i].getAttribute('data-tab');
    if(t&&t.indexOf('dev:')===0)btns[i].className=(t==='dev:'+uid)?'on':'';
  }
}
function switchDevTab(uid){
  var sel=document.getElementById('dev-list');
  if(sel)sel.value=uid;
  renderDevDetail();
  switchTab('dev:'+uid);
}
function refreshSessionInfo(){
  get('/api/session').then(function(s){
    var label=(s&&s.logged_in)?('已登录 '+(s.account||'—')+' · region '+(s.region||'—')):'未登录';
    document.getElementById('login-user').textContent=label;
    document.getElementById('user-session').textContent=label+'（会话落容器 /data，重启保持）';
  }).catch(function(){document.getElementById('login-user').textContent='—';});
  loadUserStats();
}
function loadUserStats(){
  var el=document.getElementById('user-devstats');
  if(!el)return;
  get('/api/devices').then(function(d){
    if(d.error){el.textContent=d.error;return;}
    var items=d.items||[];
    var on=0, off=0, mine=0, shared=0;
    items.forEach(function(i){
      if(i.online)on++;else off++;
      if(i.is_owner)mine++;else shared++;
    });
    el.innerHTML='共 '+items.length+' 台 · 在线 '+on+' / 离线 '+off+
      ' · 本人 '+mine+' / 他人分享 '+shared;
  }).catch(function(e){el.textContent='加载失败：'+e;});
}
function showLogin(){
  document.getElementById('login-page').style.display='block';
  document.getElementById('app-page').style.display='none';
  document.getElementById('navtabs').style.display='none';
}
var _autoTimer=null;
function toggleAutoRef(){
  if(_autoTimer){clearInterval(_autoTimer);_autoTimer=null;}
  _autoTimer=setInterval(function(){
    try{
      var ap=document.getElementById('app-page');
      if(!ap||ap.style.display==='none')return;
      loadDevices(true);
    }catch(e){}
  },60000);
}
(function tryRestore(){
  get('/api/session').then(function(s){
    if(s&&s.logged_in){enterApp();toggleAutoRef();return;}
    showLogin();
  }).catch(function(){showLogin();});
})();
setInterval(function(){
  var st=document.getElementById('stats');
  var ls=document.getElementById('live-stats');
  var rs=document.getElementById('relay-stats');
  if(!st&&!ls&&!rs)return;
  fetch('/stats').then(function(r){return r.json();}).then(function(s){
    var txt=(s.running?'LIVE':'idle')+' decoded='+s.decoded+' nals='+s.nals+
      ' subs='+s.subs+' spawns='+s.spawns+' uptime='+s.uptime_s+'s';
    if(st)st.textContent=txt;
    if(ls)ls.textContent=txt;
    if(rs)rs.textContent=txt;
    var t=document.getElementById('tr');
    if(t){
      t.textContent='当前='+s.transport+' ('+s.transport_detail+')';
      if(!s.transport_applied){ t.className='warn'; } else { t.className=''; }
    }
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
            d = data.get("data", {}) or {}
            items = d.get("items", []) or []
            infos = d.get("infos", []) or []
            fw = d.get("firmware_ver", []) or []
            fw_map = {str(f.get("model_num")): f.get("version")
                      for f in fw if isinstance(f, dict)}
            info_map = {}
            for inf in infos:
                if isinstance(inf, dict) and inf.get("device_uid"):
                    info_map[inf["device_uid"]] = inf
            result = []
            for it in items:
                uid = it.get("device_uid") or it.get("uid")
                inf = info_map.get(uid, {}) or {}
                dyn = inf.get("dynamic_info", {}) or {}
                model = inf.get("model_num") or it.get("device_model") \
                    or it.get("model", "")
                st = dyn.get("online_state", "")
                online = str(st) in ("1", "2")
                ci = inf.get("card_info", {}) or {}

                def _utc(v):
                    return v if isinstance(v, int) and v > 0 else None

                def _sd_info():
                    # SD/TF card status passthrough from cloud
                    # device_info (inf) + dynamic_info (dyn). Only scalar
                    # values are kept; traffic-SIM card_info keys are
                    # excluded (those live in card_* / icc / esim fields).
                    sd = {}
                    for src in (inf, dyn):
                        if not isinstance(src, dict):
                            continue
                        for k, v in src.items():
                            if not isinstance(v, (str, int, float,
                                                  bool)) and v is not None:
                                continue
                            lk = str(k).lower()
                            if ("sd" in lk or lk.startswith("tf")
                                    or "tf_" in lk or "disk" in lk
                                    or "storage" in lk or "record" in lk
                                    or "sdcard" in lk.replace("_", "")):
                                if ("sim" in lk or "pkg" in lk
                                        or "icc" in lk or "esim" in lk
                                        or "flow" in lk or "expire" in lk
                                        or "ubia_card" in lk
                                        or "cloud_storage" in lk):
                                    continue
                                sd[str(k)] = v
                    return sd

                result.append({
                    "uid": uid,
                    "name": it.get("device_name")
                    or inf.get("device_name") or it.get("name", ""),
                    "model": model,
                    "firmware": fw_map.get(str(model), ""),
                    "online": online,
                    "online_state": st,
                    "battery": dyn.get("battery"),
                    "charging": dyn.get("is_battery_charging", False),
                    "signal": dyn.get("signal"),
                    "low_power": dyn.get("is_low_power", False),
                    "last_active_utc": dyn.get("latest_active_utc"),
                    "has_cloud_storage": inf.get("has_cloud_storage",
                                                 False),
                    "cloud_opened": inf.get("is_cloud_storage_opened",
                                            False),
                    "bind_utc": _utc(it.get("add_utc")
                                     or inf.get("add_utc")),
                    "is_owner": it.get("is_owner",
                                       inf.get("is_owner", False)),
                    "ps_name": it.get("ps_name") or inf.get("ps_name", ""),
                    "zone_id": it.get("zone_id", inf.get("zone_id", "")),
                    "address_id": it.get("address_id")
                    or inf.get("address_id", ""),
                    "device_user": inf.get("device_user", ""),
                    "has_pwd": bool(inf.get("device_pwd")),
                    "device_pwd": inf.get("device_pwd", "") or "",
                    "dev_func": inf.get("dev_func", ""),
                    "time_diff": inf.get("time_diff", ""),
                    "cur_work_mode": inf.get("cur_work_mode", ""),
                    "want_work_mode": inf.get("want_work_mode", ""),
                    "is_panoramic": inf.get("is_panoramic_device", False),
                    "notice_on": it.get("notice_on",
                                        inf.get("notice_on", False)),
                    "can_insert_sim": it.get(
                        "can_insert_sim_card",
                        inf.get("can_insert_sim_card", False)),
                    "card_pkg_flow": ci.get("card_pkg_flow_status", ""),
                    "card_pkg_expire": ci.get("card_pkg_expire_status",
                                              ""),
                    "is_lifetime_plan": ci.get("is_lifetime_plan", False),
                    "is_ubia_card": ci.get("is_ubia_card", False),
                    "is_lock": ci.get("is_lock", False),
                    "has_icc": bool(ci.get("icc_id")
                                    or ci.get("icc_id_1")
                                    or ci.get("icc_id_2")),
                    "alexa_status": inf.get("alexa_status", ""),
                    "alexa_id": inf.get("alexa_id", ""),
                    "is_ap_device": inf.get("is_ap_device", False),
                    "location": inf.get("location", ""),
                    "is_dst": inf.get("is_dst_enabled", False),
                    "notice_enabled": inf.get("is_notice_enabled", False),
                    "ext_notice": [(e.get("name", ""),
                                    e.get("is_enabled", False))
                                   for e in (inf.get(
                                       "ext_notice_info_list") or [])
                                   if isinstance(e, dict)],
                    "permissions": inf.get("permissions", ""),
                    "product_id": inf.get("product_id", ""),
                    "device_type": inf.get("device_type", ""),
                    "esim_eid": ci.get("esim_eid", ""),
                    "using_esim": ci.get("using_card_is_esim", False),
                    "is_ubia_esim": ci.get("is_ubia_esim", False),
                    "suggest_sync_traffic": ci.get(
                        "policy_suggest_sync_traffic", False),
                    "pkg_bound_on_user": ci.get("is_pkg_bound_on_user",
                                                 False),
                    "sd": _sd_info(),
                    "lan_ip": None,
                    "lan_port": None,
                    "sid": None,
                    "sess_random": None,
                    "sess_nonce": None,
                    "sess_result": None,
                })
            self._send(200, "application/json",
                       json.dumps({"items": result, "firmware_ver": fw,
                                   "raw_code": data.get("code"),
                                   "raw_msg": data.get("msg")}).encode())
        elif path == "/api/device":
            self._send(200, "application/json",
                       json.dumps(
                           {"uid": DEV["uid"],
                            "username": DEV["username"]
                            or OPT.get("username") or "admin",
                            "has_password": bool(DEV["password"])}).encode())
        elif path == "/api/settings":
            self._send(200, "application/json",
                       json.dumps(
                           {"username": OPT.get("username") or "admin",
                            "stream": OPT["stream"], "fps": OPT["fps"],
                            "idle_timeout": OPT["idle_timeout"],
                            "http_username": OPT.get("http_username") or "",
                            "has_http_password": bool(
                                OPT.get("http_password"))}).encode())
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
            if not DEV["uid"] or not DEV["password"]:
                self._send(503, "text/plain",
                           b"device not configured (enter on web page)")
                return
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
        elif path == "/api/sd/list_live":
            self._send(200, "application/json",
                       json.dumps(read_sd_live()).encode())
            return
        elif path == "/api/sd/vod_status":
            with VOD_LOCK:
                mp4 = VOD_RUN["mp4"]
                self._send(200, "application/json",
                           json.dumps(
                               {"running": VOD_RUN["running"],
                                "start": VOD_RUN["start"],
                                "log": list(VOD_RUN["log"][-20:]),
                                "mp4": (os.path.basename(mp4)
                                        if mp4 else None)}).encode())
            return
        elif path == "/api/sd/vod_file":
            qs = (self.path.split("?", 1)[1]
                  if "?" in self.path else "")
            q = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    q[k] = v
            try:
                start = int(q.get("start", "0") or 0)
            except ValueError:
                start = 0
            mp4 = os.path.join(VODDIR, "回放_%s.mp4" % start)
            if not (os.path.isfile(mp4) and os.path.getsize(mp4) > 0):
                self._send(404, "text/plain", b"vod not ready")
                return
            try:
                with open(mp4, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send(404, "text/plain", b"vod not ready")
                return
            self._send(200, "video/mp4", body)
            return
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
        if path == "/api/settings":
            body = self._read_json()
            if body.get("username") is not None:
                OPT["username"] = str(body["username"] or "admin")
            for k, lo, hi in (("stream", 0, 99), ("fps", 1, 15),
                              ("idle_timeout", 15, 600)):
                if body.get(k) is not None:
                    try:
                        OPT[k] = max(lo, min(hi, int(body[k])))
                    except (TypeError, ValueError):
                        pass
            if body.get("http_username") is not None:
                OPT["http_username"] = str(body["http_username"] or "")
            if body.get("http_password") is not None:
                OPT["http_password"] = str(body["http_password"] or "")
            _save_settings()
            stop_pipeline()
            WAKE.set()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "restarted": True}).encode())
            return
        if path == "/api/cloud/list":
            body = self._read_json()
            if not _cloud_token:
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            now = int(time.time())
            req = {"begin": body.get("begin", now - 7 * 86400),
                   "end": body.get("end", now),
                   "device_uids": body.get("device_uids", [])}
            data, err = _cloud_call("/api/user/qry/cloudvideo/list/v2",
                                    req, _cloud_token)
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
            return
        if path == "/api/cloud/url":
            body = self._read_json()
            if not _cloud_token:
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call(
                "/api/user/qry/cloudvideo/get_video_url", {
                    "bucket_name": body.get("bucket_name"),
                    "cloud_provider": body.get("cloud_provider"),
                    "cloud_provider_int": body.get("cloud_provider_int", 1),
                    "endpoint": body.get("endpoint"),
                    "guid": body.get("guid") or body.get("itemid"),
                    "image": body.get("image"),
                    "uid": body.get("uid", ""),
                }, _cloud_token)
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
            return
        if path == "/api/device/webrtc_token":
            body = self._read_json()
            uid = body.get("uid") or ""
            if not uid:
                self._send(400, "application/json",
                           json.dumps({"error": "need uid"}).encode())
                return
            if not _cloud_token:
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call(
                "/api/user/qry/device/get_webrtc_token", {"uid": uid},
                _cloud_token)
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
            return
        if path == "/api/pipeline-stop":
            stop_pipeline()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "running": False}).encode())
            return
        if path == "/api/sd/list":
            # SD list goes P2P direct to the device (0x101 via
            # rehost_sdlist), same path family as LAN live.
            body = self._read_json()
            uid = (body.get("uid") or "").strip()
            if not uid:
                self._send(400, "application/json",
                           json.dumps({"error": "need uid"}).encode())
                return
            if not SD_LOCK.acquire(blocking=False):
                self._send(409, "application/json",
                           json.dumps({"error": "SD查询进行中，稍后再试",
                                       "events": []}).encode())
                return
            try:
                SD_RUN["running"] = True
                SD_RUN["t0"] = int(time.time())
                _load_device()
                username = DEV["username"] or OPT.get("username") or "admin"
                payload, code = run_sdlist(uid, username,
                                           DEV["password"],
                                           body.get("hours", 24),
                                           body.get("secs", 40))
            except Exception as e:
                payload, code = ({"error": "SD查询异常：%s" % str(e)[:160],
                                  "events": []}, 500)
            finally:
                SD_RUN["running"] = False
                SD_LOCK.release()
            self._send(code, "application/json",
                       json.dumps(payload).encode())
            return
        if path == "/api/sd/vod":
            # SD VOD: AVCMD command=9 vod-stream via rehost_sdlist,
            # extract stream.bin -> mp4, async (poll vod_status, play
            # vod_file in the side player).
            body = self._read_json()
            uid = (body.get("uid") or "").strip()
            try:
                start = int(body.get("start", 0) or 0)
            except (TypeError, ValueError):
                start = 0
            try:
                length = max(1, min(600, int(body.get("len", 60)
                                            or body.get("length", 60)
                                            or 60)))
            except (TypeError, ValueError):
                length = 60
            if not uid or not start:
                self._send(400, "application/json",
                           json.dumps({"error": "need uid and start"})
                           .encode())
                return
            _load_device()
            username = DEV["username"] or OPT.get("username") or "admin"
            password = DEV["password"]
            if not password:
                self._send(503, "application/json",
                           json.dumps({"error": "device password not "
                                                "configured (enter on web "
                                                "page)"}).encode())
                return
            mp4 = os.path.join(VODDIR, "回放_%s.mp4" % start)
            if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
                with VOD_LOCK:
                    VOD_RUN["start"] = start
                    VOD_RUN["mp4"] = mp4
                self._send(200, "application/json",
                           json.dumps({"ok": True, "start": start,
                                       "cached": True,
                                       "mp4": os.path.basename(mp4)})
                           .encode())
                return
            if not VOD_LOCK.acquire(blocking=False):
                self._send(409, "application/json",
                           json.dumps({"error": "SD点播进行中，稍后再试"})
                           .encode())
                return
            try:
                with VOD_LOCK:
                    if VOD_RUN["running"]:
                        self._send(409, "application/json",
                                   json.dumps(
                                       {"error": "SD点播进行中，稍后再试"})
                                   .encode())
                        return
                    VOD_RUN["running"] = True
                    VOD_RUN["start"] = start
                    VOD_RUN["log"] = []
                    VOD_RUN["mp4"] = None
                secs = min(45 + length * 2, 400)
                threading.Thread(target=_vod_worker,
                                 args=(uid, username, password, start,
                                       length, body.get("reqseq", 3)),
                                 daemon=True).start()
            except Exception:
                with VOD_LOCK:
                    VOD_RUN["running"] = False
                VOD_LOCK.release()
                raise
            else:
                VOD_LOCK.release()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "start": start,
                                   "cached": False, "secs": secs}).encode())
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
