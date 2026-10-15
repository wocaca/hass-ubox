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
(stream endpoints also accept ?key=<http_password> for browsers that
strip embedded user:pass@).
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
import urllib.parse
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
    file_opt = {}
    try:
        with open(OPTFILE, encoding="utf-8") as fh:
            file_opt = json.load(fh) or {}
            if not isinstance(file_opt, dict):
                file_opt = {}
            opt.update(file_opt)
    except (OSError, ValueError):
        pass
    # HASS 配置页是 http 鉴权的权威来源：文件里显式带了就记住，
    # _load_settings() 之后再覆盖一次（见 _load_settings() 调用处）。
    opt["_hass_http"] = {k: file_opt[k] for k in
                         ("http_username", "http_password")
                         if isinstance(file_opt.get(k), str)}
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


# ---- Saved cloud credentials (page login persists account+password under
# /data so the cloud API stays logged in across restarts and auto re-logs
# on token expiry. Explicit user choice (reverses the old never-store rule);
# file is 0600, never in the image or repo.
CLOUD_CREDS_FILE = os.environ.get("UBOX_CLOUD_CREDS_FILE",
                                  "/data/cloud.json")
_cloud_password = ""


def _save_cloud_creds(account, password, region):
    global _cloud_password
    _cloud_password = password or ""
    try:
        with open(CLOUD_CREDS_FILE, "w", encoding="utf-8") as fh:
            json.dump({"account": account, "password": password,
                       "region": region,
                       "saved_at": int(time.time())}, fh)
        try:
            os.chmod(CLOUD_CREDS_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass


def _load_cloud_creds():
    global _cloud_password
    try:
        with open(CLOUD_CREDS_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
        if d.get("account") and d.get("password"):
            _cloud_password = d["password"]
            return (d["account"], d["password"], d.get("region") or "us")
    except (OSError, ValueError):
        pass
    return None


def _has_saved_cloud_creds():
    try:
        with open(CLOUD_CREDS_FILE, encoding="utf-8") as fh:
            d = json.load(fh)
        return bool(d.get("account") and d.get("password"))
    except (OSError, ValueError):
        return False


def _clear_cloud_creds():
    global _cloud_password
    _cloud_password = ""
    try:
        os.remove(CLOUD_CREDS_FILE)
    except OSError:
        pass


def _auto_login():
    """One-shot login with saved creds. True on success, no loops."""
    creds = _load_cloud_creds()
    if not creds:
        return False
    _, err = _cloud_login(*creds)
    if err:
        return False
    _ensure_device_from_cloud(allow_pick=False)
    return True


def _cloud_token_dead(data, err):
    if err and (err.startswith("HTTP 401") or err.startswith("HTTP 403")):
        return True
    try:
        return isinstance(data, dict) and data.get("code") == 10004
    except Exception:
        return False


def _cloud_call_auto(path, body):
    """Cloud call that survives token expiry: at most one re-login retry."""
    if not _cloud_token and not _auto_login():
        return None, "not logged in (auto login failed)"
    data, err = _cloud_call(path, body, _cloud_token)
    if _cloud_token_dead(data, err):
        _clear_cloud_session()
        if not _auto_login():
            return None, "not logged in (auto login failed)"
        data, err = _cloud_call(path, body, _cloud_token)
    return data, err


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


def _resolve_device(uid):
    """(username, password, err) for P2P paths (SD list/VOD/live).

    Prefers cached DEV (device.json); falls back to the cloud device_list
    (same source the live page uses) and persists what it finds, so a
    fresh container works with zero manual device setup.
    """
    _load_device()
    if DEV["uid"] == uid and DEV["password"]:
        return (DEV["username"] or OPT.get("username") or "admin",
                DEV["password"], None)
    data, err = _cloud_call_auto("/api/v2/user/device_list", {})
    if err:
        return (None, None, err)
    try:
        d = (data.get("data", {}) or {})
        infos = {}
        for inf in (d.get("infos", []) or []):
            if isinstance(inf, dict) and inf.get("device_uid"):
                infos[inf["device_uid"]] = inf
        for it in (d.get("items", []) or []):
            if not isinstance(it, dict):
                continue
            if (it.get("device_uid") or it.get("uid")) != uid:
                continue
            inf = infos.get(uid, {}) or {}
            pwd = inf.get("device_pwd", "") or ""
            if not pwd:
                return (None, None,
                        "该设备云端无密码（进设备页手动填一次）")
            username = (inf.get("device_user", "") or "admin")
            DEV["uid"] = uid
            DEV["username"] = username
            DEV["password"] = pwd
            _save_device()
            return (username, pwd, None)
    except Exception as e:
        return (None, None, "device resolve failed: %s" % str(e)[:120])
    return (None, None, "云端无此设备（uid 对不上，先进设备页刷新）")


def _cloud_device_creds(data):
    """Yield (uid, username, password, online, name) from device_list."""
    d = (data.get("data", {}) or {}) if isinstance(data, dict) else {}
    infos = {}
    for inf in (d.get("infos", []) or []):
        if isinstance(inf, dict) and inf.get("device_uid"):
            infos[inf["device_uid"]] = inf
    for it in (d.get("items", []) or []):
        if not isinstance(it, dict):
            continue
        uid = it.get("device_uid") or it.get("uid") or ""
        if not uid:
            continue
        inf = infos.get(uid, {}) or {}
        dyn = inf.get("dynamic_info", {}) or {}
        yield (uid,
               inf.get("device_user", "") or it.get("device_user", "")
               or "admin",
               inf.get("device_pwd", "") or it.get("device_pwd", "") or "",
               str(dyn.get("online_state", "")) in ("1", "2"),
               it.get("name", "") or it.get("device_name", ""))


def _ensure_device_from_cloud(allow_pick=True):
    """Persist device.json from the cloud device list (best effort).

    Called after (auto) login so a fresh container can stream with zero
    manual device setup. Keeps the current DEV uid when still present
    (refreshing its password); otherwise picks the first online device
    with a password. With allow_pick=False only fills an empty DEV,
    never switches a configured device. Never raises.
    """
    try:
        _load_device()
        data, err = _cloud_call_auto("/api/v2/user/device_list", {})
        if err:
            return None, "devices: %s" % err
        cands = [c for c in _cloud_device_creds(data) if c[2]]
        if not cands:
            return None, "cloud devices have no password (enter on web page)"
        if DEV["uid"] and DEV["password"]:
            keep = next((c for c in cands if c[0] == DEV["uid"]), None)
            if keep:
                DEV["username"], DEV["password"] = keep[1], keep[2]
                _save_device()
                return keep[0], "kept %s" % keep[0]
            if not allow_pick:
                return None, "saved uid not in cloud list"
        cands.sort(key=lambda c: (not c[3],))
        uid, username, password = cands[0][:3]
        nm = cands[0][4]
        DEV["uid"], DEV["username"], DEV["password"] = uid, username, password
        _save_device()
        return uid, "picked %s%s" % (uid, (" (%s)" % nm) if nm else "")
    except Exception as e:
        return None, "device auto-save failed: %s" % str(e)[:120]


# ---- Persistent P2P session (manual connect switch; SD list reuses it).
# One long-lived rehost_sdlist daemon (argv "daemon") holds the session;
# LIST commands go through ./sess.cmd fifo, replies land as ioctl_*.bin
# like one-shot mode. Idle auto-disconnect saves solar-battery power.
SESS_DIR = "/tmp/ubox_sess"
SESS_CMD = os.path.join(SESS_DIR, "sess.cmd")
SESS_LOG = os.path.join(SESS_DIR, "sess.log")
SESS_IDLE = 300
SESS = {"proc": None, "running": False, "ready": False, "uid": "",
        "t0": 0, "last": 0, "note": "", "tr": ""}
SESS_LOCK = threading.Lock()
SESS_CMD_LOCK = threading.Lock()


def _sess_log_tail(n=200):
    try:
        with open(SESS_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            sz = fh.tell()
            fh.seek(max(0, sz - 2000))
            return fh.read().decode("utf-8", errors="replace")[-n:]
    except OSError:
        return ""


def _sess_log_has(marker):
    try:
        with open(SESS_LOG, "rb") as fh:
            return marker.encode() in fh.read()
    except OSError:
        return False


def _sess_hs():
    """Parse observed handshake params from the daemon log.

    randomID (our login random), client_start ret (session handle ~ sid),
    SESSION-READY via (which callback fired). Missing keys stay absent —
    never fabricated.
    """
    try:
        with open(SESS_LOG, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            sz = fh.tell()
            fh.seek(max(0, sz - 6000))
            log = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return {}
    out = {}
    m = re.search(r"randomID=(-?\d+)", log)
    if m:
        out["hs_random"] = m.group(1)
    m = re.search(r"client_start ret=(-?\d+)", log)
    if m:
        out["hs_sid"] = m.group(1)
    m = re.findall(r"SESSION-READY via (\S+)", log)
    if m:
        out["hs_ready_via"] = m[-1]
    return out


def sess_start(uid, username, password):
    """Spawn the session daemon; wait for SESSION-READY (cap 40s)."""
    with SESS_LOCK:
        p = SESS.get("proc")
        if p is not None and p.poll() is None:
            if SESS["uid"] == uid:
                SESS["last"] = int(time.time())
                return True, "already connected"
            return False, "另一设备已建联（先断开）"
        sess_stop_locked()
        try:
            os.makedirs(SESS_DIR, exist_ok=True)
            for f in glob.glob(os.path.join(SESS_DIR, "*")):
                try:
                    os.remove(f)
                except OSError:
                    pass
            os.mkfifo(SESS_CMD)
        except OSError as e:
            return False, "sess dir fail: %s" % e
        sdbin = os.path.join(BINDIR, "rehost_sdlist")
        if not (os.path.isfile(QEMU) and os.access(QEMU, os.X_OK)):
            return False, "missing executable: %s" % QEMU
        if not (os.path.isfile(sdbin) and os.access(sdbin, os.X_OK)):
            return False, "SD P2P未接入（镜像缺rehost_sdlist）"
        try:
            logfh = open(SESS_LOG, "wb")
        except OSError as e:
            return False, "sess log fail: %s" % e
        try:
            p = subprocess.Popen(
                [QEMU, "-L", ROOTFS, sdbin, uid, username, password,
                 "1", "1", "daemon"],
                cwd=SESS_DIR, stdout=logfh, stderr=subprocess.STDOUT,
                env={**os.environ, "LD_LIBRARY_PATH": BINDIR})
        except Exception as e:
            try:
                logfh.close()
            except Exception:
                pass
            return False, "sess spawn failed: %s" % str(e)[:120]
        SESS.update(proc=p, running=True, ready=False, uid=uid,
                    t0=int(time.time()), last=int(time.time()), note="",
                    tr=TR["mode"])
    for _ in range(40):
        time.sleep(1)
        if p.poll() is not None:
            with SESS_LOCK:
                SESS.update(running=False, ready=False,
                            note="daemon过早退出")
            return False, "daemon过早退出（见sess.log）"
        if _sess_log_has("SESSION-READY"):
            with SESS_LOCK:
                SESS["ready"] = True
                SESS["last"] = int(time.time())
            return True, "connected"
    return False, "建联超时（40秒无SESSION-READY）"


def sess_stop_locked():
    p = SESS.get("proc")
    SESS.update(proc=None, running=False, ready=False, note="")
    if p is None:
        return
    if p.poll() is None:
        try:
            with open(SESS_CMD, "w") as fh:
                fh.write("QUIT\n")
        except OSError:
            pass
        try:
            p.wait(timeout=8)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass


def sess_stop(auto=False):
    with SESS_LOCK:
        was = SESS["running"]
        sess_stop_locked()
        if auto and was:
            SESS["note"] = "闲置自动断开"
    return was


def sess_status():
    with SESS_LOCK:
        p = SESS.get("proc")
        alive = p is not None and p.poll() is None
        if not alive:
            if SESS["running"]:
                SESS["note"] = "daemon已退出"
            SESS.update(proc=None, running=False, ready=False)
        now = int(time.time())
        up = alive and SESS["running"]
        idle_left = (max(0, SESS_IDLE - (now - (SESS["last"] or now)))
                     if up else 0)
        return {"up": up, "ready": SESS["ready"] and alive,
                "uid": SESS["uid"] if up else "",
                "uptime_s": (now - SESS["t0"]) if (up and SESS["t0"]) else 0,
                "idle_left_s": idle_left, "note": SESS["note"],
                "sess_tr": SESS.get("tr", ""),
                "hs": _sess_hs(),
                "log_tail": _sess_log_tail()}


def sess_usable(uid):
    """Daemon reusable for uid right now (up+ready+same uid+same transport)."""
    st = sess_status()
    with LOCK:
        trmode = TR["mode"]
    return (st["up"] and st["ready"] and st["uid"] == uid
            and (st.get("sess_tr") or "") == trmode)


def _sess_send_cmd(cmd):
    """Write one command line to the daemon fifo."""
    try:
        with open(SESS_CMD, "w") as fh:
            fh.write(cmd + "\n")
        return None
    except OSError as e:
        return "会话命令失败：%s" % e


def sess_supervisor():
    while True:
        time.sleep(10)
        try:
            with SESS_LOCK:
                p = SESS.get("proc")
                overdue = (p is not None and p.poll() is None
                           and SESS["running"]
                           and int(time.time()) - (SESS["last"] or 0)
                           > SESS_IDLE)
        except Exception:
            overdue = False
        if overdue:
            sess_stop(auto=True)


def sess_cmd_list(uid, start, end, timeout=60):
    """LIST through the daemon. Same return shape as run_sdlist."""
    t0 = int(time.time())
    with SESS_LOCK:
        p = SESS.get("proc")
        if p is None or p.poll() is not None or not SESS["ready"]:
            return {"error": "未建联（先点建联）", "events": []}, 503
        if SESS["uid"] != uid:
            return {"error": "设备不一致（先断开重建）", "events": []}, 409
        try:
            before = set(glob.glob(os.path.join(SESS_DIR,
                                                "ioctl_257_*.bin")))
        except Exception:
            before = set()
    if not SESS_CMD_LOCK.acquire(timeout=15):
        return {"error": "会话忙（稍后再试）", "events": []}, 409
    try:
        err = _sess_send_cmd("LIST %d %d" % (start, end))
        if err:
            return {"error": err, "events": []}, 500
        with SESS_LOCK:
            SESS["last"] = int(time.time())
        deadline = time.time() + timeout
        hit, last_sz, stable = None, -1, 0
        while time.time() < deadline:
            try:
                now = set(glob.glob(os.path.join(SESS_DIR,
                                                 "ioctl_257_*.bin")))
            except Exception:
                now = set()
            new = sorted(now - before)
            if new:
                try:
                    sz = os.path.getsize(new[0])
                except OSError:
                    sz = -1
                if sz == last_sz and sz > 0:
                    stable += 1
                    if stable >= 2:
                        hit = new[0]
                        break
                else:
                    stable = 0
                last_sz = sz
            time.sleep(1)
    finally:
        SESS_CMD_LOCK.release()
    if hit is None:
        return {"error": "camera无0x101回包（SD卡可能未插/离线）",
                "uid": uid, "window": [start, end],
                "via": "sess-daemon", "events": []}, 502
    info = parse_sdlist(hit)
    with LOCK:
        trmode = TR["mode"]
    info.update({
        "uid": uid, "window": [start, end], "via": "sess-daemon",
        "elapsed": int(time.time()) - t0,
        "source": {"relay": "p2p-relay", "direct": "p2p-lan"}.get(
            trmode, "p2p-auto"),
    })
    return info, 200


def sess_cmd_play(uid, evstart, reqseq=3, timeout=30):
    """PLAY through the daemon. Returns (stream_path, err)."""
    with SESS_LOCK:
        p = SESS.get("proc")
        if p is None or p.poll() is not None or not SESS["ready"]:
            return None, "未建联（先点建联）"
        if SESS["uid"] != uid:
            return None, "设备不一致（先断开重建）"
        try:
            before = set(glob.glob(os.path.join(SESS_DIR, "stream_*.bin")))
        except Exception:
            before = set()
    if not SESS_CMD_LOCK.acquire(timeout=15):
        return None, "会话忙（稍后再试）"
    try:
        err = _sess_send_cmd("PLAY %d %d" % (evstart, reqseq))
        if err:
            return None, err
        with SESS_LOCK:
            SESS["last"] = int(time.time())
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                now = set(glob.glob(os.path.join(SESS_DIR, "stream_*.bin")))
            except Exception:
                now = set()
            new = sorted(now - before)
            if new:
                return new[0], None
            time.sleep(1)
        return None, "点播无流（PLAY后30秒无帧文件）"
    finally:
        SESS_CMD_LOCK.release()


def sess_cmd_seek():
    """SEEK (AVCMD 7) through the daemon. Best-effort, returns err/None."""
    if not SESS_CMD_LOCK.acquire(timeout=15):
        return "会话忙（稍后再试）"
    try:
        err = _sess_send_cmd("SEEK")
        if err:
            return err
        with SESS_LOCK:
            SESS["last"] = int(time.time())
        return None
    finally:
        SESS_CMD_LOCK.release()


def sess_cmd_stopvod():
    """STOPVOD through the daemon. Best-effort, returns err/None."""
    if not SESS_CMD_LOCK.acquire(timeout=15):
        return "会话忙（稍后再试）"
    try:
        err = _sess_send_cmd("STOPVOD")
        if err:
            return err
        with SESS_LOCK:
            SESS["last"] = int(time.time())
        return None
    finally:
        SESS_CMD_LOCK.release()


def run_sd_vod_daemon(uid, start, length, reqseq=3):
    """VOD over the persistent session: PLAY -> HLS live -> STOPVOD -> mp4.

    Same outputs as run_sd_vod (HLS dir + mp4), no new handshake. Holds
    SESS_CMD_LOCK for the whole play so LIST waits its turn.
    """
    length = max(1, min(600, int(length or 60)))
    secs = min(45 + length * 2, 400)
    try:
        reqseq = int(reqseq or 3) & 0xFFFF
    except (TypeError, ValueError):
        reqseq = 3
    os.makedirs(VODDIR, exist_ok=True)
    mp4 = os.path.join(VODDIR, "回放_%s.mp4" % start)
    h265 = os.path.join(VODDIR, "回放_%s.h265" % start)
    hlsdir = os.path.join(VODDIR, "hls_%s" % start)
    try:
        os.makedirs(hlsdir, exist_ok=True)
    except OSError:
        pass
    with VOD_LOCK:
        VOD_RUN["hls_dir"] = hlsdir
        VOD_RUN["hls_ready"] = _vod_hls_ready(hlsdir)
    if os.path.isfile(mp4) and os.path.getsize(mp4) > 0:
        _vod_log("cache hit: " + os.path.basename(mp4))
        with VOD_LOCK:
            VOD_RUN["mp4"] = mp4
        return mp4
    if not SESS_CMD_LOCK.acquire(timeout=20):
        _vod_log("会话忙，点播放弃")
        return None
    fifo = os.path.join(hlsdir, "in.hevc")
    ff = None
    fifo_w = None
    try:
        _vod_log("+ vod(sess) start=%s len=%d secs=%d" % (
            start, length, secs))
        try:
            before = set(glob.glob(os.path.join(SESS_DIR, "stream_*.bin")))
        except Exception:
            before = set()
        err = _sess_send_cmd("PLAY %d %d" % (start, reqseq))
        if err:
            _vod_log("PLAY失败：%s" % err)
            return None
        t_play = time.time()
        with SESS_LOCK:
            SESS["last"] = int(time.time())
        spath = None
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                now = set(glob.glob(os.path.join(SESS_DIR, "stream_*.bin")))
            except Exception:
                now = set()
            new = sorted(now - before)
            if new:
                spath = new[0]
                break
            time.sleep(1)
        if spath is None:
            _vod_log("点播无流（PLAY后30秒无帧文件）")
            return None
        _vod_log("vod stream: %s" % os.path.basename(spath))
        try:
            os.remove(fifo)
        except OSError:
            pass
        try:
            os.mkfifo(fifo)
        except (OSError, AttributeError) as e:
            _vod_log("fifo失败：%s" % str(e)[:80])
            return None
        try:
            ff = subprocess.Popen(
                [FFMPEG, "-hide_banner", "-loglevel", "error",
                 "-r", "30", "-f", "hevc", "-i", fifo,
                 "-c", "copy", "-f", "hls", "-hls_time", "2",
                 "-hls_list_size", "0", "-hls_playlist_type", "event",
                 "-hls_segment_type", "fmp4",
                 "-hls_fmp4_init_filename", "init.mp4",
                 "-hls_segment_filename", "seg%d.m4s", "index.m3u8"],
                cwd=hlsdir, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE)
            fifo_w = open(fifo, "wb")
        except Exception as e:
            _vod_log("ffmpeg HLS启动失败：%s" % str(e)[:80])
            return None
        st = {"off": 0, "pend": b""}
        tnv, tbytes = 0, 0
        firstv_t, sentseek = None, False
        end_t = time.time() + secs
        last_ready = False
        while time.time() < end_t:
            nv, nb = _vod_forward_frames(spath, fifo_w, st)
            tnv += nv
            tbytes += nb
            try:
                fifo_w.flush()
            except Exception:
                break
            if tnv > 0 and firstv_t is None:
                firstv_t = time.time()
                _vod_log("first video +%.0fs" % (firstv_t - t_play))
            if (not sentseek and firstv_t is not None
                    and time.time() - firstv_t >= 5):
                serr = _sess_send_cmd("SEEK")
                sentseek = True
                _vod_log("SEEK %s" % ("ok" if not serr else serr))
            ready = _vod_hls_ready(hlsdir)
            if ready and not last_ready:
                last_ready = True
                with VOD_LOCK:
                    VOD_RUN["hls_ready"] = True
                _vod_log("hls playable +%ds: %d arrays %dB" % (
                    int(time.time() - t_play), tnv, tbytes))
            with SESS_LOCK:
                SESS["last"] = int(time.time())
            time.sleep(1)
        serr = _sess_send_cmd("STOPVOD")
        _vod_log("STOPVOD %s" % ("ok" if not serr else serr))
        try:
            fifo_w.close()
        except Exception:
            pass
        fifo_w = None
        if ff is not None:
            try:
                _, fferr = ff.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                try:
                    ff.kill()
                except Exception:
                    pass
                _, fferr = ff.communicate()
            except Exception as e:
                fferr = str(e).encode("utf-8", errors="replace")
            if fferr:
                _vod_log("ffmpeg hls: %s"
                         % fferr.decode("utf-8",
                                        errors="replace")[-200:])
            _vod_log("hls done: segs=%d arrays=%d bytes=%d" % (
                _vod_hls_segs(hlsdir), tnv, tbytes))
            with VOD_LOCK:
                VOD_RUN["hls_ready"] = _vod_hls_ready(hlsdir)
    except Exception as e:
        _vod_log("VOD(sess)异常：%s" % str(e)[:120])
        return None
    finally:
        try:
            SESS_CMD_LOCK.release()
        except Exception:
            pass
        if fifo_w is not None:
            try:
                fifo_w.close()
            except Exception:
                pass
        if fifo is not None:
            try:
                os.remove(fifo)
            except OSError:
                pass
    try:
        with open(spath, "rb") as fh:
            d = fh.read()
    except OSError:
        _vod_log("no stream produced")
        return None
    if not d:
        _vod_log("no stream produced")
        return None
    try:
        with open(VODDIR + "/stream.bin", "wb") as fh:
            fh.write(d)
        nv, na, nb = vod_extract(VODDIR + "/stream.bin", h265)
    except OSError as e:
        _vod_log("stream拷贝失败：%s" % str(e)[:80])
        return None
    _vod_log("extract: video=%d other=%d bytes=%d" % (nv, na, nb))
    if nb == 0:
        _vod_log("无视频帧")
        return None
    try:
        r = subprocess.run(
            [FFMPEG, "-hide_banner", "-loglevel", "error", "-y",
             "-r", "30", "-f", "hevc", "-i", h265, "-c", "copy", mp4],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, timeout=300)
        _vod_log("mp4: %s rc=%d" % (os.path.basename(mp4), r.returncode))
        if r.returncode == 0 and os.path.isfile(mp4):
            with VOD_LOCK:
                VOD_RUN["mp4"] = mp4
            return mp4
    except Exception as e:
        _vod_log("ffmpeg失败：%s" % str(e)[:120])
    return None


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

# HASS 配置页优先：用户在“配置”页改了页面账密，重启后以它为准
#（页面内改的仍写入 settings.json，但下次重启会被配置页覆盖）。
for _k, _v in OPT.pop("_hass_http", {}).items():
    OPT[_k] = _v


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

def _new_branch_state():
    return {"t0": time.time(), "decoded": 0, "nals": 0, "restarts": 0,
            "spawns": 0, "running": False, "served": 0, "subs": 0,
            "last_sub_t": 0.0, "hls_n": 0, "hls_bytes": 0, "hls_err": ""}


def _new_branch(bid, name, transport, rundir, hlsdir):
    return {"id": bid, "name": name, "transport": transport,
            "PIPE": {"cap": None, "ff": None, "rundir": "", "hls": None,
                     "hlsfifo": None, "hlslog": None},
            "ST": _new_branch_state(),
            "LATEST": {"jpg": None, "seq": 0, "t": 0.0},
            "PRIME": {"on": False, "nxt": 0},
            "WAKE": threading.Event(),
            "rundir": rundir, "hlsdir": hlsdir,
            "pid": None, "pidrules": [], "iso": "unset"}


# 双分支：video1=直连优先(direct)，video2=中继(relay)。
# /video.mjpg 是两路的主备合并（取最新鲜帧），/video1/2.mjpg 各看一路。
BR = {"1": _new_branch("1", "video1", "direct",
                       "/tmp/ubox_run1", "/tmp/ubox_live_hls1"),
      "2": _new_branch("2", "video2", "relay",
                       "/tmp/ubox_run2", "/tmp/ubox_live_hls2")}
LOCK = threading.Lock()

# 画面角标：各分支 MJPEG 编码时烧进右上角（英文，DejaVu）。
# 主备合并流逐帧取自两路，角标自动跟当前帧走；HLS(-c copy)/mp4 不重编码，无角标。
OVERLAY_TAGS = {"1": "DIRECT video1", "2": "RELAY video2"}
OVERLAY_FONTS = ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
_drawtext_probe = {"done": False, "ok": False, "font": ""}


def _drawtext_vf(tag):
    """drawtext vf fragment for the corner tag, or '' when unavailable.

    Missing filter/font must never break the pipeline: probe once, fall
    back to plain fps silently.
    """
    p = _drawtext_probe
    if not p["done"]:
        p["done"] = True
        try:
            r = subprocess.run([FFMPEG, "-hide_banner", "-h",
                                "filter=drawtext"],
                               capture_output=True, timeout=15)
            has = r.returncode == 0
        except Exception:
            has = False
        font = next((f for f in OVERLAY_FONTS if os.path.isfile(f)), "")
        p["ok"], p["font"] = bool(has and font), font
        if not p["ok"]:
            print("overlay off (drawtext=%s font=%s)" % (has, font or "none"),
                  flush=True)
    if not p["ok"]:
        return ""
    safe = tag.replace("\\", "").replace(":", "\\:").replace("'", "")
    return (",drawtext=fontfile=%s:text='%s':x=w-tw-10:y=10:fontsize=20"
            ":fontcolor=white:box=1:boxcolor=black@0.6" % (p["font"], safe))
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


def _vod_log(msg):
    with VOD_LOCK:
        VOD_RUN["log"].append(msg)


def _vod_hls_ready(hlsdir):
    """True once the playlist references a segment (playable now)."""
    idx = os.path.join(hlsdir, "index.m3u8")
    try:
        if os.path.getsize(idx) <= 0:
            return False
        with open(idx, "rb") as fh:
            return b".m4s" in fh.read()
    except OSError:
        return False


def _vod_hls_segs(hlsdir):
    try:
        return len(glob.glob(os.path.join(hlsdir, "seg*.m4s")))
    except Exception:
        return 0


def _vod_forward_frames(stream, fifo_w, st=None):
    """Tail stream.bin ([len:4][magic][data]) -> fifo (Annex-B video only).

    Returns (video_arrays, bytes). st holds (off, pend) across polls;
    defaults to a shared dict (one-shot path). Daemon-VOD passes its own.
    Handles qemu truncating stream.bin at PLAY_START.
    """
    import struct as _st
    if st is None:
        st = _vod_forward_frames.__dict__.setdefault("st", {})
    off = st.get("off", 0)
    pend = st.get("pend", b"")
    try:
        size = os.path.getsize(stream)
    except OSError:
        return 0, 0
    if size < off:
        off, pend = 0, b""
    try:
        with open(stream, "rb") as fh:
            fh.seek(off)
            chunk = fh.read()
    except OSError:
        return 0, 0
    if not chunk and not pend:
        st["off"], st["pend"] = off, pend
        return 0, 0
    data = pend + chunk
    nv, sent, pos = 0, 0, 0
    while pos + 8 <= len(data):
        (ln,) = _st.unpack("<I", data[pos:pos + 4])
        if ln <= 0 or ln > 2000000:
            break
        if pos + 8 + ln > len(data):
            break
        payload = data[pos + 8:pos + 8 + ln]
        if payload[:4] == b"\x00\x00\x00\x01":
            try:
                fifo_w.write(payload)
                nv += 1
                sent += len(payload)
            except (BrokenPipeError, ValueError, OSError):
                break
        pos += 8 + ln
    st["off"] = off + pos
    st["pend"] = data[pos:]
    return nv, sent


def run_sd_vod(uid, username, password, start, length, reqseq=3):
    """Blocking VOD job: rehost_sdlist vod-stream -> HLS (live) + mp4.

    qemu runs under Popen; arrived frames are tailed from stream.bin into
    a FIFO read by ffmpeg, which cuts fmp4 HLS (event playlist) into
    VODDIR/hls_<start>/ — playable via /api/sd/hls while still
    downloading. When qemu ends, the FIFO closes, ffmpeg finalizes, and
    the classic stream.bin -> mp4 (-c copy) is built as fallback/download.
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
    hlsdir = os.path.join(VODDIR, "hls_%s" % start)
    try:
        os.makedirs(hlsdir, exist_ok=True)
    except OSError:
        pass
    with VOD_LOCK:
        VOD_RUN["hls_dir"] = hlsdir
        VOD_RUN["hls_ready"] = _vod_hls_ready(hlsdir)
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
    fifo = os.path.join(hlsdir, "in.hevc")
    try:
        os.remove(fifo)
    except OSError:
        pass
    try:
        os.mkfifo(fifo)
    except (OSError, AttributeError) as e:
        _vod_log("fifo失败（回落纯mp4）：%s" % str(e)[:80])
        fifo = None
    ff = None
    if fifo is not None:
        try:
            ff = subprocess.Popen(
                [FFMPEG, "-hide_banner", "-loglevel", "error",
                 "-r", "30", "-f", "hevc", "-i", fifo,
                 "-c", "copy", "-f", "hls", "-hls_time", "2",
                 "-hls_list_size", "0", "-hls_playlist_type", "event",
                 "-hls_segment_type", "fmp4",
                 "-hls_fmp4_init_filename", "init.mp4",
                 "-hls_segment_filename", "seg%d.m4s", "index.m3u8"],
                cwd=hlsdir, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE)
        except Exception as e:
            _vod_log("ffmpeg HLS启动失败（回落纯mp4）：%s" % str(e)[:80])
            ff = None
    qemu = None
    fifo_w = None
    qlog = []
    try:
        if ff is not None:
            fifo_w = open(fifo, "wb")
        qemu = subprocess.Popen(
            [QEMU, "-L", ROOTFS, sdbin, uid, username, password,
             "1", "1", str(secs), str(start), "--play", str(reqseq)],
            cwd=VODDIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env={**os.environ, "LD_LIBRARY_PATH": BINDIR})

        def _drain():
            try:
                out = qemu.stdout.read() or b""
                qlog.append(out.decode("utf-8", errors="replace"))
            except Exception:
                pass
        threading.Thread(target=_drain, daemon=True).start()

        _vod_forward_frames.__dict__["st"] = {}
        deadline = time.time() + secs + 60
        tnv, tbytes, last_ready = 0, 0, False
        while True:
            if qemu.poll() is not None:
                break
            if fifo_w is not None:
                nv, nb = _vod_forward_frames(stream, fifo_w)
                tnv += nv
                tbytes += nb
                try:
                    fifo_w.flush()
                except Exception:
                    pass
                ready = _vod_hls_ready(hlsdir)
                if ready and not last_ready:
                    last_ready = True
                    with VOD_LOCK:
                        VOD_RUN["hls_ready"] = True
                    _vod_log("hls playable: %d arrays %dB" % (tnv, tbytes))
            if time.time() > deadline:
                _vod_log("VOD超时（%ds无退出），收尾已到帧" % (secs + 60))
                try:
                    qemu.terminate()
                except Exception:
                    pass
                break
            time.sleep(1)
        try:
            qemu.wait(timeout=10)
        except Exception:
            try:
                qemu.kill()
            except Exception:
                pass
            try:
                qemu.wait(timeout=10)
            except Exception:
                pass
        tail = "".join(qlog)[-300:]
        _vod_log("qemu exit=%s %s" % (qemu.returncode, tail))
        if fifo_w is not None:
            nv, nb = _vod_forward_frames(stream, fifo_w)
            tnv += nv
            tbytes += nb
            try:
                fifo_w.close()
            except Exception:
                pass
            fifo_w = None
        if ff is not None:
            try:
                _, fferr = ff.communicate(timeout=60)
            except subprocess.TimeoutExpired:
                try:
                    ff.kill()
                except Exception:
                    pass
                _, fferr = ff.communicate()
            except Exception as e:
                fferr = str(e).encode("utf-8", errors="replace")
            if fferr:
                _vod_log("ffmpeg hls: %s"
                         % fferr.decode("utf-8",
                                        errors="replace")[-200:])
            _vod_log("hls done: segs=%d arrays=%d bytes=%d" % (
                _vod_hls_segs(hlsdir), tnv, tbytes))
            with VOD_LOCK:
                VOD_RUN["hls_ready"] = _vod_hls_ready(hlsdir)
    except Exception as e:
        _vod_log("VOD启动失败：%s" % str(e)[:120])
        return None
    finally:
        if fifo_w is not None:
            try:
                fifo_w.close()
            except Exception:
                pass
        if fifo is not None:
            try:
                os.remove(fifo)
            except OSError:
                pass
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


def _vod_worker(uid, username, password, start, length, reqseq,
                via_daemon=False):
    try:
        if via_daemon:
            run_sd_vod_daemon(uid, start, length, reqseq)
        else:
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


def split_jpegs(proc, br):
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
                br["LATEST"]["jpg"] = jpg
                br["LATEST"]["seq"] += 1
                br["LATEST"]["t"] = time.time()
                br["ST"]["decoded"] += 1


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


def _branch_rule(br, pid):
    # 每分支只封自己 qemu 进程的包：direct 封全部中继端口，
    # relay 封局域网发现端口；两分支互不干扰（全局规则是互斥的，
    # 分支起流时会自动清掉，见 branch_isolate）。
    port = RELAY_PORT if br["transport"] == "direct" else LANDISC_PORT
    return ["-m", "owner", "--pid-owner", str(pid), "-p", "udp",
            "--dport", str(port),
            "-m", "comment", "--comment", "ubox-%s" % br["name"]]


def branch_isolate(br, pid):
    """Enforce this branch's path on its own qemu PID only."""
    if not IPTABLES:
        br["iso"] = "no-iptables: shared network, path not forced"
        return False
    for m in ("relay", "direct"):
        _ipt("-D", "OUTPUT", *transport_rule(m))
    with LOCK:
        TR["applied"] = False
        TR["detail"] = ("dual: globals cleared for branch isolation "
                        "(global %s recorded)" % OPT["transport"])
    rule = _branch_rule(br, pid)
    _ipt("-D", "OUTPUT", *rule)
    rc, out = _ipt("-A", "OUTPUT", *rule)
    ok = rc == 0 and _ipt_has(rule)
    br["pidrules"] = [rule] if ok else []
    br["pid"] = pid
    via = rule[rule.index("--dport") + 1]
    br["iso"] = ("pid-owner drop udp/%s (%s-only)" % (via, br["transport"])
                 if ok else ("pid-owner failed: %s" % out))
    print("branch %s isolate pid=%s: %s" % (br["name"], pid, br["iso"]),
          flush=True)
    return ok


def branch_unisolate(br):
    for rule in br.get("pidrules", []):
        _ipt("-D", "OUTPUT", *rule)
    br["pidrules"] = []
    br["pid"] = None
    if not any(b["ST"]["running"] for b in BR.values()):
        apply_transport(OPT["transport"])


def _stop_all_branches():
    for br in BR.values():
        stop_pipeline(br)


def _wake_all_branches():
    for br in BR.values():
        br["WAKE"].set()


def stop_pipeline(br):
    cap, ff = br["PIPE"]["cap"], br["PIPE"]["ff"]
    br["PIPE"]["cap"], br["PIPE"]["ff"] = None, None
    fhls, whls = br["PIPE"].get("hls"), br["PIPE"].get("hlsfifo")
    br["PIPE"]["hls"], br["PIPE"]["hlsfifo"] = None, None
    hlslog = br["PIPE"].get("hlslog")
    br["PIPE"]["hlslog"] = None
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
    if whls is not None:
        try:
            whls.close()
        except Exception:
            pass
    if fhls is not None:
        try:
            fhls.wait(timeout=8)
        except Exception:
            try:
                fhls.kill()
            except Exception:
                pass
    if hlslog is not None:
        try:
            hlslog.close()
        except Exception:
            pass
    with LOCK:
        br["ST"]["running"] = False
    branch_unisolate(br)


def _live_hls_ready(hlsdir):
    idx = os.path.join(hlsdir, "index.m3u8")
    try:
        if os.path.getsize(idx) <= 0:
            return False
        with open(idx, "rb") as fh:
            return b".ts" in fh.read()
    except OSError:
        return False


def _live_hls_segs(hlsdir):
    try:
        return len(glob.glob(os.path.join(hlsdir, "seg*.ts")))
    except Exception:
        return 0


def live_hls_feeder(rundir, fifo_path, br):
    """Feed primed v_*.bin chunks (raw Annex-B) to the HLS ffmpeg fifo.

    The -c copy muxer needs clean codec params at probe time (a decoder
    would just wait for the next clean IDR, but the muxer gives up), and
    params only repeat per GOP. So chunks are dropped until the first
    VPS NAL is seen (buffered across chunk boundaries); everything from
    there passes through.
    """
    dbg = os.path.join(br["hlsdir"], "feeder.log")

    def _dbg(msg):
        try:
            with open(dbg, "ab") as fh:
                fh.write(("%s %s\n" % (int(time.time()), msg)).encode())
        except OSError:
            pass

    _dbg("start")
    try:
        # NOTE: buffered "+"/read-write modes demand a seekable stream and
        # fail on fifos ("not seekable"); unbuffered "wb" blocks till the
        # ffmpeg reader arrives, same as the VOD path.
        w = open(fifo_path, "wb", buffering=0)
    except OSError as e:
        _dbg("open-fail:%s" % e)
        return
    _dbg("fifo-open")
    br["PIPE"]["hlsfifo"] = w

    def _vps_off(b):
        i = b.find(b"\x00\x00\x00\x01")
        while i >= 0:
            if len(b) > i + 4 and ((b[i + 4] >> 1) & 0x3F) == 32:
                return i
            i = b.find(b"\x00\x00\x00\x01", i + 1)
        return -1

    try:
        n, seeking, pend = 0, True, b""
        while br["PIPE"].get("hls") is not None:
            while not br["PRIME"]["on"]:
                time.sleep(0.2)
                if br["PIPE"].get("hls") is None:
                    return
            if n < br["PRIME"]["nxt"]:
                n = br["PRIME"]["nxt"]
            path = os.path.join(rundir, "v_%d.bin" % n)
            if not os.path.isfile(path):
                time.sleep(0.15)
                continue
            b = stable_read(path)
            if b is None:
                time.sleep(0.1)
                continue
            if seeking:
                pend += b
                if len(pend) > 300000:
                    pend = pend[-300000:]
                off = _vps_off(pend)
                if off < 0:
                    n += 1
                    continue
                b, pend, seeking = pend[off:], b"", False
                with LOCK:
                    br["ST"]["hls_err"] = "vps@n=%d" % n
                _dbg("vps@n=%d" % n)
            try:
                w.write(b)
                w.flush()
            except (BrokenPipeError, ValueError, OSError) as e:
                with LOCK:
                    br["ST"]["hls_err"] = "write:%s" % str(e)[:60]
                return
            with LOCK:
                br["ST"]["hls_n"] += 1
                br["ST"]["hls_bytes"] += len(b)
            n += 1
    except Exception as e:
        with LOCK:
            br["ST"]["hls_err"] = "feeder:%s" % str(e)[:80]
    finally:
        try:
            w.close()
        except Exception:
            pass
        if br["PIPE"].get("hlsfifo") is w:
            br["PIPE"]["hlsfifo"] = None


def run_pipeline(br):
    rundir = br["rundir"]
    hlsdir = br["hlsdir"]
    os.makedirs(rundir, exist_ok=True)
    for f in glob.glob(os.path.join(rundir, "*")):
        try:
            os.remove(f)
        except OSError:
            pass
    br["PIPE"]["rundir"] = rundir
    _load_device()
    username = DEV["username"] or OPT.get("username") or "admin"
    if not DEV["uid"] or not DEV["password"]:
        print("branch %s: no device uid/password (enter on web page), "
              "pipeline not started" % br["name"], flush=True)
        return
    for need in (QEMU, REHOST):
        if not (os.path.isfile(need) and os.access(need, os.X_OK)):
            print("branch %s: missing executable: %s" % (br["name"], need),
                  flush=True)
            return
    cap = subprocess.Popen(
        [QEMU, "-L", ROOTFS, REHOST, DEV["uid"], username,
         DEV["password"], "1", str(OPT["stream"]), "86400"],
        cwd=rundir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env={**os.environ, "LD_LIBRARY_PATH": BINDIR})
    branch_isolate(br, cap.pid)
    vf = "fps=%d" % OPT["fps"] + _drawtext_vf(OVERLAY_TAGS[br["id"]])
    ff = subprocess.Popen(
        [FFMPEG, "-hide_banner", "-loglevel", "error",
         "-probesize", "32", "-f", "hevc", "-i", "pipe:0",
         "-vf", vf, "-q:v", "4",
         "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL)
    br["PIPE"]["cap"], br["PIPE"]["ff"] = cap, ff
    threading.Thread(target=split_jpegs, args=(ff, br),
                     daemon=True).start()
    try:
        os.makedirs(hlsdir, exist_ok=True)
        for f in glob.glob(os.path.join(hlsdir, "*")):
            try:
                os.remove(f)
            except OSError:
                pass
        fifo = os.path.join(hlsdir, "in.hevc")
        try:
            os.remove(fifo)
        except OSError:
            pass
        os.mkfifo(fifo)
        hlslog = open(os.path.join(hlsdir, "ffmpeg-hls.log"), "wb")
        br["PIPE"]["hlslog"] = hlslog
        fhls = subprocess.Popen(
            [FFMPEG, "-hide_banner", "-loglevel", "warning",
             "-r", "30", "-f", "hevc", "-i", fifo,
             "-c", "copy", "-f", "hls", "-hls_time", "2",
             "-hls_list_size", "6", "-hls_flags", "delete_segments",
             "-hls_segment_filename", "seg%d.ts", "index.m3u8"],
            cwd=hlsdir, stdout=subprocess.DEVNULL,
            stderr=hlslog)
        br["PIPE"]["hls"] = fhls
        br["PRIME"]["on"] = False
        br["PRIME"]["nxt"] = 0
        threading.Thread(target=live_hls_feeder, args=(rundir, fifo, br),
                         daemon=True).start()
    except (OSError, AttributeError) as e:
        print("branch %s live HLS off: %s" % (br["name"], str(e)[:80]),
              flush=True)
        br["PIPE"]["hls"] = None
    with LOCK:
        br["ST"]["running"] = True
        br["ST"]["spawns"] += 1
        br["ST"]["hls_n"] = 0
        br["ST"]["hls_bytes"] = 0
        br["ST"]["hls_err"] = ""
    print("branch %s pipeline spawned" % br["name"], flush=True)
    nxt, primed = 0, False
    try:
        while True:
            if br["PIPE"]["cap"] is None:
                break
            path = os.path.join(rundir, "v_%d.bin" % nxt)
            if not os.path.isfile(path):
                if cap.poll() is not None:
                    print("branch %s rehost exited rc=%s"
                          % (br["name"], cap.returncode), flush=True)
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
                br["PRIME"]["on"] = True
                br["PRIME"]["nxt"] = nxt
            try:
                ff.stdin.write(b)
                with LOCK:
                    br["ST"]["nals"] += 1
            except (BrokenPipeError, ValueError):
                with LOCK:
                    br["ST"]["restarts"] += 1
                break
            nxt += 1
    finally:
        stop_pipeline(br)
        print("branch %s pipeline stopped" % br["name"], flush=True)


def supervisor(br):
    while True:
        br["WAKE"].wait(timeout=5)
        br["WAKE"].clear()
        with LOCK:
            subs = br["ST"]["subs"]
            running = br["ST"]["running"]
            idle_for = time.time() - br["ST"]["last_sub_t"]
        if subs > 0 and not running:
            threading.Thread(target=run_pipeline, args=(br,),
                             daemon=True).start()
        elif subs == 0 and running and idle_for > OPT["idle_timeout"]:
            print("branch %s idle %.0fs, stopping pipeline"
                  % (br["name"], idle_for), flush=True)
            stop_pipeline(br)


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
.switch{position:relative;display:inline-block;width:44px;height:24px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.switch .sl{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#bbb;border-radius:24px;transition:.2s}
.switch .sl:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked + .sl{background:#2a6}
.switch input:checked + .sl:before{transform:translateX(20px)}
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
#side-player,#live-player,#relay-player,#lan-sd-player{flex:1;min-width:0;margin-bottom:0;display:flex;flex-direction:column}
#side-player video,#live-player img,#relay-player img,#lan-sd-player video{width:100%;flex:1;min-height:0;object-fit:contain;background:#000;border-radius:4px}
@media (max-width:900px){.dev-row{flex-direction:column}#side-player,#live-player,#relay-player,#lan-sd-player{width:100%;flex:auto}}
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
<div class="dev-row">
<div class="dev-left">
<div class="card">
<b>信息</b>
<div id="live-info" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin-top:10px"></div>
</div>
<div class="card">
<h2 style="margin-top:0">功能</h2>
<div id="live-funcs" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px"></div>
</div>
</div>
<div class="card" id="live-player">
<b>画面</b>
<img id="live-img" alt="live" style="margin-top:6px">
</div>
</div>
<div id="live-func-inline" style="margin-top:12px"></div>
</div><!-- /tab-live -->

<div class="tabpage" id="tab-relaylive">
<div class="dev-row">
<div class="dev-left">
<div class="card">
<b>信息</b>
<div id="relay-info" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px;margin-top:10px"></div>
</div>
<div class="card">
<h2 style="margin-top:0">功能</h2>
<div id="relay-funcs" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px"></div>
</div>
</div>
<div class="card" id="relay-player">
<b>画面</b>
<img id="relay-img" alt="live" style="margin-top:6px">
</div>
</div>
<div id="relay-func-inline" style="margin-top:12px"></div>
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
<div class="card">
  <b>设备参数</b>
  <div class="muted" style="margin-top:4px">登录后一次拉取，多处共用不重查 <span id="user-params-ts"></span></div>
  <div id="user-params" style="margin-top:6px">待加载</div>
  <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
    <input id="u-dpass" type="text" placeholder="改设备密码（明文）" style="flex:1;min-width:160px">
    <button onclick="saveUserPass()" style="white-space:nowrap;margin:0">保存密码</button>
    <span id="user-pass-msg" class="muted"></span>
  </div>
</div>
</div><!-- /tab-user -->

<div class="tabpage" id="tab-doc">
<h2 style="margin-top:0">接口</h2>
<div class="card">
   <div>本机接口：/api/login /api/logout /api/session /api/devices（含sd透传） /api/device /api/device-login /api/device/webrtc_token /api/cloud/list /api/cloud/url /api/sd/list（P2P直连0x101查SD，secs最多等待15~90s、有回包提前返回） /api/sd/list_live（查询中途看已到条目，动态显示用） /api/sess/connect /api/sess/disconnect /api/sess/status（手动建联开关+状态，SD列表优先走会话） /api/sd/vod /api/sd/vod_status /api/sd/vod_file（AVCMD command=9点播转mp4） /api/settings /api/transport /stats /snap.jpg /video.mjpg（主备合并） /video1.mjpg（直连分支） /video2.mjpg（中继分支） /api/live/start?branch=1|2 /api/live/stop?branch=1|2|all /api/live/hls（直播HLS分片，跟分支1）</div>
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
var _DEV={byUid:{},ts:0,count:0};
var _sessionSnap=null;
// 常量/变量规则：
// - 常量（一台设备终身不变）：devC(uid) 直接给缓存引用，零拷贝，禁止写入。
// - 变量（会变：在线/电量/信号/录像条数等）：必须 getDev(uid)/curParams() 拿拷贝，
//   禁止拿缓存引用（谁改一下全脏，且读到过期值）。只有 storeDevs 能写缓存。
var DEVC_CONST=['uid','model','firmware','device_type','product_id',
  'bind_utc','device_user','esim_eid'];
function storeDevs(d){
  _devs=(d&&d.items)||[];
  _DEV.byUid={};
  _devs.forEach(function(i){if(i&&i.uid)_DEV.byUid[i.uid]=i;});
  _DEV.ts=Date.now();
  _DEV.count=_devs.length;
}
function devC(uid){return (uid&&_DEV.byUid[uid])||null;}
function getDev(uid){
  var s=devC(uid);
  if(!s)return null;
  var c={};
  for(var k in s){
    if(!s.hasOwnProperty(k))continue;
    var v=s[k];
    if(DEVC_CONST.indexOf(k)>=0){c[k]=v;continue;}
    if(v&&typeof v==='object'){c[k]=JSON.parse(JSON.stringify(v));}
    else{c[k]=v;}
  }
  return c;
}
function curParams(){return getDev(curUid());}
function devVal(uid,key,fb){var i=getDev(uid);return (i&&(i[key]!==undefined&&i[key]!==null))?i[key]:(fb===undefined?'—':fb);}
function fmtTime(utc){
  if(!utc)return '—';
  try{return new Date(utc*1000).toLocaleString('zh-CN');}catch(e){return String(utc);}
}
function fmtVal(k,v){
  if(v===null||v===undefined||v==='')return '—';
  if(k==='online')return v?'在线':'离线';
  if(typeof v==='boolean')return v?'是':'否';
  if(k==='battery')return v+'%';
  if(/_utc$/.test(k))return fmtTime(v);
  if(k==='time_diff')return tzLabel(v);
  if(k==='cur_work_mode'||k==='want_work_mode')return modeLabel(v);
  if(k==='ext_notice'){
    if(!v.length)return '无';
    return v.map(function(e){return e[0]+(e[1]?'开':'关');}).join('、');
  }
  if(k==='sd'){
    var ks=Object.keys(v);
    if(!ks.length)return '无字段';
    return ks.map(function(x){return x+'='+v[x];}).join('；');
  }
  if(typeof v==='object')return JSON.stringify(v).slice(0,120);
  return String(v);
}
var PARAM_GROUPS=[
 {t:'基本信息',rows:[['名称','name'],['UID','uid'],['型号','model'],['固件','firmware'],['在线','online'],['在线态','online_state'],['绑定','bind_utc']]},
 {t:'电源状态',rows:[['电量','battery'],['充电中','charging'],['信号','signal'],['低电量','low_power'],['最后活跃','last_active_utc']]},
 {t:'归属网络',rows:[['本人设备','is_owner'],['区服','ps_name'],['zone','zone_id'],['地址','address_id'],['时区','time_diff'],['位置','location'],['AP直连','is_ap_device'],['夏令时','is_dst']]},
 {t:'云存储',rows:[['已开通','has_cloud_storage'],['已开启','cloud_opened'],['功能码','dev_func']]},
 {t:'工作模式',rows:[['当前','cur_work_mode'],['期望','want_work_mode'],['全景','is_panoramic']]},
 {t:'通知',rows:[['推送','notice_on'],['通知开关','notice_enabled'],['扩展通知','ext_notice']]},
 {t:'套餐与卡',rows:[['可插卡','can_insert_sim'],['套餐状态','card_pkg_flow'],['套餐到期','card_pkg_expire'],['终身套餐','is_lifetime_plan'],['Ubia卡','is_ubia_card'],['锁定','is_lock'],['有ICCID','has_icc'],['eSIM EID','esim_eid'],['在用eSIM','using_esim'],['Ubia eSIM','is_ubia_esim'],['流量同步建议','suggest_sync_traffic'],['套餐绑用户','pkg_bound_on_user']]},
 {t:'设备与杂项',rows:[['设备账号','device_user'],['设备密码','device_pwd'],['密码已配','has_pwd'],['Alexa','alexa_status'],['AlexaID','alexa_id'],['权限','permissions'],['产品线','product_id'],['设备类型','device_type'],['SD卡','sd'],['局域网IP','lan_ip'],['局域网端口','lan_port'],['会话sid','sid'],['会话random','sess_random'],['会话nonce','sess_nonce'],['会话结果','sess_result']]},
];
function paramTable(title,rows,get){
  var h='<div style="margin-top:8px"><b>'+title+'</b><table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:4px">';
  rows.forEach(function(r){
    h+='<tr><td class="muted" style="border-top:1px solid #eee;padding:3px 6px;width:110px">'+r[0]+'</td><td style="border-top:1px solid #eee;padding:3px 6px;word-break:break-all">'+escHtml(fmtVal(r[1],get(r[1])))+'</td></tr>';
  });
  return h+'</table></div>';
}
function renderUserParams(){
  var box=document.getElementById('user-params');
  if(!box)return;
  var i=curParams();
  var ts=document.getElementById('user-params-ts');
  if(!i){box.innerHTML='<span class="muted">待加载（登录后自动拉取）</span>';if(ts)ts.textContent='';return;}
  if(ts&&_DEV.ts)ts.textContent='· 取于 '+new Date(_DEV.ts).toLocaleTimeString('zh-CN',{hour12:false});
  var s=_sessionSnap||{};
  var h='<div class="muted" style="margin:6px 0">当前设备：'+escHtml(i.name||i.uid||'')+'</div>';
  h+=paramTable('会话',[
    ['账号','account'],['区服','region'],['已登录','logged_in'],['自动续登','auto']
  ],function(k){return s[k];});
  PARAM_GROUPS.forEach(function(g){    h+=paramTable(g.t,g.rows,function(k){return i[k];});
  });
  box.innerHTML=h;
  try{
    var inp=document.getElementById('u-dpass');
    if(inp&&!inp.value&&i.device_pwd)inp.value=i.device_pwd;
  }catch(e){}
}
function saveUserPass(){
  var msg=document.getElementById('user-pass-msg');
  var uid=curUid();
  var u=(getDev(uid)||{}).device_user||'admin';
  var inp=document.getElementById('u-dpass');
  var p=(inp&&inp.value)||'';
  if(!uid||!p){if(msg)msg.textContent='请先选设备并输入密码';return;}
  if(msg)msg.textContent='保存中…';
  post('/api/device-login',{uid:uid,username:u,password:p}).then(function(r){
    if(r.error){if(msg)msg.textContent=r.error;return;}
    if(msg)msg.textContent=r.cached?'与缓存一致，未改动':'已保存（取流已重启）';
    loadDevices();
  }).catch(function(e){if(msg)msg.textContent='保存失败：'+e;});
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
    storeDevs(d);
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
    renderUserParams();
    loadUserStats();
  }).catch(function(e){if(!quiet)show('dev-msg','请求失败：'+e);});
}
function curDev(){
  return getDev(curUid());
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
  try{renderLiveInfo();}catch(e){}
  try{renderRelayInfo();}catch(e){}
  try{renderUserParams();}catch(e){}
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
  sdHlsDestroy(v);
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
  fmsg('取设备凭证（缓存优先）…');
  llog(kind,'取设备凭证（缓存优先）…');
  get('/api/device').then(function(dev){
    if(dev&&dev.uid&&dev.uid===curUid()&&dev.has_password){
      fmsg('用已缓存设备直接取流…');
      llog(kind,'设备缓存命中，跳过云端重查');
      return {cached:true};
    }
    fmsg('取云端设备凭证…');
    llog(kind,'取云端设备凭证…');
    return get('/api/devices').then(function(d){
    if(d.error){fmsg(d.error);llog(kind,'devices失败: '+d.error);return null;}
    storeDevs(d);
    renderUserParams();
    var it=getDev(curUid())||getDev((_devs[0]||{}).uid);
    if(!it){fmsg('无设备');llog(kind,'无设备');return null;}
    if(!it.device_pwd){fmsg('该设备云端无密码');llog(kind,'云端无密码');return null;}
    fmsg('用 '+(it.name||it.uid)+' 取流…');
    llog(kind,'用 '+(it.name||it.uid)+' 登录，码流'+n);
    return post('/api/device-login',{uid:it.uid,username:it.device_user||'admin',password:it.device_pwd});
    });
  }).then(function(r){
    if(!r)return;
    if(r.error){fmsg(r.error);llog(kind,'device-login失败: '+r.error);return null;}
    llog(kind,r.cached?'设备缓存直用（未重启管线）':'device-login ok');
    return fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stream:n})});
  }).then(function(r){
    if(!r)return null;
    var bid=isDirect?'1':'2';
    return fetch('/api/live/start?branch='+bid,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({stream:n})});
  }).then(function(r){
    if(!r)return;
    return r.json();
  }).then(function(d){
    if(!d)return;
    fmsg(modeName+(n===1?'主':'辅')+'取流中…',true);
    llog(kind,'branch='+d.branch+'('+d.name+') transport='+d.transport+' running='+d.running);
    llog(kind,modeName+(n===1?'主':'辅')+'取流中，等待首帧（约10~30秒）…');
    if(isDirect){_directWanted=true;}else{_relayWanted=true;}
    switchTab(tab);
    var v=document.getElementById(imgId);
    if(v)v.src=(isDirect?'/video1.mjpg':'/video2.mjpg')+'?ts='+Date.now();
  }).catch(function(e){fmsg('启动失败');llog(kind,'启动失败: '+e);});
}
function stopLan(){stopStream('direct');}
function stopRelay(){stopStream('relay');}
function stopStream(kind){
  var isDirect=(kind==='direct');
  if(isDirect){_directWanted=false;}else{_relayWanted=false;}
  var bid=isDirect?'1':'2';
  fetch('/api/live/stop?branch='+bid,{method:'POST'}).then(function(){}).catch(function(){});
  llog(kind,'已停止（管线已掐断）');
  var v=document.getElementById('live-img');
  if(v)v.src='about:blank';
  var g=document.getElementById('relay-img');
  if(g)g.src='about:blank';
  var s=document.getElementById('side-vid');
  sdHlsDestroy(s);
  if(s)s.src='about:blank';
  var lv=document.getElementById('lan-sd-vid');
  sdHlsDestroy(lv);
  if(lv){try{lv.pause();}catch(e){}lv.removeAttribute('src');try{lv.load();}catch(e){}}
  var lhv=document.getElementById('live-hls-vid');
  sdHlsDestroy(lhv);
  stopLiveHlsPoll();
  fmsg('已停止（管线已掐断）');
}
function snapNow(){
  var v=document.getElementById('snap-view');
  if(v)v.innerHTML='<img src="/snap.jpg?ts='+Date.now()+'" style="width:100%;max-width:480px;display:block;border-radius:4px" onerror="fmsg(\'暂无帧（取流未起）\')">';
  fmsg('已抓拍',true);
}
function sessToggle(el){
  if(el&&el.checked){sessConnect();}
  else{sessDisconnect();}
}
function sessConnect(){
  var uid=curUid();
  var st=document.getElementById('sess-status');
  if(!uid){if(st)st.textContent='请先选择设备';return;}
  if(st)st.textContent='建联中…';
  sdLanLog('建联 uid='+uid);
  post('/api/sess/connect',{uid:uid}).then(function(r){
    if(!r.ok){if(st)st.textContent='建联失败: '+(r.error||'?');sdLanLog('建联失败: '+(r.error||'?'));return;}
    if(st)st.textContent='已建联 '+uid;
    sdLanLog('建联成功');
    sessRefresh();
  }).catch(function(e){if(st)st.textContent='建联请求失败：'+e;});
}
function sessDisconnect(){
  var st=document.getElementById('sess-status');
  post('/api/sess/disconnect',{}).then(function(){
    if(st)st.textContent='未建联';
    sdLanLog('已断开');
    sessRefresh();
  }).catch(function(){});
}
function sessRefresh(){
  get('/api/sess/status').then(function(s){
    var el=document.getElementById('sess-status');
    if(!el||!s)return;
    el.textContent=sessText(s);
  }).catch(function(){});
}
function sessText(s){
  if(!s||!s.up)return '未建联'+((s&&s.note)?'（'+s.note+'）':'');
  return '已建联 '+(s.uid||'')+' · '+s.uptime_s+'s · 闲置'+s.idle_left_s+'s后断'+(s.note?' · '+s.note:'');
}
var _sessSnap=null;
var _statsSnap=null;
var LIVE_FUNCS=[
 {id:'live',name:'内网直播',desc:'主/辅/停止，画面进右侧'},
 {id:'hls',name:'HLS播放',desc:'m3u8分片，浏览器播'},
 {id:'sess',name:'会话建联',desc:'手动建联/断开，SD直发包'},
 {id:'sd',name:'SD卡录像',desc:'查列表点播，画面进下方'},
];
var RELAY_FUNCS=[
 {id:'relay',name:'中继直播',desc:'主/辅/停止，画面进右侧'},
];
function renderLiveFuncs(){
  var box=document.getElementById('live-funcs');
  if(!box)return;
  var h='';
  LIVE_FUNCS.forEach(function(f){
    h+='<div class="dev-card" onclick="openLiveFunc(\''+f.id+'\')">';
    h+='<div class="nm">'+f.name+'</div>';
    h+='<div class="st">'+f.desc+'</div></div>';
  });
  box.innerHTML=h;
}
function renderRelayFuncs(){
  var box=document.getElementById('relay-funcs');
  if(!box)return;
  var h='';
  RELAY_FUNCS.forEach(function(f){
    h+='<div class="dev-card" onclick="openRelayFunc(\''+f.id+'\')">';
    h+='<div class="nm">'+f.name+'</div>';
    h+='<div class="st">'+f.desc+'</div></div>';
  });
  box.innerHTML=h;
}
var _liveFunc=null;
var _liveHlsTimer=null;
function startLiveHlsPoll(){
  stopLiveHlsPoll();
  liveHlsPoll();
  _liveHlsTimer=setInterval(liveHlsPoll,2000);
}
function stopLiveHlsPoll(){
  if(_liveHlsTimer){clearInterval(_liveHlsTimer);_liveHlsTimer=null;}
  var v=document.getElementById('live-hls-vid');
  sdHlsDestroy(v);
}
function liveHlsPoll(){
  var v=document.getElementById('live-hls-vid');
  if(!v){stopLiveHlsPoll();return;}
  var info=document.getElementById('live-hls-info');
  fetch('/stats').then(function(r){return r.json();}).then(function(s){
    var lh=s.live_hls||{};
    if(lh.ready&&v._hlsFor!=='live'){
      if(info)info.textContent='实时播放中（HLS）';
      sdHlsAttach(v,'/api/live/hls?file=index.m3u8','live','livehls');
    }else if(!v._hlsFor){
      if(info)info.textContent=s.running?('切片中…（分片'+(lh.segs||0)+'）'):'等待管线…（先播内网直播）';
    }
  }).catch(function(){});
}
function openLiveFunc(id){
  if(_liveFunc===id){
    document.getElementById('live-func-inline').innerHTML='';
    _liveFunc=null;
    stopLiveHlsPoll();
    return;
  }
  _liveFunc=id;
  stopLiveHlsPoll();
  buildLiveFunc(id);
  var el=document.getElementById('live-func-inline');
  if(el)el.scrollIntoView({behavior:'smooth',block:'nearest'});
}
var _relayFunc=null;
function openRelayFunc(id){
  if(_relayFunc===id){
    document.getElementById('relay-func-inline').innerHTML='';
    _relayFunc=null;
    return;
  }
  _relayFunc=id;
  buildRelayFunc(id);
  var el=document.getElementById('relay-func-inline');
  if(el)el.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function buildLiveFunc(id){
  var box=document.getElementById('live-func-inline');
  if(!box)return;
  if(id==='live'){
    box.innerHTML='<div class="card"><b>内网直播</b>'+
      '<div style="margin:8px 0"><button onclick="startLan(1)" style="width:100%">内网直播主</button></div>'+
      '<div style="margin:8px 0"><button onclick="startLan(0)" style="width:100%">内网直播辅</button></div>'+
      '<div style="margin:8px 0"><button onclick="stopLan()" class="danger" style="width:100%">停止</button></div>'+
      '<div id="live-msg" class="muted">idle</div>'+
      '<div id="live-stats" class="muted">idle</div>'+
      '<pre id="live-log" class="logout">等待启动…</pre>'+
      '<div class="muted" style="margin-top:4px">主=1080p / 辅=360p，设备凭证自动取云端，强制局域网直连。切走本页即停看（60秒后管线停）。</div></div>';
    return;
  }
  if(id==='sess'){
    box.innerHTML='<div class="card" style="border-color:#2a6"><b>会话（手动建联）</b>'+
      '<div style="margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
      '<button onclick="sessConnect()" style="white-space:nowrap">建联</button>'+
      '<button onclick="sessDisconnect()" class="danger" style="white-space:nowrap">断开</button>'+
      '<span id="sess-status" class="muted">未建联</span></div>'+
      '<div class="muted" style="margin-top:4px">建联后SD列表走会话直发包（秒回）；未建联自动单次建联查询。闲置5分钟自动断开省电（太阳能设备）。</div></div>';
    sessRefresh();
    return;
  }
  if(id==='hls'){
    box.innerHTML='<div class="card" style="border-color:#2a6"><b>HLS播放（内网直播）</b>'+
      '<video id="live-hls-vid" controls playsinline style="width:100%;margin-top:6px;background:#000;border-radius:4px"></video>'+
      '<div style="margin-top:6px"><span id="live-hls-info" class="muted">等待管线…（先播内网直播）</span></div>'+
      '<div class="muted" style="margin-top:4px">同一直播流的m3u8分片版，延迟比MJPEG大几秒；管线停后画面定格。</div></div>';
    startLiveHlsPoll();
    return;
  }
  if(id==='sd'){
    box.innerHTML='<div class="dev-row"><div class="dev-left">'+
      '<div class="card" style="border-color:#2a6"><b>SD卡录像（局域网直连）</b>'+
      '<div style="margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
      '<label>近 <select id="lan-sd-hours"><option value="6">6小时</option><option value="24" selected>24小时</option><option value="72">3天</option><option value="168">7天</option></select></label>'+
      '<label>等待 <select id="lan-sd-secs"><option value="20">20秒</option><option value="40" selected>40秒</option><option value="60">60秒</option><option value="90">90秒</option></select></label>'+
      '<button onclick="sdLanList()" style="white-space:nowrap">查询SD列表</button>'+
      '<span id="lan-sd-status" class="muted">已建联走会话直发包（秒回），未建联自动单次建联查询</span></div>'+
      '<pre id="lan-sd-log" class="logout">SD就绪（P2P直连查0x101，有回包即提前返回）</pre>'+
      '<div id="lan-sd-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin-top:8px"></div></div>'+
      '</div>'+
      '<div class="card" id="lan-sd-player"><b>回放</b>'+
      '<video id="lan-sd-vid" controls playsinline style="margin-top:6px;display:none"></video>'+
      '<div style="margin-top:6px"><span id="lan-sd-playinfo" class="muted">未在播</span></div>'+
      '</div></div>'+
      '<div class="muted" style="margin-top:4px">SD列表/回放走P2P直连设备（非云端）；等待时长可调。同一时间只查一个。</div>';
    return;
  }
}
function buildRelayFunc(id){
  var box=document.getElementById('relay-func-inline');
  if(!box)return;
  if(id==='relay'){
    box.innerHTML='<div class="card"><b>中继直播</b>'+
      '<div style="margin:8px 0"><button onclick="startRelay(1)" style="width:100%">中继直播主</button></div>'+
      '<div style="margin:8px 0"><button onclick="startRelay(0)" style="width:100%">中继直播辅</button></div>'+
      '<div style="margin:8px 0"><button onclick="stopRelay()" class="danger" style="width:100%">停止</button></div>'+
      '<div id="relay-msg" class="muted">idle</div>'+
      '<div id="relay-stats" class="muted">idle</div>'+
      '<pre id="relay-log" class="logout">等待启动…</pre>'+
      '<div class="muted" style="margin-top:4px">主=1080p / 辅=360p，设备凭证自动取云端，强制走公网中继（封局域网发现），异地/跨网段用它。切走本页即停看。</div></div>';
    return;
  }
}
function renderLiveInfo(){
  var box=document.getElementById('live-info');
  if(!box)return;
  var i=curDev();
  var h='';
  if(i){
    h+='<div class="dev-card"><div class="nm">'+escHtml(i.name||'?')+' '+(i.online?'<span class="ok">●在线</span>':'<span class="err">○离线</span>')+'</div>';
    h+='<div class="st">电量 '+(i.battery!=null?i.battery+'%':'—')+' · 信号 '+(i.signal!=null?i.signal:'—')+' · 活跃 '+fmtTime(i.last_active_utc)+'</div>';
    h+='<div class="st">型号 '+escHtml(i.model||'—')+' · 固件 '+escHtml(i.firmware||'—')+'</div>';
    h+='<div class="st muted">'+escHtml(i.uid||'')+'</div></div>';
  }else{
    h+='<div class="dev-card"><div class="nm">设备</div><div class="st muted">无设备（先去设备页登录）</div></div>';
  }
  var s=_sessSnap||{};
  var hs=s.hs||{};
  if(s.up){
    h+='<div class="dev-card"><div class="nm">会话 <span class="ok">●已建联</span> '+
      '<label class="switch" style="float:right"><input type="checkbox" checked onchange="sessToggle(this)"><span class="sl"></span></label></div>';
    h+='<div class="st">sid '+escHtml(hs.hs_sid||'—')+' · randomID '+escHtml(hs.hs_random||'—')+'</div>';
    h+='<div class="st">就绪经 '+escHtml(hs.hs_ready_via||'—')+' · 在线 '+s.uptime_s+'s</div>';
    h+='<div class="st">传输 '+(s.sess_tr||'—')+' · 闲置'+s.idle_left_s+'s后断'+(s.note?' · '+escHtml(s.note):'')+'</div></div>';
  }else{
    h+='<div class="dev-card"><div class="nm">会话 <span class="err">○未建联</span> '+
      '<label class="switch" style="float:right"><input type="checkbox" onchange="sessToggle(this)"><span class="sl"></span></label></div>'+
      '<div class="st muted">右滑开关建联'+(s.note?'（'+escHtml(s.note)+'）':'')+'</div></div>';
  }
  box.innerHTML=h;
}
function renderRelayInfo(){
  var box=document.getElementById('relay-info');
  if(!box)return;
  var i=curDev();
  var s=_statsSnap||{};
  var h='';
  if(i){
    h+='<div class="dev-card"><div class="nm">'+escHtml(i.name||'?')+' '+(i.online?'<span class="ok">●在线</span>':'<span class="err">○离线</span>')+'</div>';
    h+='<div class="st">电量 '+(i.battery!=null?i.battery+'%':'—')+' · 信号 '+(i.signal!=null?i.signal:'—')+' · 活跃 '+fmtTime(i.last_active_utc)+'</div>';
    h+='<div class="st muted">'+escHtml(i.uid||'')+'</div></div>';
  }else{
    h+='<div class="dev-card"><div class="nm">设备</div><div class="st muted">无设备（先去设备页登录）</div></div>';
  }
  h+='<div class="dev-card"><div class="nm">中继 <span class="muted">传输</span></div>';
  h+='<div class="st">模式 '+(s.transport||'—')+'（'+(s.transport_detail||'—')+'）</div>';
  h+='<div class="st">'+(s.running?'LIVE 解码'+s.decoded:'空闲')+' · 订阅'+(s.subs||0)+'</div></div>';
  box.innerHTML=h;
}
function sdLanLog(msg){  var el=document.getElementById('lan-sd-log');
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
var _vodTimer=null;
function sdVideoEl(where){return document.getElementById(where==='lan'?'lan-sd-vid':'side-vid');}
function sdHlsDestroy(v){if(!v)return;if(v._hls){try{v._hls.destroy();}catch(e){}v._hls=null;}v._hlsFor=null;}
function sdEnsureHlsJs(cb){
  if(window.Hls){cb(true);return;}
  if(document.getElementById('hlsjs')){
    var _t=setInterval(function(){if(window.Hls){clearInterval(_t);cb(true);}},500);
    setTimeout(function(){clearInterval(_t);cb(!!window.Hls);},15000);
    return;
  }
  var sc=document.createElement('script');sc.id='hlsjs';sc.src='/hls.js';
  sc.onload=function(){cb(!!window.Hls);};sc.onerror=function(){cb(false);};
  document.head.appendChild(sc);
}
function sdHlsAttach(v,url,start,where){
  if(!v||v._hlsFor===start)return;
  sdEnsureHlsJs(function(ok){
    if(!v||v._hlsFor===start||!ok)return;
    sdHlsDestroy(v);
    if(window.Hls&&Hls.isSupported()){
      var h=new Hls({maxBufferLength:15,liveSyncDurationCount:2});
      v._hls=h;v._hlsFor=start;
      h.loadSource(url);h.attachMedia(v);
      h.on(Hls.Events.MANIFEST_PARSED,function(){try{var p=v.play();if(p&&p.catch)p.catch(function(){});}catch(e){}});
    }else if(v.canPlayType&&v.canPlayType('application/vnd.apple.mpegurl')){
      v._hlsFor=start;v.src=url;
      try{var p2=v.play();if(p2&&p2.catch)p2.catch(function(){});}catch(e){}
    }else{return;}
    if(where==='lan'){
      v.style.display='block';
      var pi=document.getElementById('lan-sd-playinfo');
      if(pi)pi.innerHTML='实时播放中（HLS） <a href="/api/sd/vod_file?start='+start+'" download>下载</a>';
      v.scrollIntoView({behavior:'smooth',block:'nearest'});
    }else if(where==='side'){
      var vi=document.getElementById('side-info');
      if(vi)vi.textContent='实时播放中（HLS） start='+start;
      var dl=document.getElementById('side-dl');
      if(dl)dl.href='/api/sd/vod_file?start='+start;
    }
  });
}
function sdVodPlay(i,where){
  var e=_sdEvs[i];
  if(!e||!e.start)return;
  var uid=curUid();
  if(!uid)return;
  var info=(e.start_h||e.start)+' · '+(e.len_s||'?')+'s';
  sdHlsDestroy(sdVideoEl(where));
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
    _vodTimer=setInterval(function(){sdVodPoll(e.start,where);},2000);
    sdVodPoll(e.start,where);
  }).catch(function(ex){
    sdLanLog('点播请求失败: '+ex);
  });
}
function sdVodPoll(start,where){
  get('/api/sd/vod_status').then(function(s){
    var log=(s.log||[]).join(' | ').slice(-160);
    var v=sdVideoEl(where);
    var attached=!!(v&&v._hlsFor===start);
    if(s.hls&&(s.start===start)&&!attached){
      if(where==='lan'){var pi0=document.getElementById('lan-sd-playinfo');if(pi0)pi0.textContent='取到流，实时播放中 '+start+' …';}
      sdLanLog('vod '+start+' hls ready segs='+s.hls_segs);
      sdHlsAttach(v,s.hls,start,where);
    }else if(!attached){
      if(where==='lan'){var pi=document.getElementById('lan-sd-playinfo');if(pi)pi.textContent='取流中 '+start+' … '+log;}
    }
    sdLanLog('vod '+start+' running='+s.running+' hls='+!!s.hls+' '+(s.mp4||log));
    if(!s.running){
      if(_vodTimer){clearInterval(_vodTimer);_vodTimer=null;}
      if(s.mp4&&(s.start===start)){
        if(attached){
          var mp4url='/api/sd/vod_file?start='+start;
          if(where==='lan'){var pi2=document.getElementById('lan-sd-playinfo');if(pi2)pi2.innerHTML='正在播（HLS） <a href="'+mp4url+'" download>下载</a>';}
          else{var dl=document.getElementById('side-dl');if(dl)dl.href=mp4url;var vi=document.getElementById('side-info');if(vi)vi.textContent='正在播（HLS） start='+start;}
        }else{
          sdVodDone(start,where);
        }
      }else if(!attached){
        if(where==='lan'){var p3=document.getElementById('lan-sd-playinfo');if(p3)p3.textContent='点播失败 '+log;}
        else{playSide('about:blank','点播失败 '+log);}
      }
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
  try{renderLiveFuncs();}catch(e){}
  try{renderRelayFuncs();}catch(e){}
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
      if(_directWanted&&!lv.getAttribute('src'))lv.src='/video1.mjpg';
    }else{
      lv.src='about:blank';
    }
  }
  var ri=document.getElementById('relay-img');
  if(ri){
    if(name==='relaylive'){
      if(_relayWanted&&!ri.getAttribute('src'))ri.src='/video2.mjpg';
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
    _sessionSnap=s||null;
    var label=(s&&s.logged_in)?('已登录 '+(s.account||'—')+' · region '+(s.region||'—')):'未登录';
    if(s&&s.auto)label+=' · 自动续登开';
    document.getElementById('login-user').textContent=label;
    document.getElementById('user-session').textContent=label+'（凭证落容器 /data 600，重启/过期自动续）';
  }).catch(function(){document.getElementById('login-user').textContent='—';});
  loadUserStats();
  renderUserParams();
}
function loadUserStats(){
  var el=document.getElementById('user-devstats');
  if(!el)return;
  if((_devs||[]).length){
    var items=_devs;
    var on=0, off=0, mine=0, shared=0;
    items.forEach(function(i){
      if(i.online)on++;else off++;
      if(i.is_owner)mine++;else shared++;
    });
    el.innerHTML='共 '+items.length+' 台 · 在线 '+on+' / 离线 '+off+
      ' · 本人 '+mine+' / 他人分享 '+shared;
    return;
  }
  get('/api/devices').then(function(d){
    if(d.error){el.textContent=d.error;return;}
    storeDevs(d);
    renderUserParams();
    loadUserStats();
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
  var li=document.getElementById('live-info');
  var ri=document.getElementById('relay-info');
  if(!st&&!ls&&!rs&&!li&&!ri)return;
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
    if(s.sess){_sessSnap=s.sess;renderLiveInfo();var se=document.getElementById('sess-status');if(se)se.textContent=sessText(s.sess);}
    _statsSnap=s;renderRelayInfo();
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

    def _query_key_ok(self):
        # 浏览器会剥掉 URL 里嵌的 user:pass@，但 query 会原样送达：
        # /video*.mjpg?key=<http_password> /snap.jpg?key=… 免弹框直开。
        # 只放行只读流端点，页面与 API 照旧走 Basic。
        want_p = OPT.get("http_password", "")
        if not want_p:
            return False
        qs = self.path.split("?", 1)[1] if "?" in self.path else ""
        for kv in qs.split("&"):
            if kv.startswith("key="):
                return hmac.compare_digest(
                    urllib.parse.unquote(kv[4:]), want_p)
        return False

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

    def _serve_mjpeg(self, bids):
        # bids: subscribe these branches, serve the freshest frame seen
        # on any of them (主备合并). Single-element list = pure branch.
        for bid in bids:
            br = BR[bid]
            with LOCK:
                br["ST"]["subs"] += 1
                br["ST"]["last_sub_t"] = time.time()
            br["WAKE"].set()
        try:
            bnd = "uboxlive"
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "multipart/x-mixed-replace; boundary=" + bnd)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            last = (None, -1)
            while True:
                if client_gone(self.connection):
                    break
                with LOCK:
                    cands = [(BR[b]["LATEST"]["t"], BR[b]["LATEST"]["seq"],
                              BR[b]["LATEST"]["jpg"], b) for b in bids]
                    for b in bids:
                        BR[b]["ST"]["last_sub_t"] = time.time()
                cands = [c for c in cands if c[2] is not None]
                if cands:
                    t, seq, jpg, bid = max(cands)
                    if (bid, seq) != last:
                        head = ("--%s\r\nContent-Type: image/jpeg\r\n"
                                "Content-Length: %d\r\n\r\n"
                                % (bnd, len(jpg))).encode()
                        self.wfile.write(head + jpg + b"\r\n")
                        last = (bid, seq)
                        with LOCK:
                            BR[bid]["ST"]["served"] += 1
                time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError):
            pass
        finally:
            with LOCK:
                for bid in bids:
                    br = BR[bid]
                    br["ST"]["subs"] = max(0, br["ST"]["subs"] - 1)
                    br["ST"]["last_sub_t"] = time.time()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not self._auth_ok() and not (
                path in ("/video.mjpg", "/video1.mjpg", "/video2.mjpg",
                         "/snap.jpg")
                and self._query_key_ok()):
            self._deny_auth()
            return
        if path == "/":
            self._send(200, "text/html; charset=utf-8",
                       PAGE.encode("utf-8"))
        elif path == "/api/session":
            self._send(200, "application/json",
                       json.dumps(
                           {"logged_in": bool(_cloud_token),
                            "account": _cloud_account,
                            "region": _cloud_region,
                            "auto": _has_saved_cloud_creds()}).encode())
        elif path == "/api/devices":
            if not _cloud_token and not _auto_login():
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call_auto("/api/v2/user/device_list", {})
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
                s1, s2 = dict(BR["1"]["ST"]), dict(BR["2"]["ST"])
                t1, t2 = BR["1"]["LATEST"]["t"], BR["2"]["LATEST"]["t"]
                tr = dict(TR)
            now = time.time()

            def _br(bid, st, jt):
                br = BR[bid]
                return {"transport": br["transport"],
                        "running": st["running"], "spawns": st["spawns"],
                        "decoded": st["decoded"], "subs": st["subs"],
                        "served": st["served"],
                        "frame_age_ms": (int((now - jt) * 1000)
                                         if jt else None),
                        "isolation": br["iso"], "pid": br.get("pid"),
                        "hls_n": st["hls_n"], "hls_bytes": st["hls_bytes"],
                        "hls_err": st["hls_err"]}

            branches = {"video1": _br("1", s1, t1),
                        "video2": _br("2", s2, t2)}
            snap = {"decoded": s1["decoded"] + s2["decoded"],
                    "nals": s1["nals"] + s2["nals"],
                    "restarts": s1["restarts"] + s2["restarts"],
                    "spawns": s1["spawns"] + s2["spawns"],
                    "running": s1["running"] or s2["running"],
                    "served": s1["served"] + s2["served"],
                    "subs": s1["subs"] + s2["subs"],
                    "hls_n": s1["hls_n"], "hls_bytes": s1["hls_bytes"],
                    "hls_err": s1["hls_err"]}
            jt = max(t1, t2)
            snap["last_age_ms"] = (int((now - jt) * 1000) if jt else None)
            snap["uptime_s"] = int(now - min(s1["t0"], s2["t0"]))
            snap["fps"] = OPT["fps"]
            snap["transport"] = tr["mode"]
            snap["transport_applied"] = tr["applied"]
            snap["transport_detail"] = tr["detail"]
            snap["branches"] = branches
            snap["live_hls"] = {"ready": _live_hls_ready(
                                    BR["1"]["hlsdir"]),
                                "segs": _live_hls_segs(BR["1"]["hlsdir"]),
                                "n": snap["hls_n"], "bytes": snap["hls_bytes"],
                                "err": snap["hls_err"]}
            snap["sess"] = sess_status()
            self._send(200, "application/json",
                       json.dumps(snap).encode())
        elif path == "/snap.jpg":
            with LOCK:
                cands = [(BR[b]["LATEST"]["t"], BR[b]["LATEST"]["jpg"])
                         for b in ("1", "2")]
            cands = [(t, j) for t, j in cands if j is not None]
            if not cands:
                self._send(404, "text/plain", b"no frame yet")
                return
            self._send(200, "image/jpeg", max(cands)[1])
        elif path in ("/video.mjpg", "/video1.mjpg", "/video2.mjpg"):
            if not DEV["uid"] or not DEV["password"]:
                self._send(503, "text/plain",
                           b"device not configured (enter on web page)")
                return
            if path == "/video1.mjpg":
                self._serve_mjpeg(["1"])
            elif path == "/video2.mjpg":
                self._serve_mjpeg(["2"])
            else:
                # 主备合并：两路都订阅，逐帧取最新鲜者
                self._serve_mjpeg(["1", "2"])
        elif path == "/api/sd/list_live":
            self._send(200, "application/json",
                       json.dumps(read_sd_live()).encode())
            return
        elif path == "/api/sess/status":
            self._send(200, "application/json",
                       json.dumps(sess_status()).encode())
            return
        elif path == "/api/live/hls":
            qs = (self.path.split("?", 1)[1]
                  if "?" in self.path else "")
            q = {}
            for kv in qs.split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    q[k] = v
            import re as _re2
            fn = q.get("file", "")
            if (not _re2.fullmatch(r"[\w.\-]+", fn)
                    or not fn.endswith((".m3u8", ".ts"))
                    or "/" in fn or "\\" in fn):
                self._send(400, "text/plain", b"bad hls request")
                return
            fp = os.path.join(BR["1"]["hlsdir"], fn)
            if not (os.path.isfile(fp) and os.path.getsize(fp) > 0):
                self._send(404, "text/plain", b"hls not ready")
                return
            try:
                with open(fp, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send(404, "text/plain", b"hls not ready")
                return
            ctype = ("application/vnd.apple.mpegurl"
                     if fn.endswith(".m3u8") else "video/mp2t")
            self._send(200, ctype, body)
            return
        elif path == "/api/sd/vod_status":
            with VOD_LOCK:
                mp4 = VOD_RUN["mp4"]
                hlsdir = VOD_RUN.get("hls_dir") or ""
                self._send(200, "application/json",
                           json.dumps(
                               {"running": VOD_RUN["running"],
                                "start": VOD_RUN["start"],
                                "log": list(VOD_RUN["log"][-20:]),
                                "mp4": (os.path.basename(mp4)
                                        if mp4 else None),
                                "hls_ready": bool(
                                    VOD_RUN.get("hls_ready")),
                                "hls_segs": _vod_hls_segs(hlsdir),
                                "hls": ("/api/sd/hls?start=%s&file=index.m3u8"
                                        % VOD_RUN["start"])
                                if VOD_RUN.get("hls_ready") else None}
                               ).encode())
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
        elif path == "/api/sd/hls":
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
            import re as _re
            fn = q.get("file", "")
            if (not start or not _re.fullmatch(r"[\w.\-]+", fn)
                    or not fn.endswith((".m3u8", ".m4s", ".mp4"))
                    or "/" in fn or "\\" in fn):
                self._send(400, "text/plain", b"bad hls request")
                return
            fp = os.path.join(VODDIR, "hls_%s" % start, fn)
            if not (os.path.isfile(fp) and os.path.getsize(fp) > 0):
                self._send(404, "text/plain", b"hls not ready")
                return
            try:
                with open(fp, "rb") as fh:
                    body = fh.read()
            except OSError:
                self._send(404, "text/plain", b"hls not ready")
                return
            ctype = {"m3u8": "application/vnd.apple.mpegurl",
                     "m4s": "video/iso.segment",
                     "mp4": "video/mp4"}[fn.rsplit(".", 1)[1]]
            self._send(200, ctype, body)
            return
        elif path == "/hls.js":
            self._send_hls_js()
            return
        else:
            self._send(404, "text/plain", b"not found")

    def _send_hls_js(self):
        """Serve hls.js (cached under /data, fetched once from CDN)."""
        import urllib.request as _url
        js = os.environ.get("UBOX_HLSJS_FILE", "/data/hls.min.js")
        try:
            if os.path.isfile(js) and os.path.getsize(js) > 100000:
                with open(js, "rb") as fh:
                    self._send(200, "application/javascript", fh.read())
                return
        except OSError:
            pass
        try:
            req = _url.Request(
                "https://cdn.jsdelivr.net/npm/hls.js@1.5.18/dist/hls.min.js",
                headers={"User-Agent": "ubox-addon"})
            with _url.urlopen(req, timeout=30) as resp:
                data = resp.read()
            if len(data) > 100000:
                try:
                    with open(js, "wb") as fh:
                        fh.write(data)
                    try:
                        os.chmod(js, 0o644)
                    except OSError:
                        pass
                except OSError:
                    pass
                self._send(200, "application/javascript", data)
                return
        except Exception as e:
            self._send(502, "text/plain",
                       ("hls.js fetch failed: %s" % str(e)[:120]).encode())
            return
        self._send(502, "text/plain", b"hls.js fetch failed")

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
            _save_cloud_creds(account, password, region)
            # 登录即配设备：从云设备表落 device.json，新容器零手动开流
            _load_device()
            olduid = DEV["uid"]
            duid, dnote = _ensure_device_from_cloud(allow_pick=True)
            if duid and duid != olduid:
                _stop_all_branches()
                _wake_all_branches()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "account": _cloud_account,
                                   "region": _cloud_region,
                                   "device_uid": duid,
                                   "device_note": dnote}).encode())
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
            _stop_all_branches()
            _wake_all_branches()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "restarted": True}).encode())
            return
        if path == "/api/cloud/list":
            body = self._read_json()
            if not _cloud_token and not _auto_login():
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            now = int(time.time())
            req = {"begin": body.get("begin", now - 7 * 86400),
                   "end": body.get("end", now),
                   "device_uids": body.get("device_uids", [])}
            data, err = _cloud_call_auto("/api/user/qry/cloudvideo/list/v2",
                                         req)
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
            return
        if path == "/api/cloud/url":
            body = self._read_json()
            if not _cloud_token and not _auto_login():
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call_auto(
                "/api/user/qry/cloudvideo/get_video_url", {
                    "bucket_name": body.get("bucket_name"),
                    "cloud_provider": body.get("cloud_provider"),
                    "cloud_provider_int": body.get("cloud_provider_int", 1),
                    "endpoint": body.get("endpoint"),
                    "guid": body.get("guid") or body.get("itemid"),
                    "image": body.get("image"),
                    "uid": body.get("uid", ""),
                })
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
            if not _cloud_token and not _auto_login():
                self._send(401, "application/json",
                           json.dumps({"error": "not logged in"}).encode())
                return
            data, err = _cloud_call_auto(
                "/api/user/qry/device/get_webrtc_token", {"uid": uid})
            if err:
                self._send(502, "application/json",
                           json.dumps({"error": err}).encode())
                return
            self._send(200, "application/json",
                       json.dumps(data).encode())
            return
        if path == "/api/pipeline-stop":
            _stop_all_branches()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "running": False}).encode())
            return
        if path == "/api/live/start":
            # 分支启流：video1=直连优先，video2=中继。各分支 transport 固定，
            # 不再动全局 transport（分支起流会自动清掉冲突的全局规则）。
            bid = q.get("branch", "1")
            if bid not in BR:
                self._send(400, "application/json",
                           json.dumps({"error": "branch must be 1 or 2"}
                                      ).encode())
                return
            body = self._read_json()
            try:
                n = int(body.get("stream", OPT["stream"]))
            except (TypeError, ValueError):
                n = OPT["stream"]
            OPT["stream"] = n
            _save_settings()
            br = BR[bid]
            br["WAKE"].set()
            with LOCK:
                st = dict(br["ST"])
            self._send(200, "application/json",
                       json.dumps({"ok": True, "branch": bid,
                                   "name": br["name"],
                                   "transport": br["transport"],
                                   "stream": n,
                                   "running": st["running"]}).encode())
            return
        if path == "/api/live/stop":
            bid = q.get("branch", "all")
            if bid == "all":
                _stop_all_branches()
            elif bid in BR:
                stop_pipeline(BR[bid])
            else:
                self._send(400, "application/json",
                           json.dumps({"error": "branch must be 1, 2 or all"}
                                      ).encode())
                return
            self._send(200, "application/json",
                       json.dumps({"ok": True, "branch": bid}).encode())
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
                if sess_usable(uid):
                    now = int(time.time())
                    hours = max(1, min(168, int(body.get("hours", 24)
                                               or 24)))
                    secs = body.get("secs", 40)
                    try:
                        secs = max(15, min(90, int(secs or 40)))
                    except (TypeError, ValueError):
                        secs = 40
                    payload, code = sess_cmd_list(
                        uid, now - hours * 3600, now, timeout=secs + 10)
                else:
                    username, password, derr = _resolve_device(uid)
                    if derr:
                        payload, code = ({"error": derr, "events": []},
                                         401 if "not logged in" in derr
                                         else 503)
                    else:
                        payload, code = run_sdlist(
                            uid, username, password,
                            body.get("hours", 24), body.get("secs", 40))
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
            username, password, derr = _resolve_device(uid)
            if derr:
                self._send(401 if "not logged in" in derr else 503,
                           "application/json",
                           json.dumps({"error": derr}).encode())
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
                VOD_RUN["hls_ready"] = False
                VOD_RUN["hls_dir"] = ""
                secs = min(45 + length * 2, 400)
                daemon_vod = sess_usable(uid)
                threading.Thread(target=_vod_worker,
                                 args=(uid, username, password, start,
                                       length, body.get("reqseq", 3),
                                       daemon_vod),
                                 daemon=True).start()
            except Exception as e:
                with VOD_LOCK:
                    VOD_RUN["running"] = False
                _vod_log("VOD启动失败：%s" % str(e)[:120])
                self._send(500, "application/json",
                           json.dumps({"error": "vod start failed"})
                           .encode())
                return
            finally:
                VOD_LOCK.release()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "start": start,
                                   "cached": False, "secs": secs}).encode())
            return
        if path == "/api/sess/connect":
            body = self._read_json()
            uid = (body.get("uid") or "").strip()
            if not uid:
                self._send(400, "application/json",
                           json.dumps({"error": "need uid"}).encode())
                return
            username, password, derr = _resolve_device(uid)
            if derr:
                self._send(401 if "not logged in" in derr else 503,
                           "application/json",
                           json.dumps({"error": derr}).encode())
                return
            ok, msg = sess_start(uid, username, password)
            self._send(200 if ok else 504, "application/json",
                       json.dumps({"ok": ok,
                                   "msg" if ok else "error": msg,
                                   "status": sess_status()}).encode())
            return
        if path == "/api/sess/disconnect":
            was = sess_stop()
            self._send(200, "application/json",
                       json.dumps({"ok": True,
                                   "was_connected": was}).encode())
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
            if (DEV["uid"] == uid and DEV["username"] == username
                    and DEV["password"] == password):
                self._send(200, "application/json",
                           json.dumps({"ok": True, "uid": uid,
                                       "username": username,
                                       "restarted": False,
                                       "cached": True}).encode())
                return
            DEV["uid"] = uid
            DEV["username"] = username
            DEV["password"] = password
            _save_device()
            _stop_all_branches()
            _wake_all_branches()
            self._send(200, "application/json",
                       json.dumps({"ok": True, "uid": uid,
                                   "username": username,
                                   "restarted": True}).encode())
            return
        if path == "/api/logout":
            _clear_cloud_session()
            _clear_cloud_creds()
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
            _stop_all_branches()
            _wake_all_branches()
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
    _load_cloud_creds()
    _load_device()
    if not _cloud_token and _has_saved_cloud_creds():
        threading.Thread(target=_auto_login, daemon=True).start()
    print("options: stream=%d fps=%d idle=%ds transport=%s http_auth=%s cloud=%s device=%s" % (
        OPT["stream"], OPT["fps"], OPT["idle_timeout"],
        OPT["transport"], "on" if OPT.get("http_password") else "off",
        ("logged_in" if _cloud_token else "logged_out"),
        ("set" if (DEV["uid"] and DEV["password"]) else "empty")),
        flush=True)
    apply_transport(OPT["transport"])
    for br in BR.values():
        threading.Thread(target=supervisor, args=(br,),
                         daemon=True).start()
    threading.Thread(target=sess_supervisor, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", OPT["port"]), Handler)
    print("serving on :%d" % OPT["port"], flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
