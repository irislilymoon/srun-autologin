#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深澜 (Srun) 校园网认证客户端 —— 无浏览器自动登录。

协议还原自 portal (http://10.0.0.55) 自身的 static/js/jquery.srun.portal.js
与 static/bower/all/1.0.0/all.min.js，逐字节对齐。

认证流程：
  1. GET  /cgi-bin/get_challenge   -> 拿到一次性 challenge 与 client_ip
  2. 本地计算 hmd5 / info / chksum
  3. GET  /cgi-bin/srun_portal?action=login&...  -> 完成认证

用法：
  python srun_login.py params <username> <password> <challenge> <ip> <ac_id>
      # 只打印参数（用于与门户 JS 对拍，不联网登录）
  python srun_login.py login            # 认证一次
  python srun_login.py check            # 只检查当前是否已在线
  python srun_login.py watch            # 常驻守护：断了自动重连
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 极早期探针：在 import 其它模块之前记一笔时间戳。
# 用来区分三类延迟：① 任务调度延迟 ② 解释器启动延迟 ③ 我们的代码耗时。
# 平时只是一行日志，排障时是关键证据。
# ---------------------------------------------------------------------------
import os as _probe_os
import time as _probe_time


def _early_probe() -> None:
    try:
        base = _probe_os.path.dirname(_probe_os.path.abspath(__file__))
        path = _probe_os.path.join(base, "logs", "entry.log")
        _probe_os.makedirs(_probe_os.path.dirname(path), exist_ok=True)
        if _probe_os.path.exists(path) and _probe_os.path.getsize(path) > 32768:
            _probe_os.remove(path)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("%.3f pid=%d\n" % (_probe_time.time(), _probe_os.getpid()))
    except Exception:
        pass


_early_probe()

import argparse
import concurrent.futures
import ctypes
import hashlib
import hmac
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from ctypes import wintypes
from pathlib import Path

# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
PORTAL = "http://10.0.0.55"
PORTAL_HOST = "10.0.0.55"
AC_ID = "43"
TASK_NAME = "SRun.AutoLogin"
USERNAME = "STUDENT_ID"           # 学号 / 上网账号（默认占位符，真实值放 config.json）
PASSWORD = "PUT_YOUR_PASSWORD"   # 密码（建议改到 config.json 里，别写死在脚本里）
PLACEHOLDER = "PUT_YOUR_PASSWORD"


class ConfigError(RuntimeError):
    """本地配置有问题（例如密码还是占位符）。"""


# 进程退出码，供桌面 .bat 区分「成功 / 失败 / 按设计跳过」
RC_OK = 0
RC_FAIL = 1
RC_SKIP = 3
N = 200
TYPE = 1
OS_NAME = "Windows 10"
OS_PLATFORM = "Windows"
DOUBLE_STACK = 0
IGNORE = 2

# 外网连通性探测点：返回 204 即视为已联网
PROBE_URLS = (
    "http://connect.rom.miui.com/generate_204",
    "http://www.baidu.com",
)

# 自定义 base64 字母表（门户 jquery-base64 插件内硬编码，非标准表）
B64_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
B64_PAD = "="

MASK32 = 0xFFFFFFFF
DELTA = 0x86014019 | 0x183639A0          # == 0x9E3779B9
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


# --------------------------------------------------------------------------
# 1) 深澜自定义 base64（自定义字母表，标准分组与填充）
# --------------------------------------------------------------------------
def b64_encode(data: bytes) -> str:
    if not data:
        return ""
    out = []
    imax = len(data) - len(data) % 3
    for i in range(0, imax, 3):
        b10 = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2]
        out.append(B64_ALPHA[b10 >> 18 & 63])
        out.append(B64_ALPHA[b10 >> 12 & 63])
        out.append(B64_ALPHA[b10 >> 6 & 63])
        out.append(B64_ALPHA[b10 & 63])
    rem = len(data) - imax
    if rem == 1:
        b10 = data[imax] << 16
        out.append(B64_ALPHA[b10 >> 18 & 63] + B64_ALPHA[b10 >> 12 & 63] + B64_PAD + B64_PAD)
    elif rem == 2:
        b10 = (data[imax] << 16) | (data[imax + 1] << 8)
        out.append(
            B64_ALPHA[b10 >> 18 & 63]
            + B64_ALPHA[b10 >> 12 & 63]
            + B64_ALPHA[b10 >> 6 & 63]
            + B64_PAD
        )
    return "".join(out)


def b64_decode(text: str) -> bytes:
    text = text.rstrip(B64_PAD)
    out = bytearray()
    for i in range(0, len(text), 4):
        chunk = text[i:i + 4]
        acc = 0
        for j, ch in enumerate(chunk):
            acc |= B64_ALPHA.index(ch) << (18 - 6 * j)
        for j in range(len(chunk) - 1):
            out.append(acc >> (16 - 8 * j) & 0xFF)
    return bytes(out)


# --------------------------------------------------------------------------
# 2) 深澜自定义 xEncode（XXTEA 变体），严格镜像门户 JS
#    s(a,b) 按 4 字符一组做小端打包；文本模式追加长度；l(a) 还原为字节串
# --------------------------------------------------------------------------
def _pack(text: str, append_len: bool) -> list[int]:
    """镜像 JS 的 s(a, b)：按 UTF-16 code unit 4 个一组小端打包为 int32。"""
    raw = text.encode("utf-16-le")
    units = list(struct.unpack("<%dH" % (len(raw) // 2), raw))
    v: list[int] = []
    for i in range(0, len(units), 4):
        chunk = units[i:i + 4]
        # JS 里越界的 charCodeAt 返回 NaN，NaN << k 结果为 0
        while len(chunk) < 4:
            chunk.append(0)
        v.append((chunk[0] | chunk[1] << 8 | chunk[2] << 16 | chunk[3] << 24) & MASK32)
    if append_len:
        v.append(len(units))
    return v


def _unpack(v: list[int]) -> bytes:
    """镜像 JS 的 l(a, false)：每个 int32 还原为 4 字节，小端。"""
    out = bytearray()
    for x in v:
        out += bytes((x & 0xFF, x >> 8 & 0xFF, x >> 16 & 0xFF, x >> 24 & 0xFF))
    return bytes(out)


def xencode(text: str, key: str) -> bytes:
    if text == "":
        return b""
    v = _pack(text, True)
    k = _pack(key, False)
    while len(k) < 4:
        k.append(0)

    n = len(v) - 1
    z, y = v[n], v[0]
    q = math.floor(6 + 52 / (n + 1))
    d = 0

    while q > 0:
        q -= 1
        d = (d + DELTA) & MASK32
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = v[p + 1]
            m = (z >> 5) ^ (y << 2 & MASK32)
            m = (m + (((y >> 3) ^ (z << 4 & MASK32)) ^ (d ^ y))) & MASK32
            m = (m + ((k[(p & 3) ^ e] ^ z) & MASK32)) & MASK32
            z = (v[p] + m) & MASK32
            v[p] = z
            p += 1
        # 注意：JS 的 for 循环结束后 p === n，最后一块用的是 k[(n & 3) ^ e]
        y = v[0]
        m = (z >> 5) ^ (y << 2 & MASK32)
        m = (m + (((y >> 3) ^ (z << 4 & MASK32)) ^ (d ^ y))) & MASK32
        m = (m + ((k[(p & 3) ^ e] ^ z) & MASK32)) & MASK32
        z = (v[n] + m) & MASK32
        v[n] = z

    return _unpack(v)


# --------------------------------------------------------------------------
# 3) 三个派生子
# --------------------------------------------------------------------------
def hmd5(password: str, challenge: str) -> str:
    """md5(d, k) -> HMAC-MD5(key=challenge, message=password)，十六进制。
    门户用的是 blueimp-md5 的 md5(value, key) 形式，是 HMAC 而不是拼接哈希。"""
    return hmac.new(challenge.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()


def info_field(username: str, password: str, ip: str, ac_id: str, challenge: str) -> str:
    plain = json.dumps(
        {
            "username": username,
            "password": password,
            "ip": ip,
            "acid": ac_id,
            "enc_ver": "srun_bx1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "{SRBX1}" + b64_encode(xencode(plain, challenge))


def build_login_params(username: str, password: str, challenge: str, ip: str, ac_id: str) -> dict:
    info = info_field(username, password, ip, ac_id, challenge)
    pwd = hmd5(password, challenge)

    chkstr = challenge + username
    chkstr += challenge + pwd
    chkstr += challenge + ac_id
    chkstr += challenge + ip
    chkstr += challenge + str(N)
    chkstr += challenge + str(TYPE)
    chkstr += challenge + info

    return {
        "action": "login",
        "username": username,
        "password": "{MD5}" + pwd,
        "ac_id": ac_id,
        "ip": ip,
        "chksum": hashlib.sha1(chkstr.encode("utf-8")).hexdigest(),
        "info": info,
        "n": str(N),
        "type": str(TYPE),
        "os": OS_NAME,
        "name": OS_PLATFORM,
        "double_stack": str(DOUBLE_STACK),
        "ignore": str(IGNORE),
        "cas_account": "",
        "cas_password": "",
    }


# --------------------------------------------------------------------------
# 4) HTTP
# --------------------------------------------------------------------------
_JSON_RE = re.compile(r"^\s*[\w$]*\s*\((.*)\)\s*;?\s*$", re.S)


def _request(url: str, timeout: float = 10.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Referer": PORTAL + "/"})
    with _OPENER.open(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _jsonp(text: str) -> dict:
    text = text.strip()
    if text.startswith("{"):
        return json.loads(text)
    m = _JSON_RE.match(text)
    if not m:
        raise ValueError("unexpected jsonp payload: %r" % text[:200])
    return json.loads(m.group(1))


def get_challenge(username: str) -> dict:
    """取一次性 challenge 与服务器识别的 client_ip。"""
    qs = urllib.parse.urlencode(
        {
            "callback": "jQuery%d" % int(time.time() * 1000),
            "username": username,
            "ip": "",
            "_": str(int(time.time() * 1000)),
        },
        quote_via=urllib.parse.quote,
    )
    return _jsonp(_request("%s/cgi-bin/get_challenge?%s" % (PORTAL, qs)))


def get_user_info() -> dict:
    return _jsonp(_request("%s/cgi-bin/rad_user_info?callback=jQuery&_=%d" % (PORTAL, int(time.time() * 1000))))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """断网时门户会 302 劫持到认证页，跟随重定向会把认证页的 200 误判成已联网。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# 一律直连、一律不跟随重定向：
#   · 10.0.0.55 是本地址，走系统代理（例如 127.0.0.1:7890）必然失败
#   · 外网探测也必须直连，否则测不出门户劫持
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def is_online(timeout: float = 5.0) -> bool:
    """能打到外网才算在线；被重定向或撞到门户页面一律算离线。"""
    for url in PROBE_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with _OPENER.open(req, timeout=timeout) as resp:
                body = resp.read(4096)
                if resp.status == 204:
                    return True
                if resp.status == 200:
                    low = body.decode("utf-8", "replace").lower()
                    # 兜底：门户直接回 200 而不是 302 的情况
                    if PORTAL_HOST in low or "srun" in low or "深澜" in low or "portal" in low:
                        return False
                    return True
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                return False          # 被劫持重定向，说明没认证
            continue
        except Exception:
            continue
    return False


def logout(username: str | None = None, ac_id: str | None = None, ip: str | None = None) -> dict:
    """注销当前在线会话（门户的 action=logout，不需要 chksum）。"""
    cfg_user, _cfg_pass, cfg_ac = load_config()
    username = username or cfg_user
    ac_id = ac_id or cfg_ac
    if not ip:
        ip = (get_challenge(username).get("client_ip") or "")

    params = {"action": "logout", "ac_id": ac_id, "ip": ip, "username": username}
    qs = urllib.parse.urlencode({"callback": "jQuery%d" % int(time.time() * 1000), **params})
    res = _jsonp(_request("%s/cgi-bin/srun_portal?%s" % (PORTAL, qs)))
    return {"ok": res.get("error") == "ok", "resp": res}


def config_path() -> Path:
    return Path(__file__).with_name("config.json")


def _read_config() -> dict:
    cfg = config_path()
    if not cfg.exists():
        return {}
    try:
        data = json.loads(cfg.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def load_config() -> tuple[str, str, str]:
    """账号取自同目录 config.json，没有则回落到脚本顶部的常量。"""
    d = _read_config()
    return (
        str(d.get("username", USERNAME)),
        str(d.get("password", PASSWORD)),
        str(d.get("ac_id", AC_ID)),
    )


def write_config(username: str, password: str, ac_id: str, portal: str | None = None) -> Path:
    data = {"username": username, "password": password, "ac_id": ac_id}
    if portal:
        data["portal"] = portal
    cfg = config_path()
    cfg.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return cfg


def apply_config_constants() -> None:
    """允许 config.json 覆盖门户地址，换学校/换校区不用改代码。"""
    global PORTAL, PORTAL_HOST
    raw = str(_read_config().get("portal") or "").strip()
    if not raw:
        return
    if "://" not in raw:
        raw = "http://" + raw
    raw = raw.rstrip("/")
    host = urllib.parse.urlparse(raw).hostname
    if host:
        PORTAL, PORTAL_HOST = raw, host


def login(username: str | None = None, password: str | None = None, ac_id: str | None = None) -> dict:
    cfg_user, cfg_pass, cfg_ac = load_config()
    username = username or cfg_user
    password = password or cfg_pass
    ac_id = ac_id or cfg_ac

    if not password or password == PLACEHOLDER:
        raise ConfigError("config.json 里的 password 还是占位符，先填真实密码再跑 login。")

    chal = get_challenge(username)
    if chal.get("error") not in (None, "ok"):
        return {"ok": False, "stage": "get_challenge", "resp": chal}

    challenge = chal["challenge"]
    ip = chal.get("client_ip") or chal.get("online_ip") or ""
    params = build_login_params(username, password, challenge, ip, ac_id)

    qs = urllib.parse.urlencode({"callback": "jQuery%d" % int(time.time() * 1000), **params})
    res = _jsonp(_request("%s/cgi-bin/srun_portal?%s" % (PORTAL, qs)))
    return {"ok": res.get("error") == "ok" or res.get("res") == "ok", "stage": "srun_portal", "resp": res}


# --------------------------------------------------------------------------
# 5) 环境识别：是不是「有线 + 校园网」，只有这个组合才需要登录
# --------------------------------------------------------------------------
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# 虚拟网卡会伪装成 802.3（实测 TAP-Windows Adapter V9 就是），必须按名字排掉
VIRTUAL_HINTS = (
    "tap-windows", "wintun", "tailscale", "wireguard", "openvpn", "zerotier",
    "hyper-v", "vmware", "virtualbox", "virtual", "loopback", "npcap", "tunnel",
)
WIRELESS_HINTS = ("802.11", "wlan", "wi-fi", "wifi", "wireless", "无线")

_PS_ADAPTER = r"""
$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
$ip = "%s"
$addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $ip } | Select-Object -First 1
if (-not $addr) { Write-Output '{"found":false}'; exit 0 }
$ad = Get-NetAdapter -InterfaceIndex $addr.InterfaceIndex -ErrorAction SilentlyContinue
[pscustomobject]@{
  found       = $true
  name        = [string]$ad.Name
  description = [string]$ad.InterfaceDescription
  status      = [string]$ad.Status
  mediaType   = [string]$ad.MediaType
  physical    = [string]$ad.PhysicalMediaType
  ifIndex     = $addr.InterfaceIndex
} | ConvertTo-Json -Compress
"""

_adapter_cache: dict[str, dict] = {}


def route_source_ip(target: str | None = None, port: int = 80) -> str | None:
    """本机访问 target 时会用哪块网卡的哪个源 IP。UDP connect 不发包，无路由返回 None。"""
    target = target or PORTAL_HOST
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(2.0)
        sock.connect((target, port))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0] if text.strip() else ""


def _iftype_to_physical(iftype: int) -> str:
    """把 Win32 IF_TYPE 映射成和 PowerShell PhysicalMediaType 一样的字面值。"""
    if iftype == 6:                    # IF_TYPE_ETHERNET_CSMACD
        return "802.3"
    if iftype == 71:                   # IF_TYPE_IEEE80211
        return "Native 802.11"
    return "iftype:%d" % iftype


class _SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Flags", wintypes.DWORD),
    ("Next", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", _SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", wintypes.ULONG),
    ("PreferredLifetime", wintypes.ULONG),
    ("LeaseLifetime", wintypes.ULONG),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class _IP_ADAPTER_ADDRESSES(ctypes.Structure):
    """只声明到 OperStatus 为止，后面的字段用不到。x64 下偏移已实测核对。"""

    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", wintypes.ULONG),          # 0
    ("IfIndex", wintypes.DWORD),         # 4
    ("Next", ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),   # 8
    ("AdapterName", ctypes.c_char_p),                  # 16
    ("FirstUnicastAddress", ctypes.POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),  # 24
    ("FirstAnycastAddress", ctypes.c_void_p),          # 32
    ("FirstMulticastAddress", ctypes.c_void_p),        # 40
    ("FirstDnsServerAddress", ctypes.c_void_p),        # 48
    ("DnsSuffix", ctypes.c_wchar_p),                   # 56
    ("Description", ctypes.c_wchar_p),                 # 64
    ("FriendlyName", ctypes.c_wchar_p),                # 72
    ("PhysicalAddress", ctypes.c_ubyte * 8),           # 80
    ("PhysicalAddressLength", wintypes.ULONG),         # 88
    ("Flags", wintypes.DWORD),                         # 92
    ("Mtu", wintypes.ULONG),                           # 96
    ("IfType", wintypes.DWORD),                        # 100
    ("OperStatus", ctypes.c_int),                      # 104
]

_GAA_SKIP = 0x0002 | 0x0004 | 0x0008        # anycast / multicast / dns server
_ERROR_BUFFER_OVERFLOW = 111
_IF_OPER_STATUS_UP = 1


def _sockaddr_ipv4(ptr) -> str | None:
    if not ptr:
        return None
    try:
        if ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ushort))[0] != socket.AF_INET:
            return None
        return socket.inet_ntoa(ctypes.string_at(ptr + 4, 4))
    except Exception:
        return None


def _adapter_by_ip_ctypes(ip: str) -> dict | None:
    """直接调 iphlpapi!GetAdaptersAddresses。

    比启动一次 PowerShell 快三个数量级（毫秒 vs 秒级冷启动），
    开机阶段的耗时基本就省在这里。失败时返回 None，由 PowerShell / ipconfig 兜底。
    """
    if os.name != "nt":
        return None
    try:
        func = ctypes.WinDLL("iphlpapi").GetAdaptersAddresses
    except Exception:
        return None
    func.argtypes = [
        wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
        ctypes.POINTER(_IP_ADAPTER_ADDRESSES), ctypes.POINTER(wintypes.ULONG),
    ]
    func.restype = wintypes.ULONG

    size = wintypes.ULONG(15000)
    buf = ctypes.create_string_buffer(size.value)
    for _ in range(4):
        ret = func(0, _GAA_SKIP, None,
                   ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES)),
                   ctypes.byref(size))
        if ret == 0:
            break
        if ret == _ERROR_BUFFER_OVERFLOW:
            buf = ctypes.create_string_buffer(size.value)
            continue
        return None
    else:
        return None

    node = ctypes.cast(buf, ctypes.POINTER(_IP_ADAPTER_ADDRESSES))
    while node:
        ad = node.contents
        unicast = ad.FirstUnicastAddress
        while unicast:
            if _sockaddr_ipv4(unicast.contents.Address.lpSockaddr) == ip:
                return {
                    "found": True,
                    "name": ad.FriendlyName or "",
                    "description": ad.Description or "",
                    "status": "Up" if ad.OperStatus == _IF_OPER_STATUS_UP else "Down",
                    "mediaType": "",
                    "physical": _iftype_to_physical(ad.IfType),
                    "ifIndex": ad.IfIndex,
                    "source": "ctypes",
                }
            unicast = unicast.contents.Next
        node = ad.Next
    return None


def _adapter_by_ip_powershell(ip: str) -> dict | None:
    exe = _find_pwsh()
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command", _PS_ADAPTER % ip],
            capture_output=True, timeout=15, creationflags=_NO_WINDOW,
        )
    except Exception:
        return None
    text = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if data.get("found") else None


def _adapter_by_ip_ipconfig(ip: str) -> dict | None:
    """PowerShell 不可用时的兜底：解析 ipconfig 的分段标题。"""
    try:
        proc = subprocess.run(["ipconfig"], capture_output=True, timeout=15, creationflags=_NO_WINDOW)
        raw = proc.stdout or b""
    except Exception:
        return None
    for enc in ("gbk", "cp936", "utf-8"):
        try:
            text = raw.decode(enc)
            break
        except Exception:
            text = raw.decode("utf-8", "replace")

    header = None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.strip()
            continue
        if header and ip in line:
            low = header.lower()
            physical = "Native 802.11" if any(h in low for h in WIRELESS_HINTS) else "802.3"
            return {"found": True, "name": header, "description": header,
                    "status": "Up", "mediaType": "", "physical": physical, "ifIndex": -1}
    return None


def classify_adapter(info: dict) -> str:
    """-> wired / wireless / virtual / unknown"""
    label = ((info.get("description") or "") + " " + (info.get("name") or "")).lower()
    physical = (info.get("physical") or "").lower()
    media = (info.get("mediaType") or "").lower()

    if any(h in label for h in VIRTUAL_HINTS):
        return "virtual"
    if any(h in physical for h in WIRELESS_HINTS) or any(h in label for h in WIRELESS_HINTS):
        return "wireless"
    # 以 PhysicalMediaType 为准：蓝牙网卡和 WLAN 的 mediaType 也可能是 802.3
    if physical == "802.3":
        return "wired"
    if physical in ("", "unspecified", "unknown", "undefined") and media == "802.3":
        return "wired"
    return "unknown"


def probe_portal(timeout: float = 3.0) -> str:
    """确认 10.0.0.55 真的是深澜门户，避免在家庭内网里误判。

    返回 'ok' / 'unreachable' / 'not_srun'。
    """
    try:
        req = urllib.request.Request(
            "%s/srun_portal_pc?ac_id=%s" % (PORTAL, AC_ID),
            headers={"User-Agent": UA},
        )
        with _OPENER.open(req, timeout=timeout) as resp:
            flag = (resp.headers.get("SRunFlag") or "").lower()
            body = resp.read(65536).decode("utf-8", "replace")
    except Exception:
        return "unreachable"
    if "srun" in flag:
        return "ok"
    low = body.lower()
    if "srun_portal" in low or "深澜" in body or ("srun" in low and "portal" in low):
        return "ok"
    return "not_srun"


def _adapter_info(ip: str) -> dict:
    """查 ip 所属网卡，带进程内缓存（同一个 IP 只查一次）。"""
    info = _adapter_cache.get(ip)
    if info is None:
        info = (_adapter_by_ip_ctypes(ip)
                or _adapter_by_ip_powershell(ip)
                or _adapter_by_ip_ipconfig(ip)
                or {"found": False})
        _adapter_cache[ip] = info
    return info


def check_environment() -> dict:
    """返回决策：action = login / skip，附 reason 与细节，供守护与诊断复用。"""
    env: dict = {
        "action": "skip", "reason": "", "source_ip": None, "adapter": None,
        "kind": None, "campus": False, "online": False, "fast_retry": False,
    }

    # 1) 有没有通往校园门户的路由（纯 socket，不发包，毫秒级）
    ip = route_source_ip()
    env["source_ip"] = ip
    if not ip:
        env["reason"] = "没有通往 %s 的路由（网线没插 / 不在校园网）" % PORTAL_HOST
        env["fast_retry"] = True          # 刚开机网卡还没起来，快点重试
        return env

    # 2) 查网卡类型 / 探测门户指纹 / 探测外网，三者互不依赖，并行跑。
    #    串行的话 PowerShell 冷启动（新会话里 3~8 秒）会把总耗时叠加上去。
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_adapter = pool.submit(_adapter_info, ip)
        f_portal = pool.submit(probe_portal)
        f_online = pool.submit(is_online)
        info = f_adapter.result()
        probe = f_portal.result()
        online = f_online.result()

    env["adapter"] = info
    kind = classify_adapter(info) if info.get("found") else "unknown"
    env["kind"] = kind

    if kind == "wireless":
        env["reason"] = "出口是无线网卡（%s），无线已预配好，跳过" % _first_line(info.get("name", ""))
        return env
    if kind == "virtual":
        env["reason"] = "出口是虚拟网卡（%s），跳过" % _first_line(info.get("description", ""))
        return env
    if kind == "unknown":
        env["reason"] = "无法识别出口网卡类型 %s，跳过" % ip
        return env

    # 3) 确认对端真的是深澜门户
    if probe != "ok":
        if probe == "unreachable":
            env["reason"] = "%s 不可达（没拿到校园网 IP / 不在校园网），跳过" % PORTAL_HOST
            env["fast_retry"] = True      # DHCP 还没拿到地址时，快点重试
        else:
            env["reason"] = "%s 有响应但不是深澜门户（家庭/其他内网），跳过" % PORTAL_HOST
        return env
    env["campus"] = True

    # 4) 已经联网就不用管
    if online:
        env.update(online=True, reason="已联网，无需登录")
        return env

    env.update(action="login", reason="有线 + 校园网 + 未认证，执行登录")
    return env


# --------------------------------------------------------------------------
# 6) 诊断测试（给桌面测试脚本调用，输出人类可读的逐步结果）
# --------------------------------------------------------------------------
def _mask(text: str) -> str:
    if not text:
        return "(空)"
    if len(text) <= 2:
        return "*" * len(text)
    return text[0] + "*" * (len(text) - 2) + text[-1]


def _portal_reachable() -> bool:
    try:
        _request("%s/srun_portal_pc?ac_id=%s&srun_wait=1&theme=bit" % (PORTAL, AC_ID), timeout=6)
        return True
    except Exception:
        return False


def run_diagnostic(username=None, password=None, ac_id=None, log=print, force=False) -> bool | None:
    """返回 True=认证成功 / False=失败 / None=按设计跳过（不需要登录）。"""
    cfg_user, cfg_pass, cfg_ac = load_config()
    username = username or cfg_user
    password = password or cfg_pass
    ac_id = ac_id or cfg_ac

    log("=" * 60)
    log("  深澜校园网无感登录 - 连通性测试")
    log("  时间: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    log("=" * 60)

    # --- 1. 环境识别（有线？校园网？）
    log("")
    log("[1/6] 识别当前网络环境 ...")
    env = check_environment()
    info = env.get("adapter") or {}
    kind_cn = {
        "wired": "有线 Ethernet (802.3)",
        "wireless": "无线 Wi-Fi (802.11)",
        "virtual": "虚拟网卡 / VPN",
        "unknown": "无法识别",
    }.get(env.get("kind") or "unknown", "无法识别")
    log("      -> 出口网卡 : %s" % (_first_line(str(info.get("name", ""))) or "(未识别)"))
    log("      -> 本机地址 : %s" % (env.get("source_ip") or "(没有通往校园门户的路由)"))
    log("      -> 网卡类型 : %s" % kind_cn)
    log("      -> 判定结果 : %s" % env["reason"])

    if env["action"] != "login":
        if not force:
            log("")
            log("=" * 60)
            log("  按设计跳过：当前环境不需要执行登录。")
            log("  （想强制验证签名流程，可在命令行加 --force）")
            log("=" * 60)
            return None
        log("      -> 指定了 --force，忽略环境判定，继续走完整流程")

    # --- 2. 外网连通性
    log("")
    log("[2/6] 检查当前外网连通性 ...")
    already_online = env.get("online") or is_online()
    log("      -> %s" % ("已联网（链路是通的）" if already_online else "未联网（需要认证）"))

    # --- 3. portal 可达性
    log("")
    log("[3/6] 探测认证服务器 %s ..." % PORTAL)
    if not _portal_reachable():
        log("      -> 不可达")
        log("")
        log("[失败] 连不上认证服务器。请确认：")
        log("       - 网线插好、网卡已启用（不要禁用本地连接）")
        log("       - ipconfig 里本机拿到 10.x.x.x 的地址")
        log("       - 没有开代理/VPN 抢走默认路由")
        return False
    log("      -> 可达")

    # --- 4. 配置
    log("")
    log("[4/6] 读取本地配置 ...")
    if not password or password == PLACEHOLDER:
        log("      -> 密码未填写")
        log("")
        log("[失败] config.json 里的 password 还是占位符。")
        return False
    log("      -> 用户名: %s" % _mask(username))
    log("      -> 密码  : %s（长度 %d）" % (_mask(password), len(password)))
    log("      -> ac_id : %s" % ac_id)

    # --- 5. challenge
    log("")
    log("[5/6] 获取一次性挑战值 challenge ...")
    try:
        chal = get_challenge(username)
    except Exception as exc:
        log("      -> 请求失败: %s" % exc)
        return False
    if chal.get("error") not in (None, "ok"):
        log("      -> 服务端报错: %s" % json.dumps(chal, ensure_ascii=False))
        return False
    challenge = chal.get("challenge", "")
    ip = chal.get("client_ip") or chal.get("online_ip") or ""
    log("      -> client_ip = %s" % ip)
    log("      -> challenge = %s..." % challenge[:24])
    log("      -> 服务端    = %s" % chal.get("srun_ver", "?"))

    # --- 6. 提交认证
    log("")
    log("[6/6] 本地计算并提交认证 ...")
    params = build_login_params(username, password, challenge, ip, ac_id)
    log("      -> hmd5   = %s" % params["password"][:14] + "...")
    log("      -> chksum = %s..." % params["chksum"][:24])
    try:
        qs = urllib.parse.urlencode({"callback": "jQuery%d" % int(time.time() * 1000), **params})
        res = _jsonp(_request("%s/cgi-bin/srun_portal?%s" % (PORTAL, qs), timeout=15))
    except Exception as exc:
        log("      -> 请求失败: %s" % exc)
        return False

    log("      -> 服务端返回:")
    for line in json.dumps(res, indent=2, ensure_ascii=False).splitlines():
        log("         " + line)

    ok = res.get("error") == "ok" or res.get("res") == "ok"
    if ok and res.get("ploy_msg"):
        log("      -> ploy_msg = %s" % res["ploy_msg"])
    if not ok:
        log("")
        log("[失败] 认证未通过：%s" % (res.get("error_msg") or res.get("error") or res))
        log("       常见原因：密码错误 / 账号欠费 / 已在别处登录 / 需要使用校园 SSO 密码")
        return False

    # --- 复检
    log("")
    log("[复检] 等 2 秒后重新探测外网 ...")
    time.sleep(2)
    total = 0
    for attempt in range(1, 6):
        if is_online():
            total = attempt
            break
        time.sleep(2)
    if total:
        log("      -> 已联网（第 %d 次探测成功）" % total)
        log("")
        log("=" * 60)
        log("  测试通过 ✓  认证脚本工作正常，可以部署开机自启了。")
        log("=" * 60)
        return True

    log("      -> 认证接口返回成功，但外网仍不通")
    log("")
    log("=" * 60)
    log("  部分成功：认证已提交成功，但外网探测不通。")
    log("  可能是出口策略/欠费/门户重定向，请手动开浏览器确认一下。")
    log("=" * 60)
    return False


FAST_RETRY_SECONDS = 5          # 刚开机/网卡还没起好时的快重试间隔


def _acquire_single_instance(name: str = "watch"):
    """文件锁保证同名任务只有一个实例；进程退出时操作系统自动释放。"""
    try:
        import msvcrt
    except ImportError:                 # 非 Windows，退化为不做限制
        return object()
    lock_path = Path(__file__).with_name("logs") / ("%s.lock" % name)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(lock_path, "a+")
    except OSError:
        # 锁文件是别的账户（比如 SYSTEM）建的，当前用户打不开。
        # 这种情况下不阻塞，重复登录本身是幂等的，无害。
        return object()
    try:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:                     # 真被另一个实例占着
        fh.close()
        return None
    return fh


# SYSTEM 上下文里的 PATH 和交互式登录不同，必须写死候选路径
PWSH_CANDIDATES = (
    r"C:\Program Files\PowerShell\7\pwsh.exe",
    r"C:\Program Files\PowerShell\7-preview\pwsh.exe",
)


def _find_pwsh() -> str | None:
    found = shutil.which("pwsh") or shutil.which("pwsh.exe")
    if found and os.path.isfile(found):
        return found
    for path in PWSH_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def _open_log(path: str | None, default_name: str = "srun-watch.log"):
    """无控制台（pythonw）时默认写文件；超过 1MB 轮转一次。"""
    if not path:
        if sys.stdout is not None:
            return None
        path = str(Path(__file__).with_name("logs") / default_name)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.stat().st_size > 1_000_000:
        bak = target.with_name(target.name + ".1")
        if bak.exists():
            bak.unlink()
        target.rename(bak)
    return open(target, "a", encoding="utf-8", buffering=1)


def _verify_online(tries: int = 4, delay: float = 2.0) -> bool:
    for _ in range(tries):
        if is_online():
            return True
        time.sleep(delay)
    return False


def nudge_ncsi() -> bool:
    """登录成功后催一下 NCSI，让锁屏/右下角的网络图标立刻变成「已连接」。

    Windows 的网络图标由 NLA/NCSI 的探测结果决定，认证完成后它可能要等下一个
    探测周期才刷新。重启 NlaSvc 会强制它立刻重新评估。需要 SYSTEM/管理员权限。
    """
    exe = _find_pwsh()
    if not exe:
        return False
    try:
        proc = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-Command",
             "Restart-Service -Name NlaSvc -Force -ErrorAction Stop; 'ok'"],
            capture_output=True, timeout=30, creationflags=_NO_WINDOW,
        )
    except Exception:
        return False
    return b"ok" in (proc.stdout or b"")


def run_once(timeout: float = 180.0, interval: float = 2.0, log_path: str | None = None,
             max_login_attempts: int = 3, nudge: bool = False, should_stop=None) -> int:
    """开机一次性登录：等网络就绪 -> 登录 -> 立刻退出。

    不长驻、不重连。由开机自启（Windows 服务或计划任务）拉起来跑一次。
    should_stop: 可选回调，返回 True 时立即退出（服务收到 SCM 停止请求时用）。
    返回 RC_OK / RC_FAIL / RC_SKIP。
    """
    lock = _acquire_single_instance("once")
    if lock is None:
        return RC_OK                     # 已经有一次在跑，静默退出

    log_fh = _open_log(log_path, "srun-logon.log")

    def emit(msg: str) -> None:
        if log_fh is not None:
            log_fh.write(msg + "\n")
        if sys.stdout is not None:
            try:
                print(msg, flush=True)
            except Exception:
                pass

    start = time.monotonic()
    emit("=== %s 开机自动登录开始（pid=%d，最长等待 %.0f 秒）===" % (
        time.strftime("%F %T"), os.getpid(), timeout))
    if log_fh is not None:
        emit("日志文件: %s" % log_fh.name)

    deadline = start + timeout
    login_attempts = 0
    last_note = None

    while True:
        if should_stop is not None and should_stop():
            emit("%s [停止] 收到停止请求，提前退出（下次开机再试）。" % time.strftime("%F %T"))
            return RC_SKIP
        note = None
        try:
            env = check_environment()

            if env["action"] == "login":
                if login_attempts >= max_login_attempts:
                    emit("%s [放弃] 已提交 %d 次登录仍未成功，停止以免账号被锁。"
                         % (time.strftime("%F %T"), login_attempts))
                    return RC_FAIL
                login_attempts += 1
                res = login()
                resp = res.get("resp") or {}
                if res.get("ok") and _verify_online():
                    emit("%s [成功] 已联网，ip=%s，耗时 %.1f 秒，进程退出。"
                         % (time.strftime("%F %T"), env.get("source_ip"), time.monotonic() - start))
                    if nudge:
                        ok = nudge_ncsi()
                        emit("%s [图标] NCSI 刷新%s" % (time.strftime("%F %T"), "成功" if ok else "失败（可忽略）"))
                    return RC_OK
                note = "登录未成功: %s %s" % (
                    resp.get("error") or res.get("stage"),
                    resp.get("error_msg") or resp.get("suc_msg") or "")

            elif env.get("online"):
                emit("%s [完成] 已经是联网状态，无需登录，耗时 %.1f 秒。"
                     % (time.strftime("%F %T"), time.monotonic() - start))
                return RC_OK

            elif env.get("fast_retry"):
                note = env["reason"]                     # 网卡还没就绪，继续等

            else:
                emit("%s [跳过] %s" % (time.strftime("%F %T"), env["reason"]))
                return RC_SKIP

        except ConfigError as exc:
            emit("%s [配置错误] %s" % (time.strftime("%F %T"), exc))
            return RC_FAIL
        except Exception as exc:
            note = "异常: %s" % exc

        if note and note != last_note:
            emit("%s [等待] %s" % (time.strftime("%F %T"), note))
            last_note = note

        if time.monotonic() >= deadline:
            emit("%s [超时] 等待 %.0f 秒仍未完成，退出（下次开机再试）。"
                 % (time.strftime("%F %T"), timeout))
            return RC_FAIL
        time.sleep(interval)


def watch(interval: int = 30, log_path: str | None = None) -> int:
    """守护循环：只在「有线 + 校园网 + 未认证」时登录，其余情况安静跳过。"""
    lock = _acquire_single_instance()
    if lock is None:
        print("[跳过] 已经有一个守护进程在运行了", flush=True)
        return 0

    log_fh = _open_log(log_path)

    def emit(msg: str) -> None:
        # 会被重定向到日志文件，必须逐行 flush，否则看不到实时状态
        if log_fh is not None:
            log_fh.write(msg + "\n")
        if sys.stdout is not None:
            try:
                print(msg, flush=True)
            except Exception:
                pass

    emit("%s 守护启动（pid=%d），检测间隔 %d 秒" % (time.strftime("%F %T"), os.getpid(), interval))
    if log_fh is not None:
        emit("日志文件: %s" % log_fh.name)
    emit("判定规则：出口必须是有线网卡，且 %s 确认是深澜门户，且当前未联网。" % PORTAL_HOST)

    last_reason = None
    fails = 0
    while True:
        try:
            env = check_environment()
            reason = env["reason"]

            if env["action"] != "login":
                if reason != last_reason:        # 状态变化才打日志，避免刷屏
                    emit("%s [跳过] %s" % (time.strftime("%F %T"), reason))
                    last_reason = reason
                fails = 0
                time.sleep(FAST_RETRY_SECONDS if env.get("fast_retry") else interval)
                continue

            res = login()
            resp = res.get("resp") or {}
            if res.get("ok"):
                if _verify_online():
                    emit("%s [登录成功] ip=%s" % (time.strftime("%F %T"), env.get("source_ip")))
                    fails = 0
                    last_reason = None
                    time.sleep(interval)
                else:
                    fails += 1
                    last_reason = None
                    emit("%s [已提交但外网仍不通] ip=%s，%d 秒后重试"
                         % (time.strftime("%F %T"), env.get("source_ip"), min(60, 5 * fails)))
                    time.sleep(min(60, 5 * fails))
            else:
                fails += 1
                last_reason = None
                emit("%s [登录失败] %s %s（%d 秒后重试）" % (
                    time.strftime("%F %T"),
                    resp.get("error") or res.get("stage"),
                    resp.get("error_msg") or resp.get("suc_msg") or "",
                    min(60, 5 * fails),
                ))
                time.sleep(min(60, 5 * fails))
        except ConfigError as exc:
            emit("%s [配置错误] %s" % (time.strftime("%F %T"), exc))
            time.sleep(60)
        except Exception as exc:
            fails += 1
            emit("%s [异常] %s（%d 秒后重试）" % (time.strftime("%F %T"), exc, min(60, 5 * fails)))
            time.sleep(min(60, 5 * fails))
    return 0


# --------------------------------------------------------------------------
# 7.5) Windows 服务模式：开机最早的启动方式
#
# 服务由服务控制管理器（SCM）在开机早期直接拉起，不依赖任务计划程序
# 服务的就绪时机，也不依赖事件触发器——这正是壁纸类软件能「用户还没
# 登录壁纸就准备好了」的原因。实测计划任务方案要 +37s 才触发，服务
# 方案在网络栈就绪（约 +15s）后 2 秒内即可完成认证。
#
# 服务进程一进 ServiceMain 就上报 SERVICE_RUNNING（毫秒级，远低于 SCM
# 的 30 秒宽限，规避错误 1053），然后复用 run_once() 等网络就绪并完成
# 认证，结束（成功/跳过/超时）后上报 SERVICE_STOPPED 自然退出。
# 全部用 ctypes 实现，不依赖 pywin32。
# --------------------------------------------------------------------------
SVC_NAME = "SRunAutoLogin"
SVC_DISPLAY = "SRun 校园网自动登录（开机早期）"
SVC_DESCRIPTION = (
    "开机早期等待校园网就绪并自动完成深澜认证，认证结束即退出，不常驻、不重连。"
    "与旧版计划任务方案等价，但由服务控制管理器(SCM)直接拉起，"
    "触发时点远早于任务计划程序，可在用户登录前完成认证。"
)

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_AUTO_START = 0x00000002
SERVICE_ERROR_NORMAL = 0x00000001
SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_RUNNING = 0x00000003
SERVICE_STOP_PENDING = 0x00000004
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_SHUTDOWN = 0x00000005
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004
SC_MANAGER_ALL_ACCESS = 0x000F003F
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_CONFIG = 0x0001
SERVICE_QUERY_STATUS = 0x0004
SERVICE_STOP_RIGHT = 0x00000020
SERVICE_DELETE_RIGHT = 0x00010000
SERVICE_ALL_ACCESS = 0x000F01FF
ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_MARKED_FOR_DELETE = 1072
SERVICE_CONFIG_DESCRIPTION = 0x00000001
SERVICE_CONFIG_FAILURE_ACTIONS = 0x00000002
SC_ACTION_RESTART = 0x00000001
SVC_LOG_PATH = str(Path(__file__).with_name("logs") / "srun-svc.log")


class _SVC_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


_SVC_MAIN_FUNC = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
_HANDLER_EX_FUNC = ctypes.WINFUNCTYPE(
    wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)


class _SVC_TABLE_ENTRY(ctypes.Structure):
    # lpServiceProc 用 c_void_p：既能放回调实例，也能放 NULL 结尾项
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", ctypes.c_void_p)]


class _SVC_DESCRIPTION(ctypes.Structure):
    _fields_ = [("lpDescription", wintypes.LPWSTR)]


class _SC_ACTION(ctypes.Structure):
    _fields_ = [("Type", wintypes.DWORD), ("Delay", wintypes.DWORD)]


class _SVC_FAILURE_ACTIONS(ctypes.Structure):
    _fields_ = [
        ("dwResetPeriod", wintypes.DWORD),
        ("lpRebootMsg", wintypes.LPWSTR),
        ("lpCommand", wintypes.LPWSTR),
        ("cActions", wintypes.DWORD),
        ("lpsaActions", ctypes.POINTER(_SC_ACTION)),
    ]


class _QUERY_SVC_CONFIG(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    ]


_advapi32 = None
_svc_status_handle = None
_svc_stop_requested = False
_svc_main_cb = None           # 回调必须保持全局引用，被 GC 后 SCM 调用会崩溃
_svc_handler_cb = None


def _svc_advapi():
    """按需加载 advapi32 并一次性配好函数原型（句柄必须按指针宽度返回）。"""
    global _advapi32
    if _advapi32 is not None:
        return _advapi32
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    H, W, D, P = ctypes.c_void_p, wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p
    adv.OpenSCManagerW.restype = H
    adv.OpenSCManagerW.argtypes = [W, W, D]
    adv.CreateServiceW.restype = H
    adv.CreateServiceW.argtypes = [H, W, W, D, D, D, D, W, W, P, W, W, W]
    adv.OpenServiceW.restype = H
    adv.OpenServiceW.argtypes = [H, W, D]
    adv.CloseServiceHandle.restype = wintypes.BOOL
    adv.CloseServiceHandle.argtypes = [H]
    adv.QueryServiceStatus.restype = wintypes.BOOL
    adv.QueryServiceStatus.argtypes = [H, ctypes.POINTER(_SVC_STATUS)]
    adv.QueryServiceConfigW.restype = wintypes.BOOL
    adv.QueryServiceConfigW.argtypes = [H, P, D, ctypes.POINTER(D)]
    adv.StartServiceW.restype = wintypes.BOOL
    adv.StartServiceW.argtypes = [H, D, P]
    adv.ControlService.restype = wintypes.BOOL
    adv.ControlService.argtypes = [H, D, ctypes.POINTER(_SVC_STATUS)]
    adv.DeleteService.restype = wintypes.BOOL
    adv.DeleteService.argtypes = [H]
    adv.ChangeServiceConfig2W.restype = wintypes.BOOL
    adv.ChangeServiceConfig2W.argtypes = [H, D, P]
    adv.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
    adv.StartServiceCtrlDispatcherW.argtypes = [P]
    adv.RegisterServiceCtrlHandlerExW.restype = H
    adv.RegisterServiceCtrlHandlerExW.argtypes = [W, _HANDLER_EX_FUNC, P]
    adv.SetServiceStatus.restype = wintypes.BOOL
    adv.SetServiceStatus.argtypes = [H, ctypes.POINTER(_SVC_STATUS)]
    _advapi32 = adv
    return adv


def _svc_report(state, exit_code=0, checkpoint=0, wait_hint=0):
    if not _svc_status_handle:
        return
    st = _SVC_STATUS()
    st.dwServiceType = SERVICE_WIN32_OWN_PROCESS
    st.dwCurrentState = state
    st.dwControlsAccepted = (
        (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) if state == SERVICE_RUNNING else 0)
    st.dwWin32ExitCode = exit_code
    st.dwCheckPoint = checkpoint
    st.dwWaitHint = wait_hint
    _svc_advapi().SetServiceStatus(_svc_status_handle, ctypes.byref(st))


def _svc_handler(ctrl, event_type, event_data, context):
    """SCM 控制回调：收到停止/关机时置标志，run_once 会在 2 秒内感知并退出。"""
    global _svc_stop_requested
    if ctrl in (SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN):
        _svc_stop_requested = True
        _svc_report(SERVICE_STOP_PENDING, wait_hint=10000)
    return 0


def _svc_main(argc, argv):
    global _svc_status_handle
    adv = _svc_advapi()
    _svc_status_handle = adv.RegisterServiceCtrlHandlerExW(SVC_NAME, _svc_handler_cb, None)
    if not _svc_status_handle:
        return
    _svc_report(SERVICE_START_PENDING, checkpoint=1, wait_hint=5000)
    # 立刻上报 RUNNING：解除 SCM 的 30 秒启动宽限（错误 1053）。
    # 业务（等网络 + 认证，最长 180 秒）在服务已运行的状态下慢慢做。
    _svc_report(SERVICE_RUNNING)
    try:
        run_once(timeout=180.0, interval=2.0, log_path=SVC_LOG_PATH, nudge=True,
                 should_stop=lambda: _svc_stop_requested)
    except Exception:
        pass
    _svc_report(SERVICE_STOPPED)


def run_service() -> int:
    """svc 子命令入口：连接 SCM 并进入服务主循环（只能由 SCM 调用）。"""
    global _svc_main_cb, _svc_handler_cb
    _svc_main_cb = _SVC_MAIN_FUNC(_svc_main)
    _svc_handler_cb = _HANDLER_EX_FUNC(_svc_handler)
    adv = _svc_advapi()
    table = (_SVC_TABLE_ENTRY * 2)()
    table[0].lpServiceName = SVC_NAME
    table[0].lpServiceProc = ctypes.cast(_svc_main_cb, ctypes.c_void_p)
    table[1].lpServiceName = None
    table[1].lpServiceProc = None
    if not adv.StartServiceCtrlDispatcherW(ctypes.byref(table)):
        err = ctypes.get_last_error()
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            print("[提示] svc 子命令是给 Windows 服务控制管理器(SCM)调用的，不能手动运行。")
            print("       手动跑一次认证: python srun_login.py once")
            print("       安装服务      : python srun_login.py svc-install （需管理员）")
        else:
            print("[错误] StartServiceCtrlDispatcher 失败，错误码 %d" % err)
        return RC_FAIL
    return RC_OK


def _find_pythonw_for_service() -> str:
    """服务解释器：优先当前解释器同目录的 pythonw.exe（无窗口）。"""
    exe = Path(sys.executable)
    sibling = exe.with_name("pythonw.exe")
    if sibling.is_file():
        return str(sibling)
    return str(exe)


def _svc_delete_legacy_task() -> bool:
    """卸掉旧方案的计划任务，避免两套自启并存（单实例锁也会兜底）。"""
    sch = shutil.which("schtasks") or "schtasks"
    try:
        r = subprocess.run([sch, "/query", "/tn", TASK_NAME],
                           capture_output=True, creationflags=_NO_WINDOW)
    except OSError:
        return False
    if r.returncode != 0:
        return False                      # 本来就没有
    subprocess.run([sch, "/delete", "/tn", TASK_NAME, "/f"],
                   capture_output=True, creationflags=_NO_WINDOW)
    return True


def _svc_service_installed() -> bool:
    """服务是否已安装（不需要管理员权限）。"""
    adv = _svc_advapi()
    hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not hscm:
        return False
    try:
        hsvc = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_QUERY_STATUS)
        if not hsvc:
            return False
        adv.CloseServiceHandle(hsvc)
        return True
    finally:
        adv.CloseServiceHandle(hscm)


def svc_install() -> int:
    """创建 SRunAutoLogin 服务（自动启动、LocalSystem），装完立即启动验证。"""
    adv = _svc_advapi()
    hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not hscm:
        err = ctypes.get_last_error()
        print("[错误] 打开服务控制管理器失败（错误码 %d）。请以管理员身份运行。" % err)
        return RC_FAIL
    try:
        hsvc = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_ALL_ACCESS)
        if hsvc:
            adv.CloseServiceHandle(hsvc)
            print("[1/5] 发现旧服务，先停止并删除 ...")
            svc_uninstall(drop_task=False)
            for _ in range(20):           # DeleteService 是标记删除，等真正生效
                h = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_QUERY_STATUS)
                if not h:
                    break
                adv.CloseServiceHandle(h)
                time.sleep(0.5)
        else:
            print("[1/5] 无旧服务。")

        if _svc_delete_legacy_task():
            print("      已移除旧方案的计划任务 %s。" % TASK_NAME)

        pythonw = _find_pythonw_for_service()
        binpath = '"%s" "%s" svc' % (pythonw, Path(__file__).resolve())
        print("[2/5] 创建服务 %s ..." % SVC_NAME)
        hsvc = adv.CreateServiceW(
            hscm, SVC_NAME, SVC_DISPLAY,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,           # 开机自动：SCM 早期拉起
            SERVICE_ERROR_NORMAL,
            binpath,
            None, None,
            "Tcpip\x00",                  # 依赖 TCP/IP 栈（boot 早期就绪，不拖慢）
            None, None,
        )
        if not hsvc:
            err = ctypes.get_last_error()
            if err == ERROR_SERVICE_MARKED_FOR_DELETE:
                print("[错误] 服务被标记为删除但尚未生效（可能进程还挂着）。"
                      "稍等几秒重试，或先重启电脑再装。")
            else:
                print("[错误] 创建服务失败，错误码 %d" % err)
            return RC_FAIL
        try:
            print("[3/5] 设置描述 ...")
            desc = _SVC_DESCRIPTION()
            desc.lpDescription = SVC_DESCRIPTION
            adv.ChangeServiceConfig2W(hsvc, SERVICE_CONFIG_DESCRIPTION, ctypes.byref(desc))

            print("[4/5] 配置失败自动重启（万一被 1053 超时杀掉也能自愈）...")
            actions = (_SC_ACTION * 1)()
            actions[0].Type = SC_ACTION_RESTART
            actions[0].Delay = 60000       # 失败 60 秒后自动重启一次
            fa = _SVC_FAILURE_ACTIONS()
            fa.dwResetPeriod = 86400
            fa.lpRebootMsg = None
            fa.lpCommand = None
            fa.cActions = 1
            fa.lpsaActions = actions
            adv.ChangeServiceConfig2W(hsvc, SERVICE_CONFIG_FAILURE_ACTIONS, ctypes.byref(fa))

            print("[5/5] 立即启动服务（不用重启就能验证）...")
            if not adv.StartServiceW(hsvc, 0, None):
                err = ctypes.get_last_error()
                if err != ERROR_SERVICE_ALREADY_RUNNING:
                    print("[警告] 立即启动失败（错误码 %d），不影响安装，开机会自动启动。" % err)

            st = _SVC_STATUS()
            adv.QueryServiceStatus(hsvc, ctypes.byref(st))
        finally:
            adv.CloseServiceHandle(hsvc)

        state = {SERVICE_STOPPED: "已停止", SERVICE_START_PENDING: "启动中",
                 SERVICE_RUNNING: "运行中", SERVICE_STOP_PENDING: "停止中"}.get(
                     st.dwCurrentState, str(st.dwCurrentState))
        print()
        print("=" * 60)
        print("安装完成")
        print("=" * 60)
        print("  服务名   : %s" % SVC_NAME)
        print("  启动类型 : 自动（开机由 SCM 直接拉起，早于任务计划程序）")
        print("  运行身份 : LocalSystem")
        print("  执行     : %s" % binpath)
        print("  日志     : %s" % SVC_LOG_PATH)
        print("  当前状态 : %s" % state)
        print()
        print("  下次开机：服务在网络栈就绪后约 2 秒内完成认证，")
        print("  目标是「输完密码进桌面时网络已经通了」。")
        print("  看日志：Get-Content '%s' -Tail 20 -Wait" % SVC_LOG_PATH)
        print("  卸载：  pwsh -File uninstall_autostart.ps1")
        return RC_OK
    finally:
        adv.CloseServiceHandle(hscm)


def svc_uninstall(drop_task: bool = True) -> int:
    """停止并删除 SRunAutoLogin 服务；顺带清理旧方案的计划任务。"""
    adv = _svc_advapi()
    hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS)
    if not hscm:
        err = ctypes.get_last_error()
        print("[错误] 打开服务控制管理器失败（错误码 %d）。请以管理员身份运行。" % err)
        return RC_FAIL
    try:
        hsvc = adv.OpenServiceW(hscm, SVC_NAME,
                                SERVICE_STOP_RIGHT | SERVICE_QUERY_STATUS | SERVICE_DELETE_RIGHT)
        if not hsvc:
            err = ctypes.get_last_error()
            if err == ERROR_SERVICE_DOES_NOT_EXIST:
                print("服务 %s 未安装。" % SVC_NAME)
                return RC_OK
            print("[错误] 打开服务失败，错误码 %d" % err)
            return RC_FAIL
        try:
            st = _SVC_STATUS()
            adv.QueryServiceStatus(hsvc, ctypes.byref(st))
            if st.dwCurrentState != SERVICE_STOPPED:
                print("正在停止服务 ...")
                adv.ControlService(hsvc, SERVICE_CONTROL_STOP, ctypes.byref(st))
                for _ in range(30):       # run_once 每 2 秒检查停止标志，几秒内即退
                    adv.QueryServiceStatus(hsvc, ctypes.byref(st))
                    if st.dwCurrentState == SERVICE_STOPPED:
                        break
                    time.sleep(0.5)
            if not adv.DeleteService(hsvc):
                print("[错误] 删除服务失败，错误码 %d" % ctypes.get_last_error())
                return RC_FAIL
            print("服务 %s 已删除（开机不再自动登录）。" % SVC_NAME)
        finally:
            adv.CloseServiceHandle(hsvc)
        if drop_task and _svc_delete_legacy_task():
            print("已移除旧方案的计划任务 %s。" % TASK_NAME)
        return RC_OK
    finally:
        adv.CloseServiceHandle(hscm)


def svc_status() -> int:
    """查看服务的安装 / 运行状态与最近日志。"""
    adv = _svc_advapi()
    hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not hscm:
        print("[错误] 打开服务控制管理器失败，错误码 %d" % ctypes.get_last_error())
        return RC_FAIL
    try:
        hsvc = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)
        if not hsvc:
            err = ctypes.get_last_error()
            if err == ERROR_SERVICE_DOES_NOT_EXIST:
                print("服务 %s：未安装" % SVC_NAME)
                return RC_OK
            print("[错误] 打开服务失败，错误码 %d" % err)
            return RC_FAIL
        try:
            st = _SVC_STATUS()
            adv.QueryServiceStatus(hsvc, ctypes.byref(st))
            buf = ctypes.create_unicode_buffer(8192)
            needed = wintypes.DWORD(0)
            cfg = None
            if adv.QueryServiceConfigW(hsvc, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
                cfg = ctypes.cast(buf, ctypes.POINTER(_QUERY_SVC_CONFIG)).contents
            state = {SERVICE_STOPPED: "已停止", SERVICE_START_PENDING: "启动中",
                     SERVICE_RUNNING: "运行中", SERVICE_STOP_PENDING: "停止中"}.get(
                         st.dwCurrentState, str(st.dwCurrentState))
            print("服务 %s：已安装" % SVC_NAME)
            print("  状态     : %s" % state)
            if cfg:
                print("  启动类型 : %s" % {2: "自动", 3: "手动", 4: "已禁用"}.get(
                    cfg.dwStartType, str(cfg.dwStartType)))
                print("  执行     : %s" % (cfg.lpBinaryPathName or ""))
            print("  日志     : %s" % SVC_LOG_PATH)
            log = Path(SVC_LOG_PATH)
            if log.is_file():
                lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
                if lines:
                    print("  最近日志 :")
                    for line in lines[-5:]:
                        print("    " + line)
        finally:
            adv.CloseServiceHandle(hsvc)
        return RC_OK
    finally:
        adv.CloseServiceHandle(hscm)


# --------------------------------------------------------------------------
# 7) 配置编辑 / 迁移体检
# --------------------------------------------------------------------------
def _ask(label: str, current: str, secret: bool = False) -> str:
    shown = _mask(current) if secret else current
    try:
        raw = input("%s [%s]: " % (label, shown)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(1)
    return raw or current


def run_config_editor(log=print) -> int:
    """交互式修改 username / password / ac_id / portal。"""
    d = _read_config()
    cur_user = str(d.get("username", USERNAME))
    cur_pass = str(d.get("password", PASSWORD))
    cur_ac = str(d.get("ac_id", AC_ID))
    cur_portal = str(d.get("portal") or PORTAL)

    log("=" * 62)
    log("  修改校园网账号密码")
    log("=" * 62)
    log("  配置文件: %s" % config_path())
    log("")
    log("  当前用户名 : %s" % cur_user)
    log("  当前密码   : %s  (长度 %d)" % (_mask(cur_pass), len(cur_pass)))
    log("  当前 ac_id : %s" % cur_ac)
    log("  当前门户   : %s" % cur_portal)
    log("")
    log("  直接按回车 = 保持原值不变")
    log("")

    user = _ask("用户名  ", cur_user)
    pwd = _ask("密码    ", cur_pass, secret=True)
    ac = _ask("ac_id  ", cur_ac)
    portal = _ask("门户地址", cur_portal)

    if not user.strip() or not pwd:
        log("")
        log("[取消] 用户名和密码都不能为空，未做任何修改。")
        return RC_FAIL

    log("")
    log("-" * 62)
    log("  即将写入:")
    log("    用户名 : %s" % user)
    log("    密码   : %s  (长度 %d)" % (_mask(pwd), len(pwd)))
    log("    ac_id  : %s" % ac)
    log("    门户   : %s" % portal)
    log("-" * 62)
    try:
        confirm = input("  确认写入? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"
    if confirm not in ("", "y", "yes"):
        log("  已取消，未做任何修改。")
        return RC_FAIL

    cfg = write_config(user.strip(), pwd, ac.strip(), portal.strip())
    log("")
    log("  已写入 %s" % cfg)
    log("  密码以明文保存；该文件已在 .gitignore 里，不会被提交。")
    log("")
    log("  提示: 计划任务是运行时才读这个文件，不需要重新安装。")
    log("")

    try:
        go = input("  现在测试一次登录? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        go = "n"
    if go in ("", "y", "yes"):
        log("")
        rc = run_diagnostic()
        if rc is None:
            return RC_OK
        return RC_OK if rc else RC_FAIL
    return RC_OK


def doctor(log=print) -> int:
    """环境体检：换电脑、迁移、排障时先跑这个。"""
    problems: list[str] = []
    log("=" * 62)
    log("  环境体检")
    log("=" * 62)

    log("")
    log("[1] Python")
    log("      版本   : %s" % sys.version.split()[0])
    log("      解释器 : %s" % sys.executable)
    if sys.version_info < (3, 8):
        problems.append("Python 版本过低，需要 3.8 以上")

    log("")
    log("[2] 关键文件")
    for name in ("srun_login.py", "config.json"):
        p = Path(__file__).with_name(name)
        ok = p.exists()
        log("      %-16s %s" % (name, "OK" if ok else "缺失"))
        if not ok:
            problems.append("缺少 %s" % name)

    log("")
    log("[3] 配置内容")
    user, pwd, ac = load_config()
    if not pwd or pwd == PLACEHOLDER:
        log("      密码     : 未填写")
        problems.append("config.json 里还没填密码（双击『配置账号密码.bat』）")
    else:
        log("      用户名   : %s" % _mask(user))
        log("      密码     : %s (长度 %d)" % (_mask(pwd), len(pwd)))
    log("      ac_id    : %s" % ac)
    log("      门户     : %s" % PORTAL)

    log("")
    log("[4] 可选依赖（缺了也能跑）")
    log("      pwsh     : %s" % (_find_pwsh() or "未找到，会退到 ipconfig 兜底"))
    log("      ipconfig : %s" % (shutil.which("ipconfig") or "未找到"))
    log("      node     : %s" % (shutil.which("node") or "未找到（只有对拍测试用得到）"))

    log("")
    log("[5] 当前网络环境")
    try:
        env = check_environment()
        info = env.get("adapter") or {}
        log("      出口网卡 : %s" % (_first_line(str(info.get("name", ""))) or "(未识别)"))
        log("      本机地址 : %s" % (env.get("source_ip") or "(无路由)"))
        log("      判定     : %s" % env["reason"])
    except Exception as exc:
        log("      检测失败 : %s" % exc)
        problems.append("环境检测异常: %s" % exc)

    log("")
    log("[6] 开机自启（服务优先，兼容旧计划任务）")
    try:
        adv = _svc_advapi()
        hscm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if hscm:
            hsvc = adv.OpenServiceW(hscm, SVC_NAME, SERVICE_QUERY_STATUS)
            if hsvc:
                st = _SVC_STATUS()
                adv.QueryServiceStatus(hsvc, ctypes.byref(st))
                state = {SERVICE_STOPPED: "已停止", SERVICE_START_PENDING: "启动中",
                         SERVICE_RUNNING: "运行中", SERVICE_STOP_PENDING: "停止中"}.get(
                             st.dwCurrentState, str(st.dwCurrentState))
                log("      服务 %s : 已安装（%s）" % (SVC_NAME, state))
                adv.CloseServiceHandle(hsvc)
            else:
                log("      服务 %s : 未安装" % SVC_NAME)
            adv.CloseServiceHandle(hscm)
        else:
            log("      服务 %s : 查询失败（错误码 %d）" % (SVC_NAME, ctypes.get_last_error()))
    except Exception as exc:
        log("      服务查询失败 : %s" % exc)
    try:
        sch = shutil.which("schtasks") or "schtasks"
        r = subprocess.run([sch, "/query", "/tn", TASK_NAME],
                           capture_output=True, timeout=15, creationflags=_NO_WINDOW)
        if r.returncode == 0:
            log("      任务 %s : 已安装（旧方案，装服务时会自动移除）" % TASK_NAME)
        else:
            log("      任务 %s : 未安装" % TASK_NAME)
    except Exception as exc:
        log("      任务查询失败 : %s" % exc)
    try:
        if not _svc_service_installed():
            log("      装它：双击『安装开机自启.bat』（需要管理员，推荐服务方式）")
    except Exception:
        pass

    log("")
    if problems:
        log("=" * 62)
        log("  发现 %d 个问题：" % len(problems))
        for item in problems:
            log("    - %s" % item)
        log("=" * 62)
        return RC_FAIL
    log("=" * 62)
    log("  体检通过，没有发现阻塞性问题。")
    log("=" * 62)
    return RC_OK


# 允许 config.json 覆盖门户地址（换学校/换校区不用改代码）
apply_config_constants()


# --------------------------------------------------------------------------
# 8) 入口
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="深澜校园网自动认证")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("params", help="只计算参数，不联网登录（用于对拍）")
    sp.add_argument("username")
    sp.add_argument("password")
    sp.add_argument("challenge")
    sp.add_argument("ip")
    sp.add_argument("ac_id")

    sl = sub.add_parser("login", help="认证一次")
    sl.add_argument("--username")
    sl.add_argument("--password")
    sl.add_argument("--ac-id", dest="ac_id")
    sub.add_parser("check", help="检查外网连通性")
    sw = sub.add_parser("watch", help="常驻守护，断线自动重连（默认不用，可选）")
    sw.add_argument("--interval", type=int, default=30, help="检测间隔秒数，默认 30")
    sw.add_argument("--log", dest="log_path", help="日志文件；无控制台运行时默认写 logs/srun-watch.log")

    so = sub.add_parser("once", help="开机跑一次：等网络就绪->登录->退出（自启用这个）")
    so.add_argument("--timeout", type=float, default=180.0, help="最长等待秒数，默认 180")
    so.add_argument("--interval", type=float, default=2.0, help="重试间隔秒数，默认 2")
    so.add_argument("--log", dest="log_path", help="日志文件；无控制台运行时默认写 logs/srun-logon.log")
    so.add_argument("--nudge-ncsi", dest="nudge_ncsi", action="store_true",
                    help="登录后重启 NlaSvc，让网络图标立刻刷新（需 SYSTEM/管理员）")

    sc = sub.add_parser("save", help="把账号密码写进 config.json")
    sc.add_argument("username")
    sc.add_argument("password")

    sub.add_parser("config", help="交互式修改账号密码（双击『配置账号密码.bat』）")
    sub.add_parser("doctor", help="环境体检：换电脑/排障时先跑这个")

    st = sub.add_parser("test", help="逐步诊断，跑一次完整认证测试（桌面脚本调用）")
    st.add_argument("--username")
    st.add_argument("--password")
    st.add_argument("--ac-id", dest="ac_id")
    st.add_argument("--force", action="store_true", help="忽略环境判定，强制走完整流程")

    so = sub.add_parser("logout", help="注销当前会话（制造离线状态，用于测试）")
    so.add_argument("--username")
    so.add_argument("--ac-id", dest="ac_id")

    ss = sub.add_parser("status", help="打印当前环境判定（有线？校园网？要不要登录）")
    ss.add_argument("--json", action="store_true", help="以 JSON 输出")

    sub.add_parser("svc", help="以 Windows 服务身份运行（由服务控制管理器调用，勿手动执行）")
    sub.add_parser("svc-install", help="安装为开机自动启动的 Windows 服务（推荐，需管理员）")
    sub.add_parser("svc-uninstall", help="卸载 Windows 服务（需管理员）")
    sub.add_parser("svc-status", help="查看服务安装与运行状态")

    args = p.parse_args(argv)

    if args.cmd == "params":
        out = build_login_params(args.username, args.password, args.challenge, args.ip, args.ac_id)
        out["hmd5"] = hmd5(args.password, args.challenge)
        out["raw_info_plain_len"] = len(xencode(
            json.dumps({
                "username": args.username, "password": args.password, "ip": args.ip,
                "acid": args.ac_id, "enc_ver": "srun_bx1",
            }, ensure_ascii=False, separators=(",", ":")), args.challenge))
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0

    if args.cmd == "check":
        print("online" if is_online() else "offline")
        return 0

    if args.cmd == "save":
        cfg = Path(__file__).with_name("config.json")
        cfg.write_text(
            json.dumps(
                {"username": args.username, "password": args.password, "ac_id": AC_ID},
                indent=2, ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        print("saved ->", cfg)
        return 0

    if args.cmd == "config":
        return run_config_editor()

    if args.cmd == "doctor":
        return doctor()

    if args.cmd == "test":
        rc = run_diagnostic(args.username, args.password, args.ac_id, force=args.force)
        if rc is None:
            return RC_SKIP
        return RC_OK if rc else RC_FAIL

    if args.cmd == "status":
        env = check_environment()
        if args.json:
            print(json.dumps(env, indent=2, ensure_ascii=False))
        else:
            info = env.get("adapter") or {}
            print("出口网卡 : %s" % (_first_line(str(info.get("name", ""))) or "(未识别)"))
            print("本机地址 : %s" % (env.get("source_ip") or "(无路由)"))
            print("网卡类型 : %s" % (env.get("kind") or "unknown"))
            print("校园门户 : %s" % ("已确认" if env.get("campus") else "未确认"))
            print("外网状态 : %s" % ("在线" if env.get("online") else "离线"))
            print("判定     : %s -> %s" % (env["action"], env["reason"]))
        return 0

    if args.cmd == "logout":
        res = logout(args.username, args.ac_id)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        if res["ok"]:
            time.sleep(2)
            print("注销后外网状态:", "仍在线" if is_online() else "已离线")
        return 0 if res["ok"] else 1

    if args.cmd == "login":
        res = login(args.username, args.password, args.ac_id)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0 if res["ok"] else 1

    if args.cmd == "watch":
        return watch(max(5, args.interval), args.log_path)

    if args.cmd == "once":
        return run_once(args.timeout, args.interval, args.log_path, nudge=args.nudge_ncsi)

    if args.cmd == "svc":
        return run_service()
    if args.cmd == "svc-install":
        return svc_install()
    if args.cmd == "svc-uninstall":
        return svc_uninstall()
    if args.cmd == "svc-status":
        return svc_status()
    return 0


if __name__ == "__main__":
    try:  # 让 Windows 控制台正确显示中文
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        sys.exit(main())
    except ConfigError as exc:
        print("[配置错误] %s" % exc)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
