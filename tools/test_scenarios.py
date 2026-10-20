#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""场景测试：验证 check_environment() 在各种网络环境下的判定。

    python tools/test_scenarios.py

通过 monkeypatch 掉「本机实际网络」相关的三个函数来模拟场景：
  route_source_ip / _adapter_by_ip_* / probe_portal / is_online
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import srun_login as s  # noqa: E402

WIRED = {"found": True, "name": "以太网", "description": "Realtek Gaming GbE Family Controller",
         "status": "Up", "mediaType": "802.3", "physical": "802.3", "ifIndex": 3}
WIFI = {"found": True, "name": "WLAN", "description": "Intel(R) Wi-Fi 6E AX211 160MHz",
        "status": "Up", "mediaType": "Native 802.11", "physical": "Native 802.11", "ifIndex": 19}
TAP = {"found": True, "name": "以太网 3", "description": "TAP-Windows Adapter V9",
       "status": "Up", "mediaType": "802.3", "physical": "802.3", "ifIndex": 13}
HOME_WIRED = {"found": True, "name": "以太网", "description": "Realtek PCIe GbE Family Controller",
              "status": "Up", "mediaType": "802.3", "physical": "802.3", "ifIndex": 5}

SCENARIOS = [
    # 名称,                 源IP,          网卡,        门户探测,      已联网, 期望动作
    ("校园有线 + 未认证",   "10.100.0.101", WIRED,      "ok",          False, "login"),
    ("校园有线 + 已联网",   "10.100.0.101", WIRED,      "ok",          True,  "skip"),
    ("校园有线 + 拔网线",   None,             None,       "unreachable", False, "skip"),
    ("手机热点 / 校园WiFi", "172.20.10.2",    WIFI,       "ok",          False, "skip"),
    ("校园WiFi(门户可达)",  "10.100.0.7",     WIFI,       "ok",          True,  "skip"),
    ("家庭WiFi",            "192.168.1.23",   WIFI,       "not_srun",    True,  "skip"),
    ("家庭有线",            "192.168.1.23",   HOME_WIRED, "not_srun",    True,  "skip"),
    ("家庭内网也有10.0.0.55设备", "10.0.0.55", HOME_WIRED, "not_srun",    False, "skip"),
    ("宿舍 DHCP 还没拿到地址", "169.254.7.7", WIRED,      "unreachable", False, "skip"),
    ("VPN 虚拟网卡抢路线",  "172.30.247.54",  TAP,        "ok",          False, "skip"),
    ("识别不出网卡类型",    "10.100.0.101",   {"found": False}, "ok",     False, "skip"),
]


def run() -> int:
    bad = 0
    for name, src_ip, adapter, probe, online, want in SCENARIOS:
        s._adapter_cache.clear()
        s.route_source_ip = lambda *a, **k: src_ip
        # 三条查网卡的实现都要打桩，否则 ctypes 那条会绕过桩拿到真实网卡
        s._adapter_by_ip_ctypes = lambda ip: adapter
        s._adapter_by_ip_powershell = lambda ip: adapter
        s._adapter_by_ip_ipconfig = lambda ip: adapter
        s.probe_portal = lambda *a, **k: probe
        s.is_online = lambda *a, **k: online

        env = s.check_environment()
        got = env["action"]
        ok = got == want
        if not ok:
            bad += 1
        print("%s %-26s -> %-5s (want %-5s)  %s"
              % ("OK " if ok else "BAD", name, got, want, env["reason"]))

    # 恢复真实函数，避免影响同进程后续调用（本脚本到此为止）
    print("\nbad =", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(run())
