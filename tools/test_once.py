#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""场景测试：验证 run_once()（开机一次性登录）的行为。

    python tools/test_once.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import srun_login as s  # noqa: E402

WIRED = {"found": True, "name": "以太网", "description": "Realtek Gaming GbE Family Controller",
         "status": "Up", "mediaType": "802.3", "physical": "802.3", "ifIndex": 3}
WIFI = {"found": True, "name": "WLAN", "description": "Intel(R) Wi-Fi 6E AX211 160MHz",
        "status": "Up", "mediaType": "Native 802.11", "physical": "Native 802.11", "ifIndex": 19}


def env_of(action, online=False, fast_retry=False, reason=""):
    return {"action": action, "reason": reason, "source_ip": "10.100.0.101",
            "adapter": WIRED, "kind": "wired", "campus": action == "login",
            "online": online, "fast_retry": fast_retry}


def base_patch(ip, adapter):
    s._adapter_cache.clear()
    s.route_source_ip = lambda *a, **k: ip
    s._adapter_by_ip_powershell = lambda x: adapter
    s._adapter_by_ip_ipconfig = lambda x: adapter


LOG = str(Path(tempfile.gettempdir()) / "srun-test-once.log")


def case(name, checker, login_results, verify, timeout=1.0, interval=0.02, want=0,
         want_login_calls=None):
    """checker() 每次迭代被调用一次，返回 env。"""
    calls = {"login": 0, "verify": 0, "check": 0}

    def _check():
        calls["check"] += 1
        return checker(calls["check"])

    login_seq = list(login_results)

    def _login(*a, **k):
        calls["login"] += 1
        if len(login_seq) > 1:
            return login_seq.pop(0)
        return login_seq[0]

    def _verify(*a, **k):
        calls["verify"] += 1
        return verify

    s.check_environment = _check
    s.login = _login
    s._verify_online = _verify

    rc = s.run_once(timeout=timeout, interval=interval, log_path=LOG)

    problems = []
    if rc != want:
        problems.append("rc=%s want=%s" % (rc, want))
    if want_login_calls is not None and calls["login"] != want_login_calls:
        problems.append("login_calls=%d want=%d" % (calls["login"], want_login_calls))

    label = "OK " if not problems else "BAD"
    print("%s %-34s rc=%-2s checks=%-3d login=%-2d verify=%-2d  %s"
          % (label, name, rc, calls["check"], calls["login"], calls["verify"],
             "; ".join(problems)))
    return len(problems)


def main() -> int:
    bad = 0

    # 1) 已经在联网状态 -> 立刻完成，一次登录都不发
    base_patch("10.100.0.101", WIRED)
    bad += case("已联网", lambda i: env_of("skip", online=True, reason="已联网，无需登录"),
                [], True, want=s.RC_OK, want_login_calls=0)

    # 2) 无线网（校园 WiFi / 家里） -> 立刻跳过
    base_patch("192.168.1.23", WIFI)
    bad += case("无线网 -> 跳过",
                lambda i: env_of("skip", reason="出口是无线网卡（WLAN），跳过"),
                [], True, want=s.RC_SKIP, want_login_calls=0)

    # 3) 家里有线但 10.0.0.55 不是门户 -> 立刻跳过
    base_patch("192.168.1.23", WIRED)
    bad += case("家庭有线 -> 跳过",
                lambda i: env_of("skip", reason="10.0.0.55 有响应但不是深澜门户，跳过"),
                [], True, want=s.RC_SKIP, want_login_calls=0)

    # 4) 开机网卡还没就绪，第 4 次才判定成功 -> 应该一直等到能登录
    base_patch("10.100.0.101", WIRED)

    def ramp(i):
        if i < 4:
            return env_of("skip", fast_retry=True, reason="没有通往 10.0.0.55 的路由")
        return env_of("login", reason="有线 + 校园网 + 未认证，执行登录")

    bad += case("开机等待网卡就绪后登录", ramp,
                [{"ok": True, "resp": {"error": "ok"}}], True,
                want=s.RC_OK, want_login_calls=1)

    # 5) 密码错 -> 最多提交 3 次就放弃，避免账号被锁
    base_patch("10.100.0.101", WIRED)
    bad += case("登录一直失败 -> 3 次后放弃",
                lambda i: env_of("login", reason="有线 + 校园网 + 未认证，执行登录"),
                [{"ok": False, "resp": {"error": "password_error"}}], False,
                timeout=3.0, want=s.RC_FAIL, want_login_calls=3)

    # 6) 一直等不到网 -> 超时退出
    base_patch(None, None)
    bad += case("网线没插 -> 超时退出",
                lambda i: env_of("skip", fast_retry=True, reason="没有通往 10.0.0.55 的路由"),
                [], True, timeout=0.2, want=s.RC_FAIL, want_login_calls=0)

    print("\nbad =", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
