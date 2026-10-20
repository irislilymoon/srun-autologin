#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 ctypes 版 GetAdaptersAddresses 与 PowerShell Get-NetAdapter 结果一致。

    python tools/verify_adapter_api.py

ctypes 快三个数量级，但如果结构体偏移算错了会「安静地给出错误答案」，
所以必须拿系统自己的 API 逐一比对。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import srun_login as s  # noqa: E402

PS_QUERY = r"""
$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
$rows = foreach ($a in (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
    $ad = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue
    [pscustomobject]@{
        ip          = $a.IPAddress
        ifIndex     = [int]$a.InterfaceIndex
        name        = [string]$ad.Name
        description = [string]$ad.InterfaceDescription
        status      = [string]$ad.Status
        mediaType   = [string]$ad.MediaType
        physical    = [string]$ad.PhysicalMediaType
    }
}
$rows | ConvertTo-Json -Compress
"""


def ps_adapters() -> list[dict]:
    exe = s._find_pwsh()
    out = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-Command", PS_QUERY],
        capture_output=True, timeout=60,
    ).stdout.decode("utf-8", "replace").strip()
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def main() -> int:
    # 先验结构体偏移，偏移错了后面全白搭
    expect = {"IfIndex": 4, "Next": 8, "Description": 64, "FriendlyName": 72,
              "IfType": 100, "OperStatus": 104}
    bad = 0
    print("=== 结构体偏移检查 (x64) ===")
    for field, want in expect.items():
        got = getattr(s._IP_ADAPTER_ADDRESSES, field).offset
        ok = got == want
        if not ok:
            bad += 1
        print("  %s %-14s offset=%-4d (want %d)" % ("OK " if ok else "BAD", field, got, want))

    # 真正影响行为的只有三件事：ifIndex 对不对、Up/Down 对不对、分类结果对不对。
    # 字面值（physical 文案、description 后缀）不参与判定。
    print("\n=== 逐网卡比对：ifIndex / 状态 / 分类 ===")
    print("  %-34s %-16s %-6s %-8s %-9s %-9s %s"
          % ("描述", "IP", "ifIdx", "状态", "PS分类", "ctypes", "结果"))
    for row in ps_adapters():
        ip = row["ip"]
        mine = s._adapter_by_ip_ctypes(ip)

        # PowerShell 的 Get-NetAdapter 不返回 loopback / 某些隐藏适配器，
        # 此时它给不出基准值，这一行不参与判定（但打印出来备查）。
        if not row["name"]:
            print("  %-34s %-16s %-6s %-8s %-9s %-9s %s"
                  % (mine["description"][:34] if mine else "", ip,
                     "%d/-" % (mine["ifIndex"] if mine else -1),
                     "%s/-" % ("Up" if mine and mine["status"] == "Up" else "Down"),
                     "N/A", s.classify_adapter(mine) if mine else "None",
                     "N/A PowerShell 无基准数据，跳过比对"))
            continue

        if mine is None:
            print("  %-34s %-16s %-6s %-8s %-9s %-9s %s"
                  % (row["description"][:34], ip, row["ifIndex"],
                     row["status"] or "-", "-", "None", "BAD ctypes 查不到"))
            bad += 1
            continue

        idx_ok = mine["ifIndex"] == row["ifIndex"]
        up_ps = row["status"] == "Up"
        up_ct = mine["status"] == "Up"
        kind_ps = s.classify_adapter(row)
        kind_ct = s.classify_adapter(mine)
        ok = idx_ok and (up_ps == up_ct) and (kind_ps == kind_ct)
        if not ok:
            bad += 1
        print("  %-34s %-16s %-6s %-8s %-9s %-9s %s"
              % (row["description"][:34], ip,
                 "%d/%d" % (row["ifIndex"], mine["ifIndex"]),
                 "%s/%s" % ("Up" if up_ps else "Down", "Up" if up_ct else "Down"),
                 kind_ps, kind_ct, "OK " if ok else "BAD"))

    print("\nbad =", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
