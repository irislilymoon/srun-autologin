#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""随机对拍：把 srun_login.py 算出的认证参数与门户原版 JS (ref/ref_node.js) 比对。

    python tools/fuzz_vs_portal_js.py [轮数]
"""
from __future__ import annotations

import json
import random
import string
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import srun_login as s  # noqa: E402


def ref(us: str, pw: str, ch: str, ip: str, ac: str) -> dict:
    out = subprocess.run(
        ["node", str(ROOT / "ref" / "ref_node.js"), us, pw, ch, ip, ac],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def main() -> int:
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 25
    random.seed(20261016)
    alphabet = string.ascii_letters + string.digits + "!@#%&*_-."
    bad = 0
    for i in range(rounds):
        ch = "".join(random.choice("0123456789abcdef") for _ in range(64))
        pw = "".join(random.choice(alphabet) for _ in range(random.randint(4, 24)))
        us = "".join(random.choice(string.digits) for _ in range(10))
        ip = "10.%d.%d.%d" % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))
        ac = str(random.choice([43, 1, 12, 100]))

        mine = s.build_login_params(us, pw, ch, ip, ac)
        mine["hmd5"] = s.hmd5(pw, ch)
        theirs = ref(us, pw, ch, ip, ac)

        for field in ("hmd5", "password", "chksum", "info"):
            if mine[field] != theirs[field]:
                bad += 1
                print("MISMATCH round=%d field=%s" % (i, field))
                print("  py: %s" % mine[field][:120])
                print("  js: %s" % theirs[field][:120])
    print("rounds=%d mismatches=%d" % (rounds, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
