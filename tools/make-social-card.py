#!/usr/bin/env python3
"""Render tools/social/card.html to docs/social-preview.png (1280 x 640, GitHub's social
preview) with headless Chrome (Chrome from $CHROME, else the usual places).

    python3 tools/make-social-card.py
"""
from __future__ import annotations

import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHROMES = [os.environ.get("CHROME") or "", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
           "/Applications/Chromium.app/Contents/MacOS/Chromium", shutil.which("google-chrome") or "",
           shutil.which("chromium") or "", shutil.which("chromium-browser") or ""]


def main() -> int:
    browser = next((c for c in CHROMES if c and Path(c).exists()), None)
    if not browser:
        sys.exit("No Chrome found: set CHROME to its path.")
    out = ROOT / "docs" / "social-preview.png"
    subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
                    "--window-size=1280,640", f"--screenshot={out}", (ROOT / "tools" / "social" / "card.html").as_uri()],
                   check=True, capture_output=True, timeout=60)
    w, h = struct.unpack(">II", out.read_bytes()[16:24])
    print(f"{out}: {w} x {h}, {out.stat().st_size // 1024} KB")
    return 0 if (w, h) == (1280, 640) else 1


if __name__ == "__main__":
    raise SystemExit(main())
