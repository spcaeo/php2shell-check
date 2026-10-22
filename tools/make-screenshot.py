#!/usr/bin/env python3
"""Render php2shell-check's real terminal output to an SVG for the README.

    python3 tools/make-screenshot.py                       # docs/screenshot.svg
    python3 tools/make-screenshot.py old-php-7-4-shown out.svg

It runs the check on one test fixture (tests/fixtures/sites/<case>: example.com names, the
network stubbed exactly as in the tests), prints it with the CLI's own renderer and colours,
and turns the ANSI colours into SVG. Nothing in the picture is typed by hand; a line longer
than COLS is cut with "…" in the picture only.
"""
from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import php2shell_check as p2s  # noqa: E402
from tests.helpers import case_net  # noqa: E402

COLS, FONT, LINE, PAD, BAR = 110, 13.0, 18.0, 22.0, 34.0
CHAR = FONT * 0.6                                   # a monospace cell
BG, FG, DIM = "#0d1117", "#e6edf3", "#7d8590"
COLOURS = {"31": "#ff7b72", "32": "#3fb950", "33": "#d29922", "36": "#58a6ff"}
SGR = re.compile(r"\033\[([0-9;]*)m")


def cut(line: str) -> str:
    """A line longer than COLS ends in "…" (only the picture is cut, never the output)."""
    seen, out, pos = 0, [], 0
    for m in list(SGR.finditer(line)) + [None]:
        end = m.start() if m else len(line)
        text = line[pos:end]
        if seen + len(text) > COLS:
            return "".join(out) + text[:COLS - seen - 1] + "…\033[0m"
        seen += len(text)
        out.append(text + (m.group(0) if m else ""))
        pos = m.end() if m else end
    return line


def spans(line: str) -> list:
    """[(text, bold, dim, colour)] of one line of ANSI text."""
    line = cut(line)
    out, bold, dim, colour, pos = [], False, False, None, 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            out.append((line[pos:m.start()], bold, dim, colour))
        for code in (m.group(1) or "0").split(";"):
            if code == "0":
                bold, dim, colour = False, False, None
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in COLOURS:
                colour = COLOURS[code]
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], bold, dim, colour))
    return out


def svg(lines: list, title: str) -> str:
    width = PAD * 2 + COLS * CHAR
    height = BAR + PAD + len(lines) * LINE + PAD
    rows = []
    for i, line in enumerate(lines):
        y = BAR + PAD + (i + 0.8) * LINE
        parts = []
        for text, bold, dim, colour in spans(line):
            attrs = []
            if colour or dim:
                attrs.append(f'fill="{colour or DIM}"')
            if bold:
                attrs.append('font-weight="700"')
            parts.append(f"<tspan {' '.join(attrs)}>{html.escape(text)}</tspan>" if attrs else html.escape(text))
        rows.append(f'<text x="{PAD}" y="{y:.1f}" xml:space="preserve">{"".join(parts)}</text>')
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-label="{html.escape(title)}">
<title>{html.escape(title)}</title>
<rect width="100%" height="100%" rx="10" fill="{BG}"/>
<rect width="100%" height="{BAR}" rx="10" fill="#161b22"/><rect y="{BAR - 10}" width="100%" height="10" fill="#161b22"/>
<circle cx="20" cy="{BAR / 2}" r="6" fill="#ff5f56"/><circle cx="40" cy="{BAR / 2}" r="6" fill="#ffbd2e"/><circle cx="60" cy="{BAR / 2}" r="6" fill="#27c93f"/>
<text x="{width / 2:.0f}" y="{BAR / 2 + 4.5}" text-anchor="middle" fill="{DIM}" font-family="system-ui, -apple-system, Segoe UI, sans-serif" font-size="12">php2shell-check</text>
<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace" font-size="{FONT}" fill="{FG}">
{chr(10).join(rows)}
</g>
</svg>
'''


def main(argv: list) -> int:
    name = argv[0] if argv else "wordpress-woocommerce-litespeed"
    out = Path(argv[1]) if len(argv) > 1 else ROOT / "docs" / "screenshot.svg"
    case, net = case_net(name)
    with net:
        ans = p2s.check(case["typed"])
    text = p2s.render(ans, color=True, width=100)
    lines = [f"\033[2m$\033[0m python3 php2shell_check.py {case['typed']}"] + text.rstrip("\n").split("\n")
    out.write_text(svg(lines, f"php2shell-check output for {case['typed']} (test fixture {name})"), encoding="utf-8")
    print(f"{out}: {len(lines)} lines, from the fixture {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
