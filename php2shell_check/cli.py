"""The command line: the check itself, the terminal report, JSON, Markdown and exit codes."""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import textwrap
from datetime import datetime, timezone

from .advisories import ADVISORIES, load_advisories
from .cards import answer
from .fetch import Budget, read
from .safety import (ADVISORIES_URL, HOME, MAX_FETCHES, TIMEOUT, USER_AGENT, WEB_CHECK, Refused,
                     __version__, target)


def check(raw, doc=None, now=None, *, ua=USER_AGENT, max_requests=MAX_FETCHES, timeout=TIMEOUT,
          allow_private=False, budget=None) -> dict:
    """The whole check for what someone typed. Refused (in plain words) when the address is
    not checked; a site that cannot be read is an answer with `reached` false."""
    scheme, host = target(raw, allow_private)
    budget = budget or Budget(max_requests, timeout, ua=ua, allow_private=allow_private)
    return answer(host, read(scheme, host, budget), doc or ADVISORIES, now or datetime.now(timezone.utc), budget.ua)


LABELS = {"update": "UPDATE NEEDED", "login": "LOGIN OPEN", "hidden": "CHECK", "unknown": "COULD NOT CHECK",
          "tip": "TIP", "info": "INFO", "hosted": "GOOD", "good": "GOOD", "fixed": "FIXED",
          "nothing": "NOTHING APPLIES"}
TINTS = {"act": "1;31", "check": "1;33", "tips": "1;36", "good": "1;32"}
LEVELS = {"update_needed": ("update",), "check": ("update", "login", "hidden", "unknown"),
          "any": ("update", "login", "hidden", "unknown", "tip")}
HONEST = ("This reads only what your home page shows anyone. It can't see inside your server, "
          "and it doesn't test for the flaw. A hidden version is not proof either way: only the "
          "server can say (php -v, node -v).")


class Paint:
    def __init__(self, on: bool):
        self.on = on

    def __call__(self, code: str, text: str) -> str:       # each line, so a pager keeps it
        if not (self.on and text):
            return text
        return "\n".join(f"\033[{code}m{line}\033[0m" for line in text.split("\n"))


def use_color(mode: str, stream) -> bool:
    if mode != "auto":
        return mode == "always"
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def render(ans: dict, color: bool = False, width: int = 100, source: str = "built in") -> str:
    p, out = Paint(color), []
    width = max(60, min(width, 110))

    def wrap(text, first, rest=None):        # " -v" stays with its command (no-break space)
        return textwrap.fill(text.replace(" -", "\u00a0-"), width, initial_indent=first,
                             subsequent_indent=rest or first, break_long_words=False,
                             break_on_hyphens=False).replace("\u00a0", " ")
    out.append(p("1", f"php2shell-check {__version__}") + p("2", f"  {ans['host']}  {ans['checked_at']}"))
    out.append("")
    if ans["reached"]:
        out.append(p("1", wrap(ans["summary"], "")))
    else:
        out.append(p("1;33", wrap(f"Could not check {ans['host']}: {ans.get('error') or 'no answer'}.", "")))
    if ans.get("facts"):
        out.append(p("2", wrap(" · ".join(ans["facts"]), "")))
    for c in ans["cards"]:
        out += ["", p(TINTS[c["group"]], LABELS[c["kind"]]) + "  " + p("1", c["title"])]
        for s in c["saw"]:
            out.append(wrap(s["text"], "  "))
            out.append(p("2", wrap(s["url"], "    ")))
        out.append(wrap(c["means"], "  "))
        out.append(wrap("What to do: " + c["advice"], "  ", "    "))
        for src in c.get("sources") or []:
            out.append(p("2", f"  Source: {src}"))
        cmds = list(dict.fromkeys(s["command"] for s in c["saw"]))
        if cmds:
            out.append("  Check it yourself:")
            out += [p("2", "    $ ") + cmd for cmd in cmds]
    out += ["", p("1", f"What we fetched ({ans['fetches']} request{'s' if ans['fetches'] != 1 else ''})")]
    rows = [("METHOD", "STATUS", "BYTES", "URL")]
    for f in ans["fetched"]:
        tail = f" -> {f['location']}" if f.get("location") else (f"  ({f['error']})" if f.get("error") else "")
        rows.append((f["method"], str(f["status"] or "-"), f"{f['bytes']:,}" if f.get("bytes") is not None else "-",
                     f["url"] + tail))
    for i, r in enumerate(rows):
        line = f"  {r[0]:<6}  {r[1]:<6}  {r[2]:>9}  {r[3]}"
        out.append(p("2", line) if i == 0 else line)
    out.append(p("2", f"  User-Agent: {ans['agent']}"))
    out += ["", wrap(HONEST, ""), p("2", wrap(
        f"Advisories of {ans['advisories_updated']} ({source}): php2shell (CVE-2026-109618, "
        f"CVE-2026-109619) and Node.js October 2026. Prefer a browser? {WEB_CHECK}", ""))]
    return "\n".join(out) + "\n"


def _md(text) -> str:
    return str(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def markdown(ans: dict) -> str:
    """The answer as Markdown, for a GitHub job summary."""
    head = ans["summary"] if ans["reached"] else f"Could not check {ans['host']}: {ans.get('error')}."
    out = [f"## php2shell-check: {_md(ans['host'])}", "", f"**{_md(head)}**", ""]
    if ans["cards"]:
        out += ["| Status | Finding | We saw |", "| --- | --- | --- |"]
        out += [f"| {LABELS[c['kind']]} | {_md(c['title'])} | {_md(c['saw'][0]['text'][:160]) if c['saw'] else ''} |"
                for c in ans["cards"]]
    for c in ans["cards"]:
        out += ["", f"<details><summary><b>{LABELS[c['kind']]}</b>: {_md(c['title'])}</summary>", ""]
        out += [f"- {_md(s['text'])} ({_md(s['url'])})" for s in c["saw"]]
        out += ["", _md(c["means"]), "", f"What to do: {_md(c['advice'])}", ""]
        out += [f"Source: {s}" for s in c.get("sources") or []]
        out += ["", "```sh"] + list(dict.fromkeys(s["command"] for s in c["saw"])) + ["```", "", "</details>"]
    out += ["", "<details><summary>What we fetched</summary>", "", "| Method | Status | Bytes | URL |",
            "| --- | --- | --- | --- |"]
    out += [f"| {f['method']} | {f['status'] or '-'} | {f['bytes'] if f.get('bytes') is not None else '-'} | "
            f"{_md(f['url'])}{' -> ' + _md(f['location']) if f.get('location') else ''}"
            f"{' (' + _md(f['error']) + ')' if f.get('error') else ''} |" for f in ans["fetched"]]
    out += ["", "</details>", "", f"_{HONEST} Advisories of {ans['advisories_updated']}. "
            f"[php2shell-check {__version__}]({HOME})_", ""]
    return "\n".join(out)


def exit_code(ans: dict, fail_on) -> int:
    """0 clean, 1 a finding at or above `fail_on`, 2 could not check."""
    if not ans.get("reached"):
        return 2
    if fail_on and any(c["kind"] in LEVELS[fail_on] for c in ans["cards"]):
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="php2shell-check", description="Is your site exposed to the October 2026 PHP flaws (php2shell, "
        "CVE-2026-109618/109619) and the Node.js October 2026 releases? Reads only what your home page "
        "shows anyone.", epilog=f"Exit codes: 0 clean, 1 findings at or above --fail-on, 2 could not check. {HOME}")
    ap.add_argument("url", help="the site: example.com or https://www.example.com/")
    ap.add_argument("--json", action="store_true", help="print the answer as JSON (the web API's structure)")
    ap.add_argument("--fail-on", choices=tuple(LEVELS), help="exit 1 when a finding is at or above this level")
    ap.add_argument("--timeout", type=float, default=TIMEOUT, help=f"seconds per request (default {TIMEOUT:g})")
    ap.add_argument("--max-requests", type=int, default=MAX_FETCHES,
                    help=f"requests in all, redirects included (default {MAX_FETCHES})")
    ap.add_argument("--user-agent", default=USER_AGENT, help="the User-Agent sent (default: names this tool)")
    ap.add_argument("--advisories-url", help=f"load a newer advisory list (https JSON), e.g. {ADVISORIES_URL}")
    ap.add_argument("--allow-private", action="store_true",
                    help="allow names inside a network and private addresses (your own internal site)")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                    help="colours: auto (a terminal, unless NO_COLOR is set), always or never")
    ap.add_argument("--write-json", metavar="FILE", help="also write the JSON answer to FILE")
    ap.add_argument("--write-markdown", metavar="FILE", help="also write a Markdown report to FILE")
    ap.add_argument("--version", action="version", version=f"php2shell-check {__version__}")
    args = ap.parse_args(argv)
    if not 1 <= args.max_requests <= 50 or not 0.5 <= args.timeout <= 120:
        ap.error("--max-requests must be 1 to 50 and --timeout 0.5 to 120 seconds")
    if re.search(r"[\r\n\x00]", args.user_agent) or not args.user_agent.strip():
        ap.error("--user-agent must be one line")
    doc, source, warning = load_advisories(args.advisories_url, args.allow_private)
    if warning:
        print(f"php2shell-check: {warning}", file=sys.stderr)
    try:
        ans = check(args.url, doc, ua=args.user_agent.strip(), max_requests=args.max_requests,
                    timeout=args.timeout, allow_private=args.allow_private)
    except Refused as why:
        if args.json:
            print(json.dumps({"host": None, "reached": False, "reason": "refused", "error": str(why)}, indent=2))
        else:
            print(f"php2shell-check: {why}", file=sys.stderr)
        return 2
    ans["tool"] = {"name": "php2shell-check", "version": __version__, "advisories": source}
    text = json.dumps(ans, indent=2) + "\n"
    for path, content in ((args.write_json, text), (args.write_markdown, markdown(ans) if args.write_markdown else "")):
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
    if args.json:
        sys.stdout.write(text)
    else:
        sys.stdout.write(render(ans, use_color(args.color, sys.stdout),
                                shutil.get_terminal_size((100, 24)).columns, source))
    return exit_code(ans, args.fail_on)
