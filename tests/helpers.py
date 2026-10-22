"""Stand-ins for the network, shared by the tests (no test touches the network).

RFC 5737 / RFC 3849 documentation addresses stand for public ones here: `doc_refused` lets
them through, and every other address meets the real rule.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import php2shell_check as p2s

NOW = datetime(2026, 10, 21, 18, tzinfo=timezone.utc)
PUBLIC, PUBLIC2, PUBLIC6 = "192.0.2.10", "198.51.100.20", "2001:db8::10"
TESTNET = {PUBLIC, PUBLIC2, PUBLIC6}
CASES = Path(__file__).resolve().parent / "fixtures" / "sites"
real_refused = p2s.address_refused


def doc_refused(text, allow_private=False):
    """Documentation addresses stand for public ones; every other address, the real rule."""
    return None if str(text) in TESTNET else real_refused(text, allow_private)


class Net:
    """lookup and open_pinned stand-ins. names: host -> [addresses] (or a list of such lists,
    one per lookup); pages: (method, url) or url -> (status, headers, body)."""

    def __init__(self, names=None, pages=None):
        self.names, self.pages = names or {}, pages or {}
        self.looked: list = []
        self.opened: list = []

    def lookup(self, host, port):
        self.looked.append(host)
        got = self.names.get(host)
        if got is None:
            raise socket.gaierror("no such name")
        if got and isinstance(got[0], list):
            return list(got.pop(0) if len(got) > 1 else got[0])
        return list(got)

    def open(self, scheme, host, address, port, method, target, timeout, max_bytes, agent=None):
        url = f"{scheme}://{host}{target}"
        self.opened.append({"url": url, "address": address, "method": method, "agent": agent,
                            "timeout": timeout, "max_bytes": max_bytes})
        status, headers, body = self.pages.get((method, url)) or self.pages.get(url) or (404, {}, b"")
        headers = {k.lower(): (v if isinstance(v, list) else [v]) for k, v in headers.items()}
        return p2s.Answer(status, headers, body if method == "GET" else b"", url, address)

    def __enter__(self):
        self._p = [mock.patch.object(p2s, "lookup", self.lookup),
                   mock.patch.object(p2s, "open_pinned", self.open),
                   mock.patch.object(p2s, "address_refused", doc_refused)]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._p:
            p.stop()


def run(raw, net, **kw):
    with net:
        return p2s.check(raw, p2s.ADVISORIES, NOW, **kw)


def case_net(name: str) -> tuple:
    """(the case, a Net that answers its pages): every host it names resolves to PUBLIC."""
    folder = CASES / name
    case = json.loads((folder / "case.json").read_text())
    pages = {}
    for key, page in case["pages"].items():
        method, url = key.split(" ", 1)
        body = (folder / page["body_file"]).read_text() if page.get("body_file") else page.get("body", "")
        pages[(method, url)] = (page["status"], page.get("headers") or {}, body.encode())
    names = case.get("names")
    if names is None:
        names = {p2s.host_of(url): [PUBLIC] for _m, url in pages}
        names[p2s.target(case["typed"])[1]] = [PUBLIC]
    return case, Net(names=names, pages=pages)


def case_names() -> list:
    return sorted(p.name for p in CASES.iterdir() if (p / "case.json").exists())


def evidenced(case, got):
    """Every card carries proof: lines of what was seen, each with its URL and a command."""
    for card in got["cards"]:
        case.assertTrue(card["saw"], card["title"])
        for seen in card["saw"]:
            case.assertTrue(seen["text"].startswith(("We saw", "We could not")), seen["text"])
            case.assertTrue(seen["url"] and seen["command"].startswith("curl "), seen)
        case.assertTrue(card["means"].startswith("This means"), card["means"])
