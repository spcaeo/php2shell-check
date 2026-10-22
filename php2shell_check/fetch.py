"""The requests: one pinned connection per request, every rule checked at every hop, the
budget (requests, seconds), and what the check asks for (the home page, the WordPress pages)."""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import time
from collections import Counter
from urllib.parse import urljoin, urlsplit

from .blocked import blocker, challenged
from .detect import WP_ANY, Page, detect, files
from .safety import (MAX_ADDRESSES, MAX_BYTES, MAX_FETCHES, MAX_REDIRECTS, LOGIN_HOPS, PORTS,
                     REDIRECTS, TIMEOUT, USER_AGENT, Answer, Refused, Spent, Unreachable,
                     check_url, family, host_of, host_refused, resolve)

class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout):
        self._ctx = ssl.create_default_context()
        super().__init__(host, port, timeout=timeout, context=self._ctx)
        self._address = address

    def connect(self):
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._ctx.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def open_pinned(scheme, host, address, port, method, target, timeout, max_bytes, agent=USER_AGENT):
    """One request to `address`, named `host` (Host header and TLS name). Tests replace this."""
    conn = (_PinnedHTTPS if scheme == "https" else _PinnedHTTP)(host, address, port, timeout)
    shown = host if port == PORTS[scheme] else f"{host}:{port}"
    try:
        conn.request(method, target, headers={
            "Host": shown, "User-Agent": agent, "Accept-Encoding": "identity",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5", "Connection": "close"})
        res = conn.getresponse()
        headers: dict = {}
        for name, value in res.getheaders():
            headers.setdefault(name.lower(), []).append(value)
        body = res.read(max_bytes) if method == "GET" else b""
        not_after = None
        if scheme == "https":
            try:
                not_after = (conn.sock.getpeercert() or {}).get("notAfter")
            except (AttributeError, ValueError, OSError):
                pass
        return Answer(res.status, headers, body, f"{scheme}://{shown}{target}", address, not_after)
    finally:
        conn.close()


def _words(why) -> str:
    if isinstance(why, (socket.timeout, TimeoutError)):
        return "it did not answer in time"
    if isinstance(why, ssl.SSLCertVerificationError):
        return "its HTTPS certificate is not valid for this name"
    if isinstance(why, ssl.SSLError):
        return "its HTTPS connection failed"
    if isinstance(why, ConnectionRefusedError):
        return "it refused the connection"
    if isinstance(why, http.client.HTTPException):
        return "its answer could not be read"
    return "the connection failed"


class Budget:
    """The check's limits (requests, seconds, the User-Agent, the address rules) and its log."""

    def __init__(self, fetches=MAX_FETCHES, timeout=TIMEOUT, seconds=None, ua=USER_AGENT,
                 allow_private=False, clock=time.monotonic):
        self.fetches, self.used, self.clock, self.timeout = fetches, 0, clock, timeout
        self.ua, self.allow_private = ua, allow_private
        self.end = clock() + (seconds if seconds is not None else timeout * max(fetches, 1) + 5)
        self.log: list = []

    def seconds(self) -> float:
        left = min(self.timeout, self.end - self.clock())
        if left <= 0.2:
            raise Unreachable("it did not answer in time")
        return left

    def take(self) -> None:
        if self.used >= self.fetches:
            raise Spent()
        self.seconds()
        self.used += 1

    def note(self, method, url, got=None, error=None) -> None:
        row = {"method": method, "url": url[:300], "status": None, "bytes": None,
               "location": None, "error": error}
        if got is not None:
            row["status"] = got.status
            if method == "GET":
                row["bytes"] = len(got.body)
            else:
                length = (got.headers.get("content-length") or [""])[0]
                row["bytes"] = int(length) if length.isdigit() else None
            row["location"] = (got.headers.get("location") or [""])[0].strip()[:300] or None
        self.log.append(row)


def get(url: str, method: str, budget: Budget) -> Answer:
    """One request, no redirect followed: every rule checked, the name resolved once and the
    connection made to the address that passed (no second lookup to rebind). Logged."""
    try:
        scheme, host, port, path = check_url(url)
        why = host_refused(host, budget.allow_private)
        if why:
            raise Refused(why)
        addresses = resolve(host, port, budget.allow_private)
    except (Refused, Unreachable) as why:
        budget.note(method, url, error=str(why))
        raise
    try:
        budget.take()
    except Spent:
        budget.note(method, url, error=f"not fetched: the limit of {budget.fetches} requests")
        raise
    except Unreachable as why:
        budget.note(method, url, error=str(why))
        raise
    last = None
    for address in addresses[:MAX_ADDRESSES]:
        try:
            got = open_pinned(scheme, host, address, port, method, path, budget.seconds(), MAX_BYTES,
                              agent=budget.ua)
            budget.note(method, url, got)
            return got
        except ssl.SSLCertVerificationError as err:
            budget.note(method, url, error=_words(err))
            raise Unreachable(_words(err)) from None
        except (OSError, http.client.HTTPException) as err:
            last = err
    words = _words(last) if last else "the connection failed"
    budget.note(method, url, error=words)
    raise Unreachable(words)


def location(got, base: str):
    if got.status not in REDIRECTS:
        return None
    loc = (got.headers.get("location") or [""])[0].strip()
    return urljoin(got.url or base, loc) if loc else None


def follow(url: str, budget: Budget) -> Answer:
    """A GET at the end of at most MAX_REDIRECTS redirects, each hop checked as `get`."""
    for hop in range(MAX_REDIRECTS + 1):
        got = get(url, "GET", budget)
        nxt = location(got, url)
        if not nxt:
            return got
        if hop == MAX_REDIRECTS:
            break
        url = nxt
    raise Refused(f"It redirected more than {MAX_REDIRECTS} times.")


# ------------------------------------------------------------------ the check's requests

LOGIN_FORM = re.compile(r"id\s*=\s*[\"']loginform[\"']", re.I)
LOG, PWD = (re.compile(rf"name\s*=\s*[\"']{n}[\"']", re.I) for n in ("log", "pwd"))
HIDDEN = (401, 403, 404, 410)
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
                    "x-content-type-options", "referrer-policy")


def plain(words: str, timeout: float) -> str:
    """Why a site could not be read, in plain words."""
    low = (words or "").lower()
    for seen, said in (("did not answer in time", f"no answer in {timeout:g} seconds"),
                       ("no address in dns", "the name doesn't exist"),
                       ("certificate is not valid", "its certificate is invalid"),
                       ("https connection failed", "its secure connection failed"),
                       ("refused the connection", "it refused the connection"),
                       ("could not be read", "its answer could not be read")):
        if seen in low:
            return said
    return words or "it did not answer"


def page_of(got, html=None) -> Page:
    if html is None:
        html = (got.body or b"")[:MAX_BYTES].decode("utf-8", "replace")
    return Page(got.url, host_of(got.url), got.status, got.headers, html)


def origins_of(pg: Page, typed: str, allow_private: bool) -> list:
    """Other hosts of the site's own domain its page loads WordPress files from, most first."""
    counts: Counter = Counter()
    for m in re.finditer(WP_ANY, pg.html, re.I):
        raw = m.group(1) or ""
        host = host_of("https:" + raw if raw.startswith("//") else raw)
        if host and host not in (pg.host, typed) and family(host) == family(typed) \
                and not host_refused(host, allow_private):
            counts[host] += 1
    return [h for h, _n in counts.most_common()]


def login(scheme: str, host: str, budget: Budget) -> dict:
    """/wp-login.php followed to its final page within the domain, its body read: "open" only
    for WordPress's login form; hidden for 401/403/404/410, a page without it or another domain."""
    url = f"{scheme}://{host}/wp-login.php"
    chain, current = [], url
    for _hop in range(LOGIN_HOPS + 1):
        try:
            got = get(current, "GET", budget)
        except Spent:
            return {"state": "unknown", "url": url, "chain": chain,
                    "why": f"not fetched: the limit of {budget.fetches} requests"}
        except (Refused, Unreachable) as why:
            return {"state": "unknown", "url": url, "chain": chain, "why": str(why)}
        nxt = location(got, current)
        chain.append({"url": current, "status": got.status, "location": nxt})
        if nxt:
            if family(host_of(nxt)) != family(host):
                return {"state": "hidden", "url": url, "chain": chain, "why": "it sends visitors to another domain"}
            current = nxt
            continue
        if challenged(got):
            return {"state": "unknown", "url": url, "chain": chain, "why": "a bot challenge answered instead of the page"}
        body = got.body.decode("utf-8", "replace")
        if 200 <= got.status < 300:
            form = bool(LOGIN_FORM.search(body) or (LOG.search(body) and PWD.search(body)))
            return {"state": "open" if form else "hidden", "url": url, "chain": chain,
                    "why": "a WordPress login form" if form else "a page with no login form"}
        state = "hidden" if got.status in HIDDEN else "unknown"
        return {"state": state, "url": url, "chain": chain, "why": f"it answers {got.status}"}
    return {"state": "unknown", "url": url, "chain": chain, "why": "too many redirects"}


def once(url: str, budget: Budget):
    try:
        return get(url, "GET", budget)
    except (Spent, Refused, Unreachable):
        return None


def wordpress_extras(scheme: str, host: str, budget: Budget) -> dict:
    """xmlrpc.php (is XML-RPC on?) and readme.html (does it show a version?): one GET each."""
    out = {}
    got = once(f"{scheme}://{host}/xmlrpc.php", budget)
    if got is not None:
        on = got.status == 405 and b"accepts post requests only" in got.body.lower()
        out["xmlrpc"] = {"url": got.url, "status": got.status, "on": on}
    got = once(f"{scheme}://{host}/readme.html", budget)
    if got is not None:
        ver = re.search(rb"<br\s*/?>\s*Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", got.body, re.I)
        out["readme"] = {"url": got.url, "status": got.status,
                         "version": ver.group(1).decode() if ver and got.status == 200 else None}
    return out


def origin(host: str, site: Page, budget: Budget) -> dict:
    """A WordPress host of the site's domain its page loads files from: proven by those files;
    then its login page, /wp-json/ (HEAD: its headers) and its home page (HEAD: headless?)."""
    _n, _first, loaded = files(site, WP_ANY, f"file{{s}} under /wp-content/ or /wp-includes/ from {host}",
                               keep=f"^(https?:)?//{re.escape(host)}/")
    for line in loaded:
        line["text"] = line["text"].replace("We saw links to", f"We saw the page {site.url} load", 1)
    found = [{"product": "wordpress", "name": "WordPress", "version": None, "family": "cms",
              "runtime": "php", "patched": None, "saw": loaded, "host": host}]
    row = {"host": host, "role": "content origin", "found": found, "error": None,
           "login": login("https", host, budget)}
    try:
        got = get(f"https://{host}/wp-json/", "HEAD", budget)
    except (Spent, Refused, Unreachable):
        got = None
    if got is not None and not challenged(got):
        for f in detect(page_of(got, "")):
            if f["product"] == "wordpress":
                found[0]["saw"] += f["saw"]
            elif f["family"] in ("server", "cdn", "runtime"):
                found.append({**f, "host": host})
    try:
        got = get(f"https://{host}/", "HEAD", budget)
        nxt = location(got, f"https://{host}/")
        if nxt and host_of(nxt) != host:
            row["headless"] = {"url": f"https://{host}/", "status": got.status, "location": nxt[:300]}
    except (Spent, Refused, Unreachable):
        pass
    return row


def read(scheme: str, host: str, budget: Budget) -> dict:
    """The requests: {hosts, fetched}. Refused propagates; a site that cannot be read is an answer."""
    def unread(words, reason):
        return {"hosts": [{"host": host, "role": "site", "error": words, "found": [], "read": False}],
                "fetched": budget.log, "fetches": budget.used, "reason": reason}
    try:
        home = follow(f"{scheme}://{host}/", budget)
    except Unreachable as why:
        return unread(plain(str(why), budget.timeout), "unreachable")
    except Spent:
        return unread("it redirected too often", "error")
    block = blocker(home, host_of(home.url) or host)
    if block:
        out = unread({"challenge": "a bot challenge answered instead of the page",
                      "password": f"the home page answered {home.status} (it asks for a password)",
                      "denied": f"the home page answered {home.status}"}[block["kind"]], "blocked")
        out["block"] = block
        return out
    if not 200 <= home.status < 300:
        return unread(f"the home page answered {home.status}", "error")
    pg = page_of(home)
    found = detect(pg)
    row = {"host": pg.host, "role": "site", "error": None, "read": True, "found": found,
           "url": home.url, "not_after": home.not_after,
           "headers": {h: home.headers.get(h) for h in SECURITY_HEADERS if home.headers.get(h)}}
    if any(f["product"] == "wordpress" and not f.get("patched") for f in found):
        site_scheme = urlsplit(home.url).scheme or scheme
        row["login"] = login(site_scheme, pg.host, budget)
        row["extras"] = wordpress_extras(site_scheme, pg.host, budget)
    hosts = [row]
    wanted = origins_of(pg, host, budget.allow_private)
    if wanted:
        hosts.append(origin(wanted[0], pg, budget))
    return {"hosts": hosts, "fetched": budget.log, "fetches": budget.used,
            "moved": home.url if home.url.rstrip("/") != f"{scheme}://{host}" else None}
