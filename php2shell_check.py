#!/usr/bin/env python3
# GENERATED from php2shell_check/ by tools/build-single-file.py — do not edit
"""php2shell-check: is your site exposed to the October 2026 PHP flaws (php2shell)?

    python3 php2shell_check.py example.com
    curl -sSL https://raw.githubusercontent.com/spcaeo/php2shell-check/main/php2shell_check.py | python3 - example.com

Reads what a site's home page shows anyone (its headers, its generator tag, the paths of
the files it loads), after its redirects, plus a few public WordPress pages on WordPress
hosts of the same domain, and sets what it read against the advisories built into it.
GET and HEAD only, at most --max-requests requests, every one listed in the answer. It
never sends a form or a password, never asks for a secret file, never lists users, and it
does not test for the flaw.

Truth rules: every finding carries the exact lines it was read from, the URL and a curl
command that shows the same thing; what could not be read is "could not check", never a
guess; a version only when the server sent one; "update needed" only for a version read.

Safety: http and https on ports 80 and 443 only; never an IP address in any form, never a
name that only works inside a network; the name is resolved here and refused whole when any
of its addresses is not public (loopback, private, link-local, CGNAT, multicast, reserved,
cloud metadata; IPv4 inside IPv6 too), and the connection goes to the very address checked.
Every redirect is checked again. --allow-private lifts the private-address rules for a
check of your own internal site (cloud metadata, multicast and unspecified stay refused).

The source is the package php2shell_check/ (one module per concern); the single file
php2shell_check.py is generated from it by tools/build-single-file.py.

Python 3.9+, standard library only. Derived from Skald's public site check
(github.com/spcaeo/skald), relicensed MIT by its authors.

Copyright (c) 2026 Space-O Technologies. SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import sys
import textwrap
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit


# ------------------------------------------------------------------ safety.py

__version__ = "1.0.1"
HOME = "https://github.com/spcaeo/php2shell-check"
USER_AGENT = f"php2shell-check/{__version__} (+{HOME})"
ADVISORIES_URL = "https://raw.githubusercontent.com/spcaeo/php2shell-check/main/advisories.json"
WEB_CHECK = "https://skaldanalytics.com/check/"

TIMEOUT = 10.0             # seconds for one request (--timeout)
MAX_BYTES = 512 * 1024     # of one body
MAX_FETCHES = 8            # requests in one check, redirects included (--max-requests)
LOGIN_HOPS = 5             # redirects followed from /wp-login.php to its final page
MAX_REDIRECTS = 3
MAX_ADDRESSES = 2          # addresses tried per name, in the resolver's order
MAX_URL = 500
PORTS = {"http": 80, "https": 443}
REDIRECTS = (301, 302, 303, 307, 308)


class Refused(ValueError):
    """An address or a redirect a rule refuses, in plain words."""


class BadAddress(Refused):
    """What was typed is not a website address at all."""


class Unreachable(OSError):
    """No answer: the words say why."""


class Spent(Exception):
    """The check's requests are used up: what is left is not read."""


class Answer:
    def __init__(self, status, headers=None, body=b"", url="", peer="", not_after=None):
        self.status, self.headers, self.body = status, headers or {}, body
        self.url, self.peer, self.not_after = url, peer, not_after   # peer: never shown


# ------------------------------------------------------------------ addresses and names

NAME = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?"
                  r"(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$")
METADATA = {ipaddress.ip_address(a) for a in (
    "169.254.169.254", "169.254.170.2", "169.254.169.253", "100.100.100.200", "fd00:ec2::254")}
NUMERIC_LABEL = re.compile(r"^(?:\d+|0x[0-9a-f]*)$", re.I)     # 127.1, 0x7f.1: an address in disguise
CGNAT = ipaddress.ip_network("100.64.0.0/10")
NAT64 = ipaddress.ip_network("64:ff9b::/96")
NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
# Last labels that only work inside a network, or are reserved (RFC 2606, 6761, 6762, 8375).
INSIDE = {"localhost", "local", "internal", "intranet", "lan", "home", "corp", "private",
          "localdomain", "test", "invalid", "example", "arpa", "onion", "alt"}
NOT_AN_ADDRESS = "That doesn't look like a website address."


def _embedded(ip) -> list:
    """The IPv4 addresses an IPv6 address carries (mapped, 6to4, Teredo, NAT64)."""
    out = [x for x in (ip.ipv4_mapped, ip.sixtofour) if x]
    if ip.teredo:
        out.extend(ip.teredo)
    if ip in NAT64 or ip in NAT64_LOCAL:
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def address_refused(text: str, allow_private: bool = False):
    """Why this address is not fetched (plain words), or None for a public one."""
    try:
        ip = ipaddress.ip_address(str(text).split("%", 1)[0])
    except ValueError:
        return "an address that cannot be read"
    if ip in METADATA:
        return "a cloud metadata address"
    if ip.version == 6:
        for inner in _embedded(ip):
            why = address_refused(str(inner), allow_private)
            if why:
                return why
        if ip in NAT64 or ip in NAT64_LOCAL:
            return None if ip in NAT64 or allow_private else "a private address"
    if ip.is_unspecified:
        return "an unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if allow_private:
        return None
    for test, words in ((ip.is_loopback, "a loopback address (this machine itself)"),
                        (ip.is_link_local, "a link-local address"),
                        (ip.version == 4 and ip in CGNAT, "a shared (CGNAT) address"),
                        (ip.is_private, "a private address"), (ip.is_reserved, "a reserved address"),
                        (not ip.is_global, "an address that is not public")):
        if test:
            return words
    return None


def lookup(host: str, port: int) -> list:
    """The addresses of `host` (the system resolver), in its order. Tests replace this."""
    out = []
    for *_, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
        if sockaddr[0] not in out:
            out.append(sockaddr[0])
    return out


def resolve(host: str, port: int, allow_private: bool = False) -> list:
    """The addresses to connect to; Refused when ANY address of the name is not public."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        why = address_refused(str(literal), allow_private)
        if why:
            raise Refused(f"The address is {why}, which this tool does not fetch.")
        return [str(literal)]
    try:
        found = lookup(host, port)
    except (OSError, UnicodeError):
        raise Unreachable(f"{host} has no address in DNS.") from None
    if not found:
        raise Unreachable(f"{host} has no address in DNS.")
    for address in found:
        why = address_refused(address, allow_private)
        if why:
            raise Refused(f"{host} points to {why}, which this tool does not fetch."
                          + ("" if allow_private else " (--allow-private checks a site of your own network.)"))
    return found


def check_url(url: str) -> tuple:
    """(scheme, host, port, path and query) of a URL that may be fetched, or Refused."""
    try:
        parts = urlsplit(str(url).strip())
        port = parts.port
    except ValueError:
        raise Refused("That is not an address this tool can fetch.") from None
    scheme = (parts.scheme or "").lower()
    if scheme not in PORTS:
        raise Refused("Only http and https addresses are fetched.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise Refused("An address with a user name or password is not fetched.")
    if port is not None and port not in PORTS.values():
        raise Refused("Only ports 80 and 443 are fetched.")
    host = (parts.hostname or "").rstrip(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        try:
            host = host.encode("idna").decode("ascii").lower() if host else ""
        except UnicodeError:
            raise Refused("That is not a host name this tool can fetch.") from None
    if not host or (not is_ip and (not NAME.match(host) or host.endswith(".localhost"))):
        raise Refused("That is not a host name this tool can fetch.")
    if not is_ip and NUMERIC_LABEL.match(host.rsplit(".", 1)[-1]):
        raise Refused("An address written as numbers is not fetched.")
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return scheme, host, port or PORTS[scheme], target


def host_refused(host: str, allow_private: bool = False):
    """Why this name is not checked (plain words), or None."""
    host = host.lower().strip("[]").rstrip(".")
    labels = host.split(".")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if allow_private:
        return None
    if is_ip or NUMERIC_LABEL.match(labels[-1]):
        return "Type your site's name, not an IP address."
    if labels[-1] in INSIDE:
        return ("That name works only inside a network. Type the address people use on the "
                "internet (or add --allow-private for a site of your own network).")
    return None


def target(raw, allow_private: bool = False) -> tuple:
    """(scheme, host) of what someone typed (a host name, or a whole link), or Refused."""
    text = str(raw or "").strip()
    if not text or len(text) > MAX_URL or any(c.isspace() or ord(c) < 32 for c in text):
        raise BadAddress(NOT_AN_ADDRESS)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
        if re.match(r"^[a-z][a-z0-9+.-]*:(?!\d)", text, re.I):     # javascript:, file:, ...
            raise BadAddress(NOT_AN_ADDRESS)
        text = "https://" + text
    try:
        scheme, host, _port, _path = check_url(text)
    except Refused as why:
        if "port" in str(why).lower() or "password" in str(why).lower():
            raise
        raise BadAddress(NOT_AN_ADDRESS) from None
    why = host_refused(host, allow_private)
    if why:
        raise Refused(why)
    return scheme, host


def family(host: str) -> str:
    """The domain a name belongs to: <site> for wp.<site>; three labels under co.uk and the like."""
    labels = host.lower().split(".")
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3 else 2
    return ".".join(labels[-n:])


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# ------------------------------------------------------------------ detect.py

PATH_CHARS = "[-A-Za-z0-9._~%/+,;=:@&?#!$*]*"      # the same in Python and in grep -E
NAMES = {
    "wordpress": "WordPress", "woocommerce": "WooCommerce", "drupal": "Drupal", "joomla": "Joomla",
    "magento": "Magento", "laravel": "Laravel", "symfony": "Symfony", "codeigniter": "CodeIgniter",
    "prestashop": "PrestaShop", "opencart": "OpenCart", "craft": "Craft CMS", "typo3": "TYPO3",
    "statamic": "Statamic", "hugo": "Hugo", "php": "PHP", "nodejs": "Node.js", "shopify": "Shopify",
    "wix": "Wix", "squarespace": "Squarespace", "webflow": "Webflow", "hubspot": "HubSpot CMS",
    "ghost": "Ghost", "wordpresscom": "WordPress.com", "wpvip": "WordPress VIP", "nextjs": "Next.js",
    "nuxt": "Nuxt", "gatsby": "Gatsby", "remix": "Remix", "sveltekit": "SvelteKit", "astro": "Astro",
    "angular": "Angular Universal", "express": "Express", "vercel": "Vercel", "netlify": "Netlify",
    "nginx": "nginx", "apache": "Apache", "litespeed": "LiteSpeed", "openresty": "OpenResty",
    "iis": "Microsoft IIS", "caddy": "Caddy", "cloudflare": "Cloudflare", "fastly": "Fastly",
    "akamai": "Akamai", "cloudfront": "CloudFront", "sucuri": "Sucuri"}
FIREWALLS = ("cloudflare", "sucuri", "akamai", "fastly", "cloudfront")
VER = r"(\d+(?:\.\d+){0,2})"
WP_ANY = f"((https?:)?//[a-z0-9.-]+)?/wp-(content|includes)/{PATH_CHARS}"
GENERATOR = r"<meta\b[^>]*\bname\s*=\s*[\"']?generator[\"']?[^>]*>"


class Page:
    def __init__(self, url, host, status, headers=None, html=""):
        self.url, self.host, self.status, self.headers, self.html = url, host, status, headers or {}, html

    def header(self, name: str) -> str:
        return ", ".join(self.headers.get(name.lower()) or [])

    def cookies(self) -> list:
        """The cookie names the answer set (never their values)."""
        out = []
        for line in self.headers.get("set-cookie") or []:
            name = line.split("=", 1)[0].strip()
            if name and name not in out:
                out.append(name)
        return out


def _q(text: str) -> str:
    return shlex.quote(text)


def see_header(pg: Page, name: str, contains=None) -> list:
    """The header line as received (the first value that contains `contains`)."""
    pretty = {"x-powered-by": "X-Powered-By", "x-nf-request-id": "X-Nf-Request-Id"}.get(
        name, "-".join(w.capitalize() for w in name.split("-")))
    for value in pg.headers.get(name) or []:
        if contains is None or contains.lower() in value.lower():
            return [{"text": f"We saw the header {pretty}: {value.strip()[:200]}", "url": pg.url,
                     "command": f"curl -sI {_q(pg.url)} | grep -i '^{name}:'"}]
    return []


def see_cookie(pg: Page, name: str) -> list:
    return [{"text": f"We saw the site set a cookie named {name} (its value is not shown)",
             "url": pg.url, "command": f"curl -sI {_q(pg.url)} | grep -i -o '^set-cookie: {name}='"}]


def see_generator(pg: Page, word: str) -> list:
    """The generator tag that names `word` (a page can carry several: a plugin's too)."""
    for tag in re.findall(GENERATOR, pg.html, re.I):
        if word.lower() in tag.lower():
            return [{"text": f"We saw the tag {tag[:200]}", "url": pg.url,
                     "command": f"curl -s {_q(pg.url)} | grep -i -o '<meta[^>]*generator[^>]*>'"}]
    return []


def generator(pg: Page) -> str:
    out = []
    for tag in re.findall(GENERATOR, pg.html, re.I):
        got = re.search(r"\bcontent\s*=\s*[\"']([^\"']*)", tag, re.I)
        if got:
            out.append(got.group(1))
    return " | ".join(out)[:200]


def files(pg: Page, pattern: str, what: str, keep=None) -> tuple:
    """(how many different matches, the first, its evidence) of an ERE that grep and Python
    both read the same way. `keep`, a second ERE, keeps only the matches it starts."""
    found = [m.group(0) for m in re.finditer(pattern, pg.html, re.I)]
    if keep:
        found = [m for m in found if re.match(keep, m, re.I)]
    found = list(dict.fromkeys(m.lower() for m in found))
    if not found:
        return 0, None, []
    n = len(found)
    text = (f"We saw links to {n:,} different {what.format(s='' if n == 1 else 's')}, for example "
            f"{found[0][:160]}")
    then = f" | grep -i -E {_q(keep)}" if keep else ""
    return n, found[0], [{"text": text, "url": pg.url,
                          "command": f"curl -s {_q(pg.url)} | grep -o -i -E {_q(pattern)}{then} "
                                     f"| tr 'A-Z' 'a-z' | sort -u | wc -l"}]


def contains(pg: Page, needle: str, words: str) -> list:
    if needle.lower() not in pg.html.lower():
        return []
    return [{"text": f"We saw {words} in the page", "url": pg.url,
             "command": f"curl -s {_q(pg.url)} | grep -c -i {_q(needle)}"}]


def _add(out, product, fam, saw, version=None, runtime=None, patched=None) -> None:
    if not saw:
        return
    for f in out:
        if f["product"] == product:
            f["saw"] += [s for s in saw if s not in f["saw"]]
            f["version"] = f["version"] or version
            return
    out.append({"product": product, "name": NAMES[product], "version": version, "family": fam,
                "runtime": runtime, "patched": patched, "saw": saw})


def _wordpress(pg: Page, out: list) -> None:
    gen, host = generator(pg), re.escape(pg.host)
    saw, version = [], None
    got = re.search(r"WordPress\s+" + VER, gen, re.I)
    if re.search(r"\bWordPress\b", gen, re.I) and not re.search(r"WordPress\.com", gen, re.I):
        saw += see_generator(pg, "WordPress")
        version = got.group(1) if got else None
    saw += see_header(pg, "link", "api.w.org")
    saw += files(pg, WP_ANY, f"file{{s}} under /wp-content/ or /wp-includes/ on {pg.host}",
                 keep=f"^((https?:)?//{host})?/")[2]
    if not version:
        # WordPress's own core files carry its version as ?ver= (never a plugin's or a theme's).
        vers = Counter(re.findall(r"/wp-includes/(?:js|css)/[-A-Za-z0-9._/]*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b",
                                  pg.html, re.I))
        if vers:
            version, count = vers.most_common(1)[0]
            saw.append({"text": f"We saw WordPress's own core files carry ?ver={version} ({count} of them)",
                        "url": pg.url, "command": f"curl -s {_q(pg.url)} | grep -o -E '/wp-includes/(js|css)/"
                                                  f"[-A-Za-z0-9._/]*[?]ver=[0-9.]*' | sort | uniq -c"})
    _add(out, "wordpress", "cms", saw, version, "php")
    wp = next((f for f in out if f["product"] == "wordpress"), None)
    if wp:
        n, _first, multi = files(pg, f"/wp-content/uploads/sites/[0-9]+/{PATH_CHARS}",
                                 "file{s} under /wp-content/uploads/sites/ (a multisite's)")
        if n:
            wp["multisite"] = True
            _add(out, "wordpress", "cms", multi)
        got = re.search(r"WooCommerce\s+" + VER, gen, re.I)
        _add(out, "woocommerce", "cms", see_generator(pg, "WooCommerce")
             + files(pg, f"/wp-content/plugins/woocommerce/{PATH_CHARS}", "WooCommerce file{s}")[2],
             got.group(1) if got else None, "php")


def _php_apps(pg: Page, out: list) -> None:
    gen, cookies = generator(pg), pg.cookies()
    saw = see_generator(pg, "Drupal") if re.search(r"\bDrupal\b", gen, re.I) else []
    saw += see_header(pg, "x-generator", "drupal") + see_header(pg, "x-drupal-cache")
    saw += see_header(pg, "x-drupal-dynamic-cache")
    saw += files(pg, f"/sites/default/files/{PATH_CHARS}", "file{s} under /sites/default/files/")[2]
    got = re.search(r"Drupal\s+" + VER, gen + " " + pg.header("x-generator"), re.I)
    _add(out, "drupal", "cms", saw, got.group(1) if got else None, "php")
    saw = see_generator(pg, "Joomla") if re.search(r"\bJoomla\b", gen, re.I) else []
    if saw:
        saw += files(pg, f"/media/(jui|system)/{PATH_CHARS}", "file{s} under Joomla's /media/jui/ or /media/system/")[2]
        saw += contains(pg, "/administrator/", "a link to /administrator/")
    _add(out, "joomla", "cms", saw, None, "php")
    saw = [h for name in ("x-magento-cache-debug", "x-magento-tags", "x-magento-vary") for h in see_header(pg, name)]
    saw += contains(pg, "Mage.Cookies", "Magento's Mage.Cookies script")
    saw += files(pg, f"/static/version[0-9]+/{PATH_CHARS}", "file{s} under Magento's /static/version.../")[2]
    _add(out, "magento", "cms", saw, None, "php")
    session = [c for c in cookies if c.lower().endswith("_session")]
    if "XSRF-TOKEN" in cookies and session:          # Laravel's own pair
        _add(out, "laravel", "framework", see_cookie(pg, "XSRF-TOKEN") + see_cookie(pg, session[0]), None, "php")
    _add(out, "statamic", "cms", see_header(pg, "x-powered-by", "statamic"), None, "php")
    for product, cookie in (("laravel", "laravel_session"), ("symfony", "sf_redirect"),
                            ("codeigniter", "ci_session"), ("craft", "CraftSessionId"), ("opencart", "OCSESSID")):
        hit = [c for c in cookies if c.lower() == cookie.lower()]
        fam = "cms" if product in ("craft", "opencart") else "framework"
        _add(out, product, fam, see_cookie(pg, hit[0]) if hit else [], None, "php")
    if any(c.lower().startswith("prestashop-") for c in cookies) or re.search(r"\bPrestaShop\b", gen, re.I):
        saw = see_generator(pg, "PrestaShop") if re.search(r"\bPrestaShop\b", gen, re.I) else []
        saw += [s for c in cookies if c.lower().startswith("prestashop-") for s in see_cookie(pg, c)][:1]
        _add(out, "prestashop", "cms", saw, None, "php")
    _add(out, "craft", "cms", see_header(pg, "x-powered-by", "craft cms"), None, "php")
    saw = see_generator(pg, "TYPO3") if re.search(r"\bTYPO3\b", gen, re.I) else []
    saw += files(pg, f"/typo3(conf|temp)/{PATH_CHARS}", "file{s} under /typo3conf/ or /typo3temp/")[2]
    _add(out, "typo3", "cms", saw, None, "php")
    if any(f["product"] == "opencart" for f in out):
        _add(out, "opencart", "cms", files(pg, f"/catalog/view/theme/{PATH_CHARS}", "OpenCart theme file{s}")[2])


def _hosted(pg: Page, out: list) -> None:
    gen = generator(pg)
    saw = see_header(pg, "x-shopid") + see_header(pg, "x-shopify-stage") + see_header(pg, "powered-by", "shopify")
    if saw:
        saw += [s for c in pg.cookies() if c.lower().startswith("_shopify_") for s in see_cookie(pg, c)][:1]
        saw += files(pg, f"//cdn\\.shopify\\.com/{PATH_CHARS}", "file{s} on cdn.shopify.com")[2]
    _add(out, "shopify", "hosted", saw, patched="Shopify")
    saw = see_header(pg, "x-wix-request-id") + see_header(pg, "server", "pepyaka")
    saw += files(pg, f"//static\\.wixstatic\\.com/{PATH_CHARS}", "file{s} on static.wixstatic.com")[2] if saw else []
    _add(out, "wix", "hosted", saw, patched="Wix")
    saw = see_header(pg, "server", "squarespace")
    saw += files(pg, f"//static1\\.squarespace\\.com/{PATH_CHARS}", "file{s} on static1.squarespace.com")[2] if saw else []
    _add(out, "squarespace", "hosted", saw, patched="Squarespace")
    saw = contains(pg, "data-wf-site", "Webflow's data-wf-site attribute") if "data-wf-site" in pg.html else []
    saw += files(pg, f"//[a-z0-9.-]*website-files\\.com/{PATH_CHARS}", "file{s} on Webflow's website-files.com")[2] \
        if saw else []
    _add(out, "webflow", "hosted", saw, patched="Webflow")
    _add(out, "hubspot", "hosted", see_header(pg, "x-hs-hub-id") + see_header(pg, "x-powered-by", "hubspot"),
         patched="HubSpot")
    saw = see_header(pg, "x-hacker") + see_header(pg, "host-header", "wordpress.com")
    saw += see_generator(pg, "WordPress.com") if re.search(r"WordPress\.com", gen, re.I) else []
    vip = see_header(pg, "x-powered-by", "wordpress vip")
    _add(out, "wpvip", "hosted", vip, patched="WordPress VIP")
    if not vip:
        _add(out, "wordpresscom", "hosted", saw, patched="WordPress.com")
    if re.search(r"\bGhost\b", gen, re.I):
        got = re.search(r"Ghost\s+" + VER, gen, re.I)
        _add(out, "ghost", "cms", see_generator(pg, "Ghost") + see_header(pg, "x-ghost-cache-status"),
             got.group(1) if got else None, "nodejs")


def _js(pg: Page, out: list) -> None:
    gen = generator(pg)
    saw = see_header(pg, "x-powered-by", "next.js")
    saw += files(pg, f"(https?://[a-z0-9.-]+)?/_next/{PATH_CHARS}", "Next.js file{s} (/_next/)")[2]
    saw += contains(pg, "__NEXT_DATA__", "Next.js's __NEXT_DATA__ script")
    _add(out, "nextjs", "js", saw, None, "nodejs")
    saw = see_header(pg, "x-powered-by", "nuxt")
    saw += files(pg, f"(https?://[a-z0-9.-]+)?/_nuxt/{PATH_CHARS}", "Nuxt file{s} (/_nuxt/)")[2]
    saw += contains(pg, "__NUXT__", "Nuxt's __NUXT__ data")
    _add(out, "nuxt", "js", saw, None, "nodejs")
    got = re.search(r"Gatsby\s+" + VER, gen, re.I)
    saw = (see_generator(pg, "Gatsby") if got else []) + contains(pg, "___gatsby", "Gatsby's ___gatsby root")
    _add(out, "gatsby", "js", saw, got.group(1) if got else None)
    _add(out, "remix", "js", contains(pg, "__remixContext", "Remix's __remixContext script"), None, "nodejs")
    _add(out, "sveltekit", "js", files(pg, f"/_app/immutable/{PATH_CHARS}", "SvelteKit file{s} (/_app/immutable/)")[2],
         None, "nodejs")
    got = re.search(r"Hugo\s+" + VER, gen, re.I)
    _add(out, "hugo", "js", see_generator(pg, "Hugo") if got else [], got.group(1) if got else None)
    got = re.search(r"Astro\s+v?" + VER, gen, re.I)
    saw = (see_generator(pg, "Astro") if got else []) + files(pg, f"/_astro/{PATH_CHARS}", "Astro file{s} (/_astro/)")[2]
    _add(out, "astro", "js", saw, got.group(1) if got else None)
    if "ng-server-context" in pg.html:
        _add(out, "angular", "js", contains(pg, "ng-server-context", "Angular's ng-server-context "
                                            "(rendered on a server)"), None, "nodejs")
    _add(out, "express", "js", see_header(pg, "x-powered-by", "express"), None, "nodejs")


def _servers(pg: Page, out: list) -> None:
    _add(out, "vercel", "hosting", see_header(pg, "x-vercel-id") + see_header(pg, "server", "vercel"), patched="Vercel")
    _add(out, "netlify", "hosting", see_header(pg, "x-nf-request-id") + see_header(pg, "server", "netlify"),
         patched="Netlify")
    server = pg.header("server")
    for product, word in (("nginx", "nginx"), ("apache", "apache"), ("litespeed", "litespeed"),
                          ("openresty", "openresty"), ("iis", "microsoft-iis"), ("caddy", "caddy")):
        got = re.match(r"^\s*" + re.escape(word) + r"(?:/" + VER + ")?", server, re.I)
        if got:
            _add(out, product, "server", see_header(pg, "server", word), got.group(1))
    if pg.headers.get("x-litespeed-cache"):
        _add(out, "litespeed", "server", see_header(pg, "x-litespeed-cache"))
    _add(out, "cloudflare", "cdn", see_header(pg, "server", "cloudflare") + see_header(pg, "cf-ray"))
    _add(out, "fastly", "cdn", see_header(pg, "x-fastly-request-id") + see_header(pg, "x-served-by", "cache-"))
    _add(out, "akamai", "cdn", see_header(pg, "server", "akamaighost") + see_header(pg, "akamai-grn"))
    _add(out, "cloudfront", "cdn", see_header(pg, "x-amz-cf-id") + see_header(pg, "via", "cloudfront"))
    _add(out, "sucuri", "cdn", see_header(pg, "x-sucuri-id") + see_header(pg, "server", "sucuri"))
    saw = see_header(pg, "x-powered-by", "php/")
    got = re.search(r"\bPHP/" + VER, pg.header("x-powered-by"), re.I)
    session = [c for c in pg.cookies() if c.upper() == "PHPSESSID"]
    saw += see_cookie(pg, session[0]) if session else []
    if saw:
        _add(out, "php", "runtime", saw, got.group(1) if got else None, "php")


def detect(pg: Page) -> list:
    """Everything this page proves, each with its evidence: product, name, version (only what
    the server sent), family, runtime, patched (who runs the runtime for you), saw."""
    out: list = []
    for fam in (_hosted, _wordpress, _php_apps, _js, _servers):
        fam(pg, out)
    host = next((f["patched"] for f in out if f["product"] in ("wordpresscom", "wpvip")), None)
    if host:                                     # WordPress hosted by WordPress.com or VIP
        for f in out:
            if f["product"] in ("wordpress", "woocommerce"):
                f["patched"] = host
    for f in out:
        f["host"] = pg.host
    return out


def how_of(saw: list) -> str:
    text = saw[0]["text"] if saw else ""
    if text.startswith("We saw the tag"):
        return "generator tag"
    got = re.match(r"We saw the header ([A-Za-z-]+):", text)
    if got:
        return f"{got.group(1)} header"
    if text.startswith("We saw the site set a cookie"):
        return "its cookie"
    return "its files" if "load" in text or text.startswith("We saw links to") else "its page"


def runtimes(found: list) -> list:
    """PHP and Node.js on each host: the server's own version when it shows one, else "version
    not shown" with what runs on them as the evidence, and who patches them for you."""
    out = [f for f in found if f["product"] not in ("php", "nodejs")]
    for host in dict.fromkeys(f["host"] for f in found):
        here = [f for f in found if f["host"] == host]
        patched = next((f["patched"] for f in here if f["family"] in ("hosted", "hosting") and f["patched"]), None)
        for runtime in ("php", "nodejs"):
            own = next((f for f in here if f["product"] == runtime), None)
            apps = [f for f in here if f.get("runtime") == runtime and f["product"] != runtime]
            if not own and not apps:
                continue
            # A hosted platform runs PHP or Node.js for you; Vercel and Netlify run Node.js, not PHP.
            who = patched if (patched and (runtime == "nodejs" or patched not in ("Vercel", "Netlify"))) \
                else next((a["patched"] for a in apps if a.get("patched")), None)
            saw = list(own["saw"]) if own else []
            if not (own and own.get("version")) and apps:
                app = apps[0]
                ver = f" {app['version']}" if app.get("version") else ""
                saw.insert(0, {"text": f"We saw {host} runs {app['name']}{ver} ({how_of(app['saw'])}), "
                                       f"and {app['name']} runs on {NAMES[runtime]}",
                               "url": app["saw"][0]["url"], "command": app["saw"][0]["command"]})
                saw += [s for s in app["saw"] if s not in saw]
            out.append({"product": runtime, "name": NAMES[runtime], "family": "runtime",
                        "version": own.get("version") if own else None, "runtime": runtime,
                        "patched": who, "host": host, "saw": saw,
                        "under": [a["name"] + (f" {a['version']}" if a.get("version") else "") for a in apps]})
    return out


# ------------------------------------------------------------------ blocked.py

CHALLENGE = (b"challenge-platform", b"just a moment...", b"attention required!",
             b"cf-browser-verification", b"captcha", b"checking your browser")
DENIAL = (b"access denied", b"you have been blocked", b"request blocked",
          b"your access to this site has been limited")
# (name, where, what, contains): a header (by name, and a word in its value when given) or a
# phrase of the page that only that firewall sends.
FIREWALL_MARKS = (
    ("Cloudflare", "header", "cf-mitigated", None), ("Cloudflare", "header", "server", "cloudflare"),
    ("Cloudflare", "header", "cf-ray", None),
    ("Sucuri", "header", "x-sucuri-id", None), ("Sucuri", "header", "server", "sucuri"),
    ("Sucuri", "page", "sucuri website firewall", None),
    ("Akamai", "header", "server", "akamaighost"), ("Akamai", "header", "akamai-grn", None),
    ("AWS WAF", "header", "x-amzn-waf-action", None),
    ("CloudFront", "header", "x-amz-cf-id", None), ("CloudFront", "header", "via", "cloudfront"),
    ("Imperva", "header", "x-iinfo", None), ("Imperva", "header", "x-cdn", "imperva"),
    ("Imperva", "header", "x-cdn", "incapsula"),
    ("Fastly", "header", "x-fastly-request-id", None),
    ("Wordfence", "page", "generated by wordfence", None))
BLOCKED_SUMMARY = {
    "firewall": ("Your site's firewall stopped this check from this machine, so we can't see what it "
                 "shows. That's often good news: it blocks automated scanners too."),
    "password": "Your site asks for a password, so we can't see what it shows.",
}
BLOCKED_NEXT = {
    "firewall": ("To see the details, run it from a machine the firewall lets through (your office "
                 "network, or the server itself), or check by hand:"),
    "password": "To see the details, check on the server:",
}


def _first_header(got, name: str) -> str:
    return ((got.headers.get(name) or [""])[0] or "").strip().lower()


def challenged(got) -> bool:
    """A bot challenge (Cloudflare's, AWS WAF's and the like) answered instead of the page."""
    if _first_header(got, "cf-mitigated") == "challenge" or \
            _first_header(got, "x-amzn-waf-action") in ("challenge", "captcha"):
        return True
    return got.status in (403, 429, 503) and any(m in got.body[:30000].lower() for m in CHALLENGE)


def firewalls_named(pg: Page, body: bytes) -> tuple:
    """(the firewalls this answer names itself, the line that proves each: one per name)."""
    names, saw, low = [], [], body[:30000].lower()
    for name, where, what, word in FIREWALL_MARKS:
        if name in names:
            continue
        if where == "header":
            line = see_header(pg, what, word)
        else:
            line = contains(pg, what, f"\"{what}\"") if what.encode() in low else []
        if line:
            names.append(name)
            saw += line
    return names, saw


def blocker(got, host: str):
    """What blocked the check (see the module's docstring), or None when nothing did."""
    pg = Page(url=got.url, host=host, status=got.status, headers=got.headers,
              html=got.body[:30000].decode("utf-8", "replace"))
    low = got.body[:30000].lower()
    names, named = firewalls_named(pg, got.body)
    if challenged(got):
        kind = "challenge"
    elif got.status == 401:
        kind = "password"
    elif got.status in (403, 429) or (got.status == 503 and names and any(m in low for m in DENIAL)):
        kind = "denied"
    else:
        return None
    url = got.url
    what = {"challenge": " (a bot challenge, not your page)", "password": " (it asks for a password)",
            "denied": " (refused, not your page)"}[kind]
    saw = [{"text": f"We saw {url} answer {got.status}{what}", "url": url,
            "command": f"curl -sI {_q(url)} | head -n 1"}]
    for name in ("cf-mitigated", "x-amzn-waf-action", "www-authenticate"):
        saw += see_header(pg, name)
    title = re.search(r"<title[^>]*>\s*([^<]{1,120}?)\s*</title>", pg.html, re.I)
    marker = next((m.decode() for m in CHALLENGE + DENIAL if m in low), None)
    if title and marker:
        saw.append({"text": f"We saw the page title \"{title.group(1)}\"", "url": url,
                    "command": f"curl -s {_q(url)} | grep -o -i '<title>[^<]*</title>'"})
    elif marker:
        saw += contains(pg, marker, f"\"{marker}\"")
    saw += [s for s in named if s not in saw]
    if not names:                       # who answered, in its own words (nginx, Apache ...)
        saw += see_header(pg, "server")
    home = f"https://{host}/"
    commands = ([] if kind == "password" else
                [f"curl -sI {_q(home)} | grep -iE \"server|x-powered-by\""]) + ["php -v"]
    return {"kind": kind, "status": got.status, "url": url, "firewalls": names, "saw": saw,
            "commands": commands}


def blocked_words(block: dict) -> str:
    return "password" if block["kind"] == "password" else "firewall"


def blocked_card(host: str, block: dict) -> dict:
    """The "could not check" card of a blocked check: its proof, why it is not a problem with
    the site, and the commands."""
    names, status = block["firewalls"], block["status"]
    if block["kind"] == "password":
        return {"kind": "unknown", "group": "check", "title": f"{host} asks for a password, so we could not check it",
                "saw": block["saw"],
                "means": (f"This means the site answered {status}: it asks for a password (HTTP "
                          "authentication), as a private or staging site often does. It is not a problem found: "
                          "we can't see what it shows, so we say nothing about it."),
                "advice": "Check the PHP version on the server with php -v, and update if it is older than "
                          "the fixed release of its branch.",
                "hosts": [host], "commands": block["commands"], "firewalls": names}
    who = (f"{' and '.join(names) if len(names) < 3 else ', '.join(names[:-1]) + ' and ' + names[-1]} "
           "answered for your site" if names
           else "something in front of your site (a firewall or a server rule) answered")
    what = "a bot challenge" if block["kind"] == "challenge" else f"a refusal ({status})"
    return {"kind": "unknown", "group": "check", "title": f"{host}'s firewall stopped this check",
            "saw": block["saw"],
            "means": (f"This means {who} with {what} instead of your home page. This check ran from this "
                      "machine, and firewalls often let a browser through and stop scripts like this one. "
                      "It is not a problem with your site: we can't see what the page shows, so we say "
                      "nothing about it. That's often good news: it blocks automated scanners too."),
            "advice": ("Run it from a machine the firewall lets through (your office network, or the server "
                       "itself). Or look yourself: the curl line below, from a machine it lets through, shows "
                       "the Server and X-Powered-By headers, and php -v on the server shows the PHP version."),
            "hosts": [host], "commands": block["commands"], "firewalls": names}


# ------------------------------------------------------------------ fetch.py

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


# ------------------------------------------------------------------ advisories.py

ADVISORIES = {
    "schema": 1,
    "updated": "2026-10-21",
    "about": "Advisories php2shell-check matches against what a site shows. Facts only from the vendor's own advisory. Newer lists: https://github.com/spcaeo/php2shell-check/blob/main/advisories.json",
    "advisories": [
        {"id": "php-2026-10-21", "product": "php", "cves": ["CVE-2026-109618", "CVE-2026-109619"],
         "title": "PHP: unauthenticated remote code execution", "severity": "critical",
         "score": "CVSS v4 9.2", "published": "2026-10-21", "branch": "minor",
         "fixed": {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"},
         "no_fix_below": "8.2",
         "no_fix_words": "PHP 8.1 and older have no official release with the fix; only source backports exist for 7.4, 8.0 and 8.1.",
         "affected": "Sites run by PHP-FPM, mod_php (the highest risk), php-cgi, FrankenPHP or LiteSpeed.",
         "summary": "A flaw in PHP lets anyone on the internet run code on the server, without signing in.",
         "action": "Update PHP to the fixed release of its branch, then restart PHP (the FPM pool or the web server).",
         "mitigations": [
             "Set memory_limit=-1 through php_admin_value in the pool or virtual host.",
             "Set post_max_size to 8M (32M on a site that takes uploads).",
             "Set session.upload_progress.enabled=0, then restart the PHP workers.",
             "On PHP 8.5, set fatal_error_backtraces=0.",
             "At the proxy, limit the request size, the number of form fields and the number of multipart parts."],
         "mitigations_note": "These reduce the exposure; they do not make a site safe. Update.",
         "also_known_as": "php2shell",
         "firewall_notes": [
             {"product": "cloudflare",
              "words": "Cloudflare says it deployed firewall (WAF) rules against php2shell on 21 October 2026 at 03:02 UTC, on every plan with its WAF, the Free plan included, and that customers should patch even with these protections.",
              "source": "https://blog.cloudflare.com/php-vulnerabilities-waf-protection/"}],
         "sources": ["https://www.php.net/archive/2026.php#2026-10-21-5",
                     "https://www.php.net/archive/2026.php#2026-10-20-1"]},
        {"id": "nodejs-2026-10", "product": "nodejs", "cves": ["CVE-2026-111497"],
         "title": "Node.js October 2026 security releases", "severity": "high",
         "score": "highest of ten fixes", "published": "2026-10-21", "branch": "major",
         "fixed": {"22": "22.23.4", "24": "24.22.1", "26": "26.12.1"}, "no_fix_below": "22",
         "no_fix_words": "Node.js branches that have reached end of life get no fix: move to a supported branch (22, 24 or 26).",
         "affected": "Every Node.js server on a branch below the fixed release, a Next.js site's included.",
         "summary": "The most serious flaw, a Brotli decoder out-of-bounds write (CVE-2026-111497), can let a crafted request run code on the server; others are DNS NUL truncation, TLS hostname verification and keep-alive issues.",
         "action": "Update Node.js to the fixed release of its branch, rebuild the app's image if it runs in a container, and restart it.",
         "mitigations": [], "mitigations_note": "",
         "sources": ["https://nodejs.org/en/blog/vulnerability/october-2026-security-releases"]},
    ],
}


STATES = ("update_needed", "no_fix", "check_version", "fixed", "not_listed")
FIELDS = ("id", "product", "title", "severity", "published", "branch", "fixed", "sources")


def valid(doc) -> bool:
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("advisories"), list):
        return False
    for a in doc["advisories"]:
        if not isinstance(a, dict) or any(k not in a for k in FIELDS):
            return False
        if a["branch"] not in ("major", "minor") or not isinstance(a["fixed"], dict):
            return False
        if not all(str(u).startswith("https://") for u in a["sources"]):
            return False
    return True


def version(text):
    got = re.match(r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(text or ""))
    return tuple(int(x) for x in got.groups() if x is not None) if got else None


def branch_of(ver: tuple, how: str) -> tuple:
    return ver[:2] if how == "minor" else ver[:1]


def judge(advisory: dict, ver_text) -> str:
    """One product's state against one advisory."""
    ver = version(ver_text) if ver_text else None
    how = advisory["branch"]
    if ver is None or len(ver) < len(branch_of((0, 0), how)):
        return "check_version"
    mine = branch_of(ver, how)
    fixed = {branch_of(version(b) or (), how): version(v) for b, v in advisory["fixed"].items()}
    if mine in fixed:
        got = fixed[mine]
        return "fixed" if ver + (0,) * (3 - len(ver)) >= got + (0,) * (3 - len(got)) else "update_needed"
    below = version(advisory.get("no_fix_below") or "")
    if (below is not None and mine < branch_of(below, how)) or (fixed and mine < max(fixed)):
        return "no_fix"
    return "not_listed"


def match(products: list, doc: dict) -> list:
    out = [{"advisory": a["id"], "product": p["product"], "host": p.get("host"), "version": p.get("version"),
            "state": judge(a, p.get("version"))}
           for p in products for a in doc.get("advisories") or [] if a["product"] == p.get("product")]
    out.sort(key=lambda m: (STATES.index(m["state"]), m["advisory"], m["host"] or ""))
    return out


def load_advisories(url=None, allow_private=False) -> tuple:
    """(the list in use, where it came from, a warning or None). A list from `url` is used when
    it is valid and not older than the built-in one."""
    if not url:
        return ADVISORIES, "built in", None
    budget = Budget(fetches=MAX_REDIRECTS + 1, allow_private=allow_private)
    try:
        if urlsplit(url).scheme != "https":
            raise Refused("the advisories URL must be https")
        doc = json.loads(follow(url, budget).body.decode("utf-8"))
    except (Refused, Unreachable, Spent, ValueError) as why:
        return ADVISORIES, "built in", f"advisories not loaded from {url} ({why or type(why).__name__}); using the built-in list"
    if not valid(doc):
        return ADVISORIES, "built in", f"advisories at {url} are not a valid list; using the built-in list"
    if str(doc.get("updated", "")) < str(ADVISORIES["updated"]):
        return ADVISORIES, "built in", f"advisories at {url} are older than the built-in list; using the built-in list"
    return doc, url, None


# ------------------------------------------------------------------ cards.py

GROUPS = {"update": "act", "login": "act", "hidden": "check", "unknown": "check", "tip": "tips",
          "info": "tips", "hosted": "good", "good": "good", "fixed": "good", "nothing": "good"}
ORDER = ("act", "check", "tips", "good")
KINDS = tuple(GROUPS)
COMMANDS = {"php": "php -v", "nodejs": "node -v"}
HIDE = {"nginx": "set server_tokens off; in nginx's http block, then reload nginx",
        "apache": "set ServerTokens Prod and ServerSignature Off, then reload Apache",
        "litespeed": "turn off the server signature in LiteSpeed's settings",
        "openresty": "set server_tokens off; in the http block, then reload",
        "iis": "remove the Server header with URL Rewrite or removeServerHeader",
        "caddy": "remove the Server header with header -Server"}
HEADERS = (("strict-transport-security", "Strict-Transport-Security"),
           ("content-security-policy", "Content-Security-Policy"), ("x-frame-options", "X-Frame-Options"),
           ("x-content-type-options", "X-Content-Type-Options"), ("referrer-policy", "Referrer-Policy"))
CERT_WARN_DAYS = 14


def _see(text: str, url: str, cmd: str) -> dict:
    return {"text": text, "url": url, "command": cmd}


def _and(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _card(kind, title, saw, means, advice, hosts, **more) -> dict:
    return {"kind": kind, "group": GROUPS[kind], "title": title, "saw": saw, "means": means,
            "advice": advice, "hosts": hosts, **more}


def _mine(a: dict, ver):
    v = version(ver or "")
    if not v:
        return None
    branch = branch_of(v, a["branch"])
    return next((f for b, f in a["fixed"].items() if branch_of(version(b) or (), a["branch"]) == branch), None)


def advisory_card(rt: dict, a: dict, state: str, servers: list) -> dict:
    name, ver, host = rt["name"], rt.get("version"), rt["host"]
    fixed, under = [str(v) for v in a["fixed"].values()], rt.get("under") or []
    because = f"{name} {ver or 'version not shown'} on {host}" + (f", which runs {_and(under)}" if under else "")
    facts, affected = list(under), ""
    if rt["product"] == "php" and any(s["product"] == "litespeed" for s in servers):
        affected = " LiteSpeed, which serves this site, is one of the ways of running PHP the advisory lists."
        facts.append("LiteSpeed")
    base = {"advisory": a["id"], "product": rt["product"], "version": ver, "severity": a.get("severity"),
            "cves": list(a.get("cves") or []), "fixed": fixed,
            "sources": [s for s in a.get("sources") or [] if str(s).startswith("https://")],
            "because": because, "facts": facts, "also_known_as": a.get("also_known_as")}
    if state == "update_needed":
        return _card("update", f"Update needed: {name} {ver} on {host}", rt["saw"],
                     f"This means {name} {ver} is older than {_mine(a, ver)}, the fixed release of "
                     f"its branch. {a.get('summary', '')}{affected}".strip(), a.get("action", ""), [host], **base)
    if state == "no_fix":
        return _card("update", f"Update needed: {name} {ver} on {host} gets no official fix", rt["saw"],
                     f"This means {a.get('no_fix_words', '')} {a.get('summary', '')}{affected}".strip(),
                     a.get("action", ""), [host], **base)
    if state == "check_version":
        cmd = COMMANDS.get(rt["product"], "")
        return _card("hidden", f"{name} on {host}: version not shown by the server", rt["saw"],
                     f"This means we can't tell whether the fix is in. Keeping the version hidden "
                     f"is good, but the flaw works either way. {a.get('title', '')}: fixed in "
                     f"{_and(fixed)}. {a.get('no_fix_words', '')}{affected}".strip(),
                     f"Check it on the server with {cmd}, and update if it is older.", [host], command=cmd, **base)
    mine = _mine(a, ver)
    return _card("fixed", f"{name} {ver} on {host} has the fix", rt["saw"],
                 f"This means {a.get('title', '')} does not apply: "
                 + (f"fixed in {mine} on this branch." if mine and state == "fixed"
                    else f"this branch is newer than every fixed release listed ({_and(fixed)})."),
                 "Nothing to do for this advisory.", [host], **base)


def hosted_card(f: dict, runtime=None) -> dict:
    who = f["patched"]
    if f["family"] == "hosted":
        return _card("hosted", f"Hosted by {who}: they patch PHP and Node.js for you", f["saw"],
                     f"This means {who} runs the servers, and PHP or Node.js on them, and keeps them "
                     f"updated: there is nothing for you to update for these advisories.",
                     "Nothing to do on the server side. Keep your apps and accounts on it secure.",
                     [f["host"]], product=f["product"])
    name = NAMES[runtime]
    return _card("hosted", f"{name} on {f['host']} is run for you by {who}", f["saw"],
                 f"This means {who} runs {name} for this site and patches it: there is nothing for "
                 f"you to update for the {name} advisory.", "Nothing to do for this advisory.",
                 [f["host"]], product=runtime)


def firewall_card(f: dict, doc: dict, php_here: bool) -> dict:
    notes = [n for a in doc.get("advisories") or [] for n in a.get("firewall_notes") or []
             if n.get("product") == f["product"] and php_here]
    means = (f"This means a firewall and cache ({f['name']}) answers before your server. It can "
             f"block some attacks; it does not patch your server.")
    for n in notes:
        means += " " + n["words"]
    return _card("info", f"A firewall sits in front: {f['name']}", f["saw"], means,
                 "Patch anyway: the firewall is a second line, not the fix.", [f["host"]],
                 product=f["product"], sources=[n["source"] for n in notes])


def tip_card(f: dict) -> dict:
    return _card("tip", f"Your server shows its exact version: {f['name']} {f['version']}", f["saw"],
                 f"This means anyone can read it. No advisory in our list names {f['name']}, so "
                 f"this is not a flaw found: it only tells scanners what to try.",
                 f"Hide it: {HIDE.get(f['product'], 'remove the version from the Server header')}.",
                 [f["host"]], product=f["product"])


def login_card(row: dict) -> dict:
    lg, saw = row["login"], []
    for hop in lg.get("chain") or []:
        words = f"{hop['url']} answered {hop['status']}" + (
            f", sending visitors to {hop['location']}" if hop.get("location") else "")
        saw.append(_see(f"We saw {words}", hop["url"], f"curl -sI {_q(hop['url'])}"))
    last = (lg.get("chain") or [{}])[-1].get("url") or lg["url"]
    if lg["state"] == "open":
        saw.append(_see(f"We saw a WordPress login form on {last}", last,
                        f"curl -sL {_q(lg['url'])} | grep -c 'id=\"loginform\"'"))
        return _card("login", "Login page open to the internet", saw,
                     "This means anyone can try passwords there, all day.",
                     "Allow only your own addresses there, or add a second factor, and use long, "
                     "unique passwords.", [row["host"]])
    if lg["state"] == "hidden":
        if not saw:
            saw.append(_see(f"We saw {lg['url']}: {lg['why']}", lg["url"], f"curl -sI {_q(lg['url'])}"))
        elif not lg["why"].startswith("it "):
            saw.append(_see(f"We saw {last} answer with {lg['why']}", last,
                            f"curl -sL {_q(lg['url'])} | grep -c -E 'loginform|name=.pwd.'"))
        return _card("good", f"Login page on {row['host']} hidden or blocked (good)", saw,
                     "This means /wp-login.php does not show a login form to strangers.", "Nothing to do.",
                     [row["host"]])
    saw.append(_see(f"We could not read {lg['url']}: {lg['why']}", lg["url"], f"curl -sIL {_q(lg['url'])}"))
    return _card("unknown", f"Login page on {row['host']}: could not check", saw,
                 "This means we say nothing about it: we could not see it.",
                 f"Open {lg['url']} yourself: a login form there is open to anyone.", [row["host"]])


def extras_cards(row: dict) -> list:
    out, ex = [], row.get("extras") or {}
    x = ex.get("xmlrpc")
    if x and x["on"]:
        out.append(_card("tip", "XML-RPC is on", [
            _see(f"We saw {x['url']} answer {x['status']}: \"XML-RPC server accepts POST requests only.\"",
                 x["url"], f"curl -s {_q(x['url'])}")],
            "This means WordPress's old remote API answers. It is often used to try many passwords "
            "in one request.", "Turn it off if nothing you use needs it (a security plugin, or "
            "deny /xmlrpc.php in the web server).", [row["host"]]))
    r = ex.get("readme")
    if r and r.get("version"):
        out.append(_card("tip", f"readme.html shows WordPress {r['version']}", [
            _see(f"We saw {r['url']} answer {r['status']}, showing Version {r['version']}", r["url"],
                 f"curl -s {_q(r['url'])} | grep -i -o 'version [0-9.]*'")],
            "This means anyone can read your WordPress version there.",
            "Delete readme.html (WordPress puts it back on updates; a rule in the web server "
            "keeps it hidden).", [row["host"]], facts=[f"WordPress {r['version']}"]))
    return out


def headers_card(row: dict) -> dict:
    got, url = row.get("headers") or {}, row.get("url") or f"https://{row['host']}/"
    cmd = f"curl -sI {_q(url)} | grep -i -E '^({'|'.join(h for h, _ in HEADERS)}):'"
    have = {h: ", ".join(got.get(h) or []) for h, _ in HEADERS if got.get(h)}
    if "x-frame-options" not in have and "frame-ancestors" in have.get("content-security-policy", "").lower():
        have["x-frame-options"] = "(frame-ancestors in the Content-Security-Policy)"
    saw = [_see(f"We saw the header {pretty}: {have[h][:160]}", url, cmd)
           for h, pretty in HEADERS if h in have and not have[h].startswith("(")]
    missing = [pretty for h, pretty in HEADERS if h not in have]
    if missing:
        saw.append(_see(f"We saw no {_and(missing)} header in the home page's answer", url, cmd))
        return _card("tip", f"Security headers: {len(HEADERS) - len(missing)} of {len(HEADERS)}", saw,
                     "This means browsers get fewer instructions to block some attacks (framing, "
                     "content sniffing, mixed content). They do not fix PHP or Node.js; they are "
                     "worth adding.", f"Add {_and(missing)} in the web server or the app.", [row["host"]])
    return _card("good", "Security headers: all 5 set", saw,
                 "This means browsers get clear instructions to block framing, content sniffing "
                 "and mixed content.", "Nothing to do.", [row["host"]])


def cert_days(row: dict, now: datetime):
    try:
        return int((ssl.cert_time_to_seconds(row["not_after"]) - now.timestamp()) // 86400) \
            if row.get("not_after") else None
    except ValueError:
        return None


def headless_card(origin_row: dict, site_found: list, site_host: str) -> dict:
    """A WordPress on another host of the domain that the site's page loads files from."""
    front = [f for f in site_found if f["family"] == "js"][:1]
    saw = (front[0]["saw"][:1] if front else []) + origin_row["found"][0]["saw"]
    oh = origin_row["host"]
    if origin_row.get("headless"):
        h = origin_row["headless"]
        saw.append(_see(f"We saw {h['url']} answer {h['status']}, sending visitors to {h['location']}",
                        h["url"], f"curl -sI {_q(h['url'])}"))
    if front:
        return _card("info", f"Headless WordPress at {oh}", saw,
                     f"This means {site_host} ({front[0]['name']}) takes its content from a WordPress "
                     f"at {oh}. That server runs PHP, so it needs the PHP update too.",
                     f"Check PHP on the server behind {oh}.", [oh, site_host])
    return _card("info", f"WordPress at {oh}", saw,
                 f"This means {site_host} loads files from a WordPress at {oh}. That "
                 f"server runs PHP, so it needs the PHP update too.", f"Check PHP on the server behind {oh}.",
                 [oh, site_host])


def _runtime(rt: dict) -> str:
    return rt["name"] + (f" {rt['version']}" if rt.get("version") else
                         f" (run by {rt['patched']})" if rt.get("patched") else " (version hidden)")


def stack_words(here: list, rts: list) -> str:
    """What runs the site, in the order people say it: the platform or the language first,
    then the web server, then where it is hosted, then the CDN or firewall in front:
    "Your site runs PHP (version hidden) on nginx, behind CloudFront"."""
    app = next((f for fam in ("hosted", "cms", "js", "framework") for f in here if f["family"] == fam), None)
    server = next((f for f in here if f["family"] == "server"), None)
    hosting = next((f for f in here if f["family"] == "hosting"), None)
    # The language under the platform (WordPress on PHP); with no platform, the first one seen.
    rt = next((r for r in rts if app and any(u.startswith(app["name"]) for u in r.get("under") or [])),
              None if app else (rts[0] if rts else None))
    hosted = bool(app and app["family"] == "hosted")
    if app:
        words = f"Your site runs {app['name']}" + (f" {app['version']}" if app.get("version") else "")
        if rt and not hosted:
            words += f" on {_runtime(rt)}"
        if server and not hosted:
            words += f", served by {server['name']}"
    elif rt:
        words = f"Your site runs {_runtime(rt)}" + (f" on {server['name']}" if server else "")
    elif server:
        words = f"Your site is served by {server['name']}"
    elif hosting:
        words, hosting = f"Your site is hosted on {hosting['name']}", None
    else:
        words = "We can't see what runs your site"
    if hosting and not hosted and not (rt and rt.get("patched") == hosting.get("patched")):
        words += f", hosted on {hosting['name']}"
    cdns = list(dict.fromkeys(f["name"] for f in here if f["product"] in FIREWALLS))
    if cdns:
        words += ("; it sits behind " if words.startswith("We can't") else ", behind ") + _and(cdns)
    return words


def merge(cards: list) -> list:
    """Cards of the same kind and title (the same finding, seen on several hosts) as one card:
    its hosts in order, every host's evidence ("saw") kept, and the hosts named in "means".
    The order of first appearance is kept, so the counts and the summary count each once."""
    out, seen = [], {}
    for c in cards:
        key = (c["kind"], c["title"])
        first = seen.get(key)
        if first is None:
            seen[key] = c
            out.append(c)
            continue
        if first is c:
            continue
        if not first.get("merged"):
            first.update(saw=list(first.get("saw") or []), hosts=list(first.get("hosts") or []),
                         merged=True, means_one=first.get("means", ""))
        for s in c.get("saw") or []:
            if not any(s.get("text") == x.get("text") and s.get("url") == x.get("url") for x in first["saw"]):
                first["saw"].append(s)
        for h in c.get("hosts") or []:
            if h not in first["hosts"]:
                first["hosts"].append(h)
        for f in c.get("facts") or []:
            first.setdefault("facts", [])
            if f not in first["facts"]:
                first["facts"].append(f)
    for c in out:
        if c.pop("merged", False):
            one = c.pop("means_one")
            if len(c["hosts"]) > 1:
                c["means"] = f"{one} Seen on {len(c['hosts'])} hosts: {_and(c['hosts'])}.".strip()
    return out


def summary(site: dict, found: list, rts: list, cards: list) -> str:
    here = [f for f in found if f["host"] == site["host"]]
    words = stack_words(here, [r for r in rts if r["host"] == site["host"]])
    n = {g: sum(1 for c in cards if c["group"] == g) for g in ORDER}
    todo = f"{n['act']} thing{'s' if n['act'] != 1 else ''} to do now" if n["act"] else "Nothing to do now"
    rest = [f"{n['check']} to check" if n["check"] else "",
            f"{n['tips']} tip{'s' if n['tips'] != 1 else ''}" if n["tips"] else ""]
    return f"{words}. {todo}" + "".join(f", {r}" for r in rest if r) + "."


def answer(host: str, blob: dict, doc: dict, now: datetime, ua: str) -> dict:
    """The answer: the same structure as the web check's API."""
    rows = blob.get("hosts") or []
    site = next((r for r in rows if r["role"] == "site"), {"host": host})
    reached = bool(site.get("read"))
    found = [f for r in rows for f in r.get("found") or []]
    rts = [r for r in runtimes(found) if r["product"] in ("php", "nodejs")]
    cards, by_id = [], {a["id"]: a for a in doc.get("advisories") or []}
    for rt in rts:
        servers = [f for f in found if f["host"] == rt["host"] and f["family"] == "server"]
        if rt.get("patched"):
            maker = next((f for f in found if f["host"] == rt["host"] and f.get("patched") == rt["patched"]
                          and f["family"] in ("hosted", "hosting")), None)
            if maker and maker["family"] == "hosting":
                cards.append(hosted_card({**maker, "saw": maker["saw"] + rt["saw"]}, rt["product"]))
            continue
        for m in match([{"product": rt["product"], "version": rt.get("version"), "host": rt["host"]}], doc):
            cards.append(advisory_card(rt, by_id[m["advisory"]], m["state"], servers))
    php_hosts = {r["host"] for r in rts if r["product"] == "php" and not r.get("patched")}
    for f in found:
        if f["family"] == "hosted":
            cards.append(hosted_card(f))
        elif f["product"] in FIREWALLS and f["host"] == site.get("host"):
            cards.append(firewall_card(f, doc, f["host"] in php_hosts))
        elif f["family"] == "server" and f.get("version"):
            cards.append(tip_card(f))
    for row in rows:
        if row.get("login"):
            cards.append(login_card(row))
        cards += extras_cards(row)
    origin_row = next((r for r in rows if r["role"] == "content origin"), None)
    facts = []
    if reached:
        if origin_row:
            cards.append(headless_card(origin_row, [f for f in found if f["host"] == site["host"]], site["host"]))
        cards.append(headers_card(site))
        days = cert_days(site, now)
        if days is not None:
            facts.append(f"Certificate valid for {days} more day{'s' if days != 1 else ''}")
            if days < CERT_WARN_DAYS:
                url = site.get("url") or f"https://{site['host']}/"
                cards.append(_card("tip", f"Your certificate expires in {days} day{'s' if days != 1 else ''}", [
                    _see(f"We saw the certificate for {site['host']} valid until {site['not_after']}", url,
                         f"echo | openssl s_client -connect {_q(site['host'] + ':443')} -servername "
                         f"{_q(site['host'])} 2>/dev/null | openssl x509 -noout -enddate")],
                    "This means browsers will warn visitors after that date.",
                    "Renew it, or check that automatic renewal works.", [site["host"]]))
        if blob.get("moved"):
            facts.append(f"Goes to {blob['moved']}")
    if not reached:
        f = (blob.get("fetched") or [{}])[-1]
        url = f.get("url") or f"https://{host}/"
        saw = [_see(f"We could not read {url}: {site.get('error') or 'no answer'}", url, f"curl -sIL {_q(url)}")]
        block = blob.get("block") if blob.get("reason") == "blocked" else None
        if block:
            cards.append(blocked_card(host, block))
            facts += [f"Answered {block['status']}"] + (
                [f"Firewall: {_and(block['firewalls'])}"] if block["firewalls"] else [])
        else:
            cards.append(_card("unknown", f"Could not check {host}", saw,
                               "This means we say nothing about this site: we could not read it.",
                               "Check the address, or try again later.", [host]))
    elif not any(c["kind"] in ("update", "hidden", "login", "hosted") for c in cards):
        home = next((f for f in blob.get("fetched") or [] if f.get("url") == site.get("url")), {})
        named = [f["name"] for f in found if f["host"] == site["host"]]
        saw = [_see(f"We saw {site.get('url')} answer {home.get('status', 200)}"
                    + (f" ({home['bytes']:,} bytes)" if home.get("bytes") is not None else "")
                    + (f", showing {_and(named)}" if named else ", naming no server, language or framework"),
                    site.get("url"), f"curl -sI {_q(site.get('url') or '')}")]
        cards.append(_card("nothing", "Nothing we know of applies", saw,
                           f"This means none of the advisories in our list (updated {doc.get('updated')}) "
                           f"names what your site shows.", "This is only what anyone can see from outside: "
                           "keep the server and everything on it updated anyway.", [site["host"]]))
    cards.sort(key=lambda c: (ORDER.index(c["group"]), KINDS.index(c["kind"])))
    cards = merge(cards)
    products = [{"product": f["product"], "name": f["name"], "version": f.get("version"),
                 "shown": f.get("version") or (f"run by {f['patched']}" if f["family"] == "runtime"
                                               and f.get("patched") else "version not shown"
                                               if f["family"] in ("runtime", "cms", "server") else ""),
                 "family": f["family"], "host": f["host"], "patched": f.get("patched")}
                for f in [*[x for x in found if x["product"] not in ("php", "nodejs")], *rts]]
    block = None if reached else blob.get("block")
    if block:
        block = {**block, "summary": BLOCKED_SUMMARY[blocked_words(block)], "next": BLOCKED_NEXT[blocked_words(block)]}
    return {"host": host, "reached": reached, "error": None if reached else site.get("error"),
            "reason": None if reached else blob.get("reason") or "unreachable",
            "summary": summary(site, found, rts, cards) if reached else block["summary"] if block else None,
            # a site we could not read counts nothing: "could not check" is not a problem found
            "counts": {g: sum(1 for c in cards if c["group"] == g) if reached else 0 for g in ORDER},
            "checked_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "agent": ua, "fetched": blob.get("fetched") or [], "facts": facts,
            "hosts": [{"host": r["host"], "role": r["role"], "reached": bool(r.get("read") or r.get("found")),
                       "error": r.get("error")} for r in rows],
            "products": products, "cards": cards, "advisories_updated": doc.get("updated"),
            "fetches": blob.get("fetches", 0), "block": block}


# ------------------------------------------------------------------ cli.py

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
    elif ans.get("block"):
        b = ans["block"]
        out.append(p("1;33", wrap(b["summary"], "")))
        out += ["", wrap(b["next"], "")] + [p("2", "  $ ") + cmd for cmd in b["commands"]]
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
        cmds = list(dict.fromkeys([s["command"] for s in c["saw"]] + list(c.get("commands") or [])))
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
    head = ans["summary"] if ans["reached"] or ans.get("block") else \
        f"Could not check {ans['host']}: {ans.get('error')}."
    out = [f"## php2shell-check: {_md(ans['host'])}", "", f"**{_md(head)}**", ""]
    if ans.get("block"):
        out += [_md(ans["block"]["next"]), "", "```sh", *ans["block"]["commands"], "```", ""]
    if ans["cards"]:
        out += ["| Status | Finding | We saw |", "| --- | --- | --- |"]
        out += [f"| {LABELS[c['kind']]} | {_md(c['title'])} | {_md(c['saw'][0]['text'][:160]) if c['saw'] else ''} |"
                for c in ans["cards"]]
    for c in ans["cards"]:
        out += ["", f"<details><summary><b>{LABELS[c['kind']]}</b>: {_md(c['title'])}</summary>", ""]
        out += [f"- {_md(s['text'])} ({_md(s['url'])})" for s in c["saw"]]
        out += ["", _md(c["means"]), "", f"What to do: {_md(c['advice'])}", ""]
        out += [f"Source: {s}" for s in c.get("sources") or []]
        out += ["", "```sh"] + list(dict.fromkeys([s["command"] for s in c["saw"]] + list(c.get("commands") or []))) \
            + ["```", "", "</details>"]
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


if __name__ == "__main__":
    sys.exit(main())
