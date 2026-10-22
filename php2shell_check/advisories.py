"""The advisories (built in; --advisories-url loads a newer list) and how a version meets them."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from .fetch import Budget, follow
from .safety import MAX_REDIRECTS, Refused, Spent, Unreachable

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
