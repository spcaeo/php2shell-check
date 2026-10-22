"""What may be fetched: the address and name rules (SSRF guard), the limits, the errors."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

__version__ = "1.1.0"
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
