"""The answer: cards and their proof for the main kinds of site, and one check over the wire
against a web server on this machine standing for a public site."""
from __future__ import annotations

import http.server
import shlex
import threading
import time
import unittest

import php2shell_check as p2s
from tests.helpers import NOW, PUBLIC, PUBLIC2, TESTNET, Net, doc_refused, evidenced, patches, run

LOGIN_FORM = (b'<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
              b'<input name="log"><input name="pwd" type="password"></form>')
HEADLESS = ("<html><head><script src=\"/_next/static/chunks/main.js\"></script></head><body>"
            + "".join(f'<img src="https://wp.example.com/wp-content/uploads/2026/{i % 12 + 1:02d}/p{i}.webp">'
                      for i in range(289))
            + '<script id="__NEXT_DATA__" type="application/json">{}</script></body></html>').encode()
WP_JSON = {"Server": "nginx", "Link": '<https://wp.example.com/wp-json/>; rel="https://api.w.org/"'}
WP_HOME = (b'<html><head><meta name="generator" content="WordPress 6.4.2"></head>'
           b'<body><img src="/wp-content/uploads/a.png"></body></html>')


class Answers(unittest.TestCase):
    def headless(self, **pages):
        base = {"https://www.example.com/": (200, {"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "Next.js"},
                                             HEADLESS),
                "https://wp.example.com/wp-login.php": (302, {"Location": "https://wp.example.com/not_found"}, b""),
                "https://wp.example.com/not_found": (404, {}, b"<html>Not found</html>"),
                ("HEAD", "https://wp.example.com/wp-json/"): (200, WP_JSON, b"")}
        names = {"www.example.com": [PUBLIC], "wp.example.com": [PUBLIC2]}
        return run("www.example.com", Net(names=names, pages={**base, **pages}))

    def test_a_headless_wordpress_behind_a_next_site(self):
        got = self.headless()
        evidenced(self, got)
        self.assertEqual([c["kind"] for c in got["cards"]], ["hidden", "hidden", "tip", "tip", "info", "good"])
        php = next(c for c in got["cards"] if c.get("product") == "php")
        self.assertEqual(php["title"], "PHP on wp.example.com: version not shown by the server")
        self.assertEqual(php["because"], "PHP version not shown on wp.example.com, which runs WordPress")
        self.assertEqual(php["saw"][0]["text"], "We saw wp.example.com runs WordPress (its files), "
                                                "and WordPress runs on PHP")
        self.assertEqual(php["command"], "php -v")
        saw = " | ".join(s["text"] for s in php["saw"])
        self.assertIn("load 289 different files under /wp-content/ or /wp-includes/ from wp.example.com", saw)
        self.assertIn('Link: <https://wp.example.com/wp-json/>; rel="https://api.w.org/"', saw)
        self.assertTrue(php["sources"][0].startswith("https://www.php.net/"))
        self.assertEqual(php["cves"], ["CVE-2026-109618", "CVE-2026-109619"])
        node = next(c for c in got["cards"] if c.get("product") == "nodejs")
        self.assertIn("We saw the header X-Powered-By: Next.js", [s["text"] for s in node["saw"]])
        self.assertIn("26.12.1", node["means"])
        tip = next(c for c in got["cards"] if c["kind"] == "tip")
        self.assertEqual(tip["title"], "Your server shows its exact version: nginx 1.18.0")
        self.assertEqual([(f["method"], f["url"], f["status"]) for f in got["fetched"]],
                         [("GET", "https://www.example.com/", 200),
                          ("GET", "https://wp.example.com/wp-login.php", 302),
                          ("GET", "https://wp.example.com/not_found", 404),
                          ("HEAD", "https://wp.example.com/wp-json/", 200),
                          ("HEAD", "https://wp.example.com/", 404)])
        self.assertEqual(got["fetched"][0]["bytes"], len(HEADLESS))

    def test_the_login_page_open_only_with_a_form(self):
        got = self.headless(**{"https://wp.example.com/wp-login.php": (200, {}, LOGIN_FORM)})
        login = next(c for c in got["cards"] if c["kind"] == "login")
        self.assertEqual(login["title"], "Login page open to the internet")
        for page, kind in (((200, {}, b"<html><div id='__next'></div></html>"), "good"),
                           ((403, {}, b"no"), "good"),
                           ((503, {"cf-mitigated": "challenge"}, b"Just a moment..."), "unknown"),
                           ((500, {}, b"oops"), "unknown")):
            with self.subTest(page[0]):
                got = self.headless(**{"https://wp.example.com/wp-login.php": page})
                evidenced(self, got)
                kinds = [c["kind"] for c in got["cards"]]
                self.assertIn(kind, kinds)
                self.assertNotIn("login", kinds)

    def test_a_challenge_or_a_blocked_home_page_is_could_not_check(self):
        challenge = b"<html><title>Just a moment...</title><script src='/cdn-cgi/challenge-platform/h/b'></script></html>"
        for page in ((403, {"Server": "cloudflare", "cf-mitigated": "challenge"}, challenge),
                     (503, {"Server": "cloudflare"}, challenge),
                     (403, {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"}, WP_HOME)):
            with self.subTest(page[0]):
                got = run("www.example.com", Net(names={"www.example.com": [PUBLIC]},
                                                 pages={"https://www.example.com/": page}))
                evidenced(self, got)
                self.assertEqual((got["reached"], got["reason"]), (False, "blocked"))
                self.assertEqual([c["kind"] for c in got["cards"]], ["unknown"])
                self.assertEqual(got["products"], [], "nothing read from a page we could not check")

    def test_versions_shown_old_no_fix_and_fixed(self):
        def php(ver):
            return run("www.example.com", Net(names={"www.example.com": [PUBLIC]}, pages={
                "https://www.example.com/": (200, {"X-Powered-By": f"PHP/{ver}"}, b"<p>hi</p>")}))
        got = php("8.3.10")
        evidenced(self, got)
        card = got["cards"][0]
        self.assertEqual((card["kind"], card["title"]), ("update", "Update needed: PHP 8.3.10 on www.example.com"))
        self.assertIn("older than 8.3.36", card["means"])
        self.assertEqual(php("8.1.2")["cards"][0]["title"], "Update needed: PHP 8.1.2 on www.example.com gets no official fix")
        got = php("8.4.27")
        self.assertEqual([c["kind"] for c in got["cards"]], ["tip", "fixed", "nothing"])

    def test_an_unreachable_site_and_the_timeout_in_its_words(self):
        got = run("gone.example.com", Net(names={}))
        evidenced(self, got)
        self.assertEqual((got["reached"], got["error"], got["reason"]), (False, "the name doesn't exist", "unreachable"))
        self.assertEqual(p2s.plain("it did not answer in time", 7.5), "no answer in 7.5 seconds")

    def test_commands_quote_what_a_server_sent(self):
        odd = "https://www.example.com/a;echo$(id)'x"
        got = run("www.example.com", Net(names={"www.example.com": [PUBLIC]}, pages={
            "https://www.example.com/": (302, {"Location": "/a;echo$(id)'x"}, b""),
            odd: (200, {"X-Powered-By": "PHP/8.3.10"}, b"x")}))
        self.assertEqual(got["cards"][0]["saw"][0]["url"], odd)
        self.assertIn(shlex.quote(odd), got["cards"][0]["saw"][0]["command"], "the URL is one quoted word")

    def test_the_advisory_rules(self):
        php = p2s.ADVISORIES["advisories"][0]
        for ver, state in (("8.5.11", "update_needed"), ("8.5.12", "fixed"), ("8.2.35", "fixed"),
                           ("8.1.30", "no_fix"), ("7.4.33", "no_fix"), ("8.6.0", "not_listed"),
                           ("8", "check_version"), (None, "check_version")):
            with self.subTest(ver):
                self.assertEqual(p2s.judge(php, ver), state)
        node = p2s.ADVISORIES["advisories"][1]
        for ver, state in (("22.23.3", "update_needed"), ("24.22.1", "fixed"), ("20.19.0", "no_fix"),
                           ("23.1.0", "no_fix"), ("27.0.0", "not_listed")):
            with self.subTest(ver):
                self.assertEqual(p2s.judge(node, ver), state)


class FakeSite:
    """A web server on this machine standing for a public site: the stub sends every
    connection to it (the rules themselves see only documentation addresses)."""

    def __init__(self, headers=None, body=b"", sleep=0.0, login_body=b""):
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self, with_body):
                seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
                if sleep:
                    time.sleep(sleep)
                raw = login_body if self.path == "/wp-login.php" else body
                self.send_response(200)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if with_body:
                    try:
                        self.wfile.write(raw)
                    except OSError:
                        pass

            def do_GET(self):
                self._answer(True)

            def do_HEAD(self):
                self._answer(False)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.real = p2s.open_pinned

    def open(self, scheme, host, address, port, method, target, timeout, max_bytes, agent=p2s.USER_AGENT):
        assert address in TESTNET, address
        return self.real("http", host, "127.0.0.1", self.port, method, target, timeout, max_bytes, agent=agent)

    def __enter__(self):
        self._p = patches(p2s, lookup=lambda h, p: [PUBLIC], open_pinned=self.open,
                          address_refused=doc_refused)
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in self._p:
            p.stop()
        self.server.shutdown()
        self.server.server_close()


class OverTheWire(unittest.TestCase):
    def test_happy_path_against_a_local_server(self):
        body = WP_HOME.replace(b"/wp-content", b"https://www.example.com/wp-content")
        with FakeSite({"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.4.10"}, body, login_body=LOGIN_FORM) as site:
            got = p2s.check("https://www.example.com/", None, NOW)
        self.assertTrue(got["reached"])
        evidenced(self, got)
        self.assertEqual(got["cards"][0]["title"], "Update needed: PHP 8.4.10 on www.example.com")
        self.assertIn("login", [c["kind"] for c in got["cards"]])
        self.assertEqual([(m, p) for m, p, _ in site.seen],
                         [("GET", "/"), ("GET", "/wp-login.php"), ("GET", "/xmlrpc.php"), ("GET", "/readme.html")])
        for _m, _p, headers in site.seen:
            self.assertEqual(headers["user-agent"], p2s.USER_AGENT)
            self.assertNotIn("cookie", headers)
            self.assertNotIn("authorization", headers)
            self.assertTrue(headers["host"].startswith("www.example.com"))

    def test_the_size_cap(self):
        with FakeSite({}, b"<html>" + b"x" * (2 * p2s.MAX_BYTES)):
            got = p2s.get("https://www.example.com/", "GET", p2s.Budget())
        self.assertEqual(len(got.body), p2s.MAX_BYTES)

    def test_the_time_cap(self):
        with FakeSite({}, b"<html></html>", sleep=2.0):
            started = time.monotonic()
            got = p2s.check("www.example.com", None, NOW, timeout=0.5)
        self.assertLess(time.monotonic() - started, 1.8)
        self.assertFalse(got["reached"])
        self.assertEqual((got["error"], got["reason"]), ("no answer in 0.5 seconds", "unreachable"))


if __name__ == "__main__":
    unittest.main()
