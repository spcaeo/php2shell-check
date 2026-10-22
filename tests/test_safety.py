"""Safety: every way to point the check inside a network is refused (literal addresses in
every form, names that resolve inside, a name that changes its answer between the check and
the connection, a redirect inside, odd ports), and the limits hold (requests, methods, time,
size). --allow-private lifts the private-address rules only.
"""
from __future__ import annotations

import unittest

import php2shell_check as p2s
from tests.helpers import PUBLIC, PUBLIC2, Net, evidenced, run

WP_HOME = (b'<html><head><meta name="generator" content="WordPress 6.4.2"></head>'
           b'<body><img src="https://wp.example.com/wp-content/uploads/a.png">'
           b'<img src="https://cdn.example.net/wp-content/uploads/b.png"></body></html>')
INSIDE = {"a.example.com": ["10.0.0.5"], "b.example.com": ["127.0.0.1"],
          "c.example.com": ["169.254.169.254"], "d.example.com": ["fd00:ec2::254"],
          "e.example.com": ["::ffff:127.0.0.1"], "f.example.com": ["::ffff:10.0.0.1"],
          "g.example.com": ["100.64.1.1"], "h.example.com": ["fe80::1"],
          "i.example.com": ["224.0.0.1"], "j.example.com": ["0.0.0.0"],
          "k.example.com": ["::1"], "l.example.com": ["240.0.0.1"],
          "m.example.com": ["2002:7f00:1::"], "n.example.com": ["64:ff9b::a00:1"],
          "o.example.com": [PUBLIC, "192.168.1.1"]}       # one inside is enough


class Addresses(unittest.TestCase):
    def test_typed_addresses_that_are_refused_before_any_lookup(self):
        cases = [
            "", "   ", "a b.com", "x" * 600 + ".com",
            "http://127.0.0.1/", "127.0.0.1", "http://[::1]/", "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:a00:1]/", "http://[fd00:ec2::254]/", "http://169.254.169.254/",
            "http://2130706433/", "http://017700000001/", "http://0x7f000001/", "http://0x7f.1/",
            "http://127.1/", "http://10.1/", "203.0.113.9",
            "localhost", "http://localhost:8080/", "http://foo.localhost/", "printer.local",
            "db.internal", "nas.home.arpa", "router.lan", "site.test", "x.invalid", "corp",
            "ftp://example.com/", "file:///etc/passwd", "javascript:alert(1)", "gopher://example.com/",
            "https://user:pw@example.com/", "https://example.com@10.0.0.1/",
            "https://example.com:8443/", "http://example.com:22/", "http://example.com:0/",
        ]
        net = Net()
        for raw in cases:
            with self.subTest(raw), net:
                with self.assertRaises(p2s.Refused):
                    p2s.check(raw)
        self.assertEqual(net.looked, [], "nothing typed above is even looked up")
        self.assertEqual(net.opened, [])

    def test_the_typed_forms_that_are_accepted(self):
        for raw, want in (("example.com", ("https", "example.com")),
                          ("https://www.example.com/some/page?q=1", ("https", "www.example.com")),
                          ("http://example.com", ("http", "example.com")),
                          ("Example.COM.", ("https", "example.com")),
                          ("example.com:443", ("https", "example.com"))):
            with self.subTest(raw):
                self.assertEqual(p2s.target(raw), want)

    def test_names_that_resolve_inside_are_refused_whole(self):
        for host in INSIDE:
            net = Net(names=dict(INSIDE))
            with self.subTest(host):
                with self.assertRaises(p2s.Refused):
                    run(host, net)
                self.assertEqual(net.opened, [], "never connected")

    def test_allow_private_lifts_only_the_private_rules(self):
        """--allow-private: a site of your own network; metadata, multicast and 0.0.0.0 stay out."""
        still = {"c.example.com", "d.example.com", "i.example.com", "j.example.com"}
        for host in INSIDE:
            net = Net(names=dict(INSIDE), pages={f"https://{host}/": (200, {"Server": "nginx"}, b"<p>hi</p>")})
            with self.subTest(host):
                if host in still:
                    with self.assertRaises(p2s.Refused):
                        run(host, net, allow_private=True)
                    self.assertEqual(net.opened, [])
                else:
                    self.assertTrue(run(host, net, allow_private=True)["reached"])
        self.assertEqual(p2s.target("intranet.corp", allow_private=True), ("https", "intranet.corp"))
        with self.assertRaises(p2s.Refused):
            p2s.target("http://example.com:8080/", allow_private=True)

    def test_a_name_that_changes_its_answer_cannot_rebind(self):
        """Resolved once per request; the connection goes to the address that passed."""
        net = Net(names={"www.example.com": [[PUBLIC], ["127.0.0.1"]]},
                  pages={"https://www.example.com/": (200, {"Server": "nginx"}, b"<html></html>")})
        got = run("www.example.com", net)
        self.assertTrue(got["reached"])
        self.assertEqual(net.looked, ["www.example.com"])
        self.assertEqual([o["address"] for o in net.opened], [PUBLIC])
        net = Net(names={"www.example.com": [["10.0.0.1"], [PUBLIC]]})
        with self.assertRaises(p2s.Refused):
            run("www.example.com", net)
        self.assertEqual(net.opened, [])

    def test_a_rebinding_redirect_is_checked_again(self):
        net = Net(names={"www.example.com": [[PUBLIC], ["127.0.0.1"]]},
                  pages={"https://www.example.com/": (302, {"Location": "/home"}, b"")})
        with self.assertRaises(p2s.Refused):
            run("www.example.com", net)
        self.assertEqual([o["address"] for o in net.opened], [PUBLIC])

    def test_redirects_inside_or_to_odd_places_are_refused(self):
        for loc in ("http://127.0.0.1/", "http://[::ffff:127.0.0.1]/", "http://2130706433/",
                    "http://0x7f.1/", "http://inside.example.com/", "https://www.example.com:8443/",
                    "http://localhost/", "file:///etc/passwd", "http://user:pw@www.example.com/",
                    "http://169.254.169.254/latest/meta-data/"):
            net = Net(names={"www.example.com": [PUBLIC], "inside.example.com": ["10.0.0.9"]},
                      pages={"https://www.example.com/": (301, {"Location": loc}, b"")})
            with self.subTest(loc):
                with self.assertRaises(p2s.Refused):
                    run("www.example.com", net)
                self.assertEqual([o["address"] for o in net.opened], [PUBLIC])

    def test_at_most_three_redirects(self):
        pages = {f"https://www.example.com/{i}": (302, {"Location": f"/{i + 1}"}, b"") for i in range(9)}
        pages["https://www.example.com/"] = (302, {"Location": "/0"}, b"")
        net = Net(names={"www.example.com": [PUBLIC]}, pages=pages)
        with self.assertRaises(p2s.Refused) as got:
            run("www.example.com", net)
        self.assertIn("more than 3", str(got.exception))
        self.assertEqual(len(net.opened), 4)


class Limits(unittest.TestCase):
    def net(self):
        hops = {f"https://www.example.com/h{i}": (302, {"Location": f"/h{i + 1}"}, b"") for i in range(9)}
        return Net(names={"www.example.com": [PUBLIC], "example.com": [PUBLIC],
                          "wp.example.com": [PUBLIC2], "cdn.example.net": [PUBLIC2]},
                   pages={"https://example.com/": (301, {"Location": "https://www.example.com/"}, b""),
                          "https://www.example.com/": (200, {"X-Powered-By": "PHP/8.3.10"}, WP_HOME),
                          "https://www.example.com/wp-login.php": (302, {"Location": "/h0"}, b""), **hops})

    def test_at_most_max_requests_get_and_head_only_with_the_agent(self):
        net = self.net()
        got = run("example.com", net)
        self.assertEqual(len(net.opened), p2s.MAX_FETCHES)
        self.assertEqual(got["fetches"], p2s.MAX_FETCHES)
        self.assertEqual({o["method"] for o in net.opened}, {"GET"})
        self.assertEqual({o["agent"] for o in net.opened}, {p2s.USER_AGENT})
        self.assertTrue(all(o["max_bytes"] == p2s.MAX_BYTES and o["timeout"] <= p2s.TIMEOUT for o in net.opened))
        self.assertNotIn("cdn.example.net", net.looked, "another domain's server is never asked")
        self.assertEqual([h["host"] for h in got["hosts"] if h["role"] == "content origin"], ["wp.example.com"])
        skipped = [f["url"] for f in got["fetched"] if (f["error"] or "").startswith("not fetched")]
        self.assertEqual(skipped[:2], ["https://www.example.com/xmlrpc.php", "https://www.example.com/readme.html"])
        self.assertIn("https://wp.example.com/wp-login.php", skipped)
        login = next(c for c in got["cards"] if "Login page" in c["title"])
        self.assertEqual(login["kind"], "unknown", "a chain past the request limit is not a finding")
        self.assertEqual([f["status"] for f in got["fetched"][:3]], [301, 200, 302])
        evidenced(self, got)

    def test_max_requests_and_user_agent_options(self):
        net = self.net()
        got = run("example.com", net, max_requests=3, ua="MyCheck/1")
        self.assertEqual((len(net.opened), got["fetches"], got["agent"]), (3, 3, "MyCheck/1"))
        self.assertEqual({o["agent"] for o in net.opened}, {"MyCheck/1"})

    def test_the_whole_check_has_a_deadline(self):
        clock = [0.0]
        budget = p2s.Budget(fetches=8, timeout=10, seconds=30, clock=lambda: clock[0])
        budget.take()
        self.assertEqual(budget.seconds(), 10)
        clock[0] = 25.0
        self.assertEqual(budget.seconds(), 5)
        clock[0] = 30.0
        with self.assertRaises(p2s.Unreachable):
            budget.take()

    def test_secret_files_and_users_are_never_asked_for(self):
        net = self.net()
        run("example.com", net)
        paths = " ".join(o["url"] for o in net.opened)
        for word in (".env", ".git", "wp-config", "author=", "/users", "phpinfo", "backup"):
            self.assertNotIn(word, paths)


if __name__ == "__main__":
    unittest.main()
