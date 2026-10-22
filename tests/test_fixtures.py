"""The check on a corpus of sites (tests/fixtures/sites/<case>/case.json).

Each case is one kind of site or combination (WordPress behind Cloudflare, a headless
WordPress behind Next.js on Vercel, Shopify with a WordPress blog, a Cloudflare challenge
...): the answers its pages gave, as headers and trimmed HTML with example.com names, and
the cards the check must give, exactly, in order. Every card must carry evidence.

To add a platform: a detector in php2shell_check.py and a case here (CONTRIBUTING.md).
"""
from __future__ import annotations

import re
import unittest

import php2shell_check as p2s
from tests.helpers import CASES, case_names, case_net, evidenced, run


class Corpus(unittest.TestCase):
    def test_every_case_gives_its_cards_with_evidence(self):
        names = case_names()
        self.assertGreaterEqual(len(names), 22)
        for name in names:
            with self.subTest(name):
                case, net = case_net(name)
                got = run(case["typed"], net)
                want = case["expect"]
                self.assertTrue(want["cards"], f"{name}: no expectation written")
                self.assertEqual([[c["kind"], c["title"]] for c in got["cards"]], want["cards"])
                self.assertEqual(got["summary"], want["summary"])
                if "products" in want:
                    self.assertEqual(sorted(f"{p['name']} {p['shown']}".strip() + f" @{p['host']}"
                                            for p in got["products"]), sorted(want["products"]))
                evidenced(self, got)
                self.assertLessEqual(got["fetches"], p2s.MAX_FETCHES)
                self.assertTrue(all(f["method"] in ("GET", "HEAD") for f in got["fetched"]))

    def test_the_fixtures_name_only_example_domains(self):
        """Site names in the corpus are example.com ones (platform CDNs aside)."""
        allowed = ("example.com", "api.w.org", "cdn.shopify.com", "static.wixstatic.com", "website-files.com",
                   "static1.squarespace.com", "drupal.org", "wordpress.com", "a8c.com")
        for name in case_names():
            text = "".join(f.read_text() for f in (CASES / name).iterdir())
            for host in re.findall(r"https?://([a-z0-9.-]+)", text):
                with self.subTest(name=name, host=host):
                    self.assertTrue(host.endswith(allowed), host)


if __name__ == "__main__":
    unittest.main()
