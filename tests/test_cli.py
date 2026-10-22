"""The command line: the terminal output, --json, the Markdown report, the exit codes,
colours, the advisory list (built in, and --advisories-url), and running the file as
`python3 php2shell_check.py` and as `curl ... | python3 -`."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import php2shell_check as p2s
from tests.helpers import PUBLIC, Net, case_net

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "php2shell_check.py"
ANSI = re.compile(r"\033\[[0-9;]*m")


class TTY(io.StringIO):
    def isatty(self):
        return True


def cli(args, net=None, stdout=None, env=None):
    """(exit code, stdout, stderr) of main(args) with the network stubbed."""
    out, err = stdout or io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(net or Net())
        stack.enter_context(mock.patch.object(sys, "stdout", out))
        stack.enter_context(mock.patch.object(sys, "stderr", err))
        stack.enter_context(mock.patch.dict(os.environ, env or {}, clear=False))
        code = p2s.main(args)
    return code, out.getvalue(), err.getvalue()


def fixture(name, *args, **kw):
    case, net = case_net(name)
    return cli([case["typed"], *args], net, **kw)


class Terminal(unittest.TestCase):
    def test_the_report_has_every_part(self):
        code, out, _ = fixture("wordpress-woocommerce-litespeed")
        self.assertEqual(code, 0)
        self.assertIsNone(ANSI.search(out), "no colour when not a terminal")
        self.assertIn("Your site runs WordPress 6.8.1 on PHP 8.3.10, served by LiteSpeed. 1 thing to do now, 2 tips.", out)
        self.assertIn("UPDATE NEEDED  Update needed: PHP 8.3.10 on shop.example.com", out)
        self.assertIn("We saw the header X-Powered-By: PHP/8.3.10", out)
        self.assertIn("    https://shop.example.com/", out)
        self.assertIn("This means PHP 8.3.10 is older than 8.3.36", out)
        self.assertIn("What to do: Update PHP to the fixed release of its branch", out)
        self.assertIn("Source: https://www.php.net/archive/2026.php#2026-10-21-5", out)
        self.assertIn("Check it yourself:", out)
        self.assertIn("$ curl -sI https://shop.example.com/ | grep -i '^x-powered-by:'", out)
        self.assertIn("What we fetched (5 requests)", out)
        self.assertRegex(out, r"GET\s+302\s+-?[0-9,]*\s+https://shop.example.com/wp-login.php -> https://shop.example.com/my-account/")
        self.assertIn(f"User-Agent: {p2s.USER_AGENT}", out)
        flat = " ".join(out.split())
        self.assertIn("This reads only what your home page shows anyone.", flat)
        self.assertIn("doesn't test for the flaw", flat)
        self.assertIn("(php -v, node -v)", flat)
        self.assertIn(p2s.WEB_CHECK, out)

    def test_every_card_and_every_evidence_line_is_printed(self):
        case, net = case_net("headless-wordpress-next-on-vercel")
        with net:
            ans = p2s.check(case["typed"], None, None)
        _code, out, _ = fixture("headless-wordpress-next-on-vercel")
        flat = " ".join(out.split())
        for c in ans["cards"]:
            self.assertIn(c["title"], out)
            for s in c["saw"]:
                self.assertIn(" ".join(s["text"].split()), flat)
                self.assertIn(s["command"], out)

    def test_colours_on_a_terminal_unless_no_color(self):
        _c, out, _ = fixture("old-php-7-4-shown", stdout=TTY(), env={"NO_COLOR": "", "TERM": "xterm"})
        self.assertIn("\033[1;31mUPDATE NEEDED\033[0m", out)
        _c, out, _ = fixture("old-php-7-4-shown", stdout=TTY(), env={"NO_COLOR": "1"})
        self.assertIsNone(ANSI.search(out))
        _c, out, _ = fixture("old-php-7-4-shown", "--color", "never", stdout=TTY(), env={"NO_COLOR": ""})
        self.assertIsNone(ANSI.search(out))
        _c, out, _ = fixture("old-php-7-4-shown", "--color", "always")
        self.assertIsNotNone(ANSI.search(out))

    def test_could_not_check_says_so(self):
        code, out, _ = fixture("cloudflare-challenge")
        self.assertEqual(code, 2)
        self.assertIn("Your site's firewall stopped this check from this machine", out)
        self.assertIn("COULD NOT CHECK  www.example.com's firewall stopped this check", out)


class Json(unittest.TestCase):
    def test_json_is_the_web_api_structure(self):
        code, out, _ = fixture("wordpress-cloudflare-php-hidden", "--json")
        got = json.loads(out)
        self.assertEqual(code, 0)
        for key in ("host", "reached", "error", "reason", "summary", "counts", "checked_at", "agent",
                    "fetched", "facts", "hosts", "products", "cards", "advisories_updated", "fetches"):
            self.assertIn(key, got)
        self.assertEqual(got["tool"], {"name": "php2shell-check", "version": p2s.__version__, "advisories": "built in"})
        self.assertEqual([c["kind"] for c in got["cards"]], ["login", "hidden", "tip", "tip", "info"])
        self.assertEqual(set(got["cards"][0]), {"kind", "group", "title", "saw", "means", "advice", "hosts"})

    def test_a_refused_address_in_json(self):
        code, out, _ = cli(["http://127.0.0.1/", "--json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["reason"], "refused")

    def test_the_files_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            j, m = Path(tmp) / "a.json", Path(tmp) / "a.md"
            fixture("wordpress-cloudflare-php-hidden", "--write-json", str(j), "--write-markdown", str(m))
            self.assertEqual(json.loads(j.read_text())["host"], "www.example.com")
            md = m.read_text()
        self.assertIn("## php2shell-check: www.example.com", md)
        self.assertIn("| LOGIN OPEN | Login page open to the internet |", md)
        self.assertIn("```sh\ncurl ", md)
        self.assertIn("doesn't test for the flaw", md)


class ExitCodes(unittest.TestCase):
    def test_levels(self):
        table = [("old-php-7-4-shown", None, 0), ("old-php-7-4-shown", "update_needed", 1),
                 ("drupal", "update_needed", 0), ("drupal", "check", 1),
                 ("wordpress-cloudflare-php-hidden", "check", 1),
                 ("astro-static", "check", 0), ("astro-static", "any", 1),
                 ("static-site-on-netlify", "any", 0), ("wix", "check", 0),
                 ("cloudflare-challenge", None, 2), ("cloudflare-challenge", "any", 2),
                 ("name-does-not-exist", "update_needed", 2)]
        for name, level, want in table:
            with self.subTest(name=name, level=level):
                code, _o, _e = fixture(name, *(["--fail-on", level] if level else []))
                self.assertEqual(code, want)

    def test_a_refused_address_is_2_and_bad_options_are_refused(self):
        code, _o, err = cli(["printer.local"])
        self.assertEqual(code, 2)
        self.assertIn("only inside a network", err)
        for bad in (["example.com", "--max-requests", "0"], ["example.com", "--timeout", "0"],
                    ["example.com", "--user-agent", "a\nb"], ["example.com", "--fail-on", "never"]):
            with self.subTest(bad), self.assertRaises(SystemExit) as got:
                cli(bad)
            self.assertEqual(got.exception.code, 2)


class Advisories(unittest.TestCase):
    def test_the_built_in_list_is_the_repo_file(self):
        self.assertEqual(json.loads((ROOT / "advisories.json").read_text()), p2s.ADVISORIES)
        self.assertTrue(p2s.valid(p2s.ADVISORIES))
        ids = [a["id"] for a in p2s.ADVISORIES["advisories"]]
        self.assertEqual(ids, ["php-2026-10-21", "nodejs-2026-10"])
        for a in p2s.ADVISORIES["advisories"]:
            self.assertTrue(a["sources"] and all(s.startswith("https://") for s in a["sources"]))

    def url_net(self, body, status=200):
        return Net(names={"raw.example.com": [PUBLIC], "www.example.com": [PUBLIC]},
                   pages={"https://raw.example.com/a.json": (status, {}, body),
                          "https://www.example.com/": (200, {"X-Powered-By": "PHP/8.3.40"}, b"<p>hi</p>")})

    def test_a_newer_list_from_a_url(self):
        newer = json.loads(json.dumps(p2s.ADVISORIES))
        newer["updated"] = "2026-11-02"
        newer["advisories"][0]["fixed"]["8.3"] = "8.3.41"
        code, out, err = cli(["www.example.com", "--advisories-url", "https://raw.example.com/a.json", "--json"],
                             self.url_net(json.dumps(newer).encode()))
        got = json.loads(out)
        self.assertEqual((got["advisories_updated"], got["tool"]["advisories"]),
                         ("2026-11-02", "https://raw.example.com/a.json"))
        self.assertEqual(got["cards"][0]["title"], "Update needed: PHP 8.3.40 on www.example.com")
        self.assertEqual(err, "")
        self.assertEqual(got["fetches"], 1, "the list is not counted in the site's requests")

    def test_a_bad_list_keeps_the_built_in_one(self):
        older = dict(p2s.ADVISORIES, updated="2026-01-01")
        for body, words in ((b"not json", "not loaded"), (b'{"schema": 2}', "not a valid list"),
                            (json.dumps(older).encode(), "older than the built-in")):
            with self.subTest(words):
                code, out, err = cli(["www.example.com", "--advisories-url", "https://raw.example.com/a.json",
                                      "--json"], self.url_net(body))
                self.assertIn(words, err)
                self.assertEqual(json.loads(out)["advisories_updated"], p2s.ADVISORIES["updated"])
        _c, _o, err = cli(["www.example.com", "--advisories-url", "http://raw.example.com/a.json"], self.url_net(b""))
        self.assertIn("must be https", err)


class AsAFile(unittest.TestCase):
    """No network: --version, --help and a refused address only."""

    def run_script(self, args, stdin=None):
        cmd = [sys.executable, "-I"] + (["-"] if stdin else [str(SCRIPT)]) + args
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60, cwd=tempfile.gettempdir())

    def test_run_directly_and_from_stdin(self):
        got = self.run_script(["--version"])
        self.assertEqual((got.returncode, got.stdout.strip()), (0, f"php2shell-check {p2s.__version__}"))
        got = self.run_script(["--version"], stdin=SCRIPT.read_text())
        self.assertEqual((got.returncode, got.stdout.strip()), (0, f"php2shell-check {p2s.__version__}"))
        got = self.run_script(["127.0.0.1"], stdin=SCRIPT.read_text())
        self.assertEqual(got.returncode, 2)
        self.assertIn("not an IP address", got.stderr)

    def test_the_console_script_and_the_version_agree(self):
        text = (ROOT / "pyproject.toml").read_text()
        self.assertIn('php2shell-check = "php2shell_check.cli:main"', text)
        self.assertIn(f'version = "{p2s.__version__}"', text)
        self.assertIn(f"## {p2s.__version__}", (ROOT / "CHANGELOG.md").read_text())


if __name__ == "__main__":
    unittest.main()
