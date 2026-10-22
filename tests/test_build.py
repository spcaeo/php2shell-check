"""The single file: built from the package, up to date, and giving the package's answers.

php2shell_check.py is generated from php2shell_check/ by tools/build-single-file.py and
committed (the curl one-liner and the GitHub Action run it). These tests rebuild it and
fail when the committed copy differs, then run the generated file on every fixture and
check that it answers exactly as the package does."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

import php2shell_check as p2s
from tests.helpers import NOW, case_names, case_net

ROOT = Path(__file__).resolve().parent.parent
SINGLE = ROOT / "php2shell_check.py"
LIMIT = 1000


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module                  # the stand-ins find each function's module here
    spec.loader.exec_module(module)
    return module


BUILD = load(ROOT / "tools" / "build-single-file.py", "build_single_file")
ONE = load(SINGLE, "php2shell_check_single")


class Build(unittest.TestCase):
    def test_the_committed_file_is_the_build_of_the_package(self):
        self.assertEqual(SINGLE.read_text(encoding="utf-8"), BUILD.build(),
                         "php2shell_check.py is out of date: run python3 tools/build-single-file.py")
        lines = SINGLE.read_text(encoding="utf-8").split("\n")
        self.assertEqual(lines[0], "#!/usr/bin/env python3")
        self.assertEqual(lines[1], BUILD.MARK)
        self.assertIn("do not edit", lines[1])

    def test_every_source_file_is_under_the_limit(self):
        files = list((ROOT / "php2shell_check").glob("*.py")) + list((ROOT / "tests").glob("*.py")) \
            + list((ROOT / "tools").glob("*.py"))
        for path in files:
            with self.subTest(path.name):
                self.assertLess(path.read_text(encoding="utf-8").count("\n"), LIMIT)

    def test_the_single_file_stands_alone(self):
        self.assertNotIn("from .", SINGLE.read_text(encoding="utf-8"))
        self.assertNotIn("import php2shell_check", SINGLE.read_text(encoding="utf-8"))
        self.assertEqual(ONE.__version__, p2s.__version__)
        self.assertEqual(ONE.ADVISORIES, p2s.ADVISORIES)


class SameAnswers(unittest.TestCase):
    def test_the_single_file_answers_as_the_package_on_every_fixture(self):
        for name in case_names():
            with self.subTest(name):
                case, net = case_net(name)
                with net:
                    want = p2s.check(case["typed"], None, NOW)
                case, net = case_net(name, module=ONE)
                with net:
                    got = ONE.check(case["typed"], None, NOW)
                self.assertEqual(got, want)
                self.assertEqual(ONE.render(got, True, 100), p2s.render(want, True, 100))
                self.assertEqual(ONE.markdown(got), p2s.markdown(want))
                self.assertEqual(ONE.exit_code(got, "check"), p2s.exit_code(want, "check"))

    def test_the_single_file_keeps_the_address_rules(self):
        for raw in ("http://127.0.0.1/", "localhost", "db.internal", "http://[::ffff:127.0.0.1]/",
                    "https://example.com:8443/", "file:///etc/passwd"):
            with self.subTest(raw), self.assertRaises(ONE.Refused):
                ONE.target(raw)
        self.assertEqual(ONE.address_refused("169.254.169.254", True), "a cloud metadata address")


if __name__ == "__main__":
    unittest.main()
