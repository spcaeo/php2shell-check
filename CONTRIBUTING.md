# Contributing

Thank you. Issues and pull requests are welcome.

## Where the code is

The source is the package `php2shell_check/`, one module per concern:

| Module | What it does |
| --- | --- |
| `safety.py` | The address and name rules (the SSRF guard), the limits, the errors |
| `detect.py` | What one page proves: the detectors, each finding with its evidence |
| `fetch.py` | The requests: pinned connections, redirects, the budget, the WordPress pages |
| `advisories.py` | The built-in advisories and how a version meets them |
| `cards.py` | The answer: cards with what was seen, what it means, what to do |
| `cli.py` | The command line: the terminal report, JSON, Markdown, exit codes |

`php2shell_check.py` at the top is **generated** from the package by
`tools/build-single-file.py` (the curl one-liner and the GitHub Action run it). Never edit
it by hand: change the package, run `python3 tools/build-single-file.py`, and commit both.
A test and the CI fail when the two differ. Keep every source file under 1,000 lines.

## Add a platform: a detector plus a fixture

1. **The detector.** In `php2shell_check/detect.py`, add the platform to `NAMES` and read it in the family function that fits (`_hosted`, `_wordpress`,
   `_php_apps`, `_js`, `_servers`). Use the helpers so every finding carries its evidence:
   `see_header`, `see_generator`, `see_cookie`, `files`, `contains`. Then `_add(out,
   product, family, saw, version, runtime, patched)`:
   - `runtime` is `"php"` or `"nodejs"` when the platform runs on it on this host;
   - `patched` is the company that runs and patches that runtime for you (a hosted
     platform), else `None`;
   - `version` only when the server sent one (a header, the generator tag). Never from a
     theme, a year or a file name.
2. **The fixture.** Add `tests/fixtures/sites/<platform>/case.json`: what the site's pages
   answered (headers, trimmed HTML, **example.com names only**, RFC 5737 addresses if any),
   and the cards and summary the check must give. Copy a neighbour, then see what yours
   gives with a short script or by running the test and reading the difference.
3. **Rebuild the single file:** `python3 tools/build-single-file.py`.
4. **Run the tests:** `python3 -m unittest`. They must end `OK`, on Python 3.9 or newer,
   with no network.

## The rules every change keeps

- Evidence for every finding: what was seen, the URL, and a `curl` command that shows the
  same thing, counting the same way.
- "Could not check" rather than a guess. "Update needed" only for a version read.
- Standard library only, Python 3.9+; the generated single file must run on its own.
- GET and HEAD only, no secret-file probing, no user enumeration, no exploit.
- The address rules in "Safety" (README) stay on by default.

## New advisories

Add it to `advisories.json` with the vendor's own facts and source URLs (https only), and
to `ADVISORIES` in `php2shell_check/advisories.py` (a test checks they match), then
rebuild the single file. Say in `CHANGELOG.md` what
changed and where the facts come from.
