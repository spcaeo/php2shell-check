# Contributing

Thank you. Issues and pull requests are welcome.

## Add a platform: a detector plus a fixture

1. **The detector.** In `php2shell_check.py`, under "what a page proves", add the platform
   to `NAMES` and read it in the family function that fits (`_hosted`, `_wordpress`,
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
3. **Run the tests:** `python3 -m unittest`. They must end `OK`, on Python 3.9 or newer,
   with no network.

## The rules every change keeps

- Evidence for every finding: what was seen, the URL, and a `curl` command that shows the
  same thing, counting the same way.
- "Could not check" rather than a guess. "Update needed" only for a version read.
- Standard library only, one file, Python 3.9+.
- GET and HEAD only, no secret-file probing, no user enumeration, no exploit.
- The address rules in "Safety" (README) stay on by default.

## New advisories

Add it to `advisories.json` with the vendor's own facts and source URLs (https only), and
to `ADVISORIES` in the script (a test checks they match). Say in `CHANGELOG.md` what
changed and where the facts come from.
