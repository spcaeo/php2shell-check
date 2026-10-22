# GitHub setup (for the owner, not for users)

Everything below is for publishing `spcaeo/php2shell-check`. Nothing has been created on
GitHub yet; this folder has one local commit and no remote.

## Description (308 characters, limit 350)

```text
Is your site exposed to php2shell (CVE-2026-109618, CVE-2026-109619), the October 2026 PHP remote code execution flaws? A one-file, zero-dependency CLI and GitHub Action that reads what your site shows anyone, with evidence and a curl command for every finding. Also checks the Node.js October 2026 releases.
```

Website field: `https://skaldanalytics.com/check/`

## Topics

```text
php2shell cve-2026-109618 cve-2026-109619 php wordpress security vulnerability-scanner devsecops github-actions cli
```

## Social preview

`docs/social-preview.png` (1280 x 640): Settings > General > Social preview > Edit >
Upload an image. Made by `python3 tools/make-social-card.py` from `tools/social/card.html`.

## Steps to publish

1. Create the public repo `spcaeo/php2shell-check` (no README, licence or .gitignore: they
   are here), then:
   `git remote add origin git@github.com:spcaeo/php2shell-check.git && git push -u origin main`.
2. Set the description, website and topics above, and upload the social preview.
3. Settings > Code security: turn on **Private vulnerability reporting** (SECURITY.md
   points to it) and Dependabot alerts for the pinned actions.
4. Check that the **tests** workflow passes (Python 3.9 to 3.13, and the Action on
   skaldanalytics.com: one GET per run).
5. Tag the release, and the moving major tag the README's `@v1` uses:
   `git tag -a v1.0.0 -m "php2shell-check 1.0.0" && git tag -f v1 && git push origin v1.0.0 v1`.
   Then a GitHub release from `v1.0.0` with the CHANGELOG's 1.0.0 notes.
6. Optional: publish the Action to the GitHub Marketplace (the release page offers it;
   `action.yml` has a name, description and branding).
7. Optional: publish to PyPI so `pipx run php2shell-check example.com` works without
   `--spec git+...` (`python3 -m build && twine upload dist/*`; the name
   `php2shell-check` must be free there). The README shows the `--spec git+` form today.

## Pinned actions

| Action | Version | Commit |
| --- | --- | --- |
| actions/checkout | v7.0.1 | 3d3c42e5aac5ba805825da76410c181273ba90b1 |
| actions/setup-python | v7.0.0 | 5fda3b95a4ea91299a34e894583c3862153e4b97 |

Both resolved from the tags on 2026-10-21 (`gh api repos/<action>/git/ref/tags/<tag>`).
