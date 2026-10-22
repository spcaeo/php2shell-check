# Changelog

All notable changes to php2shell-check. Versions follow [semver](https://semver.org/):
a fix is a patch, a new platform or option a minor, a change to the JSON or the exit codes
a major. A new advisory list alone is not a release: it goes in `advisories.json`
(and in the script's built-in copy at the next release).

## Unreleased

## 1.0.0 (2026-10-21)

First release.

- **What it does:** reads what a site's home page shows anyone (after its redirects) and
  sets it against two advisories: php2shell (PHP, CVE-2026-109618 and CVE-2026-109619,
  fixed in 8.5.12, 8.4.27, 8.3.36 and 8.2.35) and the Node.js October 2026 security
  releases (22.23.4, 24.22.1, 26.12.1). On a WordPress host of the same domain it also
  reads `/wp-login.php`, `/xmlrpc.php`, `/readme.html`, `/wp-json/` (HEAD) and its home page
  (HEAD). At most 8 requests, GET and HEAD only, each listed in the result.
- **Evidence for every finding:** the exact header line, tag, cookie name or page
  reference, the URL it came from, and a `curl` command that shows the same thing.
  What could not be read says "could not check". "Update needed" only for a version the
  server sent.
- **Platforms:** WordPress (and WooCommerce, multisite, headless WordPress on another host
  of the domain), Drupal, Joomla, Magento, Laravel, Symfony, CodeIgniter, PrestaShop,
  OpenCart, Craft CMS, TYPO3, Statamic; Next.js, Nuxt, Remix, SvelteKit, Angular Universal,
  Express, Ghost; Gatsby, Astro, Hugo; Shopify, Wix, Squarespace, Webflow, HubSpot CMS,
  WordPress.com, WordPress VIP; Vercel, Netlify; nginx, Apache, LiteSpeed, OpenResty,
  IIS, Caddy; Cloudflare, Fastly, Akamai, CloudFront, Sucuri.
- **Output:** a plain terminal report (colours on a terminal, `NO_COLOR` respected),
  `--json` (the structure of the web check's API at skaldanalytics.com/check/),
  `--write-json` and `--write-markdown` files.
- **CI:** `--fail-on update_needed|check|any` (exit 0 clean, 1 findings at or above the
  level, 2 could not check) and a composite GitHub Action that writes a job summary.
- **Safety:** http and https on ports 80 and 443 only; never an IP address or a name that
  works only inside a network; every address a name resolves to must be public (cloud
  metadata, loopback, private, link-local, CGNAT, multicast and reserved refused, IPv4
  inside IPv6 too), and the connection goes to the address checked; every redirect checked
  again. `--allow-private` for a site of your own network.
- **Advisories** built into the file; `--advisories-url` loads a newer list.
- **Checked by:** 38 unit tests with their sub-cases (a corpus of 22 kinds of site, every
  refused address form, the limits, the CLI, `--json` and the exit codes, a local HTTP
  server), on Python 3.9 to 3.13 with no network; live runs on wordpress.org, drupal.org
  and skaldanalytics.com; the Action's shell step run locally.

Derived from Skald's public site check (github.com/spcaeo/skald), relicensed MIT by its
authors.
