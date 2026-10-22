# Changelog

All notable changes to php2shell-check. Versions follow [semver](https://semver.org/):
a fix is a patch, a new platform or option a minor, a change to the JSON or the exit codes
a major. A new advisory list alone is not a release: it goes in `advisories.json`
(and in the script's built-in copy at the next release).

## Unreleased

## 1.1.0 (2026-10-22)

From Skald's public check (2.22.1 and the fixes after it), ported with tests.

- **A firewall that stops the check now says so, with what to run instead.** Before, a
  Cloudflare-style challenge or a 403 read "Could not check <host>: a bot challenge ..." and a
  card titled "firewall blocked our check". Since this tool runs from your own machine, a block
  means the firewall stops this machine too (firewalls often let a browser through and stop
  scripts). Now: "Your site's firewall stopped this check from this machine, so we can't see
  what it shows. That's often good news: it blocks automated scanners too.", then how to see
  the details (run it from a machine the firewall lets through, or `curl -sI https://<host>/ |
  grep -iE "server|x-powered-by"` and `php -v` on the server), and a card with the proof: the
  status, the challenge's header (`cf-mitigated: challenge`, AWS WAF's `x-amzn-waf-action`) or
  page title, and the firewall its own headers or page name (Cloudflare, Sucuri, Akamai, AWS
  WAF, CloudFront, Imperva, Fastly, Wordfence). 401 says it asks for a password. A 503 counts
  only with a firewall's own denial page (a 503 alone is a site that is down). The tool never
  changes its User-Agent to get past one. JSON: a new `block` field (`kind`, `status`, `url`,
  `firewalls`, `saw`, `commands`, `summary`, `next`), `summary` set for a blocked site, and
  `counts` all 0 for any site that could not be read (could not check is not a problem found).
  The exit code is still 2. Markdown and the terminal show the commands.
- **The summary reads in the order people say it.** "Your site is served by nginx on PHP
  (version hidden) behind CloudFront" is now "Your site runs PHP (version hidden) on nginx,
  behind CloudFront.": the platform or the language first, then the web server, the host and
  the CDN. The web server is named after a platform too ("Your site runs Drupal 10 on PHP
  (version hidden), served by Apache."), and a language not under the platform is no longer
  put under it.
- **The same finding on two hosts is one card.** A headless WordPress whose front (www.) and
  content host (wp.) both send `Server: nginx/1.24.0` gave "Your server shows its exact version:
  nginx 1.24.0" twice; now one card lists both hosts, keeps each host's evidence, ends "Seen on 2
  hosts: ..." and is counted once.
- **Checked:** `tests/test_blocked.py` (a Cloudflare challenge, a plain 403 and Sucuri's 503 from
  the corpus; AWS WAF, Akamai, Wordfence, Imperva; a password; two 503s that are not blocks;
  one request, the tool's own User-Agent; the terminal and Markdown), every summary of the
  26-case corpus in a table with checks on the order of its parts, 15 combinations, and the
  merge (a new corpus case and a unit test). The single file answers as the package on every
  case.

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
- **Source and single file:** the source is the package `php2shell_check/` (one module
  per concern, each under 1,000 lines); `php2shell_check.py` is generated from it by
  `tools/build-single-file.py` and committed. A test and the CI fail when it is out of date,
  and a test runs it on every fixture and checks it answers exactly as the package does.
- **Checked by:** 43 unit tests with their sub-cases (a corpus of 22 kinds of site, every
  refused address form, the limits, the CLI, `--json` and the exit codes, a local HTTP
  server), on Python 3.9 to 3.13 with no network; live runs on wordpress.org, drupal.org
  and skaldanalytics.com; the Action's shell step run locally.

Derived from Skald's public site check (github.com/spcaeo/skald), relicensed MIT by its
authors.
