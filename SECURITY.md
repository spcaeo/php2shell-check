# Security policy

## Reporting a problem in php2shell-check

Please report a security problem in this tool (for example a way to make it fetch an
address inside a network, or to run something through its output) privately, through
GitHub's **Report a vulnerability** button on this repository's Security tab. Do not open
a public issue for it.

Please include what you ran, what happened and what you expected. We aim to answer within
a few working days, and to fix a confirmed problem in a new release with a line in
`CHANGELOG.md`.

## What this tool is, and isn't

php2shell-check reads only what a site shows anyone: GET and HEAD requests, at most 8,
each listed in its output. It doesn't test for the flaw, send forms or passwords, ask for
secret files or list users. Run it only on sites you own or are allowed to check.

A finding of this tool in someone else's site is not a vulnerability in this tool: tell
the site's owner.

## Supported versions

The latest release. Use the newest advisories with `--advisories-url` (see README).
