"""php2shell-check: is your site exposed to the October 2026 PHP flaws (php2shell)?

    python3 php2shell_check.py example.com
    curl -sSL https://raw.githubusercontent.com/spcaeo/php2shell-check/main/php2shell_check.py | python3 - example.com

Reads what a site's home page shows anyone (its headers, its generator tag, the paths of
the files it loads), after its redirects, plus a few public WordPress pages on WordPress
hosts of the same domain, and sets what it read against the advisories built into it.
GET and HEAD only, at most --max-requests requests, every one listed in the answer. It
never sends a form or a password, never asks for a secret file, never lists users, and it
does not test for the flaw.

Truth rules: every finding carries the exact lines it was read from, the URL and a curl
command that shows the same thing; what could not be read is "could not check", never a
guess; a version only when the server sent one; "update needed" only for a version read.

Safety: http and https on ports 80 and 443 only; never an IP address in any form, never a
name that only works inside a network; the name is resolved here and refused whole when any
of its addresses is not public (loopback, private, link-local, CGNAT, multicast, reserved,
cloud metadata; IPv4 inside IPv6 too), and the connection goes to the very address checked.
Every redirect is checked again. --allow-private lifts the private-address rules for a
check of your own internal site (cloud metadata, multicast and unspecified stay refused).

The source is the package php2shell_check/ (one module per concern); the single file
php2shell_check.py is generated from it by tools/build-single-file.py.

Python 3.9+, standard library only. Derived from Skald's public site check
(github.com/spcaeo/skald), relicensed MIT by its authors.

Copyright (c) 2026 Space-O Technologies. SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from .advisories import (ADVISORIES, branch_of, judge, load_advisories, match, valid,  # noqa: F401
                         version)
from .blocked import blocked_card, blocker, challenged  # noqa: F401
from .cards import answer, merge, stack_words, summary  # noqa: F401
from .cli import (LABELS, LEVELS, check, exit_code, main, markdown, render,  # noqa: F401
                  use_color)
from .detect import NAMES, Page, detect, runtimes  # noqa: F401
from .fetch import Budget, follow, get, open_pinned, plain, read  # noqa: F401
from .safety import (ADVISORIES_URL, HOME, MAX_BYTES, MAX_FETCHES, MAX_REDIRECTS,  # noqa: F401
                     TIMEOUT, USER_AGENT, WEB_CHECK, Answer, BadAddress, Refused, Spent,
                     Unreachable, __version__, address_refused, check_url, family, host_of,
                     host_refused, lookup, resolve, target)
