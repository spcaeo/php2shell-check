"""What one fetched page proves about what runs a site, each finding with its evidence.

Nothing is fetched here. Every pattern looks only at what an ordinary visit returns: the
headers, the cookie NAMES (never their values) and the HTML."""
from __future__ import annotations

import re
import shlex
from collections import Counter

PATH_CHARS = "[-A-Za-z0-9._~%/+,;=:@&?#!$*]*"      # the same in Python and in grep -E
NAMES = {
    "wordpress": "WordPress", "woocommerce": "WooCommerce", "drupal": "Drupal", "joomla": "Joomla",
    "magento": "Magento", "laravel": "Laravel", "symfony": "Symfony", "codeigniter": "CodeIgniter",
    "prestashop": "PrestaShop", "opencart": "OpenCart", "craft": "Craft CMS", "typo3": "TYPO3",
    "statamic": "Statamic", "hugo": "Hugo", "php": "PHP", "nodejs": "Node.js", "shopify": "Shopify",
    "wix": "Wix", "squarespace": "Squarespace", "webflow": "Webflow", "hubspot": "HubSpot CMS",
    "ghost": "Ghost", "wordpresscom": "WordPress.com", "wpvip": "WordPress VIP", "nextjs": "Next.js",
    "nuxt": "Nuxt", "gatsby": "Gatsby", "remix": "Remix", "sveltekit": "SvelteKit", "astro": "Astro",
    "angular": "Angular Universal", "express": "Express", "vercel": "Vercel", "netlify": "Netlify",
    "nginx": "nginx", "apache": "Apache", "litespeed": "LiteSpeed", "openresty": "OpenResty",
    "iis": "Microsoft IIS", "caddy": "Caddy", "cloudflare": "Cloudflare", "fastly": "Fastly",
    "akamai": "Akamai", "cloudfront": "CloudFront", "sucuri": "Sucuri"}
FIREWALLS = ("cloudflare", "sucuri", "akamai", "fastly", "cloudfront")
VER = r"(\d+(?:\.\d+){0,2})"
WP_ANY = f"((https?:)?//[a-z0-9.-]+)?/wp-(content|includes)/{PATH_CHARS}"
GENERATOR = r"<meta\b[^>]*\bname\s*=\s*[\"']?generator[\"']?[^>]*>"


class Page:
    def __init__(self, url, host, status, headers=None, html=""):
        self.url, self.host, self.status, self.headers, self.html = url, host, status, headers or {}, html

    def header(self, name: str) -> str:
        return ", ".join(self.headers.get(name.lower()) or [])

    def cookies(self) -> list:
        """The cookie names the answer set (never their values)."""
        out = []
        for line in self.headers.get("set-cookie") or []:
            name = line.split("=", 1)[0].strip()
            if name and name not in out:
                out.append(name)
        return out


def _q(text: str) -> str:
    return shlex.quote(text)


def see_header(pg: Page, name: str, contains=None) -> list:
    """The header line as received (the first value that contains `contains`)."""
    pretty = {"x-powered-by": "X-Powered-By", "x-nf-request-id": "X-Nf-Request-Id"}.get(
        name, "-".join(w.capitalize() for w in name.split("-")))
    for value in pg.headers.get(name) or []:
        if contains is None or contains.lower() in value.lower():
            return [{"text": f"We saw the header {pretty}: {value.strip()[:200]}", "url": pg.url,
                     "command": f"curl -sI {_q(pg.url)} | grep -i '^{name}:'"}]
    return []


def see_cookie(pg: Page, name: str) -> list:
    return [{"text": f"We saw the site set a cookie named {name} (its value is not shown)",
             "url": pg.url, "command": f"curl -sI {_q(pg.url)} | grep -i -o '^set-cookie: {name}='"}]


def see_generator(pg: Page, word: str) -> list:
    """The generator tag that names `word` (a page can carry several: a plugin's too)."""
    for tag in re.findall(GENERATOR, pg.html, re.I):
        if word.lower() in tag.lower():
            return [{"text": f"We saw the tag {tag[:200]}", "url": pg.url,
                     "command": f"curl -s {_q(pg.url)} | grep -i -o '<meta[^>]*generator[^>]*>'"}]
    return []


def generator(pg: Page) -> str:
    out = []
    for tag in re.findall(GENERATOR, pg.html, re.I):
        got = re.search(r"\bcontent\s*=\s*[\"']([^\"']*)", tag, re.I)
        if got:
            out.append(got.group(1))
    return " | ".join(out)[:200]


def files(pg: Page, pattern: str, what: str, keep=None) -> tuple:
    """(how many different matches, the first, its evidence) of an ERE that grep and Python
    both read the same way. `keep`, a second ERE, keeps only the matches it starts."""
    found = [m.group(0) for m in re.finditer(pattern, pg.html, re.I)]
    if keep:
        found = [m for m in found if re.match(keep, m, re.I)]
    found = list(dict.fromkeys(m.lower() for m in found))
    if not found:
        return 0, None, []
    n = len(found)
    text = (f"We saw links to {n:,} different {what.format(s='' if n == 1 else 's')}, for example "
            f"{found[0][:160]}")
    then = f" | grep -i -E {_q(keep)}" if keep else ""
    return n, found[0], [{"text": text, "url": pg.url,
                          "command": f"curl -s {_q(pg.url)} | grep -o -i -E {_q(pattern)}{then} "
                                     f"| tr 'A-Z' 'a-z' | sort -u | wc -l"}]


def contains(pg: Page, needle: str, words: str) -> list:
    if needle.lower() not in pg.html.lower():
        return []
    return [{"text": f"We saw {words} in the page", "url": pg.url,
             "command": f"curl -s {_q(pg.url)} | grep -c -i {_q(needle)}"}]


def _add(out, product, fam, saw, version=None, runtime=None, patched=None) -> None:
    if not saw:
        return
    for f in out:
        if f["product"] == product:
            f["saw"] += [s for s in saw if s not in f["saw"]]
            f["version"] = f["version"] or version
            return
    out.append({"product": product, "name": NAMES[product], "version": version, "family": fam,
                "runtime": runtime, "patched": patched, "saw": saw})


def _wordpress(pg: Page, out: list) -> None:
    gen, host = generator(pg), re.escape(pg.host)
    saw, version = [], None
    got = re.search(r"WordPress\s+" + VER, gen, re.I)
    if re.search(r"\bWordPress\b", gen, re.I) and not re.search(r"WordPress\.com", gen, re.I):
        saw += see_generator(pg, "WordPress")
        version = got.group(1) if got else None
    saw += see_header(pg, "link", "api.w.org")
    saw += files(pg, WP_ANY, f"file{{s}} under /wp-content/ or /wp-includes/ on {pg.host}",
                 keep=f"^((https?:)?//{host})?/")[2]
    if not version:
        # WordPress's own core files carry its version as ?ver= (never a plugin's or a theme's).
        vers = Counter(re.findall(r"/wp-includes/(?:js|css)/[-A-Za-z0-9._/]*\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b",
                                  pg.html, re.I))
        if vers:
            version, count = vers.most_common(1)[0]
            saw.append({"text": f"We saw WordPress's own core files carry ?ver={version} ({count} of them)",
                        "url": pg.url, "command": f"curl -s {_q(pg.url)} | grep -o -E '/wp-includes/(js|css)/"
                                                  f"[-A-Za-z0-9._/]*[?]ver=[0-9.]*' | sort | uniq -c"})
    _add(out, "wordpress", "cms", saw, version, "php")
    wp = next((f for f in out if f["product"] == "wordpress"), None)
    if wp:
        n, _first, multi = files(pg, f"/wp-content/uploads/sites/[0-9]+/{PATH_CHARS}",
                                 "file{s} under /wp-content/uploads/sites/ (a multisite's)")
        if n:
            wp["multisite"] = True
            _add(out, "wordpress", "cms", multi)
        got = re.search(r"WooCommerce\s+" + VER, gen, re.I)
        _add(out, "woocommerce", "cms", see_generator(pg, "WooCommerce")
             + files(pg, f"/wp-content/plugins/woocommerce/{PATH_CHARS}", "WooCommerce file{s}")[2],
             got.group(1) if got else None, "php")


def _php_apps(pg: Page, out: list) -> None:
    gen, cookies = generator(pg), pg.cookies()
    saw = see_generator(pg, "Drupal") if re.search(r"\bDrupal\b", gen, re.I) else []
    saw += see_header(pg, "x-generator", "drupal") + see_header(pg, "x-drupal-cache")
    saw += see_header(pg, "x-drupal-dynamic-cache")
    saw += files(pg, f"/sites/default/files/{PATH_CHARS}", "file{s} under /sites/default/files/")[2]
    got = re.search(r"Drupal\s+" + VER, gen + " " + pg.header("x-generator"), re.I)
    _add(out, "drupal", "cms", saw, got.group(1) if got else None, "php")
    saw = see_generator(pg, "Joomla") if re.search(r"\bJoomla\b", gen, re.I) else []
    if saw:
        saw += files(pg, f"/media/(jui|system)/{PATH_CHARS}", "file{s} under Joomla's /media/jui/ or /media/system/")[2]
        saw += contains(pg, "/administrator/", "a link to /administrator/")
    _add(out, "joomla", "cms", saw, None, "php")
    saw = [h for name in ("x-magento-cache-debug", "x-magento-tags", "x-magento-vary") for h in see_header(pg, name)]
    saw += contains(pg, "Mage.Cookies", "Magento's Mage.Cookies script")
    saw += files(pg, f"/static/version[0-9]+/{PATH_CHARS}", "file{s} under Magento's /static/version.../")[2]
    _add(out, "magento", "cms", saw, None, "php")
    session = [c for c in cookies if c.lower().endswith("_session")]
    if "XSRF-TOKEN" in cookies and session:          # Laravel's own pair
        _add(out, "laravel", "framework", see_cookie(pg, "XSRF-TOKEN") + see_cookie(pg, session[0]), None, "php")
    _add(out, "statamic", "cms", see_header(pg, "x-powered-by", "statamic"), None, "php")
    for product, cookie in (("laravel", "laravel_session"), ("symfony", "sf_redirect"),
                            ("codeigniter", "ci_session"), ("craft", "CraftSessionId"), ("opencart", "OCSESSID")):
        hit = [c for c in cookies if c.lower() == cookie.lower()]
        fam = "cms" if product in ("craft", "opencart") else "framework"
        _add(out, product, fam, see_cookie(pg, hit[0]) if hit else [], None, "php")
    if any(c.lower().startswith("prestashop-") for c in cookies) or re.search(r"\bPrestaShop\b", gen, re.I):
        saw = see_generator(pg, "PrestaShop") if re.search(r"\bPrestaShop\b", gen, re.I) else []
        saw += [s for c in cookies if c.lower().startswith("prestashop-") for s in see_cookie(pg, c)][:1]
        _add(out, "prestashop", "cms", saw, None, "php")
    _add(out, "craft", "cms", see_header(pg, "x-powered-by", "craft cms"), None, "php")
    saw = see_generator(pg, "TYPO3") if re.search(r"\bTYPO3\b", gen, re.I) else []
    saw += files(pg, f"/typo3(conf|temp)/{PATH_CHARS}", "file{s} under /typo3conf/ or /typo3temp/")[2]
    _add(out, "typo3", "cms", saw, None, "php")
    if any(f["product"] == "opencart" for f in out):
        _add(out, "opencart", "cms", files(pg, f"/catalog/view/theme/{PATH_CHARS}", "OpenCart theme file{s}")[2])


def _hosted(pg: Page, out: list) -> None:
    gen = generator(pg)
    saw = see_header(pg, "x-shopid") + see_header(pg, "x-shopify-stage") + see_header(pg, "powered-by", "shopify")
    if saw:
        saw += [s for c in pg.cookies() if c.lower().startswith("_shopify_") for s in see_cookie(pg, c)][:1]
        saw += files(pg, f"//cdn\\.shopify\\.com/{PATH_CHARS}", "file{s} on cdn.shopify.com")[2]
    _add(out, "shopify", "hosted", saw, patched="Shopify")
    saw = see_header(pg, "x-wix-request-id") + see_header(pg, "server", "pepyaka")
    saw += files(pg, f"//static\\.wixstatic\\.com/{PATH_CHARS}", "file{s} on static.wixstatic.com")[2] if saw else []
    _add(out, "wix", "hosted", saw, patched="Wix")
    saw = see_header(pg, "server", "squarespace")
    saw += files(pg, f"//static1\\.squarespace\\.com/{PATH_CHARS}", "file{s} on static1.squarespace.com")[2] if saw else []
    _add(out, "squarespace", "hosted", saw, patched="Squarespace")
    saw = contains(pg, "data-wf-site", "Webflow's data-wf-site attribute") if "data-wf-site" in pg.html else []
    saw += files(pg, f"//[a-z0-9.-]*website-files\\.com/{PATH_CHARS}", "file{s} on Webflow's website-files.com")[2] \
        if saw else []
    _add(out, "webflow", "hosted", saw, patched="Webflow")
    _add(out, "hubspot", "hosted", see_header(pg, "x-hs-hub-id") + see_header(pg, "x-powered-by", "hubspot"),
         patched="HubSpot")
    saw = see_header(pg, "x-hacker") + see_header(pg, "host-header", "wordpress.com")
    saw += see_generator(pg, "WordPress.com") if re.search(r"WordPress\.com", gen, re.I) else []
    vip = see_header(pg, "x-powered-by", "wordpress vip")
    _add(out, "wpvip", "hosted", vip, patched="WordPress VIP")
    if not vip:
        _add(out, "wordpresscom", "hosted", saw, patched="WordPress.com")
    if re.search(r"\bGhost\b", gen, re.I):
        got = re.search(r"Ghost\s+" + VER, gen, re.I)
        _add(out, "ghost", "cms", see_generator(pg, "Ghost") + see_header(pg, "x-ghost-cache-status"),
             got.group(1) if got else None, "nodejs")


def _js(pg: Page, out: list) -> None:
    gen = generator(pg)
    saw = see_header(pg, "x-powered-by", "next.js")
    saw += files(pg, f"(https?://[a-z0-9.-]+)?/_next/{PATH_CHARS}", "Next.js file{s} (/_next/)")[2]
    saw += contains(pg, "__NEXT_DATA__", "Next.js's __NEXT_DATA__ script")
    _add(out, "nextjs", "js", saw, None, "nodejs")
    saw = see_header(pg, "x-powered-by", "nuxt")
    saw += files(pg, f"(https?://[a-z0-9.-]+)?/_nuxt/{PATH_CHARS}", "Nuxt file{s} (/_nuxt/)")[2]
    saw += contains(pg, "__NUXT__", "Nuxt's __NUXT__ data")
    _add(out, "nuxt", "js", saw, None, "nodejs")
    got = re.search(r"Gatsby\s+" + VER, gen, re.I)
    saw = (see_generator(pg, "Gatsby") if got else []) + contains(pg, "___gatsby", "Gatsby's ___gatsby root")
    _add(out, "gatsby", "js", saw, got.group(1) if got else None)
    _add(out, "remix", "js", contains(pg, "__remixContext", "Remix's __remixContext script"), None, "nodejs")
    _add(out, "sveltekit", "js", files(pg, f"/_app/immutable/{PATH_CHARS}", "SvelteKit file{s} (/_app/immutable/)")[2],
         None, "nodejs")
    got = re.search(r"Hugo\s+" + VER, gen, re.I)
    _add(out, "hugo", "js", see_generator(pg, "Hugo") if got else [], got.group(1) if got else None)
    got = re.search(r"Astro\s+v?" + VER, gen, re.I)
    saw = (see_generator(pg, "Astro") if got else []) + files(pg, f"/_astro/{PATH_CHARS}", "Astro file{s} (/_astro/)")[2]
    _add(out, "astro", "js", saw, got.group(1) if got else None)
    if "ng-server-context" in pg.html:
        _add(out, "angular", "js", contains(pg, "ng-server-context", "Angular's ng-server-context "
                                            "(rendered on a server)"), None, "nodejs")
    _add(out, "express", "js", see_header(pg, "x-powered-by", "express"), None, "nodejs")


def _servers(pg: Page, out: list) -> None:
    _add(out, "vercel", "hosting", see_header(pg, "x-vercel-id") + see_header(pg, "server", "vercel"), patched="Vercel")
    _add(out, "netlify", "hosting", see_header(pg, "x-nf-request-id") + see_header(pg, "server", "netlify"),
         patched="Netlify")
    server = pg.header("server")
    for product, word in (("nginx", "nginx"), ("apache", "apache"), ("litespeed", "litespeed"),
                          ("openresty", "openresty"), ("iis", "microsoft-iis"), ("caddy", "caddy")):
        got = re.match(r"^\s*" + re.escape(word) + r"(?:/" + VER + ")?", server, re.I)
        if got:
            _add(out, product, "server", see_header(pg, "server", word), got.group(1))
    if pg.headers.get("x-litespeed-cache"):
        _add(out, "litespeed", "server", see_header(pg, "x-litespeed-cache"))
    _add(out, "cloudflare", "cdn", see_header(pg, "server", "cloudflare") + see_header(pg, "cf-ray"))
    _add(out, "fastly", "cdn", see_header(pg, "x-fastly-request-id") + see_header(pg, "x-served-by", "cache-"))
    _add(out, "akamai", "cdn", see_header(pg, "server", "akamaighost") + see_header(pg, "akamai-grn"))
    _add(out, "cloudfront", "cdn", see_header(pg, "x-amz-cf-id") + see_header(pg, "via", "cloudfront"))
    _add(out, "sucuri", "cdn", see_header(pg, "x-sucuri-id") + see_header(pg, "server", "sucuri"))
    saw = see_header(pg, "x-powered-by", "php/")
    got = re.search(r"\bPHP/" + VER, pg.header("x-powered-by"), re.I)
    session = [c for c in pg.cookies() if c.upper() == "PHPSESSID"]
    saw += see_cookie(pg, session[0]) if session else []
    if saw:
        _add(out, "php", "runtime", saw, got.group(1) if got else None, "php")


def detect(pg: Page) -> list:
    """Everything this page proves, each with its evidence: product, name, version (only what
    the server sent), family, runtime, patched (who runs the runtime for you), saw."""
    out: list = []
    for fam in (_hosted, _wordpress, _php_apps, _js, _servers):
        fam(pg, out)
    host = next((f["patched"] for f in out if f["product"] in ("wordpresscom", "wpvip")), None)
    if host:                                     # WordPress hosted by WordPress.com or VIP
        for f in out:
            if f["product"] in ("wordpress", "woocommerce"):
                f["patched"] = host
    for f in out:
        f["host"] = pg.host
    return out


def how_of(saw: list) -> str:
    text = saw[0]["text"] if saw else ""
    if text.startswith("We saw the tag"):
        return "generator tag"
    got = re.match(r"We saw the header ([A-Za-z-]+):", text)
    if got:
        return f"{got.group(1)} header"
    if text.startswith("We saw the site set a cookie"):
        return "its cookie"
    return "its files" if "load" in text or text.startswith("We saw links to") else "its page"


def runtimes(found: list) -> list:
    """PHP and Node.js on each host: the server's own version when it shows one, else "version
    not shown" with what runs on them as the evidence, and who patches them for you."""
    out = [f for f in found if f["product"] not in ("php", "nodejs")]
    for host in dict.fromkeys(f["host"] for f in found):
        here = [f for f in found if f["host"] == host]
        patched = next((f["patched"] for f in here if f["family"] in ("hosted", "hosting") and f["patched"]), None)
        for runtime in ("php", "nodejs"):
            own = next((f for f in here if f["product"] == runtime), None)
            apps = [f for f in here if f.get("runtime") == runtime and f["product"] != runtime]
            if not own and not apps:
                continue
            # A hosted platform runs PHP or Node.js for you; Vercel and Netlify run Node.js, not PHP.
            who = patched if (patched and (runtime == "nodejs" or patched not in ("Vercel", "Netlify"))) \
                else next((a["patched"] for a in apps if a.get("patched")), None)
            saw = list(own["saw"]) if own else []
            if not (own and own.get("version")) and apps:
                app = apps[0]
                ver = f" {app['version']}" if app.get("version") else ""
                saw.insert(0, {"text": f"We saw {host} runs {app['name']}{ver} ({how_of(app['saw'])}), "
                                       f"and {app['name']} runs on {NAMES[runtime]}",
                               "url": app["saw"][0]["url"], "command": app["saw"][0]["command"]})
                saw += [s for s in app["saw"] if s not in saw]
            out.append({"product": runtime, "name": NAMES[runtime], "family": "runtime",
                        "version": own.get("version") if own else None, "runtime": runtime,
                        "patched": who, "host": host, "saw": saw,
                        "under": [a["name"] + (f" {a['version']}" if a.get("version") else "") for a in apps]})
    return out
