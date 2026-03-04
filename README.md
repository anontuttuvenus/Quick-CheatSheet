# OAuth Bible - Comprehensive OAuth/OIDC Security Testing Tool

> **The all-in-one OAuth security testing framework** that consolidates attack vectors from OAuth Hunter, KOAuth, RESTler, PayloadsAllTheThings, PortSwigger Labs, Doyensec, and real-world bug bounty research (2014-2026).

## Why This Tool Exists

No single existing tool covers the full OAuth attack surface:

| Feature | OAuth Hunter | KOAuth | RESTler | PayloadsAllTheThings | **OAuth Bible** |
|---|---|---|---|---|---|
| redirect_uri bypasses | ✅ (basic) | ❌ | ❌ | ✅ (basic) | ✅ **50+ payloads, 9 categories** |
| State/CSRF testing | ✅ | ❌ | ❌ | ✅ | ✅ **10 test scenarios** |
| PKCE bypass testing | ❌ | ❌ | ❌ | ❌ | ✅ **7 bypass techniques** |
| Device Flow attacks | ❌ | ❌ | ❌ | ❌ | ✅ **6 attack vectors** |
| OIDC-specific attacks | ❌ | ❌ | ❌ | ❌ | ✅ **11 attack vectors** |
| Dynamic Registration SSRF | ❌ | ❌ | ❌ | ❌ | ✅ **7 payloads** |
| Token endpoint fuzzing | ❌ | ❌ | ✅ (generic) | ❌ | ✅ **OAuth-specific, 8 grant types** |
| Scope manipulation | ❌ | ❌ | ❌ | ❌ | ✅ **10 test cases** |
| Account takeover chains | ❌ | ❌ | ❌ | ❌ | ✅ **5 ATO vectors** |
| Token leakage detection | ❌ | ❌ | ❌ | ✅ (Referer only) | ✅ **7 leak vectors** |
| Active HTTP scanning | ✅ (mitmproxy) | ❌ | ✅ | ❌ | ✅ **requests-based** |
| Passive payload generation | ❌ | ❌ | ❌ | ✅ | ✅ **Full Burp/ZAP export** |
| Implicit flow attacks | ❌ | ❌ | ❌ | ❌ | ✅ **4 attack vectors** |
| Auth code attacks | ❌ | ❌ | ❌ | ✅ (1 check) | ✅ **6 attack vectors** |
| Client auth attacks | ❌ | ❌ | ❌ | ❌ | ✅ **5 attack vectors** |

**Total unique attack vectors: 130+** across 15 categories.

## PortSwigger Lab Coverage

OAuth Bible covers the attack techniques for **all 6 PortSwigger OAuth labs**:

| Lab | Attack Technique | OAuth Bible Phase |
|---|---|---|
| Authentication bypass via OAuth implicit flow | Modify user data in implicit grant | Phase 15 |
| Forced OAuth profile linking | Missing state / CSRF in OAuth linking | Phase 4 + 14 |
| OAuth account hijacking via redirect_uri | redirect_uri not validated | Phase 3 |
| Stealing access tokens via open redirect | Open redirect + token in fragment | Phase 3 + 6 |
| Stealing access tokens via proxy page | postMessage token leak | Phase 6 |
| SSRF via OpenID dynamic client registration | SSRF via logo_uri in registration | Phase 12 |

> **Note**: PortSwigger labs require manual browser interaction via Burp. This tool generates the exact payloads and URLs needed, but cannot auto-solve interactive labs.

## PayloadsAllTheThings Coverage

All 6 attack categories from the [OAuth Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/OAuth%20Misconfiguration/README.md) page are covered **plus 18 additional attack categories** not present in PayloadsAllTheThings.

## Installation

```bash
# No external dependencies required for passive mode
python3 oauth_bible.py --coverage

# For active scanning, install requests
pip install requests
```

## Usage

### Quick Start - Generate All Payloads
```bash
# Passive mode: generates all test payloads without making requests
python3 oauth_bible.py -u https://target.com --passive

# Export payloads for Burp Intruder / ZAP
python3 oauth_bible.py -u https://target.com --passive --export-requests payloads.txt
```

### Active Scanning
```bash
# Basic active scan
python3 oauth_bible.py -u https://target.com -c CLIENT_ID

# Through Burp proxy (recommended)
python3 oauth_bible.py -u https://target.com -c CLIENT_ID --proxy http://127.0.0.1:8080

# With known redirect_uri and client secret
python3 oauth_bible.py -u https://target.com \
  -c CLIENT_ID \
  -s CLIENT_SECRET \
  -r https://target.com/callback \
  --proxy http://127.0.0.1:8080

# With session cookie and custom headers
python3 oauth_bible.py -u https://target.com \
  --cookie "session=abc123" \
  -H "Authorization: Bearer token123" \
  -v
```

### Coverage Analysis
```bash
# See exactly what's covered vs. other tools
python3 oauth_bible.py --coverage
```

### Export Results
```bash
# JSON report
python3 oauth_bible.py -u https://target.com -o report.json

# Test requests for manual replay
python3 oauth_bible.py -u https://target.com --export-requests tests.txt
```

## Scan Phases (15 Total)

| Phase | Category | Tests | Source |
|---|---|---|---|
| 1 | Reconnaissance & Discovery | ~30 endpoint probes | Custom + OIDC spec |
| 2 | Configuration Analysis | 14 passive checks | OAuth 2.1 draft + best practices |
| 3 | Redirect URI Testing | 50+ bypass payloads | OAuth Hunter + PayloadsAllTheThings + bug bounties |
| 4 | State/CSRF Testing | 10 scenarios | OAuth Hunter + PayloadsAllTheThings |
| 5 | PKCE Testing | 7 bypass techniques | Doyensec + RFC 7636 |
| 6 | Token Security | 7 leak vectors | PayloadsAllTheThings + PortSwigger |
| 7 | Scope Manipulation | 10 test cases | Custom + provider-specific |
| 8 | Authorization Code | 6 attack vectors | PayloadsAllTheThings + PortSwigger |
| 9 | Client Authentication | 5 attack vectors | Custom + OAuth spec |
| 10 | Token Endpoint | 4 attacks + 8 grant types | RESTler-inspired + OAuth spec |
| 11 | OpenID Connect | 11 OIDC-specific attacks | PortSwigger + OIDC spec |
| 12 | Dynamic Registration | 7 SSRF payloads | PortSwigger Lab 6 + OIDC spec |
| 13 | Device Flow | 6 attack vectors | ShinyHunters research 2024-2025 |
| 14 | Account Takeover Chains | 5 ATO methods | Bug bounty research |
| 15 | Implicit Flow | 4 attack vectors | PortSwigger Lab 1 + OAuth spec |

## Architecture

```
oauth_bible.py
├── PayloadDatabase          # Master payload database (130+ vectors)
│   ├── REDIRECT_URI_BYPASSES (9 categories, 50+ payloads)
│   ├── STATE_PARAM_TESTS
│   ├── TOKEN_LEAK_VECTORS
│   ├── SCOPE_TESTS
│   ├── PKCE_BYPASSES
│   ├── OIDC_ATTACKS
│   ├── REGISTRATION_PAYLOADS
│   ├── DEVICE_FLOW_ATTACKS
│   ├── AUTH_CODE_ATTACKS
│   ├── CLIENT_AUTH_ATTACKS
│   ├── TOKEN_ENDPOINT_ATTACKS
│   ├── ACCOUNT_TAKEOVER
│   └── IMPLICIT_FLOW_ATTACKS
├── OAuthBible               # Passive scanner (payload generation)
├── ActiveScanner            # Active scanner (HTTP requests)
│   └── HTTPClient           # HTTP client with proxy support
├── Coverage Analysis        # Maps to PortSwigger + PayloadsAllTheThings
└── CLI Interface            # argparse-based CLI
```

## Integration with Burp Suite

The recommended workflow for real-world pentesting:

1. Run OAuth Bible through Burp proxy:
   ```bash
   python3 oauth_bible.py -u https://target.com --proxy http://127.0.0.1:8080 -v
   ```
2. Review captured requests in Burp Proxy history
3. Send interesting requests to Burp Repeater for manual testing
4. Use exported payloads in Burp Intruder for fuzzing
5. Combine findings with Burp's built-in OAuth detection

## Key Attack Vectors Explained

### redirect_uri Bypass Categories
- **Open redirect**: Direct domain replacement, subdomain tricks, @ symbol confusion
- **Path traversal**: `/../redirect?url=`, `%2e%2e/` encoding variations
- **Parameter pollution**: HPP with multiple redirect_uri params
- **Scheme tricks**: data: URI, javascript:, protocol-relative URLs
- **Port tricks**: Non-standard ports on legitimate domain
- **Fragment tricks**: Hash-based bypasses
- **Wildcard abuse**: Subdomain wildcards
- **Localhost tricks**: 127.0.0.1 variations, IPv6, hex IP
- **Scope change bypass**: Invalid scope to bypass redirect filter

### PKCE Bypass Techniques
1. Omit PKCE parameters entirely
2. Downgrade from S256 to plain
3. Empty code_verifier
4. Mismatched code_verifier
5. Short code_verifier (< 43 chars)
6. Method confusion (S256 challenge, plain verifier)
7. Null code_challenge

### Device Flow Attacks (2024-2025)
Based on ShinyHunters' campaign that compromised Google, Qantas, and dozens more:
1. Device code phishing (social engineering)
2. User code brute-force
3. Polling without rate limit
4. Long expiry exploitation
5. Verification URI look-alike phishing
6. Scope escalation via device flow

## Contributing

To add new attack vectors:
1. Add payloads to the appropriate list in `PayloadDatabase`
2. Add a test phase in `OAuthBible` if it's a new category
3. Update the coverage matrix
4. Test with `--coverage` flag

## References

- [CyberArk OAuth Hunter](https://github.com/cyberark/oauth-hunter)
- [Microsoft RESTler](https://github.com/microsoft/restler-fuzzer)
- [PayloadsAllTheThings - OAuth Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/OAuth%20Misconfiguration/README.md)
- [PortSwigger OAuth Labs](https://portswigger.net/web-security/oauth)
- [Doyensec OAuth Security Cheat Sheet](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 - PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8628 - Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-11)
- [OAuth Device Flow Attack Analysis 2024-2025](https://guptadeepak.com/oauth-device-flow-vulnerabilities-a-critical-analysis-of-the-2024-2025-attack-wave/)

## License

For authorized security testing only. Use responsibly.
