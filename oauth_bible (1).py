#!/usr/bin/env python3
"""
OAuth Bible - The Ultimate OAuth Security Testing Tool
========================================================
A comprehensive, all-in-one OAuth security testing framework that covers
all known OAuth vulnerabilities including:
- All PortSwigger OAuth labs
- All PayloadsAllTheThings OAuth attacks
- Latest 2025-2026 OAuth vulnerabilities
- Automated detection and exploitation

Author: Security Researcher
Version: 1.0.0 (March 2026)
"""

import argparse
import asyncio
import json
import re
import sys
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import aiohttp
import ssl
import certifi
from urllib.parse import urlencode, parse_qs, urlparse, urlunparse


class VulnerabilitySeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OAuthFlowType(Enum):
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    PASSWORD = "password"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "device_code"
    HYBRID = "hybrid"


@dataclass
class Vulnerability:
    name: str
    description: str
    severity: VulnerabilitySeverity
    evidence: Dict[str, Any]
    remediation: str
    references: List[str]
    confirmed: bool = False


@dataclass
class OAuthEndpoint:
    url: str
    method: str = "GET"
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class OAuthConfig:
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    jwks_uri: Optional[str] = None
    issuer: Optional[str] = None
    scopes_supported: List[str] = field(default_factory=list)
    response_types_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


class OAuthBible:
    """Main OAuth Security Testing Framework"""
    
    def __init__(self, target_url: str, evil_domain: str = "evil.com", 
                 proxy: Optional[str] = None, timeout: int = 30,
                 concurrent: int = 10, output_format: str = "table"):
        self.target_url = target_url.rstrip('/')
        self.evil_domain = evil_domain
        self.proxy = proxy
        self.timeout = timeout
        self.concurrent = concurrent
        self.output_format = output_format
        self.vulnerabilities: List[Vulnerability] = []
        self.oauth_config: Optional[OAuthConfig] = None
        self.discovered_endpoints: List[OAuthEndpoint] = []
        self.session: Optional[aiohttp.ClientSession] = None
        
        # SSL context that allows us to check for certificate issues
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(
            ssl=self.ssl_context,
            limit=self.concurrent,
            limit_per_host=self.concurrent
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'OAuthBible/1.0 Security Testing Tool'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
 ██████╗  █████╗ ██╗   ██╗████████╗██╗  ██╗    ██████╗ ██╗██████╗ ██╗     ███████╗
██╔═══██╗██╔══██╗██║   ██║╚══██╔══╝██║  ██║    ██╔══██╗██║██╔══██╗██║     ██╔════╝
██║   ██║██║  ██║██║   ██║   ██║   ███████║    ██████╔╝██║██████╔╝██║     █████╗  
██║   ██║██║  ██║██║   ██║   ██║   ██╔══██║    ██╔══██╗██║██╔══██╗██║     ██╔══╝  
╚██████╔╝╚█████╔╝╚██████╔╝   ██║   ██║  ██║    ██████╔╝██║██████╔╝███████╗███████╗
 ╚═════╝  ╚════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝    ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝
{Colors.END}
{Colors.YELLOW}        The Ultimate OAuth Security Testing Framework v1.0.0{Colors.END}
{Colors.GREEN}        Coverage: All PortSwigger Labs + PayloadsAllTheThings + 2025-2026 CVEs{Colors.END}
        """
        print(banner)
    
    async def discover_oauth_endpoints(self) -> OAuthConfig:
        """Discover OAuth/OIDC endpoints from target"""
        print(f"\n{Colors.BLUE}[*] Discovering OAuth/OIDC endpoints...{Colors.END}")
        
        config = OAuthConfig()
        
        # Common OAuth discovery paths
        discovery_paths = [
            '/.well-known/oauth-authorization-server',
            '/.well-known/openid-configuration',
            '/oauth/.well-known/openid-configuration',
            '/auth/.well-known/openid-configuration',
            '/oidc/.well-known/openid-configuration',
            '/.well-known/oauth2-configuration',
        ]
        
        # Common OAuth endpoint paths
        endpoint_paths = {
            'authorization': ['/oauth/authorize', '/auth/authorize', '/oauth2/authorize', 
                            '/auth', '/login/oauth/authorize', '/o/oauth2/auth'],
            'token': ['/oauth/token', '/auth/token', '/oauth2/token', 
                     '/token', '/login/oauth/access_token', '/o/oauth2/token'],
            'userinfo': ['/oauth/userinfo', '/auth/userinfo', '/oauth2/userinfo',
                        '/userinfo', '/api/user', '/oauth/me'],
            'revocation': ['/oauth/revoke', '/auth/revoke', '/oauth2/revoke', '/revoke'],
            'introspection': ['/oauth/introspect', '/auth/introspect', '/oauth2/introspect'],
            'registration': ['/oauth/register', '/auth/register', '/oauth2/register', 
                           '/connect/register'],
            'jwks': ['/oauth/jwks', '/auth/jwks', '/oauth2/jwks', '/.well-known/jwks.json'],
        }
        
        # Try discovery endpoints first
        for path in discovery_paths:
            try:
                url = f"{self.target_url}{path}"
                async with self.session.get(url, allow_redirects=True) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            config.authorization_endpoint = data.get('authorization_endpoint')
                            config.token_endpoint = data.get('token_endpoint')
                            config.userinfo_endpoint = data.get('userinfo_endpoint')
                            config.revocation_endpoint = data.get('revocation_endpoint')
                            config.introspection_endpoint = data.get('introspection_endpoint')
                            config.registration_endpoint = data.get('registration_endpoint')
                            config.jwks_uri = data.get('jwks_uri')
                            config.issuer = data.get('issuer')
                            config.scopes_supported = data.get('scopes_supported', [])
                            config.response_types_supported = data.get('response_types_supported', [])
                            config.grant_types_supported = data.get('grant_types_supported', [])
                            print(f"{Colors.GREEN}[+] Discovered OAuth/OIDC configuration at: {url}{Colors.END}")
                            break
                        except:
                            pass
            except Exception as e:
                pass
        
        # If discovery didn't work, probe common endpoints
        if not config.authorization_endpoint:
            for endpoint_type, paths in endpoint_paths.items():
                for path in paths:
                    try:
                        url = f"{self.target_url}{path}"
                        async with self.session.get(url, allow_redirects=False) as resp:
                            # Any response (even error) indicates endpoint exists
                            if endpoint_type == 'authorization':
                                config.authorization_endpoint = url
                            elif endpoint_type == 'token':
                                config.token_endpoint = url
                            elif endpoint_type == 'userinfo':
                                config.userinfo_endpoint = url
                            elif endpoint_type == 'revocation':
                                config.revocation_endpoint = url
                            elif endpoint_type == 'introspection':
                                config.introspection_endpoint = url
                            elif endpoint_type == 'registration':
                                config.registration_endpoint = url
                            elif endpoint_type == 'jwks':
                                config.jwks_uri = url
                            break
                    except:
                        pass
        
        self.oauth_config = config
        return config
    
    def add_vulnerability(self, vuln: Vulnerability):
        """Add a found vulnerability"""
        self.vulnerabilities.append(vuln)
    
    def print_vulnerability(self, vuln: Vulnerability):
        """Print a vulnerability in formatted way"""
        severity_colors = {
            VulnerabilitySeverity.CRITICAL: Colors.RED,
            VulnerabilitySeverity.HIGH: Colors.RED,
            VulnerabilitySeverity.MEDIUM: Colors.YELLOW,
            VulnerabilitySeverity.LOW: Colors.BLUE,
            VulnerabilitySeverity.INFO: Colors.WHITE
        }
        
        color = severity_colors.get(vuln.severity, Colors.WHITE)
        status = f"{Colors.GREEN}[CONFIRMED]{Colors.END}" if vuln.confirmed else f"{Colors.YELLOW}[POTENTIAL]{Colors.END}"
        
        print(f"\n{color}{Colors.BOLD}[{vuln.severity.value}] {vuln.name}{Colors.END} {status}")
        print(f"{Colors.CYAN}Description:{Colors.END} {vuln.description}")
        print(f"{Colors.CYAN}Evidence:{Colors.END}")
        for key, value in vuln.evidence.items():
            print(f"  - {key}: {value}")
        print(f"{Colors.CYAN}Remediation:{Colors.END} {vuln.remediation}")
        if vuln.references:
            print(f"{Colors.CYAN}References:{Colors.END}")
            for ref in vuln.references:
                print(f"  - {ref}")
        print("-" * 80)


# Import test modules
from redirect_uri_tests import RedirectURITester
from csrf_tests import CSRFTester
from token_tests import TokenTester
from openid_tests import OpenIDTester
from flow_tests import FlowTester
from jwt_tests import JWTTester


async def main():
    parser = argparse.ArgumentParser(
        description='OAuth Bible - The Ultimate OAuth Security Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python oauth_bible.py -u https://target.com -e attacker.com
  python oauth_bible.py -u https://target.com --all-tests
  python oauth_bible.py -u https://target.com --redirect-uri-tests --csrf-tests
        """
    )
    
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL to test')
    parser.add_argument('-e', '--evil-domain', default='evil.com',
                       help='Attacker-controlled domain for tests')
    parser.add_argument('-p', '--proxy',
                       help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-t', '--timeout', type=int, default=30,
                       help='Request timeout in seconds')
    parser.add_argument('-c', '--concurrent', type=int, default=10,
                       help='Concurrent requests')
    parser.add_argument('-o', '--output', default='table',
                       choices=['table', 'json', 'html'],
                       help='Output format')
    
    # Test categories
    parser.add_argument('--all-tests', action='store_true',
                       help='Run all tests')
    parser.add_argument('--redirect-uri-tests', action='store_true',
                       help='Run redirect_uri validation tests')
    parser.add_argument('--csrf-tests', action='store_true',
                       help='Run CSRF/state parameter tests')
    parser.add_argument('--token-tests', action='store_true',
                       help='Run token security tests')
    parser.add_argument('--openid-tests', action='store_true',
                       help='Run OpenID Connect tests')
    parser.add_argument('--flow-tests', action='store_true',
                       help='Run OAuth flow tests')
    parser.add_argument('--jwt-tests', action='store_true',
                       help='Run JWT security tests')
    parser.add_argument('--discover-only', action='store_true',
                       help='Only discover OAuth endpoints')
    
    args = parser.parse_args()
    
    async with OAuthBible(args.url, args.evil_domain, args.proxy,
                          args.timeout, args.concurrent, args.output) as bible:
        
        bible.print_banner()
        
        # Discover OAuth endpoints
        config = await bible.discover_oauth_endpoints()
        
        if args.discover_only:
            print(f"\n{Colors.GREEN}[+] Discovery complete{Colors.END}")
            return
        
        # Determine which tests to run
        run_all = args.all_tests or not any([
            args.redirect_uri_tests, args.csrf_tests, args.token_tests,
            args.openid_tests, args.flow_tests, args.jwt_tests
        ])
        
        # Run tests
        if run_all or args.redirect_uri_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] Redirect URI Validation Tests{Colors.END}")
            tester = RedirectURITester(bible)
            await tester.run_all_tests()
        
        if run_all or args.csrf_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] CSRF/State Parameter Tests{Colors.END}")
            tester = CSRFTester(bible)
            await tester.run_all_tests()
        
        if run_all or args.token_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] Token Security Tests{Colors.END}")
            tester = TokenTester(bible)
            await tester.run_all_tests()
        
        if run_all or args.openid_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] OpenID Connect Tests{Colors.END}")
            tester = OpenIDTester(bible)
            await tester.run_all_tests()
        
        if run_all or args.flow_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] OAuth Flow Tests{Colors.END}")
            tester = FlowTester(bible)
            await tester.run_all_tests()
        
        if run_all or args.jwt_tests:
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}[RUNNING] JWT Security Tests{Colors.END}")
            tester = JWTTester(bible)
            await tester.run_all_tests()
        
        # Print summary
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}SCAN SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")
        
        critical = len([v for v in bible.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL])
        high = len([v for v in bible.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])
        medium = len([v for v in bible.vulnerabilities if v.severity == VulnerabilitySeverity.MEDIUM])
        low = len([v for v in bible.vulnerabilities if v.severity == VulnerabilitySeverity.LOW])
        info = len([v for v in bible.vulnerabilities if v.severity == VulnerabilitySeverity.INFO])
        confirmed = len([v for v in bible.vulnerabilities if v.confirmed])
        
        print(f"{Colors.RED}CRITICAL: {critical}{Colors.END}")
        print(f"{Colors.RED}HIGH: {high}{Colors.END}")
        print(f"{Colors.YELLOW}MEDIUM: {medium}{Colors.END}")
        print(f"{Colors.BLUE}LOW: {low}{Colors.END}")
        print(f"{Colors.WHITE}INFO: {info}{Colors.END}")
        print(f"{Colors.GREEN}CONFIRMED: {confirmed}{Colors.END}")
        print(f"\n{Colors.CYAN}Total Vulnerabilities Found: {len(bible.vulnerabilities)}{Colors.END}")
        
        # Print all vulnerabilities
        if bible.vulnerabilities:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}VULNERABILITY DETAILS{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.END}")
            for vuln in bible.vulnerabilities:
                bible.print_vulnerability(vuln)
        
        # Output to file if requested
        if args.output == 'json':
            output_file = 'oauth_bible_results.json'
            with open(output_file, 'w') as f:
                json.dump([{
                    'name': v.name,
                    'description': v.description,
                    'severity': v.severity.value,
                    'confirmed': v.confirmed,
                    'evidence': v.evidence,
                    'remediation': v.remediation,
                    'references': v.references
                } for v in bible.vulnerabilities], f, indent=2)
            print(f"\n{Colors.GREEN}[+] Results saved to {output_file}{Colors.END}")


if __name__ == '__main__':
    asyncio.run(main())
