"""
ZeroPath - Vulnerability Scanner Module
Lightweight, resource-efficient scanning
"""
import asyncio
import re
import json
import socket
import ssl
import httpx
from urllib.parse import urlparse, urljoin
from typing import Callable, Optional
from bs4 import BeautifulSoup
import aiohttp


class VulnerabilityScanner:
    """Lightweight vulnerability scanner with resource limits."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.parsed = urlparse(target_url)
        self.findings = []
        self.visited_paths = set()
        
    async def run_full_scan(self, progress_callback: Optional[Callable] = None) -> list:
        """Run complete scan with progress updates."""
        
        async def update_progress(pct: int, msg: str):
            if progress_callback:
                await progress_callback(pct, msg)
        
        # Phase 1: Basic recon (10%)
        await update_progress(10, "Checking target accessibility...")
        accessible = await self._check_accessibility()
        if not accessible:
            return [{"type": "error", "message": "Target not accessible"}]
        
        # Phase 2: SSL/TLS check (15%)
        await update_progress(15, "Analyzing SSL/TLS configuration...")
        ssl_findings = await self._check_ssl()
        self.findings.extend(ssl_findings)
        
        # Phase 3: Header analysis (20%)
        await update_progress(20, "Checking security headers...")
        header_findings = await self._check_headers()
        self.findings.extend(header_findings)
        
        # Phase 4: Common paths discovery (35%)
        await update_progress(25, "Discovering endpoints...")
        endpoints = await self._discover_endpoints()
        
        await update_progress(35, f"Found {len(endpoints)} endpoints. Testing for vulnerabilities...")
        
        # Phase 5: XSS detection (50%)
        await update_progress(40, "Testing for XSS vulnerabilities...")
        xss_findings = await self._test_xss(endpoints[:10])  # Limit to 10 endpoints
        self.findings.extend(xss_findings)
        
        # Phase 6: SQLi detection (60%)
        await update_progress(50, "Testing for SQL injection...")
        sqli_findings = await self._test_sqli(endpoints[:10])
        self.findings.extend(sqli_findings)
        
        # Phase 7: Info disclosure (70%)
        await update_progress(55, "Checking for information disclosure...")
        info_findings = await self._check_info_disclosure()
        self.findings.extend(info_findings)
        
        # Phase 8: CORS check (75%)
        await update_progress(60, "Analyzing CORS configuration...")
        cors_findings = await self._check_cors()
        self.findings.extend(cors_findings)
        
        await update_progress(62, "Scan complete. Compiling results...")
        
        return self.findings
    
    async def _check_accessibility(self) -> bool:
        """Check if target is accessible."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self.target_url)
                return resp.status_code < 500
        except:
            return False
    
    async def _check_ssl(self) -> list:
        """Check SSL/TLS configuration."""
        findings = []
        
        if self.parsed.scheme != 'https':
            findings.append({
                "type": "vulnerability",
                "severity": "medium",
                "name": "No HTTPS",
                "description": "Target does not use HTTPS",
                "evidence": f"Scheme: {self.parsed.scheme}",
                "cwe": "CWE-319"
            })
            return findings
        
        try:
            # Simple SSL check
            ctx = ssl.create_default_context()
            with socket.create_connection((self.parsed.hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.parsed.hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiry
                    import datetime
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        findings.append({
                            "type": "vulnerability",
                            "severity": "high",
                            "name": "Expired SSL Certificate",
                            "description": "SSL certificate has expired",
                            "evidence": f"Expires: {cert['notAfter']}",
                            "cwe": "CWE-295"
                        })
        except Exception as e:
            findings.append({
                "type": "vulnerability",
                "severity": "low",
                "name": "SSL Check Failed",
                "description": "Could not verify SSL configuration",
                "evidence": str(e),
                "cwe": "CWE-295"
            })
        
        return findings
    
    async def _check_headers(self) -> list:
        """Check security headers."""
        findings = []
        
        required_headers = {
            'X-Frame-Options': ('medium', 'Clickjacking protection missing'),
            'X-Content-Type-Options': ('low', 'MIME-sniffing protection missing'),
            'Strict-Transport-Security': ('medium', 'HSTS header missing'),
            'Content-Security-Policy': ('medium', 'CSP header missing'),
            'X-XSS-Protection': ('low', 'XSS protection header missing'),
        }
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self.target_url)
                
                for header, (severity, desc) in required_headers.items():
                    if header.lower() not in [h.lower() for h in resp.headers.keys()]:
                        findings.append({
                            "type": "vulnerability",
                            "severity": severity,
                            "name": f"Missing {header}",
                            "description": desc,
                            "evidence": f"Header not found in response",
                            "cwe": "CWE-693"
                        })
                
                # Check for sensitive headers
                sensitive = ['Server', 'X-Powered-By', 'X-AspNet-Version']
                for header in sensitive:
                    if header.lower() in [h.lower() for h in resp.headers.keys()]:
                        findings.append({
                            "type": "info",
                            "severity": "info",
                            "name": f"Information Disclosure: {header}",
                            "description": f"Server reveals {header} information",
                            "evidence": f"{header}: {resp.headers.get(header)}",
                            "cwe": "CWE-200"
                        })
        
        except Exception as e:
            pass
        
        return findings
    
    async def _discover_endpoints(self) -> list:
        """Discover endpoints through common paths and sitemap."""
        endpoints = []
        common_paths = [
            '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
            '/admin', '/login', '/api', '/api/v1', '/api/v2',
            '/wp-admin', '/wp-login.php', '/administrator',
            '/config', '/backup', '/debug', '/test',
            '/graphql', '/swagger', '/api-docs', '/docs',
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Get root page links
                resp = await client.get(self.target_url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                for a in soup.find_all('a', href=True):
                    href = a['href']
                    if href.startswith('/') and href not in endpoints:
                        endpoints.append(href)
                
                # Check common paths
                for path in common_paths:
                    try:
                        resp = await client.get(urljoin(self.target_url, path))
                        if resp.status_code == 200:
                            endpoints.append(path)
                    except:
                        pass
                
        except Exception as e:
            pass
        
        return list(set(endpoints))[:20]  # Limit endpoints
    
    async def _test_xss(self, endpoints: list) -> list:
        """Test for XSS vulnerabilities."""
        findings = []
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for endpoint in endpoints[:5]:  # Limit for resource safety
                    url = urljoin(self.target_url, endpoint)
                    
                    # Test GET parameters
                    for payload in xss_payloads[:1]:  # Just one payload per endpoint
                        try:
                            resp = await client.get(url, params={'q': payload, 'search': payload, 'test': payload})
                            
                            if payload in resp.text and 'text/html' in resp.headers.get('content-type', ''):
                                findings.append({
                                    "type": "vulnerability",
                                    "severity": "high",
                                    "name": "Reflected XSS",
                                    "description": "XSS payload reflected in response",
                                    "location": f"GET {endpoint}",
                                    "payload": payload,
                                    "evidence": f"Payload reflected in HTML response",
                                    "cwe": "CWE-79"
                                })
                                break
                        except:
                            pass
        except:
            pass
        
        return findings
    
    async def _test_sqli(self, endpoints: list) -> list:
        """Test for SQL injection vulnerabilities."""
        findings = []
        sqli_payloads = ["' OR '1'='1", "1' AND '1'='1", "1 UNION SELECT NULL--"]
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for endpoint in endpoints[:5]:
                    url = urljoin(self.target_url, endpoint)
                    
                    for payload in sqli_payloads[:1]:
                        try:
                            resp = await client.get(url, params={'id': payload, 'user': payload, 'q': payload})
                            
                            # Check for SQL error patterns
                            sql_errors = [
                                'sql syntax', 'mysql', 'sqlite', 'postgresql',
                                'ora-', 'syntax error', 'unclosed quotation'
                            ]
                            
                            text_lower = resp.text.lower()
                            for error in sql_errors:
                                if error in text_lower:
                                    findings.append({
                                        "type": "vulnerability",
                                        "severity": "high",
                                        "name": "Potential SQL Injection",
                                        "description": "SQL error message detected",
                                        "location": f"GET {endpoint}",
                                        "payload": payload,
                                        "evidence": f"SQL error pattern: {error}",
                                        "cwe": "CWE-89"
                                    })
                                    break
                        except:
                            pass
        except:
            pass
        
        return findings
    
    async def _check_info_disclosure(self) -> list:
        """Check for information disclosure."""
        findings = []
        
        sensitive_files = [
            ('/.env', 'Environment variables'),
            ('/.git/config', 'Git configuration'),
            ('/package.json', 'Node.js dependencies'),
            ('/composer.json', 'PHP dependencies'),
            ('/wp-config.php', 'WordPress configuration'),
            ('/server-status', 'Apache status'),
            ('/server-info', 'Apache info'),
        ]
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                for path, desc in sensitive_files:
                    try:
                        resp = await client.get(urljoin(self.target_url, path))
                        if resp.status_code == 200 and len(resp.text) > 10:
                            findings.append({
                                "type": "vulnerability",
                                "severity": "medium",
                                "name": f"Sensitive File Exposed: {path}",
                                "description": desc,
                                "evidence": f"Status: {resp.status_code}, Length: {len(resp.text)}",
                                "cwe": "CWE-538"
                            })
                    except:
                        pass
        except:
            pass
        
        return findings
    
    async def _check_cors(self) -> list:
        """Check CORS configuration."""
        findings = []
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.options(
                    self.target_url,
                    headers={
                        'Origin': 'https://evil.com',
                        'Access-Control-Request-Method': 'GET'
                    }
                )
                
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                if acao == '*':
                    findings.append({
                        "type": "vulnerability",
                        "severity": "medium",
                        "name": "Overly Permissive CORS",
                        "description": "CORS allows any origin",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "cwe": "CWE-942"
                    })
                elif 'evil.com' in acao:
                    findings.append({
                        "type": "vulnerability",
                        "severity": "high",
                        "name": "CORS Origin Reflection",
                        "description": "CORS reflects arbitrary origin",
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "cwe": "CWE-942"
                    })
        except:
            pass
        
        return findings
