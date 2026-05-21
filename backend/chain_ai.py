"""
ZeroPath - Exploit Chain AI Module
Analyzes vulnerabilities and generates attack chains
"""
from typing import List, Callable, Optional
import asyncio


class ExploitChainAI:
    """AI-powered exploit chain generator."""
    
    # Vulnerability relationships matrix
    VULN_CHAINS = {
        # (source, target) -> chain description
        ("info_disclosure", "xss"): "Exposed configuration can reveal sensitive endpoints for XSS",
        ("info_disclosure", "sqli"): "Information leak reveals database structure",
        ("header_missing", "xss"): "Missing CSP allows XSS exploitation",
        ("header_missing", "clickjacking"): "Missing X-Frame-Options enables clickjacking",
        ("cors_misconfig", "xss"): "Bad CORS allows XSS payload delivery from external domain",
        ("cors_misconfig", "info_disclosure"): "Permissive CORS enables data exfiltration",
        ("sqli", "rce"): "SQL injection can lead to code execution via INTO OUTFILE",
        ("xss", "session_hijack"): "XSS enables session token theft",
        ("xss", "csrf_bypass"): "XSS can bypass CSRF protections",
        ("clickjacking", "csrf"): "Clickjacking can enable CSRF attacks",
    }
    
    SEVERITY_SCORE = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }
    
    async def generate_chains(
        self, 
        findings: List[dict],
        progress_callback: Optional[Callable] = None
    ) -> List[dict]:
        """Generate attack chains from findings."""
        
        chains = []
        
        async def update_progress(pct: int, msg: str):
            if progress_callback:
                await progress_callback(pct, msg)
        
        await update_progress(10, "Analyzing vulnerability relationships...")
        
        # Categorize findings
        vulns = self._categorize_findings(findings)
        
        await update_progress(30, "Building attack graph...")
        
        # Find direct chains
        direct_chains = self._find_direct_chains(vulns)
        chains.extend(direct_chains)
        
        await update_progress(50, "Identifying compound attack paths...")
        
        # Find compound chains
        compound_chains = self._find_compound_chains(vulns)
        chains.extend(compound_chains)
        
        await update_progress(70, "Generating PoC recommendations...")
        
        # Add PoC details to chains
        for chain in chains:
            chain["poc"] = self._generate_poc_recommendation(chain)
            chain["mitigation"] = self._generate_mitigation(chain)
        
        await update_progress(90, "Ranking attack paths by impact...")
        
        # Sort by severity and impact
        chains.sort(key=lambda c: c.get("total_score", 0), reverse=True)
        
        await update_progress(100, f"Generated {len(chains)} attack chains")
        
        return chains
    
    def _categorize_findings(self, findings: List[dict]) -> dict:
        """Categorize findings by vulnerability type."""
        categories = {
            "xss": [],
            "sqli": [],
            "info_disclosure": [],
            "header_missing": [],
            "cors_misconfig": [],
            "clickjacking": [],
            "ssl_issues": [],
            "exposed_files": []
        }
        
        for f in findings:
            name = f.get("name", "").lower()
            desc = f.get("description", "").lower()
            
            if "xss" in name or "cross-site" in desc:
                categories["xss"].append(f)
            elif "sql" in name or "injection" in name:
                categories["sqli"].append(f)
            elif "information" in name or "disclosure" in name or "exposed" in name:
                categories["info_disclosure"].append(f)
            elif "frame" in name or "clickjack" in name:
                categories["clickjacking"].append(f)
            elif "cors" in name:
                categories["cors_misconfig"].append(f)
            elif any(h in name for h in ["X-Frame", "CSP", "HSTS", "Header"]):
                categories["header_missing"].append(f)
            elif "ssl" in name or "certificate" in name:
                categories["ssl_issues"].append(f)
            elif "file" in name or ".env" in name or ".git" in name:
                categories["exposed_files"].append(f)
        
        return categories
    
    def _find_direct_chains(self, vulns: dict) -> list:
        """Find direct 2-step attack chains."""
        chains = []
        
        for (source_type, target_type), description in self.VULN_CHAINS.items():
            if vulns.get(source_type) and vulns.get(target_type):
                chain = {
                    "type": "direct_chain",
                    "name": f"{source_type.upper()} → {target_type.upper()} Attack Chain",
                    "description": description,
                    "steps": [
                        {
                            "step": 1,
                            "action": f"Exploit {source_type}",
                            "finding": vulns[source_type][0]
                        },
                        {
                            "step": 2,
                            "action": f"Leverage for {target_type}",
                            "finding": vulns[target_type][0]
                        }
                    ],
                    "complexity": "medium",
                    "total_score": self._calculate_chain_score(
                        vulns[source_type][0], 
                        vulns[target_type][0]
                    )
                }
                chains.append(chain)
        
        return chains
    
    def _find_compound_chains(self, vulns: dict) -> list:
        """Find multi-step compound attack chains."""
        chains = []
        
        # Chain: Info Disclosure → SQLi → RCE
        if vulns.get("info_disclosure") and vulns.get("sqli"):
            chains.append({
                "type": "compound_chain",
                "name": "Full Compromise Chain",
                "description": "Information disclosure reveals endpoints, SQL injection exploits them, leading to potential code execution",
                "steps": [
                    {
                        "step": 1,
                        "action": "Harvest information from exposed files/configs",
                        "finding": vulns["info_disclosure"][0]
                    },
                    {
                        "step": 2,
                        "action": "Exploit SQL injection on discovered endpoint",
                        "finding": vulns["sqli"][0]
                    },
                    {
                        "step": 3,
                        "action": "Attempt privilege escalation or data exfiltration",
                        "finding": {"type": "potential", "name": "Post-exploitation"}
                    }
                ],
                "complexity": "high",
                "total_score": 15,
                "impact": "Full database access, potential server compromise"
            })
        
        # Chain: Missing Headers → XSS → Session Hijack
        if vulns.get("header_missing") and vulns.get("xss"):
            chains.append({
                "type": "compound_chain",
                "name": "Session Hijacking Chain",
                "description": "Missing security headers enable XSS, which can be used to steal user sessions",
                "steps": [
                    {
                        "step": 1,
                        "action": "Identify pages without CSP protection",
                        "finding": [f for f in vulns["header_missing"] if "CSP" in f.get("name", "")][0] if any("CSP" in f.get("name", "") for f in vulns["header_missing"]) else vulns["header_missing"][0]
                    },
                    {
                        "step": 2,
                        "action": "Inject XSS payload",
                        "finding": vulns["xss"][0]
                    },
                    {
                        "step": 3,
                        "action": "Steal session cookies and hijack user account",
                        "finding": {"type": "potential", "name": "Session Theft"}
                    }
                ],
                "complexity": "medium",
                "total_score": 12,
                "impact": "User account takeover"
            })
        
        # Chain: CORS → XSS → Data Exfiltration
        if vulns.get("cors_misconfig") and vulns.get("xss"):
            chains.append({
                "type": "compound_chain",
                "name": "Cross-Origin Data Theft",
                "description": "CORS misconfiguration combined with XSS enables cross-origin data exfiltration",
                "steps": [
                    {
                        "step": 1,
                        "action": "Craft malicious page on attacker domain",
                        "finding": vulns["cors_misconfig"][0]
                    },
                    {
                        "step": 2,
                        "action": "Inject XSS that leverages CORS policy",
                        "finding": vulns["xss"][0]
                    },
                    {
                        "step": 3,
                        "action": "Exfiltrate sensitive data to attacker server",
                        "finding": {"type": "potential", "name": "Data Exfiltration"}
                    }
                ],
                "complexity": "medium",
                "total_score": 11,
                "impact": "Sensitive data theft from authenticated users"
            })
        
        return chains
    
    def _calculate_chain_score(self, *findings) -> int:
        """Calculate total severity score for a chain."""
        score = 0
        for f in findings:
            severity = f.get("severity", "info")
            score += self.SEVERITY_SCORE.get(severity, 1)
        return score
    
    def _generate_poc_recommendation(self, chain: dict) -> dict:
        """Generate PoC recommendations for a chain."""
        chain_type = chain.get("name", "").lower()
        
        if "xss" in chain_type:
            return {
                "tools": ["Burp Suite", "XSStrike", "manual testing"],
                "payloads": [
                    '<script>alert(document.domain)</script>',
                    '"><svg onload=alert(1)>'
                ],
                "steps": [
                    "1. Identify input points",
                    "2. Test with basic XSS payloads",
                    "3. Bypass any filters",
                    "4. Craft payload for cookie theft"
                ]
            }
        
        if "sqli" in chain_type:
            return {
                "tools": ["sqlmap", "Burp Suite", "manual testing"],
                "payloads": [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "1; WAITFOR DELAY '0:0:5'--"
                ],
                "steps": [
                    "1. Identify injectable parameters",
                    "2. Confirm injection with boolean tests",
                    "3. Enumerate database structure",
                    "4. Extract data or escalate"
                ]
            }
        
        if "cors" in chain_type:
            return {
                "tools": ["curl", "Burp Suite", "custom HTML page"],
                "payloads": [
                    "Origin: https://evil.com"
                ],
                "steps": [
                    "1. Test CORS with different origins",
                    "2. Craft malicious HTML page",
                    "3. Trick user to visit page",
                    "4. Exfiltrate API responses"
                ]
            }
        
        return {
            "tools": ["Burp Suite", "Browser DevTools"],
            "steps": ["Analyze vulnerability", "Craft appropriate payload", "Test in controlled environment"]
        }
    
    def _generate_mitigation(self, chain: dict) -> list:
        """Generate mitigation recommendations."""
        mitigations = []
        
        for step in chain.get("steps", []):
            finding = step.get("finding", {})
            name = finding.get("name", "").lower()
            
            if "xss" in name:
                mitigations.append({
                    "action": "Implement Content Security Policy",
                    "priority": "high",
                    "code": "Content-Security-Policy: default-src 'self'; script-src 'self'"
                })
                mitigations.append({
                    "action": "Sanitize all user inputs",
                    "priority": "high",
                    "code": "Use OWASP Java Encoder or similar"
                })
            
            if "sqli" in name:
                mitigations.append({
                    "action": "Use parameterized queries",
                    "priority": "critical",
                    "code": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                })
                mitigations.append({
                    "action": "Implement input validation",
                    "priority": "high",
                    "code": "Validate and sanitize all user inputs"
                })
            
            if "header" in name or "cors" in name:
                mitigations.append({
                    "action": "Add security headers",
                    "priority": "high",
                    "code": """X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'"""
                })
        
        return mitigations
