"""
ZeroPath - Report Generator Module
Generates beautiful HTML reports
"""
import os
from datetime import datetime
from typing import List


class ReportGenerator:
    """Generate HTML security reports."""
    
    async def generate(
        self,
        scan_id: str,
        target_url: str,
        findings: List[dict],
        attack_chains: List[dict]
    ) -> str:
        """Generate HTML report and return file path."""
        
        report_dir = "/root/zeropath/reports"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"report_{scan_id}.html")
        
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        html = self._generate_html(
            scan_id=scan_id,
            target_url=target_url,
            findings=findings,
            attack_chains=attack_chains,
            severity_counts=severity_counts
        )
        
        with open(report_path, 'w') as f:
            f.write(html)
        
        return report_path
    
    def _generate_html(self, scan_id, target_url, findings, attack_chains, severity_counts) -> str:
        """Generate the HTML content."""
        
        findings_html = ""
        for i, f in enumerate(findings, 1):
            severity_class = f.get("severity", "info").lower()
            findings_html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <span class="finding-num">#{i}</span>
                    <span class="severity-badge {severity_class}">{severity_class.upper()}</span>
                    <h4>{f.get('name', 'Unknown')}</h4>
                </div>
                <p>{f.get('description', '')}</p>
                <div class="evidence">
                    <strong>Evidence:</strong> {f.get('evidence', 'N/A')}
                </div>
                <div class="cwe">
                    <strong>CWE:</strong> {f.get('cwe', 'N/A')}
                </div>
            </div>
            """
        
        chains_html = ""
        for i, chain in enumerate(attack_chains, 1):
            steps_html = ""
            for step in chain.get("steps", []):
                finding = step.get("finding", {})
                steps_html += f"""
                <div class="chain-step">
                    <div class="step-num">Step {step.get('step', '?')}</div>
                    <div class="step-content">
                        <strong>{step.get('action', '')}</strong>
                        <div class="step-finding">{finding.get('name', 'Potential')}</div>
                    </div>
                </div>
                """
            
            mitigation_html = ""
            for m in chain.get("mitigation", []):
                mitigation_html += f"""
                <div class="mitigation-item">
                    <span class="priority {m.get('priority', 'medium')}">{m.get('priority', '').upper()}</span>
                    <span>{m.get('action', '')}</span>
                    <code>{m.get('code', '')[:100]}...</code>
                </div>
                """
            
            chains_html += f"""
            <div class="attack-chain">
                <div class="chain-header">
                    <span class="chain-type">{chain.get('type', 'chain').replace('_', ' ').upper()}</span>
                    <h4>{chain.get('name', 'Attack Chain')}</h4>
                    <span class="complexity">{chain.get('complexity', 'medium').upper()} complexity</span>
                </div>
                <p>{chain.get('description', '')}</p>
                <div class="chain-steps">
                    {steps_html}
                </div>
                <div class="chain-impact">
                    <strong>Potential Impact:</strong> {chain.get('impact', 'See steps above')}
                </div>
                <div class="mitigation-section">
                    <h5>Mitigation</h5>
                    {mitigation_html}
                </div>
            </div>
            """
        
        poc_html = ""
        if attack_chains:
            first_chain = attack_chains[0]
            poc = first_chain.get("poc", {})
            if poc:
                tools = ", ".join(poc.get("tools", []))
                payloads = "<br>".join(poc.get("payloads", []))
                steps = "<br>".join(poc.get("steps", []))
                poc_html = f"""
                <div class="poc-section">
                    <h3>Proof of Concept Guide</h3>
                    <p><strong>Recommended Tools:</strong> {tools}</p>
                    <h5>Sample Payloads:</h5>
                    <pre>{payloads}</pre>
                    <h5>Steps:</h5>
                    <pre>{steps}</pre>
                </div>
                """
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ZeroPath Security Report - {scan_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        
        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #00ff88;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #00ff88;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header .subtitle {{ color: #888; }}
        .meta {{ display: flex; gap: 20px; margin-top: 15px; flex-wrap: wrap; }}
        .meta-item {{
            background: rgba(0, 255, 136, 0.1);
            padding: 10px 15px;
            border-radius: 5px;
        }}
        .meta-item strong {{ color: #00ff88; }}
        
        /* Summary */
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #1a1a2e;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .summary-card .count {{
            font-size: 2em;
            font-weight: bold;
        }}
        .summary-card.critical .count {{ color: #ff4444; }}
        .summary-card.high .count {{ color: #ff8800; }}
        .summary-card.medium .count {{ color: #ffcc00; }}
        .summary-card.low .count {{ color: #00ccff; }}
        .summary-card.info .count {{ color: #888; }}
        
        /* Findings */
        .section {{ margin-bottom: 30px; }}
        .section h2 {{
            color: #00ff88;
            border-bottom: 2px solid #00ff88;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .finding {{
            background: #1a1a2e;
            border-left: 4px solid #888;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .finding.critical {{ border-left-color: #ff4444; }}
        .finding.high {{ border-left-color: #ff8800; }}
        .finding.medium {{ border-left-color: #ffcc00; }}
        .finding.low {{ border-left-color: #00ccff; }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .finding-num {{ color: #666; }}
        .severity-badge {{
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .severity-badge.critical {{ background: #ff4444; color: white; }}
        .severity-badge.high {{ background: #ff8800; color: white; }}
        .severity-badge.medium {{ background: #ffcc00; color: black; }}
        .severity-badge.low {{ background: #00ccff; color: black; }}
        .evidence, .cwe {{
            background: #0a0a0f;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        
        /* Attack Chains */
        .attack-chain {{
            background: linear-gradient(135deg, #1a0a2e 0%, #16133e 100%);
            border: 1px solid #8844ff;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .chain-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        .chain-type {{
            background: #8844ff;
            color: white;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.8em;
        }}
        .complexity {{
            background: #333;
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.8em;
        }}
        .chain-steps {{
            background: #0a0a0f;
            border-radius: 8px;
            padding: 15px;
            margin: 15px 0;
        }}
        .chain-step {{
            display: flex;
            gap: 15px;
            padding: 10px 0;
            border-bottom: 1px solid #222;
        }}
        .chain-step:last-child {{ border-bottom: none; }}
        .step-num {{
            background: #8844ff;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.85em;
            height: fit-content;
        }}
        .step-finding {{ color: #888; font-size: 0.9em; margin-top: 5px; }}
        .chain-impact {{
            background: rgba(255, 68, 68, 0.1);
            border-left: 3px solid #ff4444;
            padding: 10px 15px;
            margin: 15px 0;
        }}
        
        /* Mitigation */
        .mitigation-section {{
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #333;
        }}
        .mitigation-section h5 {{ color: #00ff88; margin-bottom: 10px; }}
        .mitigation-item {{
            background: #0a0a0f;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 8px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }}
        .priority {{
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .priority.critical {{ background: #ff4444; color: white; }}
        .priority.high {{ background: #ff8800; color: white; }}
        .priority.medium {{ background: #ffcc00; color: black; }}
        .mitigation-item code {{
            background: #1a1a2e;
            padding: 5px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            color: #00ff88;
        }}
        
        /* PoC Section */
        .poc-section {{
            background: #1a1a2e;
            border: 1px solid #00ccff;
            border-radius: 10px;
            padding: 25px;
            margin-top: 20px;
        }}
        .poc-section h3 {{ color: #00ccff; margin-bottom: 15px; }}
        .poc-section pre {{
            background: #0a0a0f;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        /* Footer */
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            border-top: 1px solid #222;
            margin-top: 30px;
        }}
        .footer a {{ color: #00ff88; text-decoration: none; }}
        
        /* Responsive */
        @media (max-width: 600px) {{
            .header h1 {{ font-size: 1.5em; }}
            .meta {{ flex-direction: column; }}
            .chain-header {{ flex-direction: column; align-items: flex-start; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ZeroPath Security Report</h1>
            <p class="subtitle">Autonomous Exploit Chain Analysis</p>
            <div class="meta">
                <div class="meta-item">
                    <strong>Target:</strong> {target_url}
                </div>
                <div class="meta-item">
                    <strong>Scan ID:</strong> {scan_id}
                </div>
                <div class="meta-item">
                    <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{severity_counts['critical']}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity_counts['high']}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity_counts['medium']}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity_counts['low']}</div>
                <div>Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{severity_counts['info']}</div>
                <div>Info</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔗 Attack Chains ({len(attack_chains)} found)</h2>
            {chains_html if chains_html else '<p>No attack chains identified.</p>'}
        </div>
        
        {poc_html}
        
        <div class="section">
            <h2>📋 All Findings ({len(findings)} total)</h2>
            {findings_html if findings_html else '<p>No vulnerabilities found.</p>'}
        </div>
        
        <div class="footer">
            <p>Generated by <a href="#">ZeroPath</a> - Autonomous Exploit Chain Generator</p>
            <p>This is an automated report. Manual verification recommended.</p>
        </div>
    </div>
</body>
</html>
        """
