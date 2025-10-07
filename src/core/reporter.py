"""
Knox Reporter Module
Generates security audit reports in various formats
"""
import json
from datetime import datetime
from typing import List, Dict, Any

class SecurityReporter:
    """Generate security audit reports"""

    @staticmethod
    def generate_json_report(analysis: Dict[str, Any], output_file: str = None) -> str:
        """Generate JSON report"""
        report = {
            "scan_date": datetime.now().isoformat(),
            "knox_version": "1.0.0",
            "summary": {
                "total_issues": analysis.get("total_issues", 0),
                "critical": analysis.get("critical", 0),
                "high": analysis.get("high", 0),
                "medium": analysis.get("medium", 0),
                "low": analysis.get("low", 0)
            },
            "ai_insights": analysis.get("ai_insights", ""),
            "findings": analysis.get("findings", [])
        }

        report_json = json.dumps(report, indent=2)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_json)

        return report_json

    @staticmethod
    def generate_html_report(analysis: Dict[str, Any], output_file: str = None) -> str:
        """Generate HTML report"""
        findings = analysis.get("findings", [])

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Knox Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #6366f1; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 6px; text-align: center; }}
        .stat-card.critical {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .stat-card.high {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .stat-card.medium {{ background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%); color: #333; }}
        .stat-card h3 {{ margin: 0; font-size: 32px; }}
        .stat-card p {{ margin: 5px 0 0 0; opacity: 0.9; }}
        .finding {{ background: #f9fafb; border-left: 4px solid #6366f1; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .finding.critical {{ border-left-color: #ef4444; }}
        .finding.high {{ border-left-color: #f59e0b; }}
        .finding.medium {{ border-left-color: #eab308; }}
        .finding.low {{ border-left-color: #3b82f6; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .severity-badge {{ padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #fee2e2; color: #991b1b; }}
        .severity-badge.high {{ background: #fed7aa; color: #9a3412; }}
        .severity-badge.medium {{ background: #fef3c7; color: #92400e; }}
        .severity-badge.low {{ background: #dbeafe; color: #1e40af; }}
        .code {{ background: #1f2937; color: #e5e7eb; padding: 12px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 13px; overflow-x: auto; }}
        .ai-insights {{ background: #eff6ff; border: 1px solid #bfdbfe; padding: 20px; border-radius: 6px; margin: 20px 0; }}
        .file-path {{ color: #6366f1; font-family: monospace; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Knox Security Audit Report</h1>
        <p style="color: #666;">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

        <div class="summary">
            <div class="stat-card">
                <h3>{analysis.get('total_issues', 0)}</h3>
                <p>Total Issues</p>
            </div>
            <div class="stat-card critical">
                <h3>{analysis.get('critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card high">
                <h3>{analysis.get('high', 0)}</h3>
                <p>High</p>
            </div>
            <div class="stat-card medium">
                <h3>{analysis.get('medium', 0)}</h3>
                <p>Medium</p>
            </div>
        </div>
"""

        if analysis.get("ai_insights"):
            html += f"""
        <div class="ai-insights">
            <h2>🤖 AI Security Insights</h2>
            <div style="white-space: pre-wrap;">{analysis.get('ai_insights', '')}</div>
        </div>
"""

        html += "<h2>Detailed Findings</h2>"

        for finding in findings:
            severity = finding.get('severity', 'low')
            html += f"""
        <div class="finding {severity}">
            <div class="finding-header">
                <div>
                    <strong>{finding.get('type', 'unknown').replace('_', ' ').title()}</strong>
                    <div class="file-path">{finding.get('file', 'unknown')}:{finding.get('line', '?')}</div>
                </div>
                <span class="severity-badge {severity}">{severity}</span>
            </div>
            <p>{finding.get('message', '')}</p>
            <div class="code">{finding.get('code', '').replace('<', '&lt;').replace('>', '&gt;')}</div>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""

        if output_file:
            with open(output_file, 'w') as f:
                f.write(html)

        return html

    @staticmethod
    def generate_cli_report(analysis: Dict[str, Any]) -> str:
        """Generate CLI-friendly report"""
        output = []
        output.append("\n" + "="*60)
        output.append("🔒 KNOX SECURITY AUDIT REPORT")
        output.append("="*60)

        output.append(f"\n📊 SUMMARY:")
        output.append(f"  Total Issues: {analysis.get('total_issues', 0)}")
        output.append(f"  Critical: {analysis.get('critical', 0)}")
        output.append(f"  High: {analysis.get('high', 0)}")
        output.append(f"  Medium: {analysis.get('medium', 0)}")
        output.append(f"  Low: {analysis.get('low', 0)}")

        if analysis.get("ai_insights"):
            output.append(f"\n🤖 AI INSIGHTS:")
            output.append(f"{analysis.get('ai_insights', '')}")

        output.append(f"\n📋 FINDINGS:")

        for i, finding in enumerate(analysis.get('findings', []), 1):
            severity = finding.get('severity', 'low').upper()
            output.append(f"\n  [{i}] {severity} - {finding.get('type', 'unknown').replace('_', ' ').title()}")
            output.append(f"      File: {finding.get('file', 'unknown')}:{finding.get('line', '?')}")
            output.append(f"      {finding.get('message', '')}")
            if finding.get('code'):
                output.append(f"      Code: {finding.get('code', '')}")

        output.append("\n" + "="*60 + "\n")

        return "\n".join(output)
