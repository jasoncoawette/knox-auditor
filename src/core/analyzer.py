"""
Knox AI Analyzer Module
Uses OpenAI to perform intelligent security analysis
"""
import os
from typing import List, Dict, Any
from openai import OpenAI

class AISecurityAnalyzer:
    """AI-powered security analysis using OpenAI"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None

    def analyze_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze findings with AI to provide context and recommendations"""
        if not self.client:
            return {
                "summary": f"Found {len(findings)} potential security issues",
                "analysis": "AI analysis unavailable - OpenAI API key not configured",
                "findings": findings
            }

        # Group findings by severity
        critical = [f for f in findings if f.get('severity') == 'critical']
        high = [f for f in findings if f.get('severity') == 'high']
        medium = [f for f in findings if f.get('severity') == 'medium']
        low = [f for f in findings if f.get('severity') == 'low']

        # Create summary
        summary = {
            "total_issues": len(findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "findings": findings
        }

        # Get AI analysis for critical issues
        if critical or high:
            try:
                ai_analysis = self._get_ai_insights(critical + high)
                summary["ai_insights"] = ai_analysis
            except Exception as e:
                summary["ai_insights"] = f"AI analysis failed: {str(e)}"

        return summary

    def _get_ai_insights(self, findings: List[Dict[str, Any]]) -> str:
        """Get AI insights for high-priority findings"""
        if not findings:
            return "No critical or high-severity issues found."

        # Prepare findings summary for AI
        findings_text = "\n".join([
            f"- {f.get('type', 'unknown')}: {f.get('message', '')} in {f.get('file', 'unknown')}:{f.get('line', '?')}"
            for f in findings[:10]  # Limit to top 10 to save tokens
        ])

        prompt = f"""You are a security expert analyzing code vulnerabilities.

The following security issues were detected:

{findings_text}

Provide:
1. A brief executive summary (2-3 sentences)
2. Top 3 most critical issues to fix first
3. General security recommendations

Keep response concise and actionable."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a security code auditor providing concise, actionable insights."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.7
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI analysis unavailable: {str(e)}"

    def analyze_code_snippet(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze a specific code snippet for vulnerabilities"""
        if not self.client:
            return {"error": "OpenAI API key not configured"}

        prompt = f"""Analyze this {language} code for security vulnerabilities:

```{language}
{code}
```

Identify:
1. Security vulnerabilities
2. Severity (critical/high/medium/low)
3. Specific fix recommendations

Be concise and specific."""

        try:
            response = self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a security code auditor. Provide specific, actionable security feedback."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
                temperature=0.5
            )
            return {
                "analysis": response.choices[0].message.content,
                "code": code,
                "language": language
            }
        except Exception as e:
            return {"error": str(e)}
