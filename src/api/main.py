"""
Knox API Server
FastAPI-based REST API for security auditing
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import CodeScanner
from core.analyzer import AISecurityAnalyzer
from core.reporter import SecurityReporter
from integrations.github import GitHubIntegration

app = FastAPI(
    title="Knox Security Auditor API",
    description="AI-powered security code auditing service",
    version="1.0.0"
)

# Initialize components
scanner = CodeScanner()
analyzer = AISecurityAnalyzer()
reporter = SecurityReporter()
github = GitHubIntegration()

class ScanRequest(BaseModel):
    repository_url: Optional[str] = None
    code: Optional[str] = None
    language: Optional[str] = "python"
    include_ai_analysis: bool = True

class PRScanRequest(BaseModel):
    owner: str
    repo: str
    pr_number: int
    post_comment: bool = False

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Knox Security Auditor</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                   max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
            .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #6366f1; border-bottom: 3px solid #6366f1; padding-bottom: 10px; }
            .endpoint { background: #f9fafb; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #6366f1; }
            .method { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 600; font-size: 12px; }
            .get { background: #10b981; color: white; }
            .post { background: #3b82f6; color: white; }
            code { background: #1f2937; color: #e5e7eb; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
            a { color: #6366f1; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Knox Security Auditor API</h1>
            <p>AI-powered security code auditing service for identifying vulnerabilities and security issues.</p>

            <h2>Available Endpoints:</h2>

            <div class="endpoint">
                <span class="method get">GET</span>
                <strong>/health</strong>
                <p>Health check endpoint</p>
            </div>

            <div class="endpoint">
                <span class="method post">POST</span>
                <strong>/scan/code</strong>
                <p>Scan a code snippet for security vulnerabilities</p>
                <code>{"code": "your_code_here", "language": "python"}</code>
            </div>

            <div class="endpoint">
                <span class="method post">POST</span>
                <strong>/scan/github-pr</strong>
                <p>Scan a GitHub pull request</p>
                <code>{"owner": "username", "repo": "reponame", "pr_number": 123}</code>
            </div>

            <div class="endpoint">
                <span class="method get">GET</span>
                <strong>/docs</strong>
                <p>Interactive API documentation (Swagger UI)</p>
            </div>

            <h3>Features:</h3>
            <ul>
                <li>✅ Automated vulnerability detection</li>
                <li>✅ AI-powered analysis with OpenAI</li>
                <li>✅ GitHub PR integration</li>
                <li>✅ Multi-language support</li>
                <li>✅ Detailed HTML/JSON reports</li>
            </ul>

            <p><a href="/docs">📖 View Full API Documentation</a></p>
        </div>
    </body>
    </html>
    """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Knox Security Auditor",
        "version": "1.0.0",
        "openai_configured": bool(os.getenv('OPENAI_API_KEY')),
        "github_configured": bool(os.getenv('GITHUB_TOKEN'))
    }

@app.post("/scan/code")
async def scan_code(request: ScanRequest):
    """Scan a code snippet for security vulnerabilities"""
    if not request.code:
        raise HTTPException(status_code=400, detail="Code is required")

    try:
        # For code snippets, we'll use AI analysis
        if request.include_ai_analysis:
            result = analyzer.analyze_code_snippet(request.code, request.language)
            return result
        else:
            return {
                "message": "Basic scanning not implemented for code snippets. Use include_ai_analysis=true",
                "code": request.code
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@app.post("/scan/github-pr")
async def scan_github_pr(request: PRScanRequest):
    """Scan a GitHub pull request for security issues"""
    try:
        # Get PR files
        files = github.get_pr_files(request.owner, request.repo, request.pr_number)

        if not files:
            return {
                "message": "No files found or GitHub token not configured",
                "owner": request.owner,
                "repo": request.repo,
                "pr_number": request.pr_number
            }

        # Scan each file
        all_findings = []
        for file in files:
            if file.get('status') != 'removed':
                # Get file content
                content = github.get_file_content(
                    request.owner,
                    request.repo,
                    file['filename'],
                    file.get('sha', 'main')
                )

                if content:
                    # Create temporary file for scanning
                    import tempfile
                    with tempfile.NamedTemporaryFile(mode='w', suffix=f"_{file['filename']}", delete=False) as tmp:
                        tmp.write(content)
                        tmp_path = tmp.name

                    findings = scanner.scan_file(tmp_path)

                    # Update file paths to show actual repo paths
                    for finding in findings:
                        finding['file'] = file['filename']

                    all_findings.extend(findings)

                    # Clean up
                    os.unlink(tmp_path)

        # Analyze findings
        analysis = analyzer.analyze_findings(all_findings)

        # Post comment if requested
        if request.post_comment and all_findings:
            comment = f"""## 🔒 Knox Security Audit Results

**Summary:**
- Total Issues: {analysis['total_issues']}
- Critical: {analysis['critical']}
- High: {analysis['high']}
- Medium: {analysis['medium']}

{analysis.get('ai_insights', '')}

View full details in the API response.
"""
            github.post_pr_comment(request.owner, request.repo, request.pr_number, comment)

        return analysis

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PR scan failed: {str(e)}")

@app.get("/report/demo")
async def demo_report():
    """Generate a demo HTML report"""
    demo_analysis = {
        "total_issues": 5,
        "critical": 2,
        "high": 2,
        "medium": 1,
        "low": 0,
        "ai_insights": "Demo report showing Knox's security analysis capabilities.\n\nTop priorities:\n1. Fix hardcoded API keys\n2. Implement parameterized SQL queries\n3. Enable SSL certificate verification",
        "findings": [
            {
                "file": "src/auth.py",
                "line": 42,
                "type": "hardcoded_secret",
                "severity": "critical",
                "message": "Potential hardcoded API Key detected",
                "code": "api_key = 'sk-1234567890abcdef'"
            },
            {
                "file": "src/database.py",
                "line": 78,
                "type": "sql_injection",
                "severity": "critical",
                "message": "Potential SQL injection vulnerability - use parameterized queries",
                "code": "query = f\"SELECT * FROM users WHERE id = {user_id}\""
            },
            {
                "file": "src/api.py",
                "line": 156,
                "type": "xss_vulnerability",
                "severity": "high",
                "message": "Potential XSS vulnerability - sanitize user input",
                "code": "return f\"<div>{user_input}</div>\""
            },
            {
                "file": "src/utils.py",
                "line": 23,
                "type": "insecure_function",
                "severity": "high",
                "message": "Weak hashing algorithm MD5",
                "code": "hash = hashlib.md5(password.encode())"
            },
            {
                "file": "src/config.py",
                "line": 12,
                "type": "authentication_issue",
                "severity": "medium",
                "message": "SSL certificate verification disabled",
                "code": "verify=False"
            }
        ]
    }

    html = reporter.generate_html_report(demo_analysis)
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
