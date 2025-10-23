"""
Enhanced Knox UI with GitHub Repository Scanning
Modern, clean interface for security auditing
"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict
import os
import sys
import tempfile
import shutil
import subprocess
import re

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import CodeScanner
from core.analyzer import AISecurityAnalyzer
from core.reporter import SecurityReporter
from integrations.github import GitHubIntegration

app = FastAPI(
    title="Knox Security Auditor",
    description="AI-powered security code auditing with GitHub integration",
    version="2.0.0"
)

# Initialize components
scanner = CodeScanner()
analyzer = AISecurityAnalyzer()
reporter = SecurityReporter()
github = GitHubIntegration()

class GitHubRepoScanRequest(BaseModel):
    repo_url: str
    branch: Optional[str] = "main"
    include_ai_analysis: bool = True

class ScanResult(BaseModel):
    status: str
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    issues: List[Dict]
    ranked_issues: List[Dict]
    ai_insights: Optional[str] = None

def extract_repo_info(repo_url: str) -> tuple:
    """Extract owner and repo name from GitHub URL"""
    # Support both HTTPS and SSH URLs
    patterns = [
        r'github\.com[:/]([^/]+)/([^/\.]+)',
        r'github\.com/([^/]+)/([^/]+)\.git'
    ]

    for pattern in patterns:
        match = re.search(pattern, repo_url)
        if match:
            return match.group(1), match.group(2)

    raise ValueError("Invalid GitHub repository URL")

def clone_repository(repo_url: str, branch: str = "main") -> str:
    """Clone a GitHub repository to a temporary directory"""
    temp_dir = tempfile.mkdtemp(prefix="knox_scan_")

    try:
        # Clone the repository
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir],
            check=True,
            capture_output=True,
            text=True
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {e.stderr}")

def rank_issues(findings: List[Dict]) -> List[Dict]:
    """Rank issues by severity and impact"""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    # Sort by severity, then by file
    ranked = sorted(
        findings,
        key=lambda x: (
            -severity_order.get(x.get('severity', 'low').lower(), 0),
            x.get('file', ''),
            x.get('line', 0)
        )
    )

    return ranked

def generate_solution(finding: Dict) -> str:
    """Generate a solution for a specific vulnerability"""
    solutions = {
        "hardcoded_secret": {
            "fix": "Use environment variables or a secure secrets manager",
            "example": """# Instead of:
api_key = "sk-1234..."

# Use:
import os
api_key = os.getenv('API_KEY')
"""
        },
        "sql_injection": {
            "fix": "Use parameterized queries to prevent SQL injection",
            "example": """# Instead of:
query = f"SELECT * FROM users WHERE id = {user_id}"

# Use:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
"""
        },
        "xss_vulnerability": {
            "fix": "Sanitize and escape user input before rendering",
            "example": """# Instead of:
return f"<div>{user_input}</div>"

# Use:
from html import escape
return f"<div>{escape(user_input)}</div>"
"""
        },
        "insecure_function": {
            "fix": "Use secure cryptographic functions",
            "example": """# Instead of:
import hashlib
hash = hashlib.md5(password.encode())

# Use:
import hashlib
hash = hashlib.sha256(password.encode())
# Or better yet, use bcrypt or argon2
"""
        },
        "command_injection": {
            "fix": "Avoid using shell=True and validate all inputs",
            "example": """# Instead of:
os.system(f"ls {user_input}")

# Use:
import subprocess
subprocess.run(['ls', user_input], check=True)
"""
        }
    }

    vuln_type = finding.get('type', 'unknown')
    return solutions.get(vuln_type, {
        "fix": "Review and fix this security issue",
        "example": "Consult security best practices for your language and framework"
    })

@app.get("/", response_class=HTMLResponse)
async def root():
    """Enhanced UI homepage"""
    return HTMLResponse(content="""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Knox Security Auditor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            color: white;
            margin-bottom: 40px;
            animation: fadeIn 0.6s ease-in;
        }

        .header h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }

        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .main-card {
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: slideUp 0.6s ease-out;
        }

        .input-section {
            margin-bottom: 30px;
        }

        .input-section label {
            display: block;
            font-size: 1.1em;
            font-weight: 600;
            color: #333;
            margin-bottom: 10px;
        }

        .input-group {
            display: flex;
            gap: 10px;
        }

        input[type="text"] {
            flex: 1;
            padding: 15px 20px;
            font-size: 1em;
            border: 2px solid #e2e8f0;
            border-radius: 8px;
            transition: all 0.3s;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .btn {
            padding: 15px 30px;
            font-size: 1em;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .btn-primary:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .options {
            display: flex;
            gap: 20px;
            margin-top: 15px;
        }

        .checkbox-label {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.95em;
            color: #666;
        }

        input[type="checkbox"] {
            width: 18px;
            height: 18px;
            cursor: pointer;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }

        .loading.active {
            display: block;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }

        .results {
            display: none;
            margin-top: 30px;
        }

        .results.active {
            display: block;
            animation: fadeIn 0.6s ease-in;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .summary-card.total {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .summary-card.critical {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .summary-card.high {
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }

        .summary-card.medium {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .summary-card.low {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }

        .summary-card h3 {
            font-size: 2.5em;
            margin-bottom: 5px;
        }

        .summary-card p {
            font-size: 1em;
            opacity: 0.9;
        }

        .issues-list {
            margin-top: 20px;
        }

        .issue-card {
            background: #f8f9fa;
            border-left: 5px solid;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.3s;
        }

        .issue-card:hover {
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .issue-card.critical {
            border-color: #f5576c;
            background: #fff5f5;
        }

        .issue-card.high {
            border-color: #feb47b;
            background: #fffaf0;
        }

        .issue-card.medium {
            border-color: #4facfe;
            background: #f0f9ff;
        }

        .issue-card.low {
            border-color: #43e97b;
            background: #f0fdf4;
        }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }

        .issue-title {
            flex: 1;
        }

        .issue-title h4 {
            font-size: 1.2em;
            color: #333;
            margin-bottom: 5px;
        }

        .issue-location {
            font-size: 0.9em;
            color: #666;
        }

        .severity-badge {
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }

        .severity-badge.critical {
            background: #f5576c;
        }

        .severity-badge.high {
            background: #feb47b;
        }

        .severity-badge.medium {
            background: #4facfe;
        }

        .severity-badge.low {
            background: #43e97b;
        }

        .code-block {
            background: #1f2937;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            margin: 15px 0;
            font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }

        .solution-section {
            margin-top: 15px;
            padding: 15px;
            background: white;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }

        .solution-section h5 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 1em;
        }

        .solution-section p {
            color: #666;
            margin-bottom: 10px;
            line-height: 1.6;
        }

        .ai-insights {
            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
            border-radius: 12px;
            padding: 25px;
            margin: 25px 0;
            border: 2px solid #667eea30;
        }

        .ai-insights h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }

        .ai-insights p {
            color: #333;
            line-height: 1.8;
            white-space: pre-line;
        }

        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
            padding-top: 30px;
            border-top: 1px solid #e2e8f0;
        }

        .feature {
            text-align: center;
            padding: 20px;
        }

        .feature-icon {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .feature h4 {
            color: #333;
            margin-bottom: 8px;
        }

        .feature p {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Knox Security Auditor</h1>
            <p>AI-Powered Security Analysis for GitHub Repositories</p>
        </div>

        <div class="main-card">
            <div class="input-section">
                <label for="repoUrl">GitHub Repository URL</label>
                <div class="input-group">
                    <input
                        type="text"
                        id="repoUrl"
                        placeholder="https://github.com/username/repository"
                        value=""
                    />
                    <button class="btn btn-primary" onclick="scanRepository()" id="scanBtn">
                        Scan Repository
                    </button>
                </div>
                <div class="options">
                    <label class="checkbox-label">
                        <input type="checkbox" id="aiAnalysis" checked />
                        Enable AI-Powered Analysis
                    </label>
                    <label class="checkbox-label">
                        <input type="text" id="branch" placeholder="Branch (default: main)" style="flex: none; width: 200px;" />
                    </label>
                </div>
            </div>

            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Scanning repository... This may take a few moments.</p>
            </div>

            <div class="results" id="results">
                <!-- Results will be inserted here -->
            </div>

            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🔍</div>
                    <h4>Smart Detection</h4>
                    <p>Identifies SQL injection, XSS, secrets, and more</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🤖</div>
                    <h4>AI Analysis</h4>
                    <p>GPT-powered insights and recommendations</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">📊</div>
                    <h4>Ranked Issues</h4>
                    <p>Prioritized by severity and impact</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">💡</div>
                    <h4>Fix Suggestions</h4>
                    <p>Code examples and remediation steps</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        async function scanRepository() {
            const repoUrl = document.getElementById('repoUrl').value.trim();
            const branch = document.getElementById('branch').value.trim() || 'main';
            const aiAnalysis = document.getElementById('aiAnalysis').checked;
            const scanBtn = document.getElementById('scanBtn');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');

            if (!repoUrl) {
                alert('Please enter a GitHub repository URL');
                return;
            }

            // Show loading state
            scanBtn.disabled = true;
            loading.classList.add('active');
            results.classList.remove('active');
            results.innerHTML = '';

            try {
                const response = await fetch('/api/scan-repo', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        repo_url: repoUrl,
                        branch: branch,
                        include_ai_analysis: aiAnalysis
                    })
                });

                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.detail || 'Scan failed');
                }

                displayResults(data);
            } catch (error) {
                results.innerHTML = `
                    <div class="error-message">
                        <strong>Error:</strong> ${error.message}
                    </div>
                `;
                results.classList.add('active');
            } finally {
                scanBtn.disabled = false;
                loading.classList.remove('active');
            }
        }

        function displayResults(data) {
            const results = document.getElementById('results');

            let html = `
                <div class="summary-cards">
                    <div class="summary-card total">
                        <h3>${data.total_issues}</h3>
                        <p>Total Issues</p>
                    </div>
                    <div class="summary-card critical">
                        <h3>${data.critical}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="summary-card high">
                        <h3>${data.high}</h3>
                        <p>High</p>
                    </div>
                    <div class="summary-card medium">
                        <h3>${data.medium}</h3>
                        <p>Medium</p>
                    </div>
                    <div class="summary-card low">
                        <h3>${data.low}</h3>
                        <p>Low</p>
                    </div>
                </div>
            `;

            if (data.ai_insights) {
                html += `
                    <div class="ai-insights">
                        <h3>🤖 AI Security Insights</h3>
                        <p>${data.ai_insights}</p>
                    </div>
                `;
            }

            if (data.ranked_issues && data.ranked_issues.length > 0) {
                html += '<div class="issues-list">';
                html += '<h3 style="margin-bottom: 20px; color: #333;">📋 Security Issues (Ranked by Severity)</h3>';

                data.ranked_issues.forEach((issue, index) => {
                    html += `
                        <div class="issue-card ${issue.severity}">
                            <div class="issue-header">
                                <div class="issue-title">
                                    <h4>${index + 1}. ${issue.message || issue.type}</h4>
                                    <div class="issue-location">
                                        📁 ${issue.file} &nbsp; 📍 Line ${issue.line}
                                    </div>
                                </div>
                                <span class="severity-badge ${issue.severity}">${issue.severity}</span>
                            </div>

                            ${issue.code ? `
                                <div class="code-block">${escapeHtml(issue.code)}</div>
                            ` : ''}

                            ${issue.solution ? `
                                <div class="solution-section">
                                    <h5>💡 How to Fix</h5>
                                    <p>${issue.solution.fix}</p>
                                    ${issue.solution.example ? `
                                        <div class="code-block">${escapeHtml(issue.solution.example)}</div>
                                    ` : ''}
                                </div>
                            ` : ''}
                        </div>
                    `;
                });

                html += '</div>';
            } else {
                html += '<p style="text-align: center; color: #666; padding: 40px;">No security issues found! 🎉</p>';
            }

            results.innerHTML = html;
            results.classList.add('active');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Allow Enter key to trigger scan
        document.getElementById('repoUrl').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                scanRepository();
            }
        });
    </script>
</body>
</html>
    """)

@app.post("/api/scan-repo")
async def scan_github_repo(request: GitHubRepoScanRequest):
    """Scan a complete GitHub repository"""
    try:
        # Extract owner and repo from URL
        owner, repo = extract_repo_info(request.repo_url)

        # Clone the repository
        repo_path = clone_repository(request.repo_url, request.branch)

        try:
            # Scan the repository
            findings = scanner.scan_directory(repo_path)

            # Update file paths to be relative to repo root
            for finding in findings:
                if 'file' in finding:
                    finding['file'] = finding['file'].replace(repo_path + '/', '')

            # Rank issues
            ranked_issues = rank_issues(findings)

            # Add solutions to each issue
            for issue in ranked_issues:
                issue['solution'] = generate_solution(issue)

            # Count by severity
            critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
            high = len([f for f in findings if f.get('severity', '').lower() == 'high'])
            medium = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
            low = len([f for f in findings if f.get('severity', '').lower() == 'low'])

            # AI Analysis
            ai_insights = None
            if request.include_ai_analysis and os.getenv('OPENAI_API_KEY'):
                analysis = analyzer.analyze_findings(findings)
                ai_insights = analysis.get('ai_insights', '')

            result = {
                "status": "success",
                "repository": f"{owner}/{repo}",
                "branch": request.branch,
                "total_issues": len(findings),
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "issues": findings,
                "ranked_issues": ranked_issues[:50],  # Limit to top 50
                "ai_insights": ai_insights
            }

            return result

        finally:
            # Cleanup: remove cloned repository
            shutil.rmtree(repo_path, ignore_errors=True)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Knox Security Auditor",
        "version": "2.0.0",
        "openai_configured": bool(os.getenv('OPENAI_API_KEY')),
        "github_configured": bool(os.getenv('GITHUB_TOKEN'))
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    print(f"🚀 Starting Knox Security Auditor on port {port}")
    print(f"🌐 Open http://localhost:{port} in your browser")
    uvicorn.run(app, host="0.0.0.0", port=port)
