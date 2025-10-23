"""
Knox Security Auditor - Streamlit UI
Dark theme with green text, red issues, yellow warnings
"""
import streamlit as st
import os
import sys
import tempfile
import shutil
import subprocess
import re
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.scanner import CodeScanner
from core.analyzer import AISecurityAnalyzer
from core.reporter import SecurityReporter

# Page configuration
st.set_page_config(
    page_title="Knox Security Auditor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme with green/red/yellow colors
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #0d1117;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #161b22;
    }

    /* Text colors */
    .stMarkdown, .stText, label {
        color: #58a6ff !important;
    }

    h1, h2, h3 {
        color: #7ee787 !important;
    }

    /* Input fields */
    .stTextInput input {
        background-color: #0d1117;
        color: #7ee787;
        border: 2px solid #30363d;
    }

    .stTextInput input:focus {
        border-color: #7ee787;
    }

    /* Buttons */
    .stButton button {
        background: linear-gradient(135deg, #238636 0%, #2ea043 100%);
        color: white;
        border: none;
        font-weight: 600;
        padding: 0.5rem 2rem;
        transition: all 0.3s;
    }

    .stButton button:hover {
        background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%);
        box-shadow: 0 0 20px rgba(126, 231, 135, 0.4);
    }

    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2.5rem;
        font-weight: bold;
    }

    /* Success/Error boxes */
    .stAlert {
        background-color: #161b22;
        border-left: 4px solid;
    }

    /* Code blocks */
    .stCodeBlock {
        background-color: #0d1117;
        border: 1px solid #30363d;
    }

    /* Divider */
    hr {
        border-color: #30363d;
    }

    /* Custom metric cards */
    .metric-card {
        padding: 1.5rem;
        border-radius: 8px;
        border: 2px solid;
        margin: 0.5rem 0;
        background-color: #161b22;
    }

    .metric-critical {
        border-color: #da3633;
        background: linear-gradient(135deg, #da363320 0%, #da363310 100%);
    }

    .metric-high {
        border-color: #f85149;
        background: linear-gradient(135deg, #f8514920 0%, #f8514910 100%);
    }

    .metric-medium {
        border-color: #d29922;
        background: linear-gradient(135deg, #d2992220 0%, #d2992210 100%);
    }

    .metric-low {
        border-color: #58a6ff;
        background: linear-gradient(135deg, #58a6ff20 0%, #58a6ff10 100%);
    }

    .metric-total {
        border-color: #7ee787;
        background: linear-gradient(135deg, #7ee78720 0%, #7ee78710 100%);
    }

    /* Issue cards */
    .issue-card {
        padding: 1.5rem;
        margin: 1rem 0;
        border-radius: 8px;
        border-left: 5px solid;
        background-color: #161b22;
    }

    .issue-critical {
        border-color: #da3633;
    }

    .issue-high {
        border-color: #f85149;
    }

    .issue-medium {
        border-color: #d29922;
    }

    .issue-low {
        border-color: #58a6ff;
    }

    .issue-title {
        color: #7ee787;
        font-size: 1.2rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }

    .issue-location {
        color: #58a6ff;
        font-size: 0.9rem;
        margin-bottom: 1rem;
    }

    .severity-badge {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        border-radius: 4px;
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
    }

    .badge-critical {
        background-color: #da3633;
        color: white;
    }

    .badge-high {
        background-color: #f85149;
        color: white;
    }

    .badge-medium {
        background-color: #d29922;
        color: white;
    }

    .badge-low {
        background-color: #58a6ff;
        color: white;
    }

    /* Spinner */
    .stSpinner > div {
        border-top-color: #7ee787 !important;
    }
</style>
""", unsafe_allow_html=True)

# Initialize components
@st.cache_resource
def init_scanner():
    return CodeScanner()

@st.cache_resource
def init_analyzer():
    return AISecurityAnalyzer()

scanner = init_scanner()
analyzer = init_analyzer()

def extract_repo_info(repo_url: str) -> Tuple[str, str]:
    """Extract owner and repo name from GitHub URL"""
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
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir],
            check=True,
            capture_output=True,
            text=True,
            timeout=60
        )
        return temp_dir
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {e.stderr}")
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception("Repository clone timed out")

def rank_issues(findings: List[Dict]) -> List[Dict]:
    """Rank issues by severity"""
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    return sorted(
        findings,
        key=lambda x: (
            -severity_order.get(x.get('severity', 'low').lower(), 0),
            x.get('file', ''),
            x.get('line', 0)
        )
    )

def generate_solution(finding: Dict) -> Dict:
    """Generate a solution for a specific vulnerability"""
    solutions = {
        "hardcoded_secret": {
            "fix": "Use environment variables or a secure secrets manager",
            "example": """# Instead of:
api_key = "sk-1234..."

# Use:
import os
api_key = os.getenv('API_KEY')"""
        },
        "sql_injection": {
            "fix": "Use parameterized queries to prevent SQL injection",
            "example": """# Instead of:
query = f"SELECT * FROM users WHERE id = {user_id}"

# Use:
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))"""
        },
        "xss_vulnerability": {
            "fix": "Sanitize and escape user input before rendering",
            "example": """# Instead of:
return f"<div>{user_input}</div>"

# Use:
from html import escape
return f"<div>{escape(user_input)}</div>" """
        },
        "insecure_function": {
            "fix": "Use secure cryptographic functions",
            "example": """# Instead of:
hash = hashlib.md5(password.encode())

# Use:
hash = hashlib.sha256(password.encode())
# Or better: use bcrypt or argon2"""
        },
        "command_injection": {
            "fix": "Avoid shell=True and validate all inputs",
            "example": """# Instead of:
os.system(f"ls {user_input}")

# Use:
subprocess.run(['ls', user_input], check=True)"""
        }
    }

    vuln_type = finding.get('type', 'unknown')
    return solutions.get(vuln_type, {
        "fix": "Review and fix this security issue",
        "example": "Consult security best practices for your language"
    })

# Header
st.markdown("<h1 style='text-align: center;'>🔒 Knox Security Auditor</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #7ee787; font-size: 1.2rem;'>AI-Powered Security Analysis for GitHub Repositories</p>", unsafe_allow_html=True)
st.markdown("---")

# Sidebar
with st.sidebar:
    st.markdown("## ⚙️ Configuration")

    repo_url = st.text_input(
        "🔗 GitHub Repository URL",
        placeholder="https://github.com/username/repository",
        help="Enter the full URL of the GitHub repository to scan"
    )

    branch = st.text_input(
        "🌿 Branch Name",
        value="main",
        help="Specify which branch to scan"
    )

    enable_ai = st.checkbox(
        "🤖 Enable AI Analysis",
        value=True,
        help="Use OpenAI for enhanced security insights"
    )

    st.markdown("---")

    scan_button = st.button("🚀 Scan Repository", type="primary", use_container_width=True)

    st.markdown("---")
    st.markdown("### 📊 Features")
    st.markdown("✅ Smart Detection")
    st.markdown("✅ AI-Powered Insights")
    st.markdown("✅ Ranked Issues")
    st.markdown("✅ Fix Suggestions")

    st.markdown("---")
    st.markdown("### 🔐 Detects")
    st.markdown("🔴 **Critical**: Secrets, API Keys")
    st.markdown("🔴 **High**: SQL Injection, XSS")
    st.markdown("🟡 **Medium**: Weak Crypto")
    st.markdown("🟢 **Low**: Other Issues")

# Main content
if scan_button:
    if not repo_url:
        st.error("❌ Please enter a GitHub repository URL")
    else:
        try:
            # Extract repo info
            owner, repo = extract_repo_info(repo_url)

            st.info(f"📡 Scanning repository: **{owner}/{repo}** (branch: **{branch}**)")

            # Progress bar
            progress_bar = st.progress(0)
            status_text = st.empty()

            # Clone repository
            status_text.text("🔄 Cloning repository...")
            progress_bar.progress(20)
            repo_path = clone_repository(repo_url, branch)

            try:
                # Scan repository
                status_text.text("🔍 Scanning for vulnerabilities...")
                progress_bar.progress(50)
                findings = scanner.scan_directory(repo_path)

                # Update file paths
                for finding in findings:
                    if 'file' in finding:
                        finding['file'] = finding['file'].replace(repo_path + '/', '')

                # Rank issues
                status_text.text("📊 Ranking issues by severity...")
                progress_bar.progress(70)
                ranked_issues = rank_issues(findings)

                # Add solutions
                for issue in ranked_issues:
                    issue['solution'] = generate_solution(issue)

                # Count by severity
                critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
                high = len([f for f in findings if f.get('severity', '').lower() == 'high'])
                medium = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
                low = len([f for f in findings if f.get('severity', '').lower() == 'low'])

                # AI Analysis
                ai_insights = None
                if enable_ai and os.getenv('OPENAI_API_KEY'):
                    status_text.text("🤖 Running AI analysis...")
                    progress_bar.progress(90)
                    analysis = analyzer.analyze_findings(findings)
                    ai_insights = analysis.get('ai_insights', '')

                progress_bar.progress(100)
                status_text.text("✅ Scan complete!")

                st.markdown("---")

                # Summary metrics
                st.markdown("## 📊 Scan Results")

                col1, col2, col3, col4, col5 = st.columns(5)

                with col1:
                    st.markdown(f"""
                    <div class="metric-card metric-total">
                        <div style="text-align: center;">
                            <div style="font-size: 2.5rem; font-weight: bold; color: #7ee787;">{len(findings)}</div>
                            <div style="color: #7ee787;">Total Issues</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    st.markdown(f"""
                    <div class="metric-card metric-critical">
                        <div style="text-align: center;">
                            <div style="font-size: 2.5rem; font-weight: bold; color: #da3633;">{critical}</div>
                            <div style="color: #da3633;">Critical</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown(f"""
                    <div class="metric-card metric-high">
                        <div style="text-align: center;">
                            <div style="font-size: 2.5rem; font-weight: bold; color: #f85149;">{high}</div>
                            <div style="color: #f85149;">High</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col4:
                    st.markdown(f"""
                    <div class="metric-card metric-medium">
                        <div style="text-align: center;">
                            <div style="font-size: 2.5rem; font-weight: bold; color: #d29922;">{medium}</div>
                            <div style="color: #d29922;">Medium</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                with col5:
                    st.markdown(f"""
                    <div class="metric-card metric-low">
                        <div style="text-align: center;">
                            <div style="font-size: 2.5rem; font-weight: bold; color: #58a6ff;">{low}</div>
                            <div style="color: #58a6ff;">Low</div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                # AI Insights
                if ai_insights:
                    st.markdown("---")
                    st.markdown("## 🤖 AI Security Insights")
                    st.info(ai_insights)

                # Issues list
                if ranked_issues:
                    st.markdown("---")
                    st.markdown("## 🔍 Security Issues (Ranked by Severity)")

                    for idx, issue in enumerate(ranked_issues, 1):
                        severity = issue.get('severity', 'low').lower()
                        severity_colors = {
                            'critical': '#da3633',
                            'high': '#f85149',
                            'medium': '#d29922',
                            'low': '#58a6ff'
                        }

                        with st.expander(f"**{idx}. {issue.get('message', issue.get('type', 'Security Issue'))}** - {severity.upper()}", expanded=(idx <= 3)):
                            col1, col2 = st.columns([3, 1])

                            with col1:
                                st.markdown(f"**📁 File:** `{issue.get('file', 'Unknown')}`")
                                st.markdown(f"**📍 Line:** `{issue.get('line', 'N/A')}`")

                            with col2:
                                st.markdown(f"""
                                <div class="severity-badge badge-{severity}">
                                    {severity.upper()}
                                </div>
                                """, unsafe_allow_html=True)

                            if issue.get('code'):
                                st.markdown("**🔻 Vulnerable Code:**")
                                st.code(issue['code'], language='python')

                            if issue.get('solution'):
                                st.markdown("**💡 How to Fix:**")
                                st.success(issue['solution']['fix'])

                                if issue['solution'].get('example'):
                                    st.markdown("**📝 Secure Example:**")
                                    st.code(issue['solution']['example'], language='python')
                else:
                    st.success("🎉 No security issues found! Your repository looks secure.")

            finally:
                # Cleanup
                shutil.rmtree(repo_path, ignore_errors=True)

        except Exception as e:
            st.error(f"❌ Error: {str(e)}")

else:
    # Welcome screen
    st.markdown("""
    <div style='text-align: center; padding: 3rem; color: #7ee787;'>
        <h2 style='color: #7ee787;'>👈 Enter a GitHub Repository URL to Start</h2>
        <p style='color: #58a6ff; font-size: 1.1rem;'>Knox will scan the repository and identify security vulnerabilities</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("""
        <div style='padding: 1.5rem; background-color: #161b22; border-radius: 8px; border: 2px solid #30363d;'>
            <h3 style='color: #7ee787; text-align: center;'>🔍 Smart Detection</h3>
            <p style='color: #58a6ff; text-align: center;'>Identifies SQL injection, XSS, hardcoded secrets, and more</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
        <div style='padding: 1.5rem; background-color: #161b22; border-radius: 8px; border: 2px solid #30363d;'>
            <h3 style='color: #7ee787; text-align: center;'>🤖 AI-Powered</h3>
            <p style='color: #58a6ff; text-align: center;'>GPT-powered insights and intelligent recommendations</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown("""
        <div style='padding: 1.5rem; background-color: #161b22; border-radius: 8px; border: 2px solid #30363d;'>
            <h3 style='color: #7ee787; text-align: center;'>💡 Fix Suggestions</h3>
            <p style='color: #58a6ff; text-align: center;'>Code examples and step-by-step remediation guides</p>
        </div>
        """, unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("<p style='text-align: center; color: #58a6ff;'>Built with ❤️ for the security community | Knox Security Auditor v2.0</p>", unsafe_allow_html=True)
