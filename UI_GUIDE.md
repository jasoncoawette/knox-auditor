# Knox Security Auditor - UI Guide

## 🎨 Enhanced Web Interface

Knox now includes a beautiful, modern web interface for scanning GitHub repositories!

## 🚀 Quick Start

### Option 1: Using the Startup Script
```bash
./start_ui.sh
```

### Option 2: Manual Start
```bash
python3 -m src.api.enhanced_ui
```

The UI will be available at: **http://localhost:8080**

## ✨ Features

### 🔍 GitHub Repository Scanning
- **Full Repository Analysis**: Scan any public GitHub repository
- **Branch Selection**: Choose which branch to scan (defaults to `main`)
- **AI-Powered Insights**: Get intelligent security recommendations from GPT

### 📊 Issue Ranking & Prioritization
- **Automatic Severity Ranking**: Issues sorted by Critical → High → Medium → Low
- **Smart Prioritization**: Most dangerous vulnerabilities displayed first
- **Visual Severity Badges**: Color-coded badges for easy identification

### 💡 Solution Generation
- **Fix Recommendations**: Every issue includes a "How to Fix" section
- **Code Examples**: See secure code alternatives
- **Best Practices**: Learn proper security patterns

### 🎯 Vulnerability Detection
Knox detects:
- **Critical**: Hardcoded secrets, API keys, passwords
- **High**: SQL injection, XSS, command injection, insecure deserialization
- **Medium**: Weak cryptography (MD5, SHA1), debug mode enabled
- **Low**: Other security concerns

## 🎨 UI Components

### Summary Cards
Beautiful gradient cards showing:
- Total issues found
- Critical issues count
- High severity issues
- Medium severity issues
- Low severity issues

### AI Insights Section
When AI analysis is enabled, you'll see:
- Overall security assessment
- Top priority fixes
- Risk analysis
- Recommendations

### Issue Cards
Each issue displays:
- **Severity Badge**: Visual indicator of risk level
- **Location**: File path and line number
- **Vulnerable Code**: The problematic code snippet
- **Fix Solution**: How to remediate the issue
- **Code Example**: Secure alternative implementation

## 📖 Usage

### Scanning a Repository

1. **Enter Repository URL**
   ```
   https://github.com/username/repository
   ```

2. **Optional: Specify Branch**
   - Leave blank for `main` branch
   - Or enter branch name (e.g., `develop`, `feature/new-auth`)

3. **Enable/Disable AI Analysis**
   - Check the box for GPT-powered insights
   - Uncheck for faster scanning without AI

4. **Click "Scan Repository"**
   - Wait for the scan to complete (typically 10-30 seconds)
   - Results will appear below

### Understanding Results

**Critical Issues** 🔴
- Require immediate attention
- Could lead to data breaches or system compromise
- Example: Hardcoded API keys, SQL injection

**High Issues** 🟠
- Serious security concerns
- Should be fixed soon
- Example: XSS vulnerabilities, weak crypto

**Medium Issues** 🔵
- Important but not urgent
- Fix in next sprint
- Example: Debug mode enabled, missing security headers

**Low Issues** 🟢
- Minor concerns
- Address when convenient
- Example: Code quality issues with security implications

## 🛠️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```env
# OpenAI Configuration (for AI analysis)
OPENAI_API_KEY=your_openai_api_key_here

# GitHub Configuration (for private repos)
GITHUB_TOKEN=your_github_token_here
```

### Without API Keys
- Repository scanning works without any API keys (for public repos)
- AI analysis requires an OpenAI API key
- Private repository scanning requires a GitHub token

## 🎯 Example Workflows

### Workflow 1: Quick Security Check
```
1. Paste GitHub repo URL
2. Leave AI analysis enabled
3. Click "Scan Repository"
4. Review critical and high issues first
5. Click on issues to see fix suggestions
```

### Workflow 2: Detailed Code Review
```
1. Scan repository with AI enabled
2. Read AI insights for overall assessment
3. Work through issues by severity
4. Use code examples to implement fixes
5. Re-scan to verify fixes
```

### Workflow 3: Pre-Deployment Audit
```
1. Specify production branch
2. Enable AI analysis
3. Scan repository
4. Ensure zero critical issues
5. Document high/medium issues for backlog
```

## 🔐 Security & Privacy

- **No Data Storage**: Repositories are cloned temporarily and deleted after scanning
- **Local Processing**: Code analysis happens on your machine
- **API Security**: OpenAI API only receives code snippets, not full repos
- **Private Repos**: Requires GitHub token with appropriate permissions

## 🎨 UI Customization

The UI uses a modern gradient design with:
- Responsive layout (works on desktop and mobile)
- Smooth animations and transitions
- Color-coded severity levels
- Clean, readable typography
- Dark code blocks for better contrast

## 📱 Browser Compatibility

Tested on:
- ✅ Chrome/Chromium
- ✅ Firefox
- ✅ Safari
- ✅ Edge

## 🐛 Troubleshooting

### Server won't start
```bash
# Check if port 8080 is in use
lsof -i :8080

# Use a different port
PORT=3000 python3 -m src.api.enhanced_ui
```

### No results showing
- Verify the repository URL is correct
- Check that the branch exists
- Ensure the repository is public (or you have a GitHub token)

### AI analysis not working
- Verify OPENAI_API_KEY is set in .env
- Check your OpenAI API quota
- Try scanning without AI first

### Scan taking too long
- Large repositories may take 1-2 minutes
- Consider scanning specific branches
- Check your internet connection for cloning

## 🚀 Advanced Features

### API Endpoints

The UI is built on FastAPI with these endpoints:

```
GET  /               - Web UI
GET  /health        - Health check
POST /api/scan-repo - Scan GitHub repository
```

### Programmatic Access

You can also use the API directly:

```bash
curl -X POST http://localhost:8080/api/scan-repo \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/user/repo",
    "branch": "main",
    "include_ai_analysis": true
  }'
```

## 📝 Tips & Best Practices

1. **Start with Critical**: Always fix critical issues first
2. **Use AI Insights**: Read the AI summary for context
3. **Follow Examples**: Use provided code examples as templates
4. **Regular Scans**: Scan after major changes or before releases
5. **Branch Scanning**: Scan feature branches before merging
6. **Documentation**: Save scan results for compliance records

## 🎓 Learning Resources

Each vulnerability type includes:
- Description of the security issue
- Why it's dangerous
- How to fix it properly
- Code examples (before/after)

Use Knox as a learning tool to improve your security knowledge!

## 🤝 Contributing

Found a bug or want to improve the UI?
1. Check the existing issues
2. Create a new issue with details
3. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

---

**Built with ❤️ for the security community**

For more information, visit: [Knox Documentation](https://github.com/jasoncoawette/knox-auditor)
