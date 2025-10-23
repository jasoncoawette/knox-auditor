# 🎨 Knox Streamlit UI - Deployment Guide

## ✨ New Dark Theme UI with Streamlit!

Your Knox Security Auditor now has a beautiful dark-themed Streamlit interface with:
- **Dark background** with **green text**
- **Red** for critical issues
- **Yellow** for warnings
- Full GitHub repository scanning
- AI-powered insights
- Issue ranking and fix suggestions

---

## 🚀 Quick Deploy to Railway

### Changes Made:
✅ New Streamlit UI with dark theme
✅ Railway deployment configured
✅ All dependencies updated
✅ Repository scanning functionality
✅ Issue ranking with solutions

### Deploy Steps:

**1. Commit and Push Changes:**
```bash
git add .
git commit -m "Add Streamlit UI with dark theme"
git push origin main
```

**2. Railway Auto-Deploys:**
- Railway will detect the changes
- Build with new Streamlit configuration
- Deploy automatically to your URL

**3. Set Environment Variables in Railway:**
Go to Railway Dashboard → Your Project → Variables:

```
OPENAI_API_KEY=your_openai_api_key_here
GITHUB_TOKEN=your_github_token (optional, for private repos)
```

---

## 🖥️ Test Locally First

```bash
# Install dependencies
pip install -r requirements.txt

# Run Streamlit app
streamlit run streamlit_app.py
```

Visit: **http://localhost:8501**

---

## 🎨 UI Features

### Dark Theme Colors:
- Background: Dark gray/black (#0d1117)
- Primary Text: Green (#7ee787)
- Secondary Text: Blue (#58a6ff)
- Critical Issues: Red (#da3633)
- High Issues: Orange/Red (#f85149)
- Medium Issues: Yellow (#d29922)
- Low Issues: Blue (#58a6ff)

### Components:
1. **Sidebar Configuration**
   - Repository URL input
   - Branch selection
   - AI analysis toggle
   - Scan button

2. **Summary Cards**
   - Total issues
   - Critical count (red)
   - High count (orange)
   - Medium count (yellow)
   - Low count (blue)

3. **AI Insights Section**
   - Overall security assessment
   - Top priority fixes
   - Risk analysis

4. **Issue Cards**
   - Expandable details
   - Severity badges
   - File location
   - Vulnerable code
   - Fix suggestions
   - Secure code examples

---

## 📁 Files Changed

### New Files:
- **streamlit_app.py** - Main Streamlit application
- **.streamlit/config.toml** - Theme configuration
- **STREAMLIT_DEPLOYMENT.md** - This guide

### Updated Files:
- **requirements.txt** - Added streamlit and gitpython
- **Procfile** - Updated to run Streamlit
- **railway.json** - Updated start command
- **.gitignore** - Added Streamlit cache

---

## 🔐 How It Works

1. **User enters GitHub URL** in sidebar
2. **App clones repository** temporarily
3. **Scanner analyzes all files** for vulnerabilities
4. **Issues are ranked** by severity
5. **AI generates insights** (if enabled)
6. **Solutions are provided** with code examples
7. **Temp files are deleted** after scan

### Security:
- No permanent storage of code
- Repositories cloned to temp directories
- Files deleted immediately after scanning
- OpenAI API optional
- GitHub token optional (only for private repos)

---

## 🎯 Usage Guide

### Scanning a Repository:

1. **Enter GitHub URL**
   ```
   https://github.com/username/repository
   ```

2. **Select Branch** (default: main)
   - main
   - develop
   - feature/branch-name

3. **Enable AI Analysis** ✓
   - Requires OpenAI API key
   - Provides intelligent insights
   - Suggests priority fixes

4. **Click "Scan Repository"**

5. **View Results:**
   - Summary metrics at top
   - AI insights (if enabled)
   - Ranked list of issues
   - Expandable issue cards with fixes

---

## 🛠️ Railway Configuration

**Procfile:**
```
web: streamlit run streamlit_app.py --server.port=$PORT --server.address=0.0.0.0
```

**railway.json:**
```json
{
  "deploy": {
    "startCommand": "streamlit run streamlit_app.py --server.port=$PORT --server.address=0.0.0.0 --server.headless=true"
  }
}
```

**.streamlit/config.toml:**
```toml
[theme]
primaryColor = "#7ee787"
backgroundColor = "#0d1117"
secondaryBackgroundColor = "#161b22"
textColor = "#7ee787"
```

---

## 🔍 What Gets Detected

### Critical (Red):
- 🔴 Hardcoded API keys
- 🔴 Hardcoded passwords
- 🔴 Hardcoded secrets

### High (Orange):
- 🟠 SQL injection vulnerabilities
- 🟠 XSS vulnerabilities
- 🟠 Command injection
- 🟠 Insecure deserialization

### Medium (Yellow):
- 🟡 Weak cryptography (MD5, SHA1)
- 🟡 Debug mode enabled
- 🟡 Missing security headers

### Low (Blue):
- 🔵 Code quality issues
- 🔵 Minor security concerns

---

## 📊 Example Output

After scanning, you'll see:

```
📊 Scan Results
╔════════════════════╗
║ Total Issues: 12   ║
║ Critical:     3    ║ 🔴
║ High:         5    ║ 🟠
║ Medium:       3    ║ 🟡
║ Low:          1    ║ 🔵
╚════════════════════╝

🤖 AI Security Insights:
"Your repository contains several critical security
vulnerabilities that should be addressed immediately..."

🔍 Security Issues:

1. Hardcoded API Key - CRITICAL 🔴
   📁 src/config.py:15
   🔻 Code: api_key = "sk-1234..."
   💡 Fix: Use environment variables

[... more issues ...]
```

---

## 💡 Tips for Best Results

1. **Start with Critical** - Fix red issues first
2. **Use AI Insights** - Read the overall assessment
3. **Follow Code Examples** - Use provided secure alternatives
4. **Scan Regularly** - After major changes
5. **Branch Scanning** - Test feature branches before merging

---

## 🐛 Troubleshooting

### Local Testing Issues:

**Port already in use:**
```bash
streamlit run streamlit_app.py --server.port=8502
```

**Dependencies missing:**
```bash
pip install -r requirements.txt
```

**Git not found:**
```bash
# Install git
brew install git  # macOS
apt-get install git  # Linux
```

### Railway Deployment Issues:

**Check Railway Logs:**
```bash
railway logs
```

**Verify Environment Variables:**
- Go to Railway Dashboard
- Click "Variables" tab
- Ensure OPENAI_API_KEY is set (if using AI)

**Build Fails:**
- Check requirements.txt is up to date
- Verify Python version (3.8+)
- Check railway.json start command

---

## 🎉 You're Ready!

Your Knox Security Auditor with the new dark theme Streamlit UI is ready to deploy!

### Next Steps:

1. ✅ **Commit changes** to git
2. ✅ **Push to GitHub**
3. ✅ **Wait for Railway auto-deploy** (~2-3 minutes)
4. ✅ **Add environment variables** in Railway
5. ✅ **Test your live deployment**

### Your Railway URL will be:
```
https://your-app-name.up.railway.app
```

Find it in Railway Dashboard → Deployments → Domains

---

## 🔗 Useful Links

- **Railway Dashboard**: https://railway.app/dashboard
- **Streamlit Docs**: https://docs.streamlit.io
- **OpenAI API Keys**: https://platform.openai.com/api-keys
- **GitHub Tokens**: https://github.com/settings/tokens

---

## 📞 Need Help?

- Check Railway logs for deployment errors
- Test locally first with `streamlit run streamlit_app.py`
- Verify all environment variables are set
- Ensure `git` is installed for repository cloning

---

**Built with ❤️ using Streamlit, Python, and Knox Security Engine**

🔒 **Knox Security Auditor v2.0** - Now with Dark Theme! 🎨
