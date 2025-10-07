# Knox Quick Start Guide

## 🚀 Setup in 3 Minutes

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Keys

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Edit `.env` and add your keys:

```env
# REQUIRED for AI analysis
OPENAI_API_KEY=sk-your-key-here

# OPTIONAL - for GitHub PR integration
GITHUB_TOKEN=ghp_your-token-here

# OPTIONAL - for voice features
ELEVEN_LABS_API_KEY=your-key-here
```

### 3. Run Knox!

#### Try the Demo First:
```bash
python knox.py demo
```

#### Scan Local Code:
```bash
python knox.py scan /path/to/your/code
```

#### Start Web API:
```bash
python knox.py server
```
Then visit: http://localhost:8000

---

## 🔑 Where to Get API Keys

### OpenAI API Key (Required for AI features)
1. Go to https://platform.openai.com/
2. Sign up or log in
3. Navigate to API Keys
4. Click "Create new secret key"
5. Copy the key (starts with `sk-`)
6. Add to `.env`: `OPENAI_API_KEY=sk-your-key-here`

### GitHub Token (Optional - for PR scanning)
1. Go to https://github.com/settings/tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `read:org`
4. Click "Generate token"
5. Copy the token (starts with `ghp_`)
6. Add to `.env`: `GITHUB_TOKEN=ghp-your-token-here`

### Eleven Labs API Key (Optional - for voice)
1. Go to https://elevenlabs.io/
2. Sign up for free account
3. Go to Profile → API Keys
4. Copy your key
5. Add to `.env`: `ELEVEN_LABS_API_KEY=your-key-here`

---

## 📋 Quick Commands

```bash
# Demo with sample vulnerable code
python knox.py demo

# Scan current directory
python knox.py scan .

# Scan specific files
python knox.py scan --files src/auth.py src/api.py

# Generate HTML report
python knox.py scan . --format html --output report.html

# Audit GitHub PR
python knox.py audit-pr --repo owner/repo --pr 123

# Start API server
python knox.py server --port 8000
```

---

## 🌐 Deploy to Railway

1. Install Railway CLI:
```bash
npm i -g @railway/cli
```

2. Login to Railway:
```bash
railway login
```

3. Deploy:
```bash
railway init
railway up
```

4. Set environment variables in Railway dashboard:
   - Go to your project
   - Click "Variables"
   - Add `OPENAI_API_KEY`

Your API will be live at: `https://your-app.railway.app`

---

## 💡 Using the API

Once the server is running, you can:

### Scan Code via API:
```bash
curl -X POST http://localhost:8000/scan/code \
  -H "Content-Type: application/json" \
  -d '{"code": "password = \"admin123\"", "language": "python"}'
```

### View Demo Report:
Open browser to: http://localhost:8000/report/demo

### Interactive Docs:
Open browser to: http://localhost:8000/docs

---

## 🎯 For Your Boeing Interview

**What to Show:**

1. **Live Demo**: Run `python knox.py demo` to show real-time vulnerability detection

2. **Web Interface**: Start the server and show the beautiful HTML reports at `/report/demo`

3. **API Capabilities**: Show the Swagger docs at `/docs`

4. **Real Scan**: Scan a real repo and generate a report:
   ```bash
   python knox.py scan . --format html --output boeing-demo.html
   ```

5. **GitHub Integration**: If you have a test PR, show:
   ```bash
   python knox.py audit-pr --repo yourname/test-repo --pr 1 --comment
   ```

**Talk About:**
- AI-powered analysis using OpenAI GPT
- Detected 300+ vulnerabilities across 15 repos (your achievement!)
- 60% reduction in manual review time
- Multi-language support
- Production-ready FastAPI backend
- Cloud deployment ready (Railway/Heroku/AWS)

**Key Features to Highlight:**
✅ Pattern-based vulnerability detection
✅ AI-powered contextual analysis
✅ GitHub PR integration
✅ RESTful API
✅ Beautiful HTML reports
✅ CLI + Web interface
✅ Production-ready code structure

---

## 📞 Need Help?

- Check README.md for full documentation
- View API docs at `/docs` when server is running
- All code is well-commented

**Good luck with your Boeing interview! 🚀**
