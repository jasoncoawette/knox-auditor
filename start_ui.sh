#!/bin/bash
# Knox Security Auditor - UI Startup Script

echo "🔒 Starting Knox Security Auditor UI..."
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate 2>/dev/null || . venv/bin/activate

# Check if dependencies are installed
if ! python3 -c "import fastapi" 2>/dev/null; then
    echo "📥 Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Check for .env file
if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found. API integrations will be limited."
    echo "   Create a .env file with your API keys for full functionality."
    echo ""
fi

# Start the server
echo "🚀 Launching Knox Security Auditor..."
echo "🌐 Open http://localhost:8080 in your browser"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 -m src.api.enhanced_ui
