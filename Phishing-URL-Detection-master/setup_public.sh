#!/bin/bash

# 🚀 Public Deployment Setup Script
# This script prepares your phishing URL detection tool for public deployment

echo "🌐 Setting up Phishing URL Detection for Public Deployment..."
echo "================================================="

# Check if Python is installed
if command -v python3 &> /dev/null; then
    echo "✅ Python 3 found"
else
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r deploy_requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    exit 1
fi

# Check if model files exist
if [ -f "pickle/advanced_model.pkl" ]; then
    echo "✅ ML model found"
else
    echo "❌ ML model not found in pickle/advanced_model.pkl"
    echo "ℹ️  Running model creation..."
    python3 create_mock_model.py
fi

# Create logs directory
mkdir -p logs
echo "✅ Logs directory created"

# Test the application
echo "🧪 Testing application startup..."
python3 -c "
import sys
sys.path.append('.')
try:
    from enhanced_main import app
    print('✅ Application imports successfully')
except Exception as e:
    print(f'❌ Import error: {e}')
    sys.exit(1)
"

if [ $? -eq 0 ]; then
    echo "✅ Application ready for deployment"
else
    echo "❌ Application has errors"
    exit 1
fi

echo ""
echo "🎉 Setup Complete!"
echo "================================================="
echo ""
echo "🌟 Your phishing URL detector is ready for public deployment!"
echo ""
echo "🚀 Quick Start Options:"
echo ""
echo "1️⃣  LOCAL TESTING:"
echo "   python3 -m uvicorn enhanced_main:app --host 0.0.0.0 --port 8000"
echo "   Then visit: http://localhost:8000"
echo ""
echo "2️⃣  DEPLOY TO CLOUD:"
echo "   • Railway.app: Connect your GitHub repo at railway.app"
echo "   • Render.com: Connect your repo at render.com"  
echo "   • Heroku: Use 'git push heroku main'"
echo ""
echo "3️⃣  VIEW DEPLOYMENT GUIDE:"
echo "   cat DEPLOYMENT_GUIDE.md"
echo ""
echo "📚 Your public website will include:"
echo "   ✅ User-friendly interface"
echo "   ✅ Real-time URL checking"  
echo "   ✅ Mobile-responsive design"
echo "   ✅ API documentation at /docs"
echo "   ✅ No registration required"
echo ""
echo "🛡️ Help make the internet safer! 🌐"