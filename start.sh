#!/bin/bash

# Render.com startup script
echo "🚀 Starting SecureURL Guardian on Render..."

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create required directories
mkdir -p templates static reports

# Start the application
echo "🛡️ Launching phishing detection service..."
python simplified_responsive_app.py