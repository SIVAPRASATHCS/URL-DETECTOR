#!/bin/bash
# Production deployment script for Linux/Unix systems

echo "Starting Phishing URL Detection API..."
cd "$(dirname "$0")"

# Install dependencies if needed
pip install -r deploy_requirements.txt

# Run with production settings
uvicorn enhanced_main:app --host 0.0.0.0 --port 8000 --workers 4