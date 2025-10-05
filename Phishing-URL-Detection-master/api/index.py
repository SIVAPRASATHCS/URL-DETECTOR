"""
Vercel-compatible entry point for the Phishing URL Detection API
"""

import os
import sys
from pathlib import Path

# Add the parent directory to the path
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

try:
    # Import the FastAPI app
    from enhanced_main import app
    
    # Export for Vercel
    handler = app
    
except ImportError as e:
    print(f"Import error: {e}")
    # Fallback minimal app
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    
    app = FastAPI()
    
    @app.get("/")
    async def root():
        return {"message": "Phishing URL Detector API", "status": "running"}
    
    @app.get("/health")
    async def health():
        return {"status": "healthy"}
    
    handler = app