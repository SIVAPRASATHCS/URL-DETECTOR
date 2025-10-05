"""
Vercel-compatible entry point for the Phishing URL Detection API
"""

import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    from enhanced_main import app
    
    # Vercel expects a handler function
    def handler(request, response):
        return app(request, response)
    
    # Also export the app directly for compatibility
    application = app
    
except Exception as e:
    print(f"Error importing enhanced_main: {e}")
    # Create a minimal fallback app
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    
    app = FastAPI(title="Phishing URL Detector", description="Error loading main application")
    
    @app.get("/")
    async def fallback():
        return JSONResponse({
            "error": "Application failed to load",
            "message": "Please check deployment configuration"
        })
    
    application = app