#!/usr/bin/env python3
"""
Railway deployment startup verification script
This ensures all dependencies are working before starting the main app
"""

import sys
import os

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = [
        'fastapi',
        'uvicorn',
        'aiohttp',
        'beautifulsoup4',
        'requests',
        'whois',
        'aiosqlite',
        'numpy',
        'pandas',
        'sklearn'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} - OK")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - MISSING")
    
    return len(missing_packages) == 0

def check_model_files():
    """Check if ML model files exist"""
    model_path = "pickle/advanced_model.pkl"
    if os.path.exists(model_path):
        print(f"✅ Model file found: {model_path}")
        return True
    else:
        print(f"❌ Model file missing: {model_path}")
        return False

def main():
    """Main verification function"""
    print("🚀 Railway Deployment Verification")
    print("=" * 40)
    
    # Check dependencies
    print("\n📦 Checking Dependencies:")
    deps_ok = check_dependencies()
    
    # Check model files
    print("\n🤖 Checking ML Model:")
    model_ok = check_model_files()
    
    # Check FastAPI app
    print("\n⚡ Testing FastAPI Import:")
    try:
        from enhanced_main import app
        print("✅ FastAPI app imports successfully")
        app_ok = True
    except Exception as e:
        print(f"❌ FastAPI import failed: {e}")
        app_ok = False
    
    # Final result
    print("\n" + "=" * 40)
    if deps_ok and model_ok and app_ok:
        print("🎉 ALL CHECKS PASSED - Ready for Railway deployment!")
        return 0
    else:
        print("❌ Some checks failed - Review issues above")
        return 1

if __name__ == "__main__":
    sys.exit(main())