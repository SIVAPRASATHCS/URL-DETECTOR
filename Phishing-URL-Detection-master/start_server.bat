@echo off
echo 🌐 Starting Public Phishing URL Detection Service...
echo =====================================================
cd /d "%~dp0"

echo 📦 Installing/checking dependencies...
C:\Users\sivap\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m pip install -r deploy_requirements.txt

if errorlevel 1 (
    echo ❌ Failed to install dependencies
    pause
    exit /b 1
)

echo ✅ Dependencies ready

echo 🧪 Testing application...
C:\Users\sivap\AppData\Local\Microsoft\WindowsApps\python3.13.exe -c "from enhanced_main import app; print('✅ Application ready')"

if errorlevel 1 (
    echo ❌ Application has errors
    pause
    exit /b 1
)

echo 🚀 Starting public server...
echo.
echo 🌟 Your Phishing URL Detector is now running!
echo 📱 Access at: http://localhost:8000
echo 📚 API Docs: http://localhost:8000/docs
echo 🛑 Press Ctrl+C to stop
echo.

C:\Users\sivap\AppData\Local\Microsoft\WindowsApps\python3.13.exe -m uvicorn enhanced_main:app --host 0.0.0.0 --port 8000

pause