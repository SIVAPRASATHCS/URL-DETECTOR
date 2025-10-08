# 🚀 Windows Deployment Script for SecureURL Guardian
# PowerShell script for easy deployment to various platforms

Write-Host "🛡️ SecureURL Guardian - Windows Deployment Script" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Function to display colored messages
function Write-Success {
    param($Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Info {
    param($Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

function Write-Warning {
    param($Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param($Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# Check prerequisites
function Check-Prerequisites {
    Write-Info "Checking prerequisites..."
    
    # Check Python
    try {
        $pythonVersion = python --version 2>$null
        if ($pythonVersion) {
            Write-Success "Python is installed: $pythonVersion"
        }
    } catch {
        Write-Error "Python is not installed or not in PATH"
        Write-Info "Please install Python 3.8+ from https://python.org"
        exit 1
    }
    
    # Check Git
    try {
        $gitVersion = git --version 2>$null
        if ($gitVersion) {
            Write-Success "Git is installed: $gitVersion"
        }
    } catch {
        Write-Error "Git is not installed or not in PATH"
        Write-Info "Please install Git from https://git-scm.com"
        exit 1
    }
    
    # Check requirements.txt
    if (Test-Path "requirements.txt") {
        Write-Success "requirements.txt found"
    } else {
        Write-Error "requirements.txt not found"
        Write-Info "Please ensure you're in the project directory"
        exit 1
    }
}

# Deployment functions
function Deploy-Streamlit {
    Write-Info "Preparing for Streamlit Cloud deployment..."
    Write-Host ""
    Write-Info "📋 Follow these steps:"
    Write-Info "1. Open https://share.streamlit.io/ in your browser"
    Write-Info "2. Sign in with your GitHub account"
    Write-Info "3. Click 'New app'"
    Write-Info "4. Select repository: SIVAPRASATHCS/url_detector"
    Write-Info "5. Main file: simplified_responsive_app.py"
    Write-Info "6. Click Deploy!"
    Write-Host ""
    Write-Success "Your app will be live at: https://sivaprasathcs-url-detector-simplified-responsive-app-xxxxx.streamlit.app/"
}

function Deploy-Railway {
    Write-Info "Preparing for Railway deployment..."
    Write-Host ""
    Write-Info "📋 Follow these steps:"
    Write-Info "1. Open https://railway.app/ in your browser"
    Write-Info "2. Sign up with GitHub"
    Write-Info "3. Click 'New Project' → 'Deploy from GitHub repo'"
    Write-Info "4. Select your url_detector repository"
    Write-Info "5. Railway will auto-detect and deploy!"
    Write-Host ""
    Write-Success "Your app will be live at: https://your-app.railway.app/"
}

function Deploy-Render {
    Write-Info "Preparing for Render deployment..."
    Write-Host ""
    Write-Info "📋 Follow these steps:"
    Write-Info "1. Open https://render.com/ in your browser"
    Write-Info "2. Sign up with GitHub"
    Write-Info "3. Click 'New' → 'Web Service'"
    Write-Info "4. Connect your repository"
    Write-Info "5. Build Command: pip install -r requirements.txt"
    Write-Info "6. Start Command: python simplified_responsive_app.py"
    Write-Info "7. Click 'Create Web Service'"
    Write-Host ""
    Write-Success "Your app will be live at: https://your-app.onrender.com/"
}

function Deploy-Heroku {
    Write-Info "Preparing for Heroku deployment..."
    
    # Check if Heroku CLI is available
    try {
        $herokuVersion = heroku --version 2>$null
        if ($herokuVersion) {
            Write-Info "Heroku CLI found. Deploying..."
            heroku login
            $appName = "secureurl-guardian-$(Get-Random -Maximum 9999)"
            heroku create $appName
            git push heroku main
            Write-Success "Deployed to Heroku! URL: https://$appName.herokuapp.com/"
        }
    } catch {
        Write-Warning "Heroku CLI not found"
        Write-Info "📋 Manual deployment steps:"
        Write-Info "1. Download Heroku CLI: https://devcenter.heroku.com/articles/heroku-cli"
        Write-Info "2. Run: heroku login"
        Write-Info "3. Run: heroku create your-app-name"
        Write-Info "4. Run: git push heroku main"
    }
}

function Deploy-Docker {
    Write-Info "Preparing Docker deployment..."
    
    # Check if Docker is available
    try {
        $dockerVersion = docker --version 2>$null
        if ($dockerVersion) {
            Write-Info "Docker found. Building image..."
            docker build -t secureurl-guardian .
            Write-Info "Starting container..."
            docker run -p 8003:8003 -d --name secureurl-guardian secureurl-guardian
            Write-Success "Docker container running on http://localhost:8003"
        }
    } catch {
        Write-Error "Docker not found"
        Write-Info "Please install Docker Desktop from https://docker.com"
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "🚀 Select deployment platform:" -ForegroundColor Cyan
    Write-Host "1) Streamlit Cloud (Easiest - Recommended)"
    Write-Host "2) Railway (Auto-deploy)"
    Write-Host "3) Render (Free tier)"
    Write-Host "4) Heroku (Professional)"
    Write-Host "5) Docker (Local)"
    Write-Host "6) Show all options"
    Write-Host "7) Exit"
    Write-Host ""
}

function Show-AllOptions {
    Write-Host "🌟 All Deployment Options:" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    
    if (Test-Path "ALTERNATIVE_DEPLOYMENTS.md") {
        Get-Content "ALTERNATIVE_DEPLOYMENTS.md" | Write-Host
    } else {
        Write-Info "For detailed deployment options, see ALTERNATIVE_DEPLOYMENTS.md"
    }
}

# Main execution
function Main {
    Check-Prerequisites
    
    while ($true) {
        Show-Menu
        $choice = Read-Host "Enter your choice (1-7)"
        
        switch ($choice) {
            1 { Deploy-Streamlit; break }
            2 { Deploy-Railway; break }
            3 { Deploy-Render; break }
            4 { Deploy-Heroku; break }
            5 { Deploy-Docker; break }
            6 { Show-AllOptions }
            7 { 
                Write-Info "Goodbye! Happy deploying! 🚀"
                exit 0 
            }
            default { 
                Write-Warning "Invalid option. Please choose 1-7."
            }
        }
    }
    
    Write-Host ""
    Write-Success "Deployment process completed!"
    Write-Info "Your SecureURL Guardian is now protecting users! 🛡️"
}

# Run the main function
Main