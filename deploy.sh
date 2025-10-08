#!/bin/bash

# 🚀 Universal Deployment Script for SecureURL Guardian
# This script helps you deploy to any platform quickly

echo "🛡️ SecureURL Guardian - Universal Deployment Script"
echo "=================================================="
echo

# Function to display colored text
print_success() {
    echo -e "\033[32m✅ $1\033[0m"
}

print_info() {
    echo -e "\033[34mℹ️  $1\033[0m"
}

print_warning() {
    echo -e "\033[33m⚠️  $1\033[0m"
}

print_error() {
    echo -e "\033[31m❌ $1\033[0m"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."
    
    # Check Python
    if command -v python3 &> /dev/null; then
        print_success "Python 3 is installed"
    else
        print_error "Python 3 is not installed. Please install Python 3.8+"
        exit 1
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        print_success "Git is installed"
    else
        print_error "Git is not installed. Please install Git"
        exit 1
    fi
    
    # Check if requirements.txt exists
    if [ -f "requirements.txt" ]; then
        print_success "requirements.txt found"
    else
        print_error "requirements.txt not found. Please ensure you're in the project directory"
        exit 1
    fi
}

# Deploy to different platforms
deploy_streamlit() {
    print_info "Preparing for Streamlit Cloud deployment..."
    print_info "1. Go to https://share.streamlit.io/"
    print_info "2. Sign in with GitHub"
    print_info "3. Click 'New app'"
    print_info "4. Select repository: SIVAPRASATHCS/url_detector"
    print_info "5. Main file: simplified_responsive_app.py"
    print_info "6. Click Deploy!"
    print_success "Streamlit Cloud setup instructions displayed"
}

deploy_railway() {
    print_info "Preparing for Railway deployment..."
    
    # Check if railway CLI is installed
    if command -v railway &> /dev/null; then
        print_info "Railway CLI found. Deploying..."
        railway login
        railway init
        railway up
        print_success "Deployed to Railway!"
    else
        print_info "Railway CLI not found. Manual deployment:"
        print_info "1. Go to https://railway.app/"
        print_info "2. Sign up with GitHub"
        print_info "3. New Project → Deploy from GitHub repo"
        print_info "4. Select your repository"
        print_info "5. Deploy automatically!"
    fi
}

deploy_render() {
    print_info "Preparing for Render deployment..."
    print_info "1. Go to https://render.com/"
    print_info "2. Sign up with GitHub"
    print_info "3. New → Web Service"
    print_info "4. Connect repository"
    print_info "5. Build Command: pip install -r requirements.txt"
    print_info "6. Start Command: python simplified_responsive_app.py"
    print_info "7. Deploy!"
    print_success "Render setup instructions displayed"
}

deploy_heroku() {
    print_info "Preparing for Heroku deployment..."
    
    # Check if heroku CLI is installed
    if command -v heroku &> /dev/null; then
        print_info "Heroku CLI found. Deploying..."
        heroku login
        heroku create secureurl-guardian-$(date +%s)
        git push heroku main
        print_success "Deployed to Heroku!"
    else
        print_info "Heroku CLI not found. Install from: https://devcenter.heroku.com/articles/heroku-cli"
        print_info "Then run: heroku login && heroku create your-app-name && git push heroku main"
    fi
}

deploy_flyio() {
    print_info "Preparing for Fly.io deployment..."
    
    # Check if flyctl is installed
    if command -v flyctl &> /dev/null; then
        print_info "Fly.io CLI found. Deploying..."
        flyctl auth login
        flyctl launch --copy-config --name secureurl-guardian-$(date +%s)
        flyctl deploy
        print_success "Deployed to Fly.io!"
    else
        print_info "Fly.io CLI not found. Install from: https://fly.io/docs/hands-on/install-flyctl/"
        print_info "Then run: flyctl launch && flyctl deploy"
    fi
}

deploy_docker() {
    print_info "Preparing Docker deployment..."
    
    if command -v docker &> /dev/null; then
        print_info "Building Docker image..."
        docker build -t secureurl-guardian .
        print_info "Running Docker container..."
        docker run -p 8003:8003 -d --name secureurl-guardian secureurl-guardian
        print_success "Docker container is running on http://localhost:8003"
    else
        print_error "Docker is not installed. Please install Docker first."
    fi
}

# Main menu
show_menu() {
    echo "Select deployment platform:"
    echo "1) Streamlit Cloud (Easiest - Recommended)"
    echo "2) Railway (Auto-deploy)"
    echo "3) Render (Free tier)"
    echo "4) Heroku (Professional)"
    echo "5) Fly.io (Fast global)"
    echo "6) Docker (Local)"
    echo "7) Show all options"
    echo "8) Exit"
    echo
}

# Main execution
main() {
    check_prerequisites
    echo
    
    while true; do
        show_menu
        read -p "Enter your choice (1-8): " choice
        echo
        
        case $choice in
            1)
                deploy_streamlit
                break
                ;;
            2)
                deploy_railway
                break
                ;;
            3)
                deploy_render
                break
                ;;
            4)
                deploy_heroku
                break
                ;;
            5)
                deploy_flyio
                break
                ;;
            6)
                deploy_docker
                break
                ;;
            7)
                echo "🌟 All Deployment Options:"
                echo "=========================="
                cat ALTERNATIVE_DEPLOYMENTS.md
                echo
                ;;
            8)
                print_info "Goodbye! Happy deploying! 🚀"
                exit 0
                ;;
            *)
                print_warning "Invalid option. Please choose 1-8."
                echo
                ;;
        esac
    done
    
    echo
    print_success "Deployment process completed!"
    print_info "Your SecureURL Guardian is now protecting users! 🛡️"
}

# Run the script
main