# Configuration for production deployment
import os

# Server Configuration
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8000))
WORKERS = int(os.environ.get("WORKERS", 1))

# Database Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./phishing_detection.db")

# Security Configuration
SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"

# API Configuration
MAX_REQUESTS_PER_MINUTE = int(os.environ.get("MAX_REQUESTS_PER_MINUTE", 60))
ENABLE_CORS = os.environ.get("ENABLE_CORS", "True").lower() == "true"

# Model Configuration
MODEL_PATH = os.environ.get("MODEL_PATH", "pickle/advanced_model.pkl")

# Logging Configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FILE = os.environ.get("LOG_FILE", "logs/app.log")

print(f"🚀 Production Config Loaded - Port: {PORT}, Workers: {WORKERS}, Debug: {DEBUG}")