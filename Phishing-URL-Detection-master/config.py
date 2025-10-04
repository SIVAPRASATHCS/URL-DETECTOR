"""
Configuration settings for the Phishing URL Detection system
"""

import os
from typing import Optional
from pydantic import BaseSettings

class Settings(BaseSettings):
    """Application settings"""
    
    # Basic app settings
    app_name: str = "Phishing URL Detection API"
    version: str = "2.0.0"
    debug: bool = False
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database settings
    database_url: str = "sqlite:///./phishing_detection.db"
    
    # Redis settings (optional)
    redis_url: Optional[str] = None
    
    # Security settings
    secret_key: str = "your-secret-key-change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 3600  # 1 hour
    
    # Feature extraction settings
    request_timeout: int = 10
    max_redirects: int = 5
    
    # External APIs (optional)
    virustotal_api_key: Optional[str] = None
    google_safe_browsing_api_key: Optional[str] = None
    
    # Monitoring
    enable_metrics: bool = True
    
    # CORS settings
    allowed_origins: list = ["*"]  # In production, specify actual domains
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Global settings instance
settings = Settings()

# Development/production configs
class DevelopmentConfig(Settings):
    debug: bool = True
    
class ProductionConfig(Settings):
    debug: bool = False
    allowed_origins: list = ["https://yourdomain.com"]  # Specify actual domains

def get_settings() -> Settings:
    """Get settings based on environment"""
    env = os.getenv("ENVIRONMENT", "development")
    
    if env == "production":
        return ProductionConfig()
    else:
        return DevelopmentConfig()