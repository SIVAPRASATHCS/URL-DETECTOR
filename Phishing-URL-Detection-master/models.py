"""
Pydantic models for the Phishing URL Detection API
"""

from pydantic import BaseModel, HttpUrl, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    """Risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class URLScanRequest(BaseModel):
    """Request model for URL scanning"""
    url: str
    include_features: Optional[bool] = False
    check_real_time: Optional[bool] = True
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        """Validate and normalize URL"""
        if not v:
            raise ValueError("URL cannot be empty")
        
        # Add protocol if missing
        if not v.startswith(('http://', 'https://')):
            v = 'https://' + v
        
        return v

class ThreatIntelligence(BaseModel):
    """Threat intelligence information"""
    suspicious_patterns: Optional[Dict[str, Any]] = None
    domain_reputation: Optional[Dict[str, Any]] = None
    ssl_analysis: Optional[Dict[str, Any]] = None
    blacklist_status: Optional[Dict[str, Any]] = None

class URLScanResponse(BaseModel):
    """Response model for URL scanning"""
    url: str
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_level: RiskLevel
    analysis_time: float
    timestamp: datetime
    scan_id: Optional[str] = None
    features: Optional[Dict[str, float]] = None
    threat_intel: Optional[ThreatIntelligence] = None
    recommendations: Optional[List[str]] = None
    
    @model_validator(mode='before')
    @classmethod
    def determine_risk_level(cls, values):
        """Determine risk level based on risk score"""
        if isinstance(values, dict):
            risk_score = values.get('risk_score', 0.5)
            
            if risk_score >= 0.8:
                values['risk_level'] = RiskLevel.CRITICAL
            elif risk_score >= 0.6:
                values['risk_level'] = RiskLevel.HIGH
            elif risk_score >= 0.4:
                values['risk_level'] = RiskLevel.MEDIUM
            else:
                values['risk_level'] = RiskLevel.LOW
        
        return values

class BatchScanRequest(BaseModel):
    """Request model for batch URL scanning"""
    urls: List[str]
    include_features: Optional[bool] = False
    check_real_time: Optional[bool] = False  # Disabled by default for batch
    
    @field_validator('urls')
    @classmethod
    def validate_urls(cls, v):
        """Validate URLs list"""
        if not v:
            raise ValueError("URLs list cannot be empty")
        if len(v) > 100:
            raise ValueError("Maximum 100 URLs allowed per batch")
        return v

class BatchScanResponse(BaseModel):
    """Response model for batch URL scanning"""
    results: List[URLScanResponse]
    total_processed: int
    total_phishing: int
    total_safe: int
    avg_analysis_time: float
    batch_id: Optional[str] = None

class ScanHistory(BaseModel):
    """Model for scan history entry"""
    url: str
    is_phishing: bool
    confidence: float
    risk_score: float
    risk_level: RiskLevel
    analysis_time: float
    timestamp: datetime
    
    @model_validator(mode='before')
    @classmethod
    def determine_risk_level(cls, values):
        """Determine risk level based on risk score"""
        if isinstance(values, dict):
            risk_score = values.get('risk_score', 0.5)
            
            if risk_score >= 0.8:
                values['risk_level'] = RiskLevel.CRITICAL
            elif risk_score >= 0.6:
                values['risk_level'] = RiskLevel.HIGH
            elif risk_score >= 0.4:
                values['risk_level'] = RiskLevel.MEDIUM
            else:
                values['risk_level'] = RiskLevel.LOW
        
        return values

class SystemStats(BaseModel):
    """Model for system statistics"""
    total_scans: int
    phishing_detected: int
    safe_urls: int
    detection_rate: float
    avg_analysis_time: float
    avg_confidence: float
    uptime: Optional[str] = None

class DailyStats(BaseModel):
    """Model for daily statistics"""
    date: str
    total_scans: int
    phishing_detected: int
    safe_urls: int
    avg_analysis_time: float

class APIUsageStats(BaseModel):
    """Model for API usage statistics"""
    endpoint: str
    requests: int
    avg_response_time: float

class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    timestamp: datetime
    model_loaded: bool
    database_connected: bool
    version: str
    uptime: Optional[str] = None

class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    message: str
    timestamp: datetime
    request_id: Optional[str] = None

class FeatureImportance(BaseModel):
    """Model for feature importance"""
    feature_name: str
    importance: float
    description: Optional[str] = None

class ModelInfo(BaseModel):
    """Model information"""
    name: str
    version: str
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    training_date: Optional[datetime] = None
    feature_count: int
    features: Optional[List[FeatureImportance]] = None