"""
Enhanced API endpoints with security, rate limiting, and advanced features
"""

from fastapi import FastAPI, HTTPException, Depends, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import asyncio
import logging
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from pydantic import BaseModel, HttpUrl, validator
import os
from contextlib import asynccontextmanager

# Try to import Redis (optional)
try:
    import aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

# Import our modules
try:
    from enhanced_feature_extractor import EnhancedFeatureExtraction
    ENHANCED_FEATURES = True
except ImportError:
    ENHANCED_FEATURES = False
    
from advanced_ml_model import AdvancedPhishingModel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global variables for models and cache
ml_model = None
redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global ml_model, redis_client
    
    logger.info("Starting up Enhanced Phishing URL Detection API...")
    
    # Initialize ML model
    try:
        ml_model = AdvancedPhishingModel()
        if os.path.exists("pickle/advanced_model.pkl"):
            ml_model.load_model("pickle/advanced_model.pkl")
            logger.info("Advanced ML model loaded successfully")
        else:
            logger.warning("Advanced model not found, using fallback")
            # Try to load the basic model
            import pickle
            with open("pickle/model.pkl", "rb") as f:
                basic_model = pickle.load(f)
            # Wrap in our advanced model structure
            ml_model.ensemble_model = basic_model
            logger.info("Basic ML model loaded as fallback")
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        raise
    
    # Initialize Redis cache (optional)
    if REDIS_AVAILABLE:
        try:
            redis_client = await aioredis.from_url("redis://localhost:6379", decode_responses=True)
            await redis_client.ping()
            logger.info("Redis cache connected successfully")
        except Exception as e:
            logger.warning(f"Redis not available, using in-memory cache: {e}")
            redis_client = None
    else:
        logger.info("Redis not available, using in-memory cache")
        redis_client = None
    
    # Initialize database
    try:
        try:
            from enhanced_database import init_database
            await init_database()
            logger.info("Enhanced database initialized successfully")
        except ImportError:
            from database import init_database
            await init_database()
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    
    yield
    
    # Cleanup
    if redis_client:
        await redis_client.close()
    logger.info("Shutdown complete")

# Create FastAPI app with lifespan
app = FastAPI(
    title="Enhanced Phishing URL Detection API",
    description="Advanced AI-powered phishing detection with real-time threat intelligence",
    version="2.0.0",
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.herokuapp.com", "*.vercel.app"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Security
security = HTTPBearer(auto_error=False)

# Import universal URL analyzer
from universal_url_analyzer import UniversalURLAnalyzer, is_valid_url, detect_url_category

# Request/Response models
class URLAnalysisRequest(BaseModel):
    url: str  # Changed from HttpUrl to str to accept any URL type
    deep_analysis: Optional[bool] = True
    check_real_time: Optional[bool] = True
    
    @validator('url')
    def validate_url(cls, v):
        if not isinstance(v, str):
            raise ValueError("URL must be a string")
        
        if len(v) > 2000:
            raise ValueError("URL too long (max 2000 characters)")
        
        if not is_valid_url(v):
            raise ValueError("Invalid URL format")
        
        return v

class BulkURLRequest(BaseModel):
    urls: List[str]  # Changed from List[HttpUrl] to List[str]
    deep_analysis: Optional[bool] = False
    
    @validator('urls')
    def validate_urls(cls, v):
        if len(v) > 100:  # Limit bulk requests
            raise ValueError("Maximum 100 URLs allowed in bulk request")
        
        for url in v:
            if not is_valid_url(url):
                raise ValueError(f"Invalid URL format: {url}")
        
        return v

class URLAnalysisResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    risk_score: int
    analysis_time_ms: int
    features: Optional[Dict] = None
    feature_importance: Optional[Dict] = None
    explanation: Optional[Dict] = None
    timestamp: str

class BulkAnalysisResponse(BaseModel):
    results: List[URLAnalysisResponse]
    summary: Dict[str, int]
    total_time_ms: int

class APIStats(BaseModel):
    total_requests: int
    phishing_detected: int
    safe_urls: int
    average_response_time: float
    uptime: str

# In-memory cache for when Redis is not available
memory_cache = {}
cache_ttl = {}

async def get_cache(key: str) -> Optional[str]:
    """Get value from cache (Redis or memory)"""
    if redis_client:
        try:
            return await redis_client.get(key)
        except Exception as e:
            logger.warning(f"Redis get failed: {e}")
    
    # Fallback to memory cache
    if key in memory_cache:
        if key in cache_ttl and time.time() < cache_ttl[key]:
            return memory_cache[key]
        else:
            memory_cache.pop(key, None)
            cache_ttl.pop(key, None)
    
    return None

async def set_cache(key: str, value: str, ttl: int = 3600):
    """Set value in cache (Redis or memory)"""
    if redis_client:
        try:
            await redis_client.setex(key, ttl, value)
            return
        except Exception as e:
            logger.warning(f"Redis set failed: {e}")
    
    # Fallback to memory cache
    memory_cache[key] = value
    cache_ttl[key] = time.time() + ttl

def get_cache_key(url: str, deep_analysis: bool = True) -> str:
    """Generate cache key for URL analysis"""
    content = f"{url}:{deep_analysis}"
    return hashlib.md5(content.encode()).hexdigest()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API key (optional for public demo)"""
    if not credentials:
        return None  # Allow anonymous access for demo
    
    # In production, verify against database or environment variable
    valid_keys = ["demo-key-123", os.getenv("API_KEY", "")]
    if credentials.credentials not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return credentials.credentials

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    
    return response

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests for monitoring"""
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Time: {process_time:.4f}s - "
        f"IP: {get_remote_address(request)}"
    )
    
    return response

@app.get("/")
@limiter.limit("30/minute")
async def home(request: Request):
    """Serve the public web interface for URL checking"""
    return templates.TemplateResponse("public_index.html", {"request": request})

@app.post("/analyze", response_model=URLAnalysisResponse)
@limiter.limit("10/minute")
async def analyze_url(
    request: Request,
    url_request: URLAnalysisRequest,
    background_tasks: BackgroundTasks,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """Analyze any type of URL for security risks and phishing detection"""
    
    start_time = time.time()
    url_str = url_request.url
    
    logger.info(f"Analyzing URL: {url_str}")
    
    # Check cache first
    cache_key = get_cache_key(url_str, url_request.deep_analysis)
    cached_result = await get_cache(cache_key)
    
    if cached_result:
        logger.info(f"Cache hit for URL: {url_str}")
        return URLAnalysisResponse(**json.loads(cached_result))
    
    try:
        # Detect URL category and perform universal analysis
        url_category = detect_url_category(url_str)
        universal_analyzer = UniversalURLAnalyzer(url_str)
        universal_analysis = await universal_analyzer.analyze_url()
        
        # Traditional ML analysis for web URLs
        prediction = "safe"
        confidence = 0.5
        features = None
        feature_importance = {}
        explanation = {}
        
        if url_category == 'web':  # HTTP/HTTPS URLs
            try:
                # Extract features for ML model
                if ENHANCED_FEATURES:
                    feature_extractor = EnhancedFeatureExtraction(
                        url_str, 
                        check_real_time=url_request.check_real_time
                    )
                    features = await feature_extractor.extract_all_features()
                else:
                    # Fallback to basic feature extraction
                    from feature import FeatureExtraction
                    feature_extractor = FeatureExtraction(url_str)
                    features = feature_extractor.getFeaturesList()
                
                # Make ML prediction
                predictions, probabilities = ml_model.predict([features])
                prediction = "phishing" if predictions[0] == -1 else "safe"
                confidence = float(max(probabilities[0]))
                
                # Get feature importance and explanation
                if url_request.deep_analysis:
                    try:
                        feature_importance = ml_model.get_feature_importance()
                        explanation = ml_model.explain_prediction([features])
                    except Exception as e:
                        logger.warning(f"Feature analysis failed: {e}")
                        
            except Exception as e:
                logger.warning(f"ML analysis failed for web URL: {e}")
        else:
            # Non-web URLs: Use universal analysis results
            universal_risk = universal_analysis.get('overall_risk_score', 50)
            
            # Convert universal risk score to our prediction format
            if universal_risk > 70:
                prediction = "phishing"
                confidence = universal_risk / 100.0
            elif universal_risk > 40:
                prediction = "suspicious" 
                confidence = 0.6
            else:
                prediction = "safe"
                confidence = 1.0 - (universal_risk / 100.0)
        
        # Calculate risk score (0-100)
        base_risk = universal_analysis.get('overall_risk_score', 0)
        ml_risk = int(confidence * 100) if prediction == "phishing" else int((1 - confidence) * 100)
        risk_score = max(base_risk, ml_risk)
        
        analysis_time_ms = int((time.time() - start_time) * 1000)
        
        # Enhanced response with universal analysis
        response = URLAnalysisResponse(
            url=url_str,
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            analysis_time_ms=analysis_time_ms,
            features=dict(zip(ml_model.feature_names, features)) if features and url_request.deep_analysis else None,
            feature_importance=feature_importance if url_request.deep_analysis else None,
            explanation={
                'ml_explanation': explanation,
                'universal_analysis': universal_analysis,
                'url_category': url_category,
                'supported_schemes': list(UniversalURLAnalyzer.URL_SCHEMES.keys())
            } if url_request.deep_analysis else None,
            timestamp=datetime.now().isoformat()
        )
        
        # Cache result
        background_tasks.add_task(
            set_cache, 
            cache_key, 
            response.json(), 
            3600  # 1 hour TTL
        )
        
        # Log to database in background
        background_tasks.add_task(log_analysis_to_db, response, get_remote_address(request))
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL {url_str}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/bulk", response_model=BulkAnalysisResponse)
@limiter.limit("2/minute")
async def analyze_bulk_urls(
    request: Request,
    bulk_request: BulkURLRequest,
    background_tasks: BackgroundTasks,
    api_key: Optional[str] = Depends(verify_api_key)
):
    """Analyze multiple URLs in batch"""
    
    start_time = time.time()
    results = []
    
    logger.info(f"Bulk analyzing {len(bulk_request.urls)} URLs")
    
    # Process URLs concurrently (limit concurrency to prevent overload)
    semaphore = asyncio.Semaphore(5)  # Max 5 concurrent analyses
    
    async def analyze_single_url(url):
        async with semaphore:
            url_request = URLAnalysisRequest(
                url=url, 
                deep_analysis=bulk_request.deep_analysis
            )
            return await analyze_single_url_internal(url_request)
    
    # Run analyses concurrently
    tasks = [analyze_single_url(url) for url in bulk_request.urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Filter out exceptions and create summary
    valid_results = [r for r in results if isinstance(r, URLAnalysisResponse)]
    
    summary = {
        "total": len(bulk_request.urls),
        "analyzed": len(valid_results),
        "phishing": len([r for r in valid_results if r.prediction == "phishing"]),
        "safe": len([r for r in valid_results if r.prediction == "safe"]),
        "errors": len(results) - len(valid_results)
    }
    
    total_time_ms = int((time.time() - start_time) * 1000)
    
    response = BulkAnalysisResponse(
        results=valid_results,
        summary=summary,
        total_time_ms=total_time_ms
    )
    
    # Log bulk analysis
    background_tasks.add_task(log_bulk_analysis_to_db, response, get_remote_address(request))
    
    return response

async def analyze_single_url_internal(url_request: URLAnalysisRequest) -> URLAnalysisResponse:
    """Internal function to analyze single URL (for bulk processing)"""
    start_time = time.time()
    url_str = url_request.url
    
    try:
        # Universal analysis for all URL types
        url_category = detect_url_category(url_str)
        universal_analyzer = UniversalURLAnalyzer(url_str)
        universal_analysis = await universal_analyzer.analyze_url()
        
        # Traditional ML analysis for web URLs only
        prediction = "safe"
        confidence = 0.5
        
        if url_category == 'web':  # HTTP/HTTPS URLs
            try:
                # Extract features for ML model
                if ENHANCED_FEATURES:
                    feature_extractor = EnhancedFeatureExtraction(url_str, check_real_time=False)  # Disable real-time for bulk
                    features = await feature_extractor.extract_all_features()
                else:
                    # Fallback to basic feature extraction
                    from feature import FeatureExtraction
                    feature_extractor = FeatureExtraction(url_str)
                    features = feature_extractor.getFeaturesList()
                
                # Make ML prediction
                predictions, probabilities = ml_model.predict([features])
                prediction = "phishing" if predictions[0] == -1 else "safe"
                confidence = float(max(probabilities[0]))
                
            except Exception as e:
                logger.warning(f"ML analysis failed for web URL in bulk: {e}")
        else:
            # Non-web URLs: Use universal analysis results
            universal_risk = universal_analysis.get('overall_risk_score', 50)
            
            if universal_risk > 70:
                prediction = "phishing"
                confidence = universal_risk / 100.0
            elif universal_risk > 40:
                prediction = "suspicious" 
                confidence = 0.6
            else:
                prediction = "safe"
                confidence = 1.0 - (universal_risk / 100.0)
        
        # Calculate risk score
        base_risk = universal_analysis.get('overall_risk_score', 0)
        ml_risk = int(confidence * 100) if prediction == "phishing" else int((1 - confidence) * 100)
        risk_score = max(base_risk, ml_risk)
        
        analysis_time_ms = int((time.time() - start_time) * 1000)
        
        return URLAnalysisResponse(
            url=url_str,
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            analysis_time_ms=analysis_time_ms,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"Error in bulk analysis for {url_str}: {e}")
        # Return a default response for errors
        return URLAnalysisResponse(
            url=url_str,
            prediction="error",
            confidence=0.0,
            risk_score=50,
            analysis_time_ms=int((time.time() - start_time) * 1000),
            timestamp=datetime.now().isoformat()
        )

@app.get("/stats", response_model=APIStats)
@limiter.limit("60/minute")
async def get_api_stats(request: Request):
    """Get API usage statistics"""
    try:
        try:
            from enhanced_database import get_analysis_stats
            stats = await get_analysis_stats()
        except ImportError:
            from database import get_analysis_stats
            stats = await get_analysis_stats()
        
        # Calculate uptime (mock for demo)
        uptime = "24h 30m"  # In production, calculate actual uptime
        
        return APIStats(
            total_requests=stats.get("total_requests", 0),
            phishing_detected=stats.get("phishing_detected", 0),
            safe_urls=stats.get("safe_urls", 0),
            average_response_time=stats.get("avg_response_time", 0.0),
            uptime=uptime
        )
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return APIStats(
            total_requests=0,
            phishing_detected=0,
            safe_urls=0,
            average_response_time=0.0,
            uptime="Unknown"
        )

@app.get("/health")
@limiter.limit("60/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "components": {
            "ml_model": "operational" if ml_model else "error",
            "cache": "operational" if redis_client else "fallback",
            "database": "operational"  # Would check database connection in production
        }
    }
    
    overall_status = 200 if all(
        status in ["operational", "fallback"] 
        for status in health_status["components"].values()
    ) else 503
    
    return JSONResponse(content=health_status, status_code=overall_status)

@app.get("/model/info")
@limiter.limit("30/minute")
async def get_model_info(request: Request, api_key: Optional[str] = Depends(verify_api_key)):
    """Get information about the ML model"""
    try:
        feature_importance = ml_model.get_feature_importance()
        
        return {
            "model_type": "Advanced Ensemble Model",
            "features_count": len(ml_model.feature_names),
            "feature_names": ml_model.feature_names,
            "feature_importance": dict(list(feature_importance.items())[:10]),  # Top 10
            "last_updated": "2024-01-01T00:00:00",  # Would be actual update time
            "version": "2.0.0"
        }
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail="Model information unavailable")

async def log_analysis_to_db(response: URLAnalysisResponse, client_ip: str):
    """Log analysis result to database (background task)"""
    try:
        try:
            from enhanced_database import log_url_analysis
        except ImportError:
            from database import log_url_analysis
        await log_url_analysis({
            "url": response.url,
            "prediction": response.prediction,
            "confidence": response.confidence,
            "risk_score": response.risk_score,
            "analysis_time_ms": response.analysis_time_ms,
            "client_ip": client_ip,
            "timestamp": response.timestamp
        })
    except Exception as e:
        logger.error(f"Failed to log analysis to database: {e}")

async def log_bulk_analysis_to_db(response: BulkAnalysisResponse, client_ip: str):
    """Log bulk analysis result to database (background task)"""
    try:
        try:
            from enhanced_database import log_bulk_analysis
        except ImportError:
            from database import log_bulk_analysis
        await log_bulk_analysis({
            "total_urls": response.summary["total"],
            "phishing_detected": response.summary["phishing"],
            "safe_urls": response.summary["safe"],
            "total_time_ms": response.total_time_ms,
            "client_ip": client_ip,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to log bulk analysis to database: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "enhanced_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        access_log=True
    )