"""
Modern FastAPI backend for Phishing URL Detection
Upgraded with async support, proper error handling, and REST API
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, HttpUrl, field_validator
import asyncio
import aiohttp
import logging
from typing import Optional, List, Dict
import numpy as np
import pickle
import time
from datetime import datetime
import os
from contextlib import asynccontextmanager

# Import our feature extraction (with fix)
from enhanced_feature_extractor import EnhancedFeatureExtraction
from database import DatabaseManager
from models import URLScanRequest, URLScanResponse, ScanHistory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for model and database
ml_model = None
db_manager = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global ml_model, db_manager
    
    # Startup
    logger.info("Starting up Phishing URL Detection API...")
    
    # Load ML model
    try:
        import os
        model_path = os.path.join(os.path.dirname(__file__), "pickle", "model.pkl")
        with open(model_path, "rb") as f:
            ml_model = pickle.load(f)
        logger.info("ML model loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        raise
    
    # Initialize database
    try:
        db_manager = DatabaseManager()
        await db_manager.init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization failed: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    if db_manager:
        await db_manager.close()

# Create FastAPI app
app = FastAPI(
    title="Phishing URL Detection API",
    description="Advanced phishing URL detection using machine learning with real-time threat intelligence",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic models
class URLAnalysisRequest(BaseModel):
    url: str
    include_features: Optional[bool] = False
    check_real_time: Optional[bool] = True
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            v = 'https://' + v
        return v

class URLAnalysisResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    risk_score: float
    analysis_time: float
    timestamp: datetime
    features: Optional[Dict] = None
    threat_intel: Optional[Dict] = None
    scan_id: Optional[str] = None

class BatchAnalysisRequest(BaseModel):
    urls: List[str]
    include_features: Optional[bool] = False

# API Routes

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main page"""
    try:
        with open("templates/enhanced_index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="""
        <html>
            <head><title>Phishing URL Detection API</title></head>
            <body>
                <h1>Phishing URL Detection API</h1>
                <p>API is running! Visit <a href="/docs">/docs</a> for API documentation.</p>
                <p>Visit <a href="/health">/health</a> to check system status.</p>
            </body>
        </html>
        """)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "model_loaded": ml_model is not None,
        "database_connected": db_manager is not None and await db_manager.is_connected() if db_manager else False,
        "version": "2.0.0"
    }

@app.post("/api/v1/analyze", response_model=URLAnalysisResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze a single URL for phishing detection
    """
    start_time = time.time()
    
    try:
        logger.info(f"Analyzing URL: {request.url}")
        
        # Extract features using enhanced extractor
        feature_extractor = EnhancedFeatureExtraction(
            request.url, 
            check_real_time=request.check_real_time
        )
        
        # Get features and threat intelligence
        features = await feature_extractor.extract_all_features()
        threat_intel = await feature_extractor.get_threat_intelligence()
        
        # Prepare features for ML model
        feature_vector = np.array(features).reshape(1, -1)
        
        # Make prediction
        prediction = ml_model.predict(feature_vector)[0]
        probabilities = ml_model.predict_proba(feature_vector)[0]
        
        # Calculate confidence and risk score
        confidence = max(probabilities)
        risk_score = probabilities[0] if prediction == -1 else (1 - probabilities[1])
        
        is_phishing = prediction == -1
        analysis_time = time.time() - start_time
        
        # Prepare response
        response = URLAnalysisResponse(
            url=request.url,
            is_phishing=is_phishing,
            confidence=float(confidence),
            risk_score=float(risk_score),
            analysis_time=analysis_time,
            timestamp=datetime.now(),
            features=dict(zip(feature_extractor.feature_names, features)) if request.include_features else None,
            threat_intel=threat_intel if request.check_real_time else None
        )
        
        # Save to database in background
        if db_manager:
            background_tasks.add_task(
                save_scan_result,
                request.url,
                is_phishing,
                confidence,
                risk_score,
                analysis_time,
                features if request.include_features else None
            )
        
        logger.info(f"Analysis completed for {request.url}: {'PHISHING' if is_phishing else 'SAFE'} (confidence: {confidence:.2f})")
        
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL {request.url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/v1/batch-analyze")
async def batch_analyze_urls(request: BatchAnalysisRequest):
    """
    Analyze multiple URLs in batch
    """
    if len(request.urls) > 100:  # Limit batch size
        raise HTTPException(status_code=400, detail="Maximum 100 URLs per batch")
    
    results = []
    
    for url in request.urls:
        try:
            analysis_request = URLAnalysisRequest(
                url=url,
                include_features=request.include_features,
                check_real_time=False  # Disable real-time checks for batch to improve speed
            )
            result = await analyze_url(analysis_request, BackgroundTasks())
            results.append(result)
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
                "timestamp": datetime.now()
            })
    
    return {"results": results, "total": len(request.urls)}

@app.get("/api/v1/stats")
async def get_statistics():
    """Get system statistics"""
    if not db_manager:
        return {"error": "Database not available"}
    
    try:
        stats = await db_manager.get_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")

@app.get("/api/v1/history")
async def get_scan_history(limit: int = 50, offset: int = 0):
    """Get recent scan history"""
    if not db_manager:
        return {"error": "Database not available"}
    
    try:
        history = await db_manager.get_scan_history(limit=limit, offset=offset)
        return {"history": history, "limit": limit, "offset": offset}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")

# Background task functions
async def save_scan_result(url: str, is_phishing: bool, confidence: float, risk_score: float, analysis_time: float, features: Optional[List] = None):
    """Save scan result to database"""
    if db_manager:
        try:
            await db_manager.save_scan_result(
                url=url,
                is_phishing=is_phishing,
                confidence=confidence,
                risk_score=risk_score,
                analysis_time=analysis_time,
                features=features
            )
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"error": "Endpoint not found", "message": "The requested endpoint does not exist"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "message": "An unexpected error occurred"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )