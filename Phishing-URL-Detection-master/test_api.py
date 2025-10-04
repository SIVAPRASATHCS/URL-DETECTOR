"""
Test suite for the Phishing URL Detection API
"""

import pytest
import asyncio
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
import numpy as np

# Import our modules
from main import app
from enhanced_feature_extractor import EnhancedFeatureExtraction
from database import DatabaseManager

# Test client
client = TestClient(app)

class TestAPI:
    """Test the FastAPI endpoints"""
    
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
    
    def test_root_endpoint(self):
        """Test root endpoint returns HTML"""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    @patch('main.ml_model')
    def test_analyze_url_endpoint(self, mock_model):
        """Test URL analysis endpoint"""
        # Mock the ML model
        mock_model.predict.return_value = np.array([1])  # Safe URL
        mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])
        
        test_data = {
            "url": "https://google.com",
            "include_features": False,
            "check_real_time": False
        }
        
        response = client.post("/api/v1/analyze", json=test_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "url" in data
        assert "is_phishing" in data
        assert "confidence" in data
        assert "risk_score" in data
    
    def test_analyze_url_invalid_data(self):
        """Test URL analysis with invalid data"""
        response = client.post("/api/v1/analyze", json={})
        assert response.status_code == 422  # Validation error

class TestFeatureExtractor:
    """Test the enhanced feature extractor"""
    
    @pytest.mark.asyncio
    async def test_feature_extractor_initialization(self):
        """Test feature extractor initialization"""
        extractor = EnhancedFeatureExtraction("https://example.com", check_real_time=False)
        assert extractor.url == "https://example.com"
        assert extractor.domain == "example.com"
    
    @pytest.mark.asyncio
    async def test_using_ip_feature(self):
        """Test IP detection feature"""
        # Test with IP
        extractor = EnhancedFeatureExtraction("https://192.168.1.1", check_real_time=False)
        result = extractor._using_ip()
        assert result == -1  # Suspicious
        
        # Test with domain
        extractor = EnhancedFeatureExtraction("https://google.com", check_real_time=False)
        result = extractor._using_ip()
        assert result == 1   # Safe
    
    @pytest.mark.asyncio
    async def test_long_url_feature(self):
        """Test long URL detection"""
        # Short URL
        short_url = "https://a.com"
        extractor = EnhancedFeatureExtraction(short_url, check_real_time=False)
        assert extractor._long_url() == 1
        
        # Long URL
        long_url = "https://example.com/" + "a" * 100
        extractor = EnhancedFeatureExtraction(long_url, check_real_time=False)
        assert extractor._long_url() == -1
    
    @pytest.mark.asyncio
    async def test_https_feature(self):
        """Test HTTPS detection"""
        # HTTPS URL
        extractor = EnhancedFeatureExtraction("https://google.com", check_real_time=False)
        assert extractor._https() == 1
        
        # HTTP URL
        extractor = EnhancedFeatureExtraction("http://google.com", check_real_time=False)
        assert extractor._https() == -1
    
    @pytest.mark.asyncio
    async def test_symbol_feature(self):
        """Test @ symbol detection"""
        # URL with @
        extractor = EnhancedFeatureExtraction("https://user@example.com", check_real_time=False)
        assert extractor._symbol() == -1
        
        # URL without @
        extractor = EnhancedFeatureExtraction("https://example.com", check_real_time=False)
        assert extractor._symbol() == 1

class TestDatabaseManager:
    """Test database operations"""
    
    @pytest.mark.asyncio
    async def test_database_initialization(self):
        """Test database initialization"""
        db = DatabaseManager(db_path=":memory:")  # Use in-memory database
        await db.init_db()
        
        # Test connection
        assert await db.is_connected()
        
        await db.close()
    
    @pytest.mark.asyncio
    async def test_save_scan_result(self):
        """Test saving scan results"""
        db = DatabaseManager(db_path=":memory:")
        await db.init_db()
        
        await db.save_scan_result(
            url="https://test.com",
            is_phishing=False,
            confidence=0.9,
            risk_score=0.1,
            analysis_time=1.5
        )
        
        # Verify it was saved
        history = await db.get_scan_history(limit=1)
        assert len(history) == 1
        assert history[0]["url"] == "https://test.com"
        
        await db.close()
    
    @pytest.mark.asyncio
    async def test_get_statistics(self):
        """Test getting statistics"""
        db = DatabaseManager(db_path=":memory:")
        await db.init_db()
        
        # Add some test data
        await db.save_scan_result("https://safe.com", False, 0.9, 0.1, 1.0)
        await db.save_scan_result("https://phish.com", True, 0.95, 0.9, 1.2)
        
        stats = await db.get_statistics()
        assert "overall" in stats
        assert stats["overall"]["total_scans"] == 2
        assert stats["overall"]["phishing_detected"] == 1
        assert stats["overall"]["safe_urls"] == 1
        
        await db.close()

class TestUtilities:
    """Test utility functions"""
    
    def test_risk_level_calculation(self):
        """Test risk level calculation logic"""
        from models import URLScanResponse, RiskLevel
        from datetime import datetime
        
        # High risk
        response = URLScanResponse(
            url="https://test.com",
            is_phishing=True,
            confidence=0.9,
            risk_score=0.85,
            risk_level=RiskLevel.LOW,  # Will be overridden
            analysis_time=1.0,
            timestamp=datetime.now()
        )
        assert response.risk_level == RiskLevel.CRITICAL
        
        # Low risk
        response = URLScanResponse(
            url="https://test.com",
            is_phishing=False,
            confidence=0.9,
            risk_score=0.2,
            risk_level=RiskLevel.LOW,  # Will be overridden
            analysis_time=1.0,
            timestamp=datetime.now()
        )
        assert response.risk_level == RiskLevel.LOW

# Integration tests
class TestIntegration:
    """Integration tests"""
    
    @pytest.mark.asyncio
    async def test_full_analysis_pipeline(self):
        """Test the complete analysis pipeline"""
        # This would test the full flow from URL input to result
        # For now, we'll test the feature extraction pipeline
        
        extractor = EnhancedFeatureExtraction("https://example.com", check_real_time=False)
        
        # Test that we can extract all features
        features = await extractor.extract_all_features()
        
        # Should return 30 features (traditional feature set)
        assert len(features) == 30
        
        # All features should be numeric
        assert all(isinstance(f, (int, float)) for f in features)
        
        # Features should be in expected range (-1, 0, 1)
        assert all(f in [-1, 0, 1] for f in features)

# Performance tests
class TestPerformance:
    """Performance and load tests"""
    
    @pytest.mark.asyncio
    async def test_feature_extraction_performance(self):
        """Test feature extraction performance"""
        import time
        
        start_time = time.time()
        
        extractor = EnhancedFeatureExtraction("https://google.com", check_real_time=False)
        await extractor.extract_all_features()
        
        extraction_time = time.time() - start_time
        
        # Should complete within reasonable time (5 seconds without real-time checks)
        assert extraction_time < 5.0

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])