"""
Enhanced Database Module with Analytics and Monitoring
"""

import aiosqlite
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import json

logger = logging.getLogger(__name__)

DB_PATH = "enhanced_phishing_detection.db"

async def init_database():
    """Initialize the database with all required tables"""
    async with aiosqlite.connect(DB_PATH) as db:
        # URL Analysis Log table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS url_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                analysis_time_ms INTEGER NOT NULL,
                client_ip TEXT,
                timestamp TEXT NOT NULL,
                features TEXT,  -- JSON string of features
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Bulk Analysis Log table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS bulk_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_urls INTEGER NOT NULL,
                phishing_detected INTEGER NOT NULL,
                safe_urls INTEGER NOT NULL,
                total_time_ms INTEGER NOT NULL,
                client_ip TEXT,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # API Usage Stats table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                endpoint TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                response_time_ms INTEGER NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                api_key TEXT,
                timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Threat Intelligence Cache table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url_hash TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL NOT NULL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT  -- JSON string for additional data
            )
        """)
        
        # Model Performance Metrics table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS model_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_version TEXT NOT NULL,
                accuracy REAL NOT NULL,
                precision_phishing REAL NOT NULL,
                recall_phishing REAL NOT NULL,
                f1_score REAL NOT NULL,
                false_positive_rate REAL NOT NULL,
                evaluation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT  -- JSON string for additional metrics
            )
        """)
        
        # User Feedback table (for continuous improvement)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS user_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER,
                url TEXT NOT NULL,
                predicted_result TEXT NOT NULL,
                user_reported_result TEXT NOT NULL,
                confidence_rating INTEGER,  -- 1-5 scale
                comments TEXT,
                client_ip TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (analysis_id) REFERENCES url_analyses (id)
            )
        """)
        
        # Create indexes for better performance
        await db.execute("CREATE INDEX IF NOT EXISTS idx_url_analyses_timestamp ON url_analyses(timestamp)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_url_analyses_prediction ON url_analyses(prediction)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage(endpoint)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_intelligence_hash ON threat_intelligence(url_hash)")
        
        await db.commit()
        logger.info("Enhanced database initialized successfully")

async def log_url_analysis(analysis_data: Dict):
    """Log URL analysis result to database"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO url_analyses (
                    url, prediction, confidence, risk_score, analysis_time_ms, 
                    client_ip, timestamp, features
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                analysis_data["url"],
                analysis_data["prediction"],
                analysis_data["confidence"],
                analysis_data["risk_score"],
                analysis_data["analysis_time_ms"],
                analysis_data.get("client_ip"),
                analysis_data["timestamp"],
                json.dumps(analysis_data.get("features")) if analysis_data.get("features") else None
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to log URL analysis: {e}")

async def log_bulk_analysis(bulk_data: Dict):
    """Log bulk analysis result to database"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO bulk_analyses (
                    total_urls, phishing_detected, safe_urls, total_time_ms, 
                    client_ip, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                bulk_data["total_urls"],
                bulk_data["phishing_detected"],
                bulk_data["safe_urls"],
                bulk_data["total_time_ms"],
                bulk_data.get("client_ip"),
                bulk_data["timestamp"]
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to log bulk analysis: {e}")

async def log_api_usage(usage_data: Dict):
    """Log API usage for monitoring"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO api_usage (
                    endpoint, method, status_code, response_time_ms, 
                    client_ip, user_agent, api_key, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                usage_data["endpoint"],
                usage_data["method"],
                usage_data["status_code"],
                usage_data["response_time_ms"],
                usage_data.get("client_ip"),
                usage_data.get("user_agent"),
                usage_data.get("api_key"),
                usage_data["timestamp"]
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to log API usage: {e}")

async def get_analysis_stats(days: int = 7) -> Dict:
    """Get analysis statistics for the specified number of days"""
    try:
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(DB_PATH) as db:
            # Total requests
            cursor = await db.execute("""
                SELECT COUNT(*) FROM url_analyses 
                WHERE timestamp > ?
            """, (cutoff_date,))
            total_requests = (await cursor.fetchone())[0]
            
            # Phishing detected
            cursor = await db.execute("""
                SELECT COUNT(*) FROM url_analyses 
                WHERE prediction = 'phishing' AND timestamp > ?
            """, (cutoff_date,))
            phishing_detected = (await cursor.fetchone())[0]
            
            # Safe URLs
            cursor = await db.execute("""
                SELECT COUNT(*) FROM url_analyses 
                WHERE prediction = 'safe' AND timestamp > ?
            """, (cutoff_date,))
            safe_urls = (await cursor.fetchone())[0]
            
            # Average response time
            cursor = await db.execute("""
                SELECT AVG(analysis_time_ms) FROM url_analyses 
                WHERE timestamp > ?
            """, (cutoff_date,))
            avg_response_time = (await cursor.fetchone())[0] or 0.0
            
            # Daily breakdown
            cursor = await db.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    COUNT(*) as total,
                    SUM(CASE WHEN prediction = 'phishing' THEN 1 ELSE 0 END) as phishing,
                    SUM(CASE WHEN prediction = 'safe' THEN 1 ELSE 0 END) as safe,
                    AVG(analysis_time_ms) as avg_time
                FROM url_analyses 
                WHERE timestamp > ?
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            """, (cutoff_date,))
            daily_stats = await cursor.fetchall()
            
            return {
                "total_requests": total_requests,
                "phishing_detected": phishing_detected,
                "safe_urls": safe_urls,
                "avg_response_time": avg_response_time,
                "daily_breakdown": [
                    {
                        "date": row[0],
                        "total": row[1],
                        "phishing": row[2],
                        "safe": row[3],
                        "avg_time": row[4]
                    } for row in daily_stats
                ]
            }
    except Exception as e:
        logger.error(f"Failed to get analysis stats: {e}")
        return {
            "total_requests": 0,
            "phishing_detected": 0,
            "safe_urls": 0,
            "avg_response_time": 0.0,
            "daily_breakdown": []
        }

async def get_top_phishing_domains(limit: int = 10, days: int = 7) -> List[Dict]:
    """Get top phishing domains detected in the last N days"""
    try:
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT 
                    SUBSTR(url, INSTR(url, '://') + 3) as domain,
                    COUNT(*) as count,
                    AVG(confidence) as avg_confidence
                FROM url_analyses 
                WHERE prediction = 'phishing' AND timestamp > ?
                GROUP BY SUBSTR(url, INSTR(url, '://') + 3)
                ORDER BY count DESC
                LIMIT ?
            """, (cutoff_date, limit))
            
            results = await cursor.fetchall()
            
            return [
                {
                    "domain": row[0].split('/')[0] if '/' in row[0] else row[0],  # Extract just domain
                    "detections": row[1],
                    "avg_confidence": row[2]
                } for row in results
            ]
    except Exception as e:
        logger.error(f"Failed to get top phishing domains: {e}")
        return []

async def store_threat_intelligence(url: str, threat_level: str, source: str, confidence: float, metadata: Dict = None):
    """Store threat intelligence data"""
    try:
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT OR REPLACE INTO threat_intelligence (
                    url_hash, url, threat_level, source, confidence, 
                    last_updated, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                url_hash,
                url,
                threat_level,
                source,
                confidence,
                datetime.now().isoformat(),
                json.dumps(metadata) if metadata else None
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to store threat intelligence: {e}")

async def get_threat_intelligence(url: str) -> Optional[Dict]:
    """Get threat intelligence for a URL"""
    try:
        import hashlib
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT threat_level, source, confidence, last_updated, metadata
                FROM threat_intelligence 
                WHERE url_hash = ?
            """, (url_hash,))
            
            result = await cursor.fetchone()
            
            if result:
                return {
                    "threat_level": result[0],
                    "source": result[1],
                    "confidence": result[2],
                    "last_updated": result[3],
                    "metadata": json.loads(result[4]) if result[4] else None
                }
    except Exception as e:
        logger.error(f"Failed to get threat intelligence: {e}")
    
    return None

async def store_user_feedback(feedback_data: Dict):
    """Store user feedback for model improvement"""
    try:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("""
                INSERT INTO user_feedback (
                    analysis_id, url, predicted_result, user_reported_result,
                    confidence_rating, comments, client_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                feedback_data.get("analysis_id"),
                feedback_data["url"],
                feedback_data["predicted_result"],
                feedback_data["user_reported_result"],
                feedback_data.get("confidence_rating"),
                feedback_data.get("comments"),
                feedback_data.get("client_ip")
            ))
            await db.commit()
    except Exception as e:
        logger.error(f"Failed to store user feedback: {e}")

async def get_model_accuracy_over_time(days: int = 30) -> List[Dict]:
    """Calculate model accuracy over time using user feedback"""
    try:
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("""
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as total_feedback,
                    SUM(CASE WHEN predicted_result = user_reported_result THEN 1 ELSE 0 END) as correct,
                    AVG(confidence_rating) as avg_user_confidence
                FROM user_feedback 
                WHERE created_at > ?
                GROUP BY DATE(created_at)
                ORDER BY date DESC
            """, (cutoff_date,))
            
            results = await cursor.fetchall()
            
            return [
                {
                    "date": row[0],
                    "total_feedback": row[1],
                    "accuracy": row[2] / row[1] if row[1] > 0 else 0,
                    "avg_user_confidence": row[3]
                } for row in results
            ]
    except Exception as e:
        logger.error(f"Failed to get model accuracy over time: {e}")
        return []

async def cleanup_old_data(days: int = 90):
    """Clean up old data to maintain database performance"""
    try:
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(DB_PATH) as db:
            # Clean up old analysis logs
            await db.execute("DELETE FROM url_analyses WHERE timestamp < ?", (cutoff_date,))
            
            # Clean up old API usage logs
            await db.execute("DELETE FROM api_usage WHERE timestamp < ?", (cutoff_date,))
            
            # Clean up old bulk analyses
            await db.execute("DELETE FROM bulk_analyses WHERE timestamp < ?", (cutoff_date,))
            
            await db.commit()
            
        logger.info(f"Cleaned up data older than {days} days")
    except Exception as e:
        logger.error(f"Failed to cleanup old data: {e}")

async def export_analytics_data(format: str = "json", days: int = 30) -> Dict:
    """Export analytics data for external analysis"""
    try:
        stats = await get_analysis_stats(days)
        top_domains = await get_top_phishing_domains(20, days)
        accuracy_data = await get_model_accuracy_over_time(days)
        
        export_data = {
            "export_date": datetime.now().isoformat(),
            "period_days": days,
            "summary_stats": stats,
            "top_phishing_domains": top_domains,
            "model_accuracy_trend": accuracy_data,
            "metadata": {
                "format": format,
                "version": "2.0.0"
            }
        }
        
        return export_data
    except Exception as e:
        logger.error(f"Failed to export analytics data: {e}")
        return {}

# Initialize database on import
if __name__ == "__main__":
    asyncio.run(init_database())