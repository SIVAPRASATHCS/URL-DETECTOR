"""
Database management for Phishing URL Detection
Handles scan history, statistics, and user data
"""

import asyncio
import aiosqlite
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Async database manager using SQLite for simplicity"""
    
    def __init__(self, db_path: str = "phishing_detection.db"):
        self.db_path = db_path
        self.connection = None
    
    async def init_db(self):
        """Initialize database and create tables"""
        try:
            self.connection = await aiosqlite.connect(self.db_path)
            await self._create_tables()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    async def _create_tables(self):
        """Create database tables"""
        # Scan results table
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                is_phishing BOOLEAN NOT NULL,
                confidence REAL NOT NULL,
                risk_score REAL NOT NULL,
                analysis_time REAL NOT NULL,
                features TEXT,  -- JSON string of features
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT
            )
        """)
        
        # Statistics table
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL,
                total_scans INTEGER DEFAULT 0,
                phishing_detected INTEGER DEFAULT 0,
                safe_urls INTEGER DEFAULT 0,
                avg_analysis_time REAL DEFAULT 0,
                UNIQUE(date)
            )
        """)
        
        # API usage table (for future rate limiting)
        await self.connection.execute("""
            CREATE TABLE IF NOT EXISTS api_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key TEXT,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                response_time REAL
            )
        """)
        
        await self.connection.commit()
    
    async def save_scan_result(
        self, 
        url: str, 
        is_phishing: bool, 
        confidence: float, 
        risk_score: float, 
        analysis_time: float,
        features: Optional[List] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """Save scan result to database"""
        try:
            features_json = json.dumps(features) if features else None
            
            await self.connection.execute("""
                INSERT INTO scan_results 
                (url, is_phishing, confidence, risk_score, analysis_time, features, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (url, is_phishing, confidence, risk_score, analysis_time, features_json, ip_address, user_agent))
            
            # Update daily statistics
            today = datetime.now().date()
            await self.connection.execute("""
                INSERT INTO statistics (date, total_scans, phishing_detected, safe_urls, avg_analysis_time)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                    total_scans = total_scans + 1,
                    phishing_detected = phishing_detected + ?,
                    safe_urls = safe_urls + ?,
                    avg_analysis_time = (avg_analysis_time * (total_scans - 1) + ?) / total_scans
            """, (
                today, 
                1 if is_phishing else 0, 
                0 if is_phishing else 1, 
                analysis_time,
                1 if is_phishing else 0, 
                0 if is_phishing else 1, 
                analysis_time
            ))
            
            await self.connection.commit()
            
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
            await self.connection.rollback()
            raise
    
    async def get_scan_history(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Get recent scan history"""
        try:
            cursor = await self.connection.execute("""
                SELECT url, is_phishing, confidence, risk_score, analysis_time, timestamp
                FROM scan_results 
                ORDER BY timestamp DESC 
                LIMIT ? OFFSET ?
            """, (limit, offset))
            
            rows = await cursor.fetchall()
            
            return [
                {
                    "url": row[0],
                    "is_phishing": bool(row[1]),
                    "confidence": row[2],
                    "risk_score": row[3],
                    "analysis_time": row[4],
                    "timestamp": row[5]
                }
                for row in rows
            ]
            
        except Exception as e:
            logger.error(f"Failed to get scan history: {e}")
            return []
    
    async def get_statistics(self, days: int = 30) -> Dict:
        """Get system statistics"""
        try:
            # Overall stats
            cursor = await self.connection.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    SUM(CASE WHEN is_phishing = 1 THEN 1 ELSE 0 END) as phishing_detected,
                    SUM(CASE WHEN is_phishing = 0 THEN 1 ELSE 0 END) as safe_urls,
                    AVG(analysis_time) as avg_analysis_time,
                    AVG(confidence) as avg_confidence
                FROM scan_results
                WHERE timestamp >= date('now', '-{} days')
            """.format(days))
            
            overall = await cursor.fetchone()
            
            # Daily stats for the last N days
            cursor = await self.connection.execute("""
                SELECT date, total_scans, phishing_detected, safe_urls, avg_analysis_time
                FROM statistics 
                WHERE date >= date('now', '-{} days')
                ORDER BY date DESC
            """.format(days))
            
            daily_stats = await cursor.fetchall()
            
            # Top phishing domains
            cursor = await self.connection.execute("""
                SELECT 
                    SUBSTR(url, INSTR(url, '://') + 3) as domain,
                    COUNT(*) as count
                FROM scan_results 
                WHERE is_phishing = 1 
                    AND timestamp >= date('now', '-{} days')
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
            """.format(days))
            
            top_phishing = await cursor.fetchall()
            
            return {
                "overall": {
                    "total_scans": overall[0] or 0,
                    "phishing_detected": overall[1] or 0,
                    "safe_urls": overall[2] or 0,
                    "avg_analysis_time": round(overall[3] or 0, 3),
                    "avg_confidence": round(overall[4] or 0, 3),
                    "detection_rate": round((overall[1] or 0) / max(overall[0] or 1, 1) * 100, 2)
                },
                "daily_stats": [
                    {
                        "date": row[0],
                        "total_scans": row[1],
                        "phishing_detected": row[2],
                        "safe_urls": row[3],
                        "avg_analysis_time": round(row[4], 3)
                    }
                    for row in daily_stats
                ],
                "top_phishing_domains": [
                    {"domain": row[0], "count": row[1]}
                    for row in top_phishing
                ],
                "period_days": days
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"error": str(e)}
    
    async def log_api_usage(
        self, 
        ip_address: str, 
        endpoint: str, 
        response_time: float,
        api_key: Optional[str] = None
    ):
        """Log API usage for monitoring and rate limiting"""
        try:
            await self.connection.execute("""
                INSERT INTO api_usage (api_key, ip_address, endpoint, response_time)
                VALUES (?, ?, ?, ?)
            """, (api_key, ip_address, endpoint, response_time))
            
            await self.connection.commit()
            
        except Exception as e:
            logger.error(f"Failed to log API usage: {e}")
    
    async def get_api_usage_stats(self, hours: int = 24) -> Dict:
        """Get API usage statistics"""
        try:
            cursor = await self.connection.execute("""
                SELECT 
                    endpoint,
                    COUNT(*) as requests,
                    AVG(response_time) as avg_response_time
                FROM api_usage 
                WHERE timestamp >= datetime('now', '-{} hours')
                GROUP BY endpoint
                ORDER BY requests DESC
            """.format(hours))
            
            endpoint_stats = await cursor.fetchall()
            
            cursor = await self.connection.execute("""
                SELECT 
                    ip_address,
                    COUNT(*) as requests
                FROM api_usage 
                WHERE timestamp >= datetime('now', '-{} hours')
                GROUP BY ip_address
                ORDER BY requests DESC
                LIMIT 10
            """.format(hours))
            
            top_ips = await cursor.fetchall()
            
            return {
                "endpoint_stats": [
                    {
                        "endpoint": row[0],
                        "requests": row[1],
                        "avg_response_time": round(row[2], 3)
                    }
                    for row in endpoint_stats
                ],
                "top_ips": [
                    {"ip": row[0], "requests": row[1]}
                    for row in top_ips
                ],
                "period_hours": hours
            }
            
        except Exception as e:
            logger.error(f"Failed to get API usage stats: {e}")
            return {"error": str(e)}
    
    async def is_connected(self) -> bool:
        """Check if database connection is active"""
        try:
            if self.connection:
                await self.connection.execute("SELECT 1")
                return True
        except:
            pass
        return False
    
    async def close(self):
        """Close database connection"""
        if self.connection:
            await self.connection.close()
            logger.info("Database connection closed")