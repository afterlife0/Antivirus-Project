"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Threat Database - Centralized Threat Information Management

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)
- src.utils.crypto_utils (CryptoUtils)
- src.core.app_config (AppConfig)

Connected Components (files that import from this module):
- src.core.file_manager (FileManager)
- src.detection.signature_detector (SignatureDetector)
- src.intelligence.threat_intel (ThreatIntelligence)
- src.ui.quarantine_window (QuarantineWindow)
- src.core.scanner_engine (ScannerEngine)

Integration Points:
- Centralized threat information storage and retrieval
- Signature database management
- Threat classification database
- Known hash database for rapid lookup
- Threat family and variant tracking
- Reputation scoring and tracking
- SQLite-based persistent storage
- Thread-safe database operations
- Database maintenance and optimization
- Integration with quarantine system

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: ThreatDatabase
□ Dependencies properly imported with EXACT class names
□ All connected files can access ThreatDatabase functionality
□ SQLite database implementation
□ Thread-safe operations
□ Comprehensive threat tracking
□ Integration points established
"""

import os
import sys
import logging
import sqlite3
import threading
import time
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler
from src.utils.crypto_utils import CryptoUtils
from src.core.app_config import AppConfig


class ThreatType(Enum):
    """Types of threats tracked in the database."""
    MALWARE = "malware"
    VIRUS = "virus"
    TROJAN = "trojan"
    WORM = "worm"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    BACKDOOR = "backdoor"
    KEYLOGGER = "keylogger"
    BOTNET = "botnet"
    PUA = "potentially_unwanted_application"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


class ThreatSeverity(Enum):
    """Severity levels for threats."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatStatus(Enum):
    """Status of threat entries."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    QUARANTINED = "quarantined"
    DELETED = "deleted"
    WHITELISTED = "whitelisted"


@dataclass
class ThreatEntry:
    """Container for threat database entries."""
    threat_id: str
    file_hash_md5: str
    file_hash_sha256: str
    file_name: str
    file_path: str
    threat_type: ThreatType
    threat_family: str
    threat_variant: str
    severity: ThreatSeverity
    confidence_score: float
    first_seen: str
    last_seen: str
    detection_count: int
    signature_ids: List[str]
    yara_rules: List[str]
    file_size: int
    reputation_score: float
    status: ThreatStatus
    metadata: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""


@dataclass
class SignatureEntry:
    """Container for signature database entries."""
    signature_id: str
    signature_name: str
    signature_type: str
    signature_data: bytes
    threat_type: ThreatType
    threat_family: str
    creation_date: str
    last_updated: str
    enabled: bool
    confidence: float
    false_positive_rate: float
    detection_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatDatabase:
    """
    Centralized threat information database management system.
    
    Provides comprehensive threat tracking and signature management with:
    - SQLite-based persistent storage
    - Thread-safe database operations  
    - Threat classification and tracking
    - Signature database management
    - Hash-based rapid threat lookup
    - Reputation scoring system
    - Database maintenance and optimization
    - Integration with detection systems
    """
    
    def __init__(self, config: Optional[AppConfig] = None):
        """
        Initialize Threat Database.
        
        Args:
            config: Application configuration instance
        """
        self.encoding_handler = EncodingHandler()
        self.crypto_utils = CryptoUtils()
        self.config = config or AppConfig()
        self.logger = logging.getLogger("ThreatDatabase")
        
        # Database configuration
        self.db_dir = self._get_database_directory()
        self.threat_db_path = self.db_dir / "threats.db"
        self.signature_db_path = self.db_dir / "signatures.db"
        
        # Database connections
        self.threat_connection = None
        self.signature_connection = None
        
        # Thread safety
        self._threat_db_lock = threading.Lock()
        self._signature_db_lock = threading.Lock()
        
        # Caching for performance
        self._hash_cache = {}
        self._signature_cache = {}
        self._cache_max_size = 10000
        self._cache_ttl = 3600  # 1 hour
        
        # Statistics
        self.stats = {
            'total_threats': 0,
            'active_threats': 0,
            'total_signatures': 0,
            'active_signatures': 0,
            'database_size': 0,
            'last_updated': None
        }
        
        # Initialize database
        self._initialize_databases()
        self._load_statistics()
        
        self.logger.info("ThreatDatabase initialized")
    
    def _get_database_directory(self) -> Path:
        """Get database directory path."""
        try:
            # Try to get from config
            db_path = self.config.get_setting("database.path")
            if db_path:
                return Path(db_path)
            
            # Fallback to signatures directory
            project_root = Path(__file__).parent.parent.parent.parent
            return project_root / "signatures"
            
        except Exception as e:
            self.logger.error(f"Error getting database directory: {e}")
            return Path("signatures")
    
    def _initialize_databases(self) -> bool:
        """Initialize threat and signature databases."""
        try:
            # Create database directory
            self.db_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize threat database
            self._initialize_threat_database()
            
            # Initialize signature database
            self._initialize_signature_database()
            
            self.logger.info("Threat databases initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing databases: {e}")
            return False
    
    def _initialize_threat_database(self) -> bool:
        """Initialize threat database tables."""
        try:
            with self._threat_db_lock:
                self.threat_connection = sqlite3.connect(
                    str(self.threat_db_path),
                    check_same_thread=False,
                    timeout=30.0
                )
                self.threat_connection.row_factory = sqlite3.Row
                
                cursor = self.threat_connection.cursor()
                
                # Create threats table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        threat_id TEXT NOT NULL UNIQUE,
                        file_hash_md5 TEXT NOT NULL,
                        file_hash_sha256 TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        file_path TEXT,
                        threat_type TEXT NOT NULL,
                        threat_family TEXT,
                        threat_variant TEXT,
                        severity TEXT NOT NULL,
                        confidence_score REAL NOT NULL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        detection_count INTEGER DEFAULT 1,
                        signature_ids TEXT,
                        yara_rules TEXT,
                        file_size INTEGER,
                        reputation_score REAL DEFAULT 0.0,
                        status TEXT NOT NULL,
                        metadata TEXT,
                        notes TEXT
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_md5 ON threats(file_hash_md5)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_sha256 ON threats(file_hash_sha256)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON threats(threat_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_family ON threats(threat_family)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_status ON threats(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity)")
                
                self.threat_connection.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error initializing threat database: {e}")
            return False
    
    def _initialize_signature_database(self) -> bool:
        """Initialize signature database tables."""
        try:
            with self._signature_db_lock:
                self.signature_connection = sqlite3.connect(
                    str(self.signature_db_path),
                    check_same_thread=False,
                    timeout=30.0
                )
                self.signature_connection.row_factory = sqlite3.Row
                
                cursor = self.signature_connection.cursor()
                
                # Create signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_id TEXT NOT NULL UNIQUE,
                        signature_name TEXT NOT NULL,
                        signature_type TEXT NOT NULL,
                        signature_data BLOB NOT NULL,
                        threat_type TEXT NOT NULL,
                        threat_family TEXT,
                        creation_date TEXT NOT NULL,
                        last_updated TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT 1,
                        confidence REAL DEFAULT 1.0,
                        false_positive_rate REAL DEFAULT 0.0,
                        detection_count INTEGER DEFAULT 0,
                        metadata TEXT
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_signature_id ON signatures(signature_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_signature_type ON signatures(signature_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_signature_family ON signatures(threat_family)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_signature_enabled ON signatures(enabled)")
                
                self.signature_connection.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error initializing signature database: {e}")
            return False
    
    def add_threat(self, threat_entry: ThreatEntry) -> bool:
        """
        Add a new threat entry to the database.
        
        Args:
            threat_entry: ThreatEntry object to add
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self._threat_db_lock:
                cursor = self.threat_connection.cursor()
                
                # Convert lists and dicts to JSON
                signature_ids_json = json.dumps(threat_entry.signature_ids)
                yara_rules_json = json.dumps(threat_entry.yara_rules)
                metadata_json = json.dumps(threat_entry.metadata)
                
                cursor.execute("""
                    INSERT OR REPLACE INTO threats (
                        threat_id, file_hash_md5, file_hash_sha256, file_name, file_path,
                        threat_type, threat_family, threat_variant, severity, confidence_score,
                        first_seen, last_seen, detection_count, signature_ids, yara_rules,
                        file_size, reputation_score, status, metadata, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat_entry.threat_id,
                    threat_entry.file_hash_md5,
                    threat_entry.file_hash_sha256,
                    threat_entry.file_name,
                    threat_entry.file_path,
                    threat_entry.threat_type.value,
                    threat_entry.threat_family,
                    threat_entry.threat_variant,
                    threat_entry.severity.value,
                    threat_entry.confidence_score,
                    threat_entry.first_seen,
                    threat_entry.last_seen,
                    threat_entry.detection_count,
                    signature_ids_json,
                    yara_rules_json,
                    threat_entry.file_size,
                    threat_entry.reputation_score,
                    threat_entry.status.value,
                    metadata_json,
                    threat_entry.notes
                ))
                
                self.threat_connection.commit()
                
                # Update cache
                self._hash_cache[threat_entry.file_hash_md5] = threat_entry
                self._hash_cache[threat_entry.file_hash_sha256] = threat_entry
                
                self.logger.info(f"Added threat: {threat_entry.threat_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error adding threat: {e}")
            return False
    
    def lookup_threat_by_hash(self, file_hash: str) -> Optional[ThreatEntry]:
        """
        Look up threat by file hash (MD5 or SHA256).
        
        Args:
            file_hash: File hash to look up
            
        Returns:
            ThreatEntry if found, None otherwise
        """
        try:
            # Check cache first
            if file_hash in self._hash_cache:
                cache_entry = self._hash_cache[file_hash]
                if self._is_cache_valid(cache_entry):
                    return cache_entry
            
            with self._threat_db_lock:
                cursor = self.threat_connection.cursor()
                
                cursor.execute("""
                    SELECT * FROM threats 
                    WHERE file_hash_md5 = ? OR file_hash_sha256 = ?
                    LIMIT 1
                """, (file_hash, file_hash))
                
                row = cursor.fetchone()
                if row:
                    threat_entry = self._row_to_threat_entry(row)
                    
                    # Update cache
                    self._hash_cache[file_hash] = threat_entry
                    
                    return threat_entry
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error looking up threat by hash: {e}")
            return None
    
    def _row_to_threat_entry(self, row: sqlite3.Row) -> ThreatEntry:
        """Convert database row to ThreatEntry object."""
        return ThreatEntry(
            threat_id=row['threat_id'],
            file_hash_md5=row['file_hash_md5'],
            file_hash_sha256=row['file_hash_sha256'],
            file_name=row['file_name'],
            file_path=row['file_path'],
            threat_type=ThreatType(row['threat_type']),
            threat_family=row['threat_family'],
            threat_variant=row['threat_variant'],
            severity=ThreatSeverity(row['severity']),
            confidence_score=row['confidence_score'],
            first_seen=row['first_seen'],
            last_seen=row['last_seen'],
            detection_count=row['detection_count'],
            signature_ids=json.loads(row['signature_ids'] or '[]'),
            yara_rules=json.loads(row['yara_rules'] or '[]'),
            file_size=row['file_size'],
            reputation_score=row['reputation_score'],
            status=ThreatStatus(row['status']),
            metadata=json.loads(row['metadata'] or '{}'),
            notes=row['notes'] or ""
        )
    
    def _is_cache_valid(self, entry: Any) -> bool:
        """Check if cache entry is still valid."""
        # Simple cache validation - could be enhanced with TTL
        return True
    
    def _load_statistics(self) -> None:
        """Load database statistics."""
        try:
            with self._threat_db_lock:
                cursor = self.threat_connection.cursor()
                
                # Count threats
                cursor.execute("SELECT COUNT(*) FROM threats")
                self.stats['total_threats'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM threats WHERE status = 'active'")
                self.stats['active_threats'] = cursor.fetchone()[0]
            
            with self._signature_db_lock:
                cursor = self.signature_connection.cursor()
                
                # Count signatures
                cursor.execute("SELECT COUNT(*) FROM signatures")
                self.stats['total_signatures'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM signatures WHERE enabled = 1")
                self.stats['active_signatures'] = cursor.fetchone()[0]
            
            self.stats['last_updated'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Error loading statistics: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary containing database statistics
        """
        self._load_statistics()
        return self.stats.copy()
    
    def shutdown(self) -> None:
        """Graceful shutdown of database connections."""
        try:
            if self.threat_connection:
                self.threat_connection.close()
                
            if self.signature_connection:
                self.signature_connection.close()
                
            self.logger.info("ThreatDatabase shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during database shutdown: {e}")
