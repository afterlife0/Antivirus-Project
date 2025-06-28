"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Signature Detector - Hash-based Malware Detection

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)
- src.utils.crypto_utils (CryptoUtils)
- src.utils.file_utils (FileUtils)

Connected Components (files that import from this module):
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.core.scanner_engine (ScannerEngine)
- src.core.threat_database (ThreatDatabase)

Integration Points:
- Signature-based malware detection using cryptographic hashes
- Known threat identification through signature matching
- Signature database management and storage
- Fast hash-based scanning for immediate threat detection
- Integration with ensemble voting system for global classification
- Signature update and synchronization capabilities
- Multi-hash algorithm support (MD5, SHA1, SHA256, SHA512)
- Binary pattern matching and string signatures
- File reputation checking via signature database
- Real-time signature scanning with minimal performance impact

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: SignatureDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access SignatureDetector functionality
□ Signature detection implemented
□ Hash-based matching functional
□ Database integration working
□ Performance optimization included
□ Update mechanism integrated
"""

import os
import sys
import logging
import sqlite3
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Set
import json
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler
from src.utils.crypto_utils import CryptoUtils
from src.utils.file_utils import FileUtils


class SignatureType(Enum):
    """Types of signatures supported."""
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    HASH_SHA512 = "hash_sha512"
    BINARY_PATTERN = "binary_pattern"
    STRING_PATTERN = "string_pattern"
    SECTION_HASH = "section_hash"
    IMPORT_HASH = "import_hash"


class ThreatCategory(Enum):
    """Threat categories for signatures."""
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    WORM = "worm"
    VIRUS = "virus"
    BACKDOOR = "backdoor"
    POTENTIALLY_UNWANTED = "pua"


@dataclass
class SignatureMatch:
    """Container for signature match results."""
    signature_id: str
    signature_type: SignatureType
    threat_name: str
    threat_category: ThreatCategory
    confidence: float
    risk_score: float
    signature_data: str
    match_offset: Optional[int]
    match_length: Optional[int]
    detection_timestamp: str
    signature_source: str
    additional_info: Dict[str, Any]


@dataclass
class SignatureDetectionResult:
    """Container for complete signature detection results."""
    file_path: str
    file_hash_sha256: str
    detected: bool
    matches: List[SignatureMatch]
    total_signatures_checked: int
    detection_time: float
    file_size: int
    scan_timestamp: str
    confidence: float
    risk_score: float
    threat_classification: str
    recommended_action: str


class SignatureDetector:
    """
    Signature-based Malware Detection System.
    
    Provides fast signature-based detection using multiple hash algorithms,
    binary patterns, and string signatures for known malware identification.
    
    Features:
    - Multi-hash signature matching (MD5, SHA1, SHA256, SHA512)
    - Binary pattern matching for code signatures
    - String pattern matching for malware identifiers
    - SQLite-based signature database with indexing
    - Real-time signature updates and synchronization
    - Performance-optimized scanning with caching
    - Integration with ensemble voting system
    - Comprehensive threat categorization
    - Detailed match reporting and analysis
    """
    
    def __init__(self, signature_db_path: Optional[Union[str, Path]] = None):
        """
        Initialize Signature Detector.
        
        Args:
            signature_db_path: Path to signature database file
        """
        self.encoding_handler = EncodingHandler()
        self.crypto_utils = CryptoUtils()
        self.file_utils = FileUtils()
        self.logger = logging.getLogger("SignatureDetector")
        
        # Database configuration
        self.signature_db_path = signature_db_path or self._get_default_db_path()
        self.db_connection = None
        self.db_lock = threading.Lock()
        
        # Signature caching for performance
        self.hash_cache = {}
        self.pattern_cache = {}
        self.cache_max_size = 10000
        self.cache_ttl = 3600  # 1 hour
        
        # Detection configuration
        self.supported_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
            '.vbs', '.js', '.jar', '.apk', '.dex', '.so', '.dylib'
        }
        
        # Performance settings
        self.max_file_size = 100 * 1024 * 1024  # 100MB max
        self.chunk_size = 64 * 1024  # 64KB chunks for large files
        self.pattern_scan_limit = 10 * 1024 * 1024  # 10MB for pattern scanning
        
        # Statistics tracking
        self.total_scans = 0
        self.total_detections = 0
        self.total_scan_time = 0.0
        self.cache_hits = 0
        self.cache_misses = 0
        
        # Thread safety
        self._stats_lock = threading.Lock()
        
        # Initialize database and load signatures
        self._initialize_database()
        self._load_signature_cache()
        
        self.logger.info(f"SignatureDetector initialized with database: {self.signature_db_path}")
    
    def _get_default_db_path(self) -> Path:
        """Get default signature database path."""
        try:
            # Get project root directory
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent.parent
            
            # Create signatures directory if it doesn't exist
            signatures_dir = project_root / "signatures"
            signatures_dir.mkdir(exist_ok=True)
            
            return signatures_dir / "virus_signatures.db"
            
        except Exception as e:
            self.logger.error(f"Error getting default database path: {e}")
            return Path("virus_signatures.db")
    
    def _initialize_database(self) -> bool:
        """Initialize signature database with required tables."""
        try:
            with self.db_lock:
                self.db_connection = sqlite3.connect(
                    str(self.signature_db_path),
                    check_same_thread=False,
                    timeout=30.0
                )
                self.db_connection.row_factory = sqlite3.Row
                
                cursor = self.db_connection.cursor()
                
                # Create hash signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS hash_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_type TEXT NOT NULL,
                        hash_value TEXT NOT NULL UNIQUE,
                        threat_name TEXT NOT NULL,
                        threat_category TEXT NOT NULL,
                        confidence REAL DEFAULT 1.0,
                        risk_score REAL DEFAULT 0.8,
                        signature_source TEXT,
                        created_date TEXT,
                        last_updated TEXT,
                        additional_info TEXT
                    )
                """)
                
                # Create pattern signatures table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pattern_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature_type TEXT NOT NULL,
                        pattern_data TEXT NOT NULL,
                        threat_name TEXT NOT NULL,
                        threat_category TEXT NOT NULL,
                        confidence REAL DEFAULT 0.8,
                        risk_score REAL DEFAULT 0.7,
                        pattern_description TEXT,
                        signature_source TEXT,
                        created_date TEXT,
                        last_updated TEXT,
                        additional_info TEXT
                    )
                """)
                
                # Create detection statistics table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detection_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_hash TEXT NOT NULL,
                        detection_date TEXT NOT NULL,
                        threat_name TEXT NOT NULL,
                        signature_type TEXT NOT NULL,
                        file_path TEXT,
                        file_size INTEGER,
                        detection_time REAL
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_hash_value ON hash_signatures(hash_value)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_category ON hash_signatures(threat_category)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_pattern_type ON pattern_signatures(signature_type)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_detection_date ON detection_stats(detection_date)")
                
                self.db_connection.commit()
                
                # Load default signatures if database is empty
                self._load_default_signatures()
                
                self.logger.info("Signature database initialized successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            return False
    
    def _load_default_signatures(self) -> None:
        """Load default signature set if database is empty."""
        try:
            cursor = self.db_connection.cursor()
            
            # Check if signatures exist
            cursor.execute("SELECT COUNT(*) FROM hash_signatures")
            hash_count = cursor.fetchone()[0]
            
            if hash_count == 0:
                self.logger.info("Loading default signatures...")
                
                # Sample malware hashes (in production, these would come from threat intelligence)
                default_hash_signatures = [
                    {
                        'signature_type': 'hash_sha256',
                        'hash_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',  # Empty file (test)
                        'threat_name': 'Test.EmptyFile',
                        'threat_category': 'malware',
                        'confidence': 0.5,
                        'risk_score': 0.1,
                        'signature_source': 'default_signatures',
                        'additional_info': '{"description": "Test signature for empty files"}'
                    },
                    # Add more real signatures in production
                ]
                
                # Sample pattern signatures
                default_pattern_signatures = [
                    {
                        'signature_type': 'string_pattern',
                        'pattern_data': 'This program cannot be run in DOS mode',
                        'threat_name': 'Generic.DOSStub',
                        'threat_category': 'potentially_unwanted',
                        'confidence': 0.3,
                        'risk_score': 0.2,
                        'pattern_description': 'Standard DOS stub message',
                        'signature_source': 'default_signatures',
                        'additional_info': '{"description": "Common DOS stub pattern"}'
                    }
                ]
                
                # Insert default hash signatures
                for sig in default_hash_signatures:
                    sig['created_date'] = datetime.now().isoformat()
                    sig['last_updated'] = datetime.now().isoformat()
                    
                    cursor.execute("""
                        INSERT OR IGNORE INTO hash_signatures 
                        (signature_type, hash_value, threat_name, threat_category, 
                         confidence, risk_score, signature_source, created_date, 
                         last_updated, additional_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sig['signature_type'], sig['hash_value'], sig['threat_name'],
                        sig['threat_category'], sig['confidence'], sig['risk_score'],
                        sig['signature_source'], sig['created_date'], sig['last_updated'],
                        sig['additional_info']
                    ))
                
                # Insert default pattern signatures
                for sig in default_pattern_signatures:
                    sig['created_date'] = datetime.now().isoformat()
                    sig['last_updated'] = datetime.now().isoformat()
                    
                    cursor.execute("""
                        INSERT OR IGNORE INTO pattern_signatures 
                        (signature_type, pattern_data, threat_name, threat_category,
                         confidence, risk_score, pattern_description, signature_source,
                         created_date, last_updated, additional_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        sig['signature_type'], sig['pattern_data'], sig['threat_name'],
                        sig['threat_category'], sig['confidence'], sig['risk_score'],
                        sig['pattern_description'], sig['signature_source'],
                        sig['created_date'], sig['last_updated'], sig['additional_info']
                    ))
                
                self.db_connection.commit()
                self.logger.info("Default signatures loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading default signatures: {e}")
    
    def _load_signature_cache(self) -> None:
        """Load frequently used signatures into memory cache."""
        try:
            cursor = self.db_connection.cursor()
            
            # Load hash signatures into cache
            cursor.execute("""
                SELECT signature_type, hash_value, threat_name, threat_category,
                       confidence, risk_score, signature_source, additional_info
                FROM hash_signatures
                ORDER BY confidence DESC, risk_score DESC
                LIMIT ?
            """, (self.cache_max_size // 2,))
            
            for row in cursor.fetchall():
                cache_key = f"{row['signature_type']}:{row['hash_value']}"
                self.hash_cache[cache_key] = {
                    'threat_name': row['threat_name'],
                    'threat_category': row['threat_category'],
                    'confidence': row['confidence'],
                    'risk_score': row['risk_score'],
                    'signature_source': row['signature_source'],
                    'additional_info': row['additional_info'],
                    'cached_time': time.time()
                }
            
            self.logger.info(f"Loaded {len(self.hash_cache)} hash signatures into cache")
            
        except Exception as e:
            self.logger.error(f"Error loading signature cache: {e}")
    
    def detect(self, file_path: Union[str, Path]) -> Optional[SignatureDetectionResult]:
        """
        Perform signature-based detection on a file.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Signature detection result or None if scan fails
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            if not file_path.exists() or not file_path.is_file():
                self.logger.error(f"File not found or not a file: {file_path}")
                return None
            
            self.logger.info(f"Starting signature detection for: {file_path.name}")
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                self.logger.warning(f"File too large ({file_size} bytes), skipping: {file_path.name}")
                return self._create_detection_result(
                    file_path, "", False, [], 0, time.time() - start_time,
                    file_size, "File too large for signature scanning"
                )
            
            # Check file extension
            if file_path.suffix.lower() not in self.supported_extensions:
                self.logger.debug(f"Unsupported file extension: {file_path.suffix}")
                return self._create_detection_result(
                    file_path, "", False, [], 0, time.time() - start_time,
                    file_size, "Unsupported file type"
                )
            
            # Calculate file hashes
            file_hashes = self._calculate_file_hashes(file_path)
            if not file_hashes:
                return None
            
            # Perform hash-based detection
            hash_matches = self._detect_hash_signatures(file_hashes, file_path)
            
            # Perform pattern-based detection (for smaller files)
            pattern_matches = []
            if file_size <= self.pattern_scan_limit:
                pattern_matches = self._detect_pattern_signatures(file_path)
            
            # Combine all matches
            all_matches = hash_matches + pattern_matches
            total_signatures_checked = len(self.hash_cache) + (len(pattern_matches) if pattern_matches else 0)
            
            # Determine detection result
            detected = len(all_matches) > 0
            confidence = max([match.confidence for match in all_matches]) if all_matches else 0.0
            risk_score = max([match.risk_score for match in all_matches]) if all_matches else 0.0
            
            # Determine threat classification
            threat_classification = self._determine_threat_classification(all_matches)
            
            # Calculate processing time
            detection_time = time.time() - start_time
            
            # Update statistics
            self._update_statistics(detection_time, detected)
            
            # Log detection to database
            if detected:
                self._log_detection(file_hashes['sha256'], file_path, all_matches[0], detection_time, file_size)
            
            # Create detection result
            result = SignatureDetectionResult(
                file_path=str(file_path),
                file_hash_sha256=file_hashes['sha256'],
                detected=detected,
                matches=all_matches,
                total_signatures_checked=total_signatures_checked,
                detection_time=detection_time,
                file_size=file_size,
                scan_timestamp=datetime.now().isoformat(),
                confidence=confidence,
                risk_score=risk_score,
                threat_classification=threat_classification,
                recommended_action=self._get_recommended_action(threat_classification, confidence)
            )
            
            self.logger.info(f"Signature detection completed: {detected} "
                           f"({len(all_matches)} matches, {detection_time:.3f}s)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in signature detection for {file_path}: {e}")
            return None
    
    def _calculate_file_hashes(self, file_path: Path) -> Optional[Dict[str, str]]:
        """Calculate multiple hashes for a file."""
        try:
            return {
                'md5': self.crypto_utils.calculate_file_hash(file_path, 'md5'),
                'sha1': self.crypto_utils.calculate_file_hash(file_path, 'sha1'),
                'sha256': self.crypto_utils.calculate_file_hash(file_path, 'sha256'),
                'sha512': self.crypto_utils.calculate_file_hash(file_path, 'sha512')
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating file hashes: {e}")
            return None
    
    def _detect_hash_signatures(self, file_hashes: Dict[str, str], file_path: Path) -> List[SignatureMatch]:
        """Detect hash-based signatures."""
        try:
            matches = []
            
            for hash_type, hash_value in file_hashes.items():
                cache_key = f"hash_{hash_type}:{hash_value}"
                
                # Check cache first
                if cache_key in self.hash_cache:
                    cached_sig = self.hash_cache[cache_key]
                    
                    # Check cache TTL
                    if time.time() - cached_sig['cached_time'] < self.cache_ttl:
                        self.cache_hits += 1
                        
                        match = SignatureMatch(
                            signature_id=cache_key,
                            signature_type=SignatureType(f"hash_{hash_type}"),
                            threat_name=cached_sig['threat_name'],
                            threat_category=ThreatCategory(cached_sig['threat_category']),
                            confidence=cached_sig['confidence'],
                            risk_score=cached_sig['risk_score'],
                            signature_data=hash_value,
                            match_offset=None,
                            match_length=None,
                            detection_timestamp=datetime.now().isoformat(),
                            signature_source=cached_sig['signature_source'],
                            additional_info=json.loads(cached_sig['additional_info']) if cached_sig['additional_info'] else {}
                        )
                        matches.append(match)
                        continue
                
                # Query database
                self.cache_misses += 1
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT threat_name, threat_category, confidence, risk_score,
                           signature_source, additional_info
                    FROM hash_signatures
                    WHERE signature_type = ? AND hash_value = ?
                """, (f"hash_{hash_type}", hash_value))
                
                row = cursor.fetchone()
                if row:
                    match = SignatureMatch(
                        signature_id=f"db_{hash_type}:{hash_value}",
                        signature_type=SignatureType(f"hash_{hash_type}"),
                        threat_name=row['threat_name'],
                        threat_category=ThreatCategory(row['threat_category']),
                        confidence=row['confidence'],
                        risk_score=row['risk_score'],
                        signature_data=hash_value,
                        match_offset=None,
                        match_length=None,
                        detection_timestamp=datetime.now().isoformat(),
                        signature_source=row['signature_source'],
                        additional_info=json.loads(row['additional_info']) if row['additional_info'] else {}
                    )
                    matches.append(match)
                    
                    # Add to cache
                    if len(self.hash_cache) < self.cache_max_size:
                        self.hash_cache[cache_key] = {
                            'threat_name': row['threat_name'],
                            'threat_category': row['threat_category'],
                            'confidence': row['confidence'],
                            'risk_score': row['risk_score'],
                            'signature_source': row['signature_source'],
                            'additional_info': row['additional_info'],
                            'cached_time': time.time()
                        }
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Error detecting hash signatures: {e}")
            return []
    
    def _detect_pattern_signatures(self, file_path: Path) -> List[SignatureMatch]:
        """Detect pattern-based signatures."""
        try:
            matches = []
            
            # Read file content for pattern matching
            file_content = self.file_utils.read_file_safely(file_path, binary=True)
            if not file_content:
                return matches
            
            # Query pattern signatures from database
            cursor = self.db_connection.cursor()
            cursor.execute("""
                SELECT pattern_data, threat_name, threat_category, confidence,
                       risk_score, pattern_description, signature_source, additional_info
                FROM pattern_signatures
                WHERE signature_type IN ('string_pattern', 'binary_pattern')
            """)
            
            for row in cursor.fetchall():
                pattern_data = row['pattern_data']
                
                # Search for pattern in file content
                if isinstance(file_content, bytes):
                    if isinstance(pattern_data, str):
                        pattern_bytes = pattern_data.encode('utf-8', errors='ignore')
                    else:
                        pattern_bytes = pattern_data
                    
                    match_offset = file_content.find(pattern_bytes)
                    if match_offset != -1:
                        match = SignatureMatch(
                            signature_id=f"pattern:{pattern_data[:20]}",
                            signature_type=SignatureType.STRING_PATTERN,
                            threat_name=row['threat_name'],
                            threat_category=ThreatCategory(row['threat_category']),
                            confidence=row['confidence'],
                            risk_score=row['risk_score'],
                            signature_data=pattern_data,
                            match_offset=match_offset,
                            match_length=len(pattern_bytes),
                            detection_timestamp=datetime.now().isoformat(),
                            signature_source=row['signature_source'],
                            additional_info=json.loads(row['additional_info']) if row['additional_info'] else {}
                        )
                        matches.append(match)
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Error detecting pattern signatures: {e}")
            return []
    
    def _determine_threat_classification(self, matches: List[SignatureMatch]) -> str:
        """Determine overall threat classification from matches."""
        try:
            if not matches:
                return "clean"
            
            # Get the highest confidence match
            best_match = max(matches, key=lambda x: x.confidence)
            return best_match.threat_category.value
            
        except Exception as e:
            self.logger.error(f"Error determining threat classification: {e}")
            return "unknown"
    
    def _get_recommended_action(self, threat_classification: str, confidence: float) -> str:
        """Get recommended action based on threat classification and confidence."""
        try:
            if threat_classification == "clean":
                return "allow"
            
            high_risk_threats = ["ransomware", "trojan", "rootkit", "backdoor"]
            
            if threat_classification in high_risk_threats:
                return "quarantine_immediately"
            elif confidence >= 0.8:
                return "quarantine_immediately"
            elif confidence >= 0.6:
                return "quarantine_with_user_confirmation"
            else:
                return "flag_for_review"
                
        except Exception as e:
            self.logger.error(f"Error getting recommended action: {e}")
            return "flag_for_review"
    
    def _create_detection_result(self, file_path: Path, file_hash: str, detected: bool,
                               matches: List[SignatureMatch], signatures_checked: int,
                               detection_time: float, file_size: int, 
                               classification: str) -> SignatureDetectionResult:
        """Create a signature detection result."""
        return SignatureDetectionResult(
            file_path=str(file_path),
            file_hash_sha256=file_hash,
            detected=detected,
            matches=matches,
            total_signatures_checked=signatures_checked,
            detection_time=detection_time,
            file_size=file_size,
            scan_timestamp=datetime.now().isoformat(),
            confidence=max([m.confidence for m in matches]) if matches else 0.0,
            risk_score=max([m.risk_score for m in matches]) if matches else 0.0,
            threat_classification=classification,
            recommended_action=self._get_recommended_action(classification, 
                                                          max([m.confidence for m in matches]) if matches else 0.0)
        )
    
    def _update_statistics(self, detection_time: float, detected: bool) -> None:
        """Update detection statistics."""
        try:
            with self._stats_lock:
                self.total_scans += 1
                self.total_scan_time += detection_time
                if detected:
                    self.total_detections += 1
                    
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def _log_detection(self, file_hash: str, file_path: Path, match: SignatureMatch,
                      detection_time: float, file_size: int) -> None:
        """Log detection to database."""
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO detection_stats
                (file_hash, detection_date, threat_name, signature_type,
                 file_path, file_size, detection_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                file_hash, datetime.now().isoformat(), match.threat_name,
                match.signature_type.value, str(file_path), file_size, detection_time
            ))
            self.db_connection.commit()
            
        except Exception as e:
            self.logger.error(f"Error logging detection: {e}")
    
    def add_signature(self, signature_type: SignatureType, signature_data: str,
                     threat_name: str, threat_category: ThreatCategory,
                     confidence: float = 1.0, risk_score: float = 0.8,
                     signature_source: str = "manual", 
                     additional_info: Optional[Dict[str, Any]] = None) -> bool:
        """
        Add a new signature to the database.
        
        Args:
            signature_type: Type of signature
            signature_data: Signature data (hash, pattern, etc.)
            threat_name: Name of the threat
            threat_category: Category of the threat
            confidence: Confidence level (0.0-1.0)
            risk_score: Risk score (0.0-1.0)
            signature_source: Source of the signature
            additional_info: Additional metadata
            
        Returns:
            True if signature added successfully, False otherwise
        """
        try:
            with self.db_lock:
                cursor = self.db_connection.cursor()
                
                if signature_type.value.startswith('hash_'):
                    # Add hash signature
                    cursor.execute("""
                        INSERT OR REPLACE INTO hash_signatures
                        (signature_type, hash_value, threat_name, threat_category,
                         confidence, risk_score, signature_source, created_date,
                         last_updated, additional_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        signature_type.value, signature_data, threat_name,
                        threat_category.value, confidence, risk_score,
                        signature_source, datetime.now().isoformat(),
                        datetime.now().isoformat(),
                        json.dumps(additional_info) if additional_info else None
                    ))
                else:
                    # Add pattern signature
                    cursor.execute("""
                        INSERT OR REPLACE INTO pattern_signatures
                        (signature_type, pattern_data, threat_name, threat_category,
                         confidence, risk_score, pattern_description, signature_source,
                         created_date, last_updated, additional_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        signature_type.value, signature_data, threat_name,
                        threat_category.value, confidence, risk_score,
                        additional_info.get('description', '') if additional_info else '',
                        signature_source, datetime.now().isoformat(),
                        datetime.now().isoformat(),
                        json.dumps(additional_info) if additional_info else None
                    ))
                
                self.db_connection.commit()
                
                # Clear relevant cache entries
                self._invalidate_cache()
                
                self.logger.info(f"Added signature: {threat_name} ({signature_type.value})")
                return True
                
        except Exception as e:
            self.logger.error(f"Error adding signature: {e}")
            return False
    
    def update_signatures(self, signature_updates: List[Dict[str, Any]]) -> int:
        """
        Bulk update signatures from external source.
        
        Args:
            signature_updates: List of signature update dictionaries
            
        Returns:
            Number of signatures successfully updated
        """
        try:
            updated_count = 0
            
            for update in signature_updates:
                try:
                    signature_type = SignatureType(update['signature_type'])
                    threat_category = ThreatCategory(update['threat_category'])
                    
                    success = self.add_signature(
                        signature_type=signature_type,
                        signature_data=update['signature_data'],
                        threat_name=update['threat_name'],
                        threat_category=threat_category,
                        confidence=update.get('confidence', 1.0),
                        risk_score=update.get('risk_score', 0.8),
                        signature_source=update.get('signature_source', 'update'),
                        additional_info=update.get('additional_info')
                    )
                    
                    if success:
                        updated_count += 1
                        
                except Exception as update_error:
                    self.logger.error(f"Error processing signature update: {update_error}")
                    continue
            
            self.logger.info(f"Updated {updated_count}/{len(signature_updates)} signatures")
            return updated_count
            
        except Exception as e:
            self.logger.error(f"Error updating signatures: {e}")
            return 0
    
    def _invalidate_cache(self) -> None:
        """Invalidate signature cache."""
        try:
            self.hash_cache.clear()
            self.pattern_cache.clear()
            self._load_signature_cache()
            
        except Exception as e:
            self.logger.error(f"Error invalidating cache: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics."""
        try:
            with self._stats_lock:
                cursor = self.db_connection.cursor()
                
                # Get signature counts
                cursor.execute("SELECT COUNT(*) FROM hash_signatures")
                hash_signatures_count = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM pattern_signatures")
                pattern_signatures_count = cursor.fetchone()[0]
                
                # Get recent detections
                cursor.execute("""
                    SELECT COUNT(*) FROM detection_stats
                    WHERE detection_date >= date('now', '-7 days')
                """)
                recent_detections = cursor.fetchone()[0]
                
                return {
                    'total_scans': self.total_scans,
                    'total_detections': self.total_detections,
                    'detection_rate': self.total_detections / self.total_scans if self.total_scans > 0 else 0.0,
                    'average_scan_time': self.total_scan_time / self.total_scans if self.total_scans > 0 else 0.0,
                    'hash_signatures_count': hash_signatures_count,
                    'pattern_signatures_count': pattern_signatures_count,
                    'total_signatures': hash_signatures_count + pattern_signatures_count,
                    'cache_hits': self.cache_hits,
                    'cache_misses': self.cache_misses,
                    'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0.0,
                    'recent_detections_7days': recent_detections,
                    'database_path': str(self.signature_db_path),
                    'last_updated': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {}
    
    def is_signature_detector_healthy(self) -> bool:
        """Check if signature detector is healthy."""
        try:
            # Check database connection
            if not self.db_connection:
                return False
            
            # Check if we have signatures
            cursor = self.db_connection.cursor()
            cursor.execute("SELECT COUNT(*) FROM hash_signatures")
            hash_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM pattern_signatures")
            pattern_count = cursor.fetchone()[0]
            
            return (hash_count + pattern_count) > 0
            
        except Exception as e:
            self.logger.error(f"Error checking detector health: {e}")
            return False
    
    def cleanup_old_detections(self, days_to_keep: int = 30) -> int:
        """
        Clean up old detection records.
        
        Args:
            days_to_keep: Number of days of detection records to keep
            
        Returns:
            Number of records deleted
        """
        try:
            cursor = self.db_connection.cursor()
            
            cursor.execute("""
                DELETE FROM detection_stats
                WHERE detection_date < date('now', '-{} days')
            """.format(days_to_keep))
            
            deleted_count = cursor.rowcount
            self.db_connection.commit()
            
            self.logger.info(f"Cleaned up {deleted_count} old detection records")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old detections: {e}")
            return 0
    
    def __del__(self):
        """Cleanup database connection."""
        try:
            if self.db_connection:
                self.db_connection.close()
        except:
            pass


# Utility function for easy detector creation
def create_signature_detector(signature_db_path: Optional[Union[str, Path]] = None) -> SignatureDetector:
    """
    Convenience function to create a signature detector.
    
    Args:
        signature_db_path: Optional path to signature database
        
    Returns:
        Initialized SignatureDetector instance
    """
    try:
        return SignatureDetector(signature_db_path)
    except Exception as e:
        logging.getLogger("SignatureDetector").error(f"Error creating signature detector: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import tempfile
    
    print("Testing SignatureDetector...")
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as temp_file:
        temp_file.write("This is a test executable file")
        temp_file_path = temp_file.name
    
    try:
        # Create signature detector
        detector = SignatureDetector()
        print(f"✅ SignatureDetector created successfully")
        
        # Test health check
        is_healthy = detector.is_signature_detector_healthy()
        print(f"✅ Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Test signature detection
        result = detector.detect(temp_file_path)
        if result:
            print(f"✅ Detection completed: {result.detected}")
            print(f"   File: {Path(result.file_path).name}")
            print(f"   Signatures checked: {result.total_signatures_checked}")
            print(f"   Detection time: {result.detection_time:.3f}s")
            print(f"   Matches: {len(result.matches)}")
        
        # Test statistics
        stats = detector.get_statistics()
        print(f"✅ Statistics retrieved: {len(stats)} categories")
        print(f"   Total signatures: {stats.get('total_signatures', 0)}")
        print(f"   Hash signatures: {stats.get('hash_signatures_count', 0)}")
        print(f"   Pattern signatures: {stats.get('pattern_signatures_count', 0)}")
        
        # Test signature addition
        success = detector.add_signature(
            signature_type=SignatureType.HASH_SHA256,
            signature_data="test_hash_12345",
            threat_name="Test.Signature",
            threat_category=ThreatCategory.MALWARE,
            confidence=0.9,
            risk_score=0.8
        )
        print(f"✅ Signature Addition: {'Success' if success else 'Failed'}")
        
        print("✅ SignatureDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ SignatureDetector test failed: {e}")
    
    finally:
        # Cleanup
        try:
            os.unlink(temp_file_path)
        except:
            pass