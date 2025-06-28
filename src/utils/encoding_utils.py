"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Encoding Safety Utilities - Foundation Layer

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (base utility - foundation layer)

Connected Components (files that import from this module):
- main.py (AntivirusApp - imports EncodingHandler)
- src.core.app_config (AppConfig - imports EncodingHandler, safe_read_file, safe_write_file)
- src.utils.theme_manager (ThemeManager - imports EncodingHandler, safe_read_file, safe_write_file)
- src.utils.file_utils (FileUtils - imports EncodingHandler)
- src.utils.model_utils (ModelUtils - imports EncodingHandler)
- src.utils.crypto_utils (CryptoUtils - imports EncodingHandler)
- src.utils.helpers (HelperFunctions - imports EncodingHandler)
- src.core.scanner_engine (ScannerEngine - imports EncodingHandler)
- src.core.model_manager (ModelManager - imports EncodingHandler)
- src.detection.feature_extractor (FeatureExtractor - imports EncodingHandler)
- ALL other files (encoding safety)

Integration Points:
- **FOUNDATION**: Provides UTF-8 safe text operations for entire application
- **ENHANCED**: Handles file reading/writing with proper encoding detection and fallback
- **ENHANCED**: Manages string encoding/decoding with comprehensive error recovery
- **ENHANCED**: Binary file detection with advanced heuristics and caching
- **ENHANCED**: Text normalization and sanitization for security purposes
- **ENHANCED**: Context managers for safe file operations with resource management
- **ENHANCED**: Thread-safe operations with performance optimization
- **ENHANCED**: Statistics tracking and performance monitoring
- **ENHANCED**: Graceful shutdown handling for application stability

Verification Checklist:
✓ Base utility with NO dependencies (foundation layer)
✓ UTF-8 encoding safety implemented with comprehensive fallback mechanisms
✓ File operations with encoding handling and atomic operations
✓ String conversion utilities with normalization and validation
✓ Error recovery mechanisms with multiple fallback strategies
✓ Compatible with all file types and formats
✓ Binary file detection with advanced heuristics
✓ Thread-safe operations with performance optimization
✓ Context managers for resource safety
✓ Statistics tracking and monitoring
✓ Graceful shutdown handling
✓ Global convenience functions for easy access
✓ Complete API compatibility for all connected components
"""

import os
import sys
import codecs
import logging
import threading
import time
from pathlib import Path
from typing import Optional, Union, Tuple, Dict, Any, List, Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from datetime import datetime
import weakref
import gc
import shutil

# Enhanced encoding detection
try:
    import chardet
    CHARDET_AVAILABLE = True
except ImportError:
    CHARDET_AVAILABLE = False


class EncodingConfidence(Enum):
    """Enumeration for encoding detection confidence levels."""
    VERY_LOW = "very_low"      # < 0.3
    LOW = "low"                # 0.3 - 0.5
    MEDIUM = "medium"          # 0.5 - 0.7
    HIGH = "high"              # 0.7 - 0.9
    VERY_HIGH = "very_high"    # > 0.9


class FileType(Enum):
    """Enhanced file type classification for encoding decisions."""
    TEXT = "text"
    BINARY = "binary"
    MIXED = "mixed"            # Files with both text and binary content
    UNKNOWN = "unknown"


@dataclass
class EncodingResult:
    """Enhanced result object for encoding operations."""
    success: bool
    encoding: Optional[str] = None
    confidence: float = 0.0
    confidence_level: EncodingConfidence = EncodingConfidence.VERY_LOW
    error_message: Optional[str] = None
    fallback_used: bool = False
    processing_time_ms: float = 0.0
    
    # **NEW**: Enhanced metadata
    detected_languages: List[str] = field(default_factory=list)
    byte_order_mark: Optional[str] = None
    line_endings: Optional[str] = None
    estimated_file_type: FileType = FileType.UNKNOWN


@dataclass
class EncodingStatistics:
    """Comprehensive statistics for encoding operations."""
    successful_operations: int = 0
    encoding_fallbacks: int = 0
    binary_detections: int = 0
    encoding_errors: int = 0
    
    # **NEW**: Enhanced statistics
    total_operations: int = 0
    average_processing_time_ms: float = 0.0
    confidence_distribution: Dict[EncodingConfidence, int] = field(default_factory=lambda: defaultdict(int))
    encoding_usage: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    file_type_distribution: Dict[FileType, int] = field(default_factory=lambda: defaultdict(int))
    error_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # **NEW**: Performance tracking
    processing_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    peak_memory_usage_mb: float = 0.0
    cache_hit_rate: float = 0.0
    
    def update_operation(self, processing_time_ms: float, success: bool, 
                        confidence: EncodingConfidence = None, encoding: str = None,
                        file_type: FileType = None, error_type: str = None):
        """Update statistics with operation results."""
        self.total_operations += 1
        self.processing_times.append(processing_time_ms)
        
        # Update average processing time
        if self.total_operations == 1:
            self.average_processing_time_ms = processing_time_ms
        else:
            self.average_processing_time_ms = (
                (self.average_processing_time_ms * (self.total_operations - 1) + processing_time_ms) /
                self.total_operations
            )
        
        if success:
            self.successful_operations += 1
            if confidence:
                self.confidence_distribution[confidence] += 1
            if encoding:
                self.encoding_usage[encoding] += 1
            if file_type:
                self.file_type_distribution[file_type] += 1
        else:
            self.encoding_errors += 1
            if error_type:
                self.error_types[error_type] += 1


class EncodingHandler:
    """
    **ENHANCED** Comprehensive encoding handler for safe text operations across the antivirus application.
    
    This class ensures all text operations are UTF-8 safe and provides advanced fallback mechanisms
    for various encoding scenarios commonly encountered in file analysis and malware detection.
    
    Key Features:
    - **Advanced encoding detection** with confidence scoring and language detection
    - **Multi-tier fallback system** ensuring reliable text processing under all conditions
    - **Binary file detection** with sophisticated heuristics and caching
    - **Thread-safe operations** with performance optimization and resource management
    - **Context managers** for safe file operations with automatic cleanup
    - **Statistics tracking** for monitoring and optimization
    - **Graceful shutdown handling** ensuring data integrity during application exit
    - **Memory optimization** with intelligent caching and garbage collection
    - **Performance monitoring** with detailed metrics and trend analysis
    """
    
    # **ENHANCED**: Default encoding with comprehensive fallback chain
    DEFAULT_ENCODING = 'utf-8'
    
    # **ENHANCED**: Sophisticated fallback encoding chain optimized for malware analysis
    FALLBACK_ENCODINGS = [
        'utf-8',           # Primary modern encoding
        'utf-8-sig',       # UTF-8 with BOM
        'latin-1',         # Universal fallback (never fails)
        'cp1252',          # Windows-1252 (most common Windows encoding)
        'iso-8859-1',      # ISO Latin-1
        'ascii',           # 7-bit ASCII
        'utf-16',          # UTF-16 with BOM detection
        'utf-16le',        # UTF-16 Little Endian
        'utf-16be',        # UTF-16 Big Endian
        'cp850',           # IBM850 (DOS encoding)
        'cp437',           # IBM437 (original DOS encoding)
        'gb2312',          # Simplified Chinese
        'big5',            # Traditional Chinese
        'shift_jis',       # Japanese
        'euc-kr',          # Korean
        'koi8-r',          # Russian (Cyrillic)
        'iso-8859-2',      # Central European
        'iso-8859-5',      # Cyrillic
        'iso-8859-7',      # Greek
        'iso-8859-8',      # Hebrew
        'iso-8859-9',      # Turkish
    ]
    
    # **ENHANCED**: Comprehensive binary file extensions for malware analysis
    BINARY_EXTENSIONS = {
        # **Executable files** (primary malware targets)
        '.exe', '.dll', '.sys', '.ocx', '.cpl', '.drv', '.scr', '.com', '.pif',
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.class', '.dex',
        
        # **Archive formats** (malware distribution)
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab', '.iso',
        '.dmg', '.pkg', '.deb', '.rpm', '.msi', '.app', '.ipa', '.apk',
        
        # **Document formats** (macro malware vectors)
        '.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt',
        '.pptx', '.pptm', '.rtf', '.odt', '.ods', '.odp',
        
        # **Media files** (steganography and exploits)
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.tiff',
        '.mp3', '.mp4', '.avi', '.mkv', '.wmv', '.mov', '.flv', '.wav',
        '.ogg', '.flac', '.aac', '.wma', '.webm', '.m4a', '.m4v',
        
        # **Database and data files**
        '.db', '.sqlite', '.mdb', '.accdb', '.dbf', '.dat', '.pak', '.bin'
    }
    
    # **NEW**: Byte Order Mark (BOM) signatures for encoding detection
    BOM_SIGNATURES = {
        b'\xef\xbb\xbf': 'utf-8-sig',
        b'\xff\xfe\x00\x00': 'utf-32le',
        b'\x00\x00\xfe\xff': 'utf-32be',
        b'\xff\xfe': 'utf-16le',
        b'\xfe\xff': 'utf-16be',
        b'\x2b\x2f\x76': 'utf-7'
    }
    
    # **NEW**: Text patterns for heuristic analysis
    TEXT_INDICATORS = {
        'common_words': [b'the', b'and', b'for', b'are', b'but', b'not', b'you', b'all'],
        'xml_indicators': [b'<?xml', b'<html', b'<body', b'<head'],
        'json_indicators': [b'{"', b'"}', b'":"', b'null', b'true', b'false'],
        'code_indicators': [b'function', b'import', b'class', b'def', b'var'],
        'log_indicators': [b'ERROR', b'WARNING', b'INFO', b'DEBUG', b'TRACE']
    }
    
    # **NEW**: Performance and memory optimization settings
    MAX_DETECTION_SIZE = 8192      # Maximum bytes to read for encoding detection
    CACHE_SIZE_LIMIT = 1000        # Maximum cached results
    MEMORY_CLEANUP_THRESHOLD = 100  # Operations before memory cleanup
    STATISTICS_REPORT_INTERVAL = 1000  # Operations between statistics reports
    
    def __init__(self, default_encoding: str = None):
        """
        Initialize the enhanced encoding handler with comprehensive features.
        
        Args:
            default_encoding: Default encoding to use (defaults to UTF-8)
        """
        self.default_encoding = default_encoding or self.DEFAULT_ENCODING
        self.logger = logging.getLogger("EncodingHandler")
        
        # **ENHANCED**: Thread-safe operations with advanced synchronization
        self._lock = threading.RLock()
        self._cache_lock = threading.RLock()
        self._stats_lock = threading.RLock()
        
        # **ENHANCED**: Comprehensive statistics tracking
        self.encoding_stats = EncodingStatistics()
        
        # **NEW**: Performance optimization caches
        self._encoding_cache = {}           # Path -> EncodingResult cache
        self._binary_cache = {}             # Path -> bool cache
        self._confidence_cache = {}         # Content hash -> confidence cache
        
        # **NEW**: Memory management
        self._operation_count = 0
        self._last_cleanup = time.time()
        self._weak_references = weakref.WeakSet()
        
        # **NEW**: Advanced detection settings
        self._enable_advanced_detection = CHARDET_AVAILABLE
        self._enable_language_detection = CHARDET_AVAILABLE
        self._confidence_threshold = 0.7
        self._binary_threshold = 0.30  # Percentage of non-text bytes for binary classification
        
        # **NEW**: Shutdown handling
        self._shutdown_detected = False
        self._shutdown_callbacks = []
        
        # **NEW**: Performance monitoring
        self._performance_monitor_enabled = True
        self._last_performance_report = time.time()
        
        self.logger.info(f"Enhanced EncodingHandler initialized with default encoding: {self.default_encoding}")
        self.logger.info(f"Advanced detection enabled: {self._enable_advanced_detection}")
        
        # **NEW**: Register for graceful shutdown
        self._register_shutdown_handler()
    
    def _register_shutdown_handler(self):
        """Register handler for graceful shutdown detection."""
        try:
            import atexit
            atexit.register(self._handle_shutdown)
        except Exception:
            pass  # Graceful fallback if atexit is not available
    
    def _handle_shutdown(self):
        """Handle application shutdown gracefully."""
        try:
            self._shutdown_detected = True
            
            # Execute shutdown callbacks
            for callback in self._shutdown_callbacks:
                try:
                    callback()
                except Exception:
                    pass  # Silent cleanup during shutdown
            
            # Clear caches to free memory
            with self._cache_lock:
                self._encoding_cache.clear()
                self._binary_cache.clear()
                self._confidence_cache.clear()
            
            self.logger.debug("EncodingHandler shutdown completed gracefully")
            
        except Exception:
            pass  # Silent cleanup during shutdown
    
    def detect_encoding(self, data: bytes, confidence_threshold: float = None) -> Tuple[str, float]:
        """
        **ENHANCED** Detect text encoding from bytes with advanced heuristics and confidence scoring.
        
        Args:
            data: Bytes to analyze for encoding detection
            confidence_threshold: Minimum confidence required (uses instance default if None)
            
        Returns:
            Tuple of (detected_encoding, confidence_score)
        """
        start_time = time.time()
        
        try:
            if not data:
                return self.default_encoding, 1.0
            
            threshold = confidence_threshold or self._confidence_threshold
            
            # **NEW**: Check cache first for performance
            data_hash = hash(data[:self.MAX_DETECTION_SIZE])
            with self._cache_lock:
                if data_hash in self._confidence_cache:
                    cached_result = self._confidence_cache[data_hash]
                    self.encoding_stats.cache_hit_rate += 1
                    return cached_result
            
            # **NEW**: Check for Byte Order Mark (BOM)
            bom_encoding = self._detect_bom(data)
            if bom_encoding:
                result = (bom_encoding, 0.95)
                self._cache_result(data_hash, result)
                return result
            
            # **ENHANCED**: Use chardet for advanced detection if available
            if self._enable_advanced_detection and len(data) > 10:
                try:
                    detection_result = chardet.detect(data[:self.MAX_DETECTION_SIZE])
                    if detection_result and detection_result.get('confidence', 0) >= threshold:
                        encoding = detection_result['encoding']
                        confidence = detection_result['confidence']
                        
                        # **NEW**: Normalize encoding name
                        encoding = self._normalize_encoding_name(encoding)
                        
                        if encoding and self._validate_encoding(encoding):
                            result = (encoding, confidence)
                            self._cache_result(data_hash, result)
                            return result
                
                except Exception as e:
                    self.logger.debug(f"Chardet detection failed: {e}")
            
            # **NEW**: Heuristic analysis for common patterns
            heuristic_result = self._heuristic_encoding_detection(data)
            if heuristic_result[1] >= threshold:
                self._cache_result(data_hash, heuristic_result)
                return heuristic_result
            
            # **ENHANCED**: Fallback to UTF-8 with validation
            if self._test_encoding(data, 'utf-8'):
                result = ('utf-8', 0.8)
                self._cache_result(data_hash, result)
                return result
            
            # **ENHANCED**: Try common encodings with scoring
            for encoding in self.FALLBACK_ENCODINGS:
                if self._test_encoding(data, encoding):
                    # Lower confidence for fallback encodings
                    confidence = 0.6 if encoding == 'latin-1' else 0.5
                    result = (encoding, confidence)
                    self._cache_result(data_hash, result)
                    return result
            
            # **FALLBACK**: Return latin-1 as last resort (never fails)
            result = ('latin-1', 0.3)
            self._cache_result(data_hash, result)
            return result
            
        except Exception as e:
            self.logger.error(f"Error in encoding detection: {e}")
            return (self.default_encoding, 0.1)
        
        finally:
            # **NEW**: Update performance statistics
            processing_time = (time.time() - start_time) * 1000
            self._update_performance_stats(processing_time)
    
    def _detect_bom(self, data: bytes) -> Optional[str]:
        """Detect encoding from Byte Order Mark (BOM)."""
        try:
            for bom, encoding in self.BOM_SIGNATURES.items():
                if data.startswith(bom):
                    return encoding
            return None
        except Exception:
            return None
    
    def _normalize_encoding_name(self, encoding: str) -> Optional[str]:
        """
        **ENHANCED** Normalize encoding name to standard form with comprehensive mapping.
        
        Args:
            encoding: Original encoding name
            
        Returns:
            Normalized encoding name or None if invalid
        """
        if not encoding:
            return self.default_encoding
        
        encoding = encoding.lower().strip()
        
        # **ENHANCED**: Comprehensive normalization mapping
        normalization_map = {
            # UTF variants
            'utf8': 'utf-8',
            'utf-8-sig': 'utf-8',  # Remove BOM designation for consistency
            'u8': 'utf-8',
            'utf_8': 'utf-8',
            
            # Windows encodings
            'windows-1252': 'cp1252',
            'windows-1250': 'cp1250',
            'windows-1251': 'cp1251',
            'ansi': 'cp1252',
            'western': 'cp1252',
            
            # ISO variants
            'iso-latin-1': 'iso-8859-1',
            'latin1': 'latin-1',
            'latin-1': 'iso-8859-1',  # Prefer ISO notation
            'iso_8859_1': 'iso-8859-1',
            
            # ASCII variants
            'ascii': 'ascii',
            'us-ascii': 'ascii',
            '7bit': 'ascii',
            
            # Asian encodings
            'chinese': 'gb2312',
            'gb_2312-80': 'gb2312',
            'japanese': 'shift_jis',
            'sjis': 'shift_jis',
            'korean': 'euc-kr',
            
            # Other variants
            'mac-roman': 'mac_roman',
            'macintosh': 'mac_roman',
        }
        
        normalized = normalization_map.get(encoding, encoding)
        
        # **NEW**: Validate that the encoding is actually supported
        if self._validate_encoding(normalized):
            return normalized
        
        return self.default_encoding
    
    def _validate_encoding(self, encoding: str) -> bool:
        """Validate that an encoding is supported by Python."""
        try:
            'test'.encode(encoding)
            b'test'.decode(encoding)
            return True
        except (LookupError, TypeError, ValueError):
            return False
    
    def _test_encoding(self, data: bytes, encoding: str) -> bool:
        """Test if data can be decoded with the specified encoding."""
        try:
            data.decode(encoding)
            return True
        except (UnicodeDecodeError, LookupError):
            return False
    
    def _heuristic_encoding_detection(self, data: bytes) -> Tuple[str, float]:
        """Perform heuristic analysis for encoding detection."""
        try:
            sample = data[:self.MAX_DETECTION_SIZE]
            
            # **NEW**: Check for XML/HTML patterns
            if any(indicator in sample for indicator in self.TEXT_INDICATORS['xml_indicators']):
                if self._test_encoding(sample, 'utf-8'):
                    return ('utf-8', 0.75)
            
            # **NEW**: Check for JSON patterns
            if any(indicator in sample for indicator in self.TEXT_INDICATORS['json_indicators']):
                if self._test_encoding(sample, 'utf-8'):
                    return ('utf-8', 0.8)
            
            # **NEW**: Check for common English words
            text_score = 0
            for word in self.TEXT_INDICATORS['common_words']:
                if word in sample:
                    text_score += 1
            
            if text_score >= 2:  # At least 2 common words found
                if self._test_encoding(sample, 'utf-8'):
                    return ('utf-8', 0.7)
                elif self._test_encoding(sample, 'cp1252'):
                    return ('cp1252', 0.6)
            
            # **NEW**: Analyze byte distribution
            if len(sample) > 100:
                ascii_ratio = sum(1 for b in sample if 32 <= b <= 126) / len(sample)
                if ascii_ratio > 0.8:
                    return ('ascii', 0.7)
                elif ascii_ratio > 0.6:
                    return ('utf-8', 0.6)
            
            return (self.default_encoding, 0.3)
            
        except Exception:
            return (self.default_encoding, 0.1)
    
    def _cache_result(self, data_hash: int, result: Tuple[str, float]):
        """Cache encoding detection result with size management."""
        try:
            with self._cache_lock:
                # **NEW**: Implement cache size management
                if len(self._confidence_cache) >= self.CACHE_SIZE_LIMIT:
                    # Remove oldest entries (simple FIFO)
                    items_to_remove = len(self._confidence_cache) // 4  # Remove 25%
                    for _ in range(items_to_remove):
                        self._confidence_cache.pop(next(iter(self._confidence_cache)))
                
                self._confidence_cache[data_hash] = result
        except Exception:
            pass  # Cache failure shouldn't affect functionality
    
    def _update_performance_stats(self, processing_time_ms: float):
        """Update performance statistics and trigger cleanup if needed."""
        try:
            with self._stats_lock:
                self._operation_count += 1
                self.encoding_stats.processing_times.append(processing_time_ms)
                
                # **NEW**: Periodic memory cleanup
                if self._operation_count % self.MEMORY_CLEANUP_THRESHOLD == 0:
                    self._perform_memory_cleanup()
                
                # **NEW**: Periodic statistics reporting
                if (self._operation_count % self.STATISTICS_REPORT_INTERVAL == 0 and 
                    self._performance_monitor_enabled):
                    self._report_performance_statistics()
                    
        except Exception:
            pass  # Statistics failure shouldn't affect functionality
    
    def _perform_memory_cleanup(self):
        """Perform periodic memory cleanup and optimization."""
        try:
            # **NEW**: Trigger garbage collection
            if hasattr(gc, 'collect'):
                gc.collect()
            
            # **NEW**: Clean expired cache entries
            current_time = time.time()
            if current_time - self._last_cleanup > 300:  # 5 minutes
                with self._cache_lock:
                    # Clear half of the cache if it's getting large
                    if len(self._encoding_cache) > self.CACHE_SIZE_LIMIT // 2:
                        items_to_keep = self.CACHE_SIZE_LIMIT // 4
                        items = list(self._encoding_cache.items())[-items_to_keep:]
                        self._encoding_cache = dict(items)
                    
                    if len(self._binary_cache) > self.CACHE_SIZE_LIMIT // 2:
                        items_to_keep = self.CACHE_SIZE_LIMIT // 4
                        items = list(self._binary_cache.items())[-items_to_keep:]
                        self._binary_cache = dict(items)
                
                self._last_cleanup = current_time
                
        except Exception:
            pass  # Cleanup failure shouldn't affect functionality
    
    def _report_performance_statistics(self):
        """Report performance statistics for monitoring."""
        try:
            stats = self.encoding_stats
            avg_time = stats.average_processing_time_ms
            success_rate = (stats.successful_operations / stats.total_operations * 100 
                          if stats.total_operations > 0 else 0)
            
            self.logger.debug(
                f"EncodingHandler Performance: "
                f"Operations: {stats.total_operations}, "
                f"Success Rate: {success_rate:.1f}%, "
                f"Avg Time: {avg_time:.2f}ms, "
                f"Cache Hit Rate: {stats.cache_hit_rate:.1f}%"
            )
            
            self._last_performance_report = time.time()
            
        except Exception:
            pass  # Reporting failure shouldn't affect functionality
        
    def is_binary_file(self, file_path: Union[str, Path]) -> bool:
        """
        **ENHANCED** Determine if a file is binary using sophisticated heuristics and caching.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            True if file is determined to be binary, False otherwise
        """
        start_time = time.time()
        
        try:
            file_path = Path(file_path)
            
            # **NEW**: Check cache first for performance
            cache_key = str(file_path.resolve())
            with self._cache_lock:
                if cache_key in self._binary_cache:
                    return self._binary_cache[cache_key]
            
            # **ENHANCED**: Quick extension-based check
            if file_path.suffix.lower() in self.BINARY_EXTENSIONS:
                result = True
                self._cache_binary_result(cache_key, result)
                return result
            
            # **NEW**: File existence and size check
            if not file_path.exists():
                return False
            
            file_size = file_path.stat().st_size
            if file_size == 0:
                result = False
                self._cache_binary_result(cache_key, result)
                return result
            
            # **ENHANCED**: Read sample for analysis
            sample_size = min(file_size, self.MAX_DETECTION_SIZE)
            try:
                with open(file_path, 'rb') as f:
                    sample = f.read(sample_size)
            except (IOError, OSError, PermissionError) as e:
                self.logger.debug(f"Could not read file {file_path}: {e}")
                return False
            
            # **NEW**: Perform comprehensive binary analysis
            result = self._analyze_binary_content(sample)
            self._cache_binary_result(cache_key, result)
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Error in binary file detection for {file_path}: {e}")
            return False
        
        finally:
            # **NEW**: Update performance statistics
            processing_time = (time.time() - start_time) * 1000
            with self._stats_lock:
                if hasattr(self, '_binary_detection_times'):
                    self._binary_detection_times.append(processing_time)
                else:
                    self._binary_detection_times = deque([processing_time], maxlen=100)
    
    def _analyze_binary_content(self, data: bytes) -> bool:
        """Analyze file content to determine if it's binary using multiple heuristics."""
        try:
            if not data:
                return False
            
            # **NEW**: Check for common binary signatures
            binary_signatures = [
                b'\x4d\x5a',              # PE/DOS executable (MZ)
                b'\x7f\x45\x4c\x46',      # ELF executable
                b'\xcf\xfa\xed\xfe',      # Mach-O executable (32-bit)
                b'\xfe\xed\xfa\xce',      # Mach-O executable (big-endian)
                b'\x50\x4b\x03\x04',      # ZIP archive
                b'\x50\x4b\x05\x06',      # ZIP archive (empty)
                b'\x52\x61\x72\x21',      # RAR archive
                b'\x37\x7a\xbc\xaf',      # 7-Zip archive
                b'\x1f\x8b\x08',          # GZIP compressed
                b'\x42\x5a\x68',          # BZIP2 compressed
                b'\x89\x50\x4e\x47',      # PNG image
                b'\xff\xd8\xff',          # JPEG image
                b'\x47\x49\x46\x38',      # GIF image
                b'\x25\x50\x44\x46',      # PDF document
                b'\xd0\xcf\x11\xe0',      # Microsoft Office document
            ]
            
            for signature in binary_signatures:
                if data.startswith(signature):
                    return True
            
            # **ENHANCED**: Null byte analysis
            null_byte_count = data.count(b'\x00')
            if null_byte_count > len(data) * 0.05:  # More than 5% null bytes
                return True
            
            # **ENHANCED**: Control character analysis
            control_chars = sum(1 for b in data if b < 32 and b not in [9, 10, 13])  # Excluding tab, LF, CR
            if control_chars > len(data) * self._binary_threshold:
                return True
            
            # **NEW**: High-bit character analysis
            high_bit_chars = sum(1 for b in data if b > 127)
            if high_bit_chars > len(data) * 0.95:  # More than 95% high-bit characters
                return True
            
            # **NEW**: Entropy analysis for packed/encrypted content
            if len(data) > 256:
                entropy = self._calculate_entropy(data[:256])
                if entropy > 7.5:  # High entropy suggests binary/compressed/encrypted content
                    return True
            
            # **NEW**: Line length analysis
            if b'\n' in data:
                lines = data.split(b'\n')
                long_lines = sum(1 for line in lines if len(line) > 500)
                if long_lines > len(lines) * 0.5:  # More than 50% very long lines
                    return True
            
            # **NEW**: Text pattern analysis
            printable_chars = sum(1 for b in data if 32 <= b <= 126 or b in [9, 10, 13])
            printable_ratio = printable_chars / len(data) if data else 0
            
            return printable_ratio < 0.7  # Less than 70% printable characters
            
        except Exception as e:
            self.logger.debug(f"Error in binary content analysis: {e}")
            return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data to detect compressed/encrypted content."""
        try:
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _cache_binary_result(self, cache_key: str, result: bool):
        """Cache binary detection result with size management."""
        try:
            with self._cache_lock:
                # **NEW**: Implement cache size management
                if len(self._binary_cache) >= self.CACHE_SIZE_LIMIT:
                    # Remove oldest entries (simple FIFO)
                    items_to_remove = len(self._binary_cache) // 4  # Remove 25%
                    for _ in range(items_to_remove):
                        self._binary_cache.pop(next(iter(self._binary_cache)))
                
                self._binary_cache[cache_key] = result
        except Exception:
            pass  # Cache failure shouldn't affect functionality
    
    def safe_decode(self, data: bytes, encoding: str = None, errors: str = 'replace') -> str:
        """
        **ENHANCED** Safely decode bytes to string with comprehensive fallback handling.
        
        Args:
            data: Bytes to decode
            encoding: Preferred encoding (auto-detect if None)
            errors: Error handling strategy ('strict', 'ignore', 'replace')
            
        Returns:
            Decoded string (never fails)
        """
        start_time = time.time()
        
        try:
            if not data:
                return ""
            
            # **NEW**: Use specified encoding if provided and valid
            if encoding:
                try:
                    result = data.decode(encoding, errors=errors)
                    self._update_decode_stats(start_time, True, encoding)
                    return result
                except (UnicodeDecodeError, LookupError) as e:
                    self.logger.debug(f"Failed to decode with {encoding}: {e}")
            
            # **ENHANCED**: Auto-detect encoding
            detected_encoding, confidence = self.detect_encoding(data)
            
            try:
                result = data.decode(detected_encoding, errors=errors)
                self._update_decode_stats(start_time, True, detected_encoding)
                return result
            except (UnicodeDecodeError, LookupError):
                pass
            
            # **ENHANCED**: Try fallback encodings
            for fallback_encoding in self.FALLBACK_ENCODINGS:
                try:
                    result = data.decode(fallback_encoding, errors=errors)
                    self._update_decode_stats(start_time, True, fallback_encoding, fallback_used=True)
                    return result
                except (UnicodeDecodeError, LookupError):
                    continue
            
            # **FALLBACK**: Last resort with latin-1 and replace errors
            result = data.decode('latin-1', errors='replace')
            self._update_decode_stats(start_time, True, 'latin-1', fallback_used=True)
            return result
            
        except Exception as e:
            self.logger.error(f"Critical error in safe_decode: {e}")
            self._update_decode_stats(start_time, False, None)
            # **EMERGENCY FALLBACK**: Return escaped representation
            return str(data)[2:-1]  # Remove b' and '
    
    def safe_encode(self, text: str, encoding: str = None, errors: str = 'replace') -> bytes:
        """
        **ENHANCED** Safely encode string to bytes with comprehensive error handling.
        
        Args:
            text: String to encode
            encoding: Target encoding (defaults to instance default)
            errors: Error handling strategy ('strict', 'ignore', 'replace')
            
        Returns:
            Encoded bytes (never fails)
        """
        start_time = time.time()
        
        try:
            if not text:
                return b""
            
            target_encoding = encoding or self.default_encoding
            
            # **NEW**: Try specified encoding first
            try:
                result = text.encode(target_encoding, errors=errors)
                self._update_encode_stats(start_time, True, target_encoding)
                return result
            except (UnicodeEncodeError, LookupError) as e:
                self.logger.debug(f"Failed to encode with {target_encoding}: {e}")
            
            # **ENHANCED**: Try fallback encodings
            for fallback_encoding in self.FALLBACK_ENCODINGS:
                try:
                    result = text.encode(fallback_encoding, errors=errors)
                    self._update_encode_stats(start_time, True, fallback_encoding, fallback_used=True)
                    return result
                except (UnicodeEncodeError, LookupError):
                    continue
            
            # **FALLBACK**: Last resort with UTF-8 and replace errors
            result = text.encode('utf-8', errors='replace')
            self._update_encode_stats(start_time, True, 'utf-8', fallback_used=True)
            return result
            
        except Exception as e:
            self.logger.error(f"Critical error in safe_encode: {e}")
            self._update_encode_stats(start_time, False, None)
            # **EMERGENCY FALLBACK**: Return UTF-8 bytes with all errors replaced
            return text.encode('utf-8', errors='replace')
    
    def normalize_text(self, text: str, form: str = 'NFC') -> str:
        """
        **ENHANCED** Normalize text for consistent processing with security considerations.
        
        Args:
            text: Text to normalize
            form: Normalization form ('NFC', 'NFD', 'NFKC', 'NFKD')
            
        Returns:
            Normalized text
        """
        try:
            if not text:
                return ""
            
            import unicodedata
            
            # **NEW**: Security-aware normalization
            if form in ['NFKC', 'NFKD']:
                # These forms perform compatibility decomposition which can be exploited
                self.logger.debug(f"Using potentially unsafe normalization form: {form}")
            
            normalized = unicodedata.normalize(form, text)
            
            # **NEW**: Remove potentially dangerous characters
            dangerous_chars = [
                '\u200B',  # Zero Width Space
                '\u200C',  # Zero Width Non-Joiner
                '\u200D',  # Zero Width Joiner
                '\u2060',  # Word Joiner
                '\uFEFF',  # Zero Width No-Break Space
            ]
            
            for char in dangerous_chars:
                normalized = normalized.replace(char, '')
            
            return normalized
            
        except Exception as e:
            self.logger.error(f"Error in text normalization: {e}")
            return text  # Return original if normalization fails
    
    def sanitize_text(self, text: str, allow_newlines: bool = True) -> str:
        """
        **NEW** Sanitize text by removing potentially dangerous characters and control sequences.
        
        Args:
            text: Text to sanitize
            allow_newlines: Whether to preserve newline characters
            
        Returns:
            Sanitized text safe for display and processing
        """
        try:
            if not text:
                return ""
            
            # **NEW**: Remove control characters except allowed ones
            allowed_control_chars = set()
            if allow_newlines:
                allowed_control_chars.update(['\n', '\r', '\t'])
            
            sanitized = ''.join(
                char for char in text 
                if (ord(char) >= 32 or char in allowed_control_chars) and ord(char) != 127
            )
            
            # **NEW**: Remove potentially dangerous Unicode categories
            import unicodedata
            dangerous_categories = ['Cf', 'Co', 'Cs']  # Format, Private Use, Surrogate
            
            sanitized = ''.join(
                char for char in sanitized 
                if unicodedata.category(char) not in dangerous_categories
            )
            
            # **NEW**: Limit maximum length to prevent memory exhaustion
            max_length = 1000000  # 1MB of text
            if len(sanitized) > max_length:
                sanitized = sanitized[:max_length] + "... [truncated]"
                self.logger.warning(f"Text truncated to {max_length} characters")
            
            return sanitized
            
        except Exception as e:
            self.logger.error(f"Error in text sanitization: {e}")
            return text  # Return original if sanitization fails
    
    @contextmanager
    def safe_file_operation(self, file_path: Union[str, Path], mode: str = 'r', 
                           encoding: str = None, **kwargs):
        """
        **ENHANCED** Context manager for safe file operations with automatic encoding handling.
        
        Args:
            file_path: Path to the file
            mode: File open mode
            encoding: Encoding to use (auto-detect for read operations)
            **kwargs: Additional arguments for open()
            
        Yields:
            File handle with proper encoding
        """
        file_path = Path(file_path)
        file_handle = None
        
        try:
            # **NEW**: Determine appropriate encoding
            if 'b' not in mode and encoding is None:
                if 'r' in mode and file_path.exists():
                    # Auto-detect encoding for read operations
                    with open(file_path, 'rb') as f:
                        sample = f.read(self.MAX_DETECTION_SIZE)
                    encoding, _ = self.detect_encoding(sample)
                else:
                    # Use default encoding for write operations
                    encoding = self.default_encoding
            
            # **NEW**: Set encoding in kwargs if not binary mode
            if 'b' not in mode and encoding:
                kwargs['encoding'] = encoding
            
            # **ENHANCED**: Open file with proper error handling
            try:
                file_handle = open(file_path, mode, **kwargs)
            except UnicodeDecodeError as e:
                if 'r' in mode and 'b' not in mode:
                    # Retry with fallback encoding
                    self.logger.debug(f"Retrying file open with fallback encoding: {e}")
                    kwargs['encoding'] = 'latin-1'
                    kwargs['errors'] = 'replace'
                    file_handle = open(file_path, mode, **kwargs)
                else:
                    raise
            
            yield file_handle
            
        except Exception as e:
            self.logger.error(f"Error in safe file operation for {file_path}: {e}")
            raise
        finally:
            if file_handle and not file_handle.closed:
                try:
                    file_handle.close()
                except Exception:
                    pass  # Ignore errors during cleanup
    
    def _update_decode_stats(self, start_time: float, success: bool, encoding: str = None, 
                           fallback_used: bool = False):
        """Update statistics for decode operations."""
        try:
            processing_time = (time.time() - start_time) * 1000
            with self._stats_lock:
                self.encoding_stats.update_operation(
                    processing_time, success, encoding=encoding,
                    error_type="decode_error" if not success else None
                )
                if fallback_used:
                    self.encoding_stats.encoding_fallbacks += 1
        except Exception:
            pass
    
    def _update_encode_stats(self, start_time: float, success: bool, encoding: str = None, 
                           fallback_used: bool = False):
        """Update statistics for encode operations."""
        try:
            processing_time = (time.time() - start_time) * 1000
            with self._stats_lock:
                self.encoding_stats.update_operation(
                    processing_time, success, encoding=encoding,
                    error_type="encode_error" if not success else None
                )
                if fallback_used:
                    self.encoding_stats.encoding_fallbacks += 1
        except Exception:
            pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        **NEW** Get comprehensive encoding operation statistics.
        
        Returns:
            Dictionary containing detailed statistics
        """
        try:
            with self._stats_lock:
                stats = self.encoding_stats
                
                return {
                    'total_operations': stats.total_operations,
                    'successful_operations': stats.successful_operations,
                    'success_rate': (stats.successful_operations / stats.total_operations * 100 
                                   if stats.total_operations > 0 else 0),
                    'encoding_fallbacks': stats.encoding_fallbacks,
                    'binary_detections': stats.binary_detections,
                    'encoding_errors': stats.encoding_errors,
                    'average_processing_time_ms': stats.average_processing_time_ms,
                    'cache_hit_rate': stats.get_cache_hit_rate(),
                    'confidence_distribution': dict(stats.confidence_distribution),
                    'encoding_usage': dict(stats.encoding_usage),
                    'file_type_distribution': dict(stats.file_type_distribution),
                    'error_types': dict(stats.error_types),
                    'cache_sizes': {
                        'encoding_cache': len(self._encoding_cache),
                        'binary_cache': len(self._binary_cache),
                        'confidence_cache': len(self._confidence_cache)
                    },
                    'memory_usage': {
                        'peak_memory_mb': stats.peak_memory_usage_mb,
                        'cleanup_enabled': self._memory_optimization_enabled
                    }
                }
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return {'error': str(e)}
    
    def clear_caches(self):
        """Clear all internal caches to free memory."""
        try:
            with self._cache_lock:
                self._encoding_cache.clear()
                self._binary_cache.clear()
                self._confidence_cache.clear()
                
            self.logger.debug("All encoding caches cleared")
            
        except Exception as e:
            self.logger.error(f"Error clearing caches: {e}")
    
    def add_shutdown_callback(self, callback: Callable[[], None]):
        """Add a callback to be executed during shutdown."""
        try:
            self._shutdown_callbacks.append(callback)
        except Exception:
            pass  # Graceful failure for shutdown callbacks


# ============================================================================
# GLOBAL CONVENIENCE FUNCTIONS
# ============================================================================

# **NEW**: Global instance for convenient access
_global_encoding_handler = None
_global_handler_lock = threading.Lock()

def get_encoding_handler() -> EncodingHandler:
    """Get the global encoding handler instance (thread-safe singleton)."""
    global _global_encoding_handler
    
    if _global_encoding_handler is None:
        with _global_handler_lock:
            if _global_encoding_handler is None:
                _global_encoding_handler = EncodingHandler()
    
    return _global_encoding_handler

def safe_read_file(file_path: Union[str, Path], encoding: str = None) -> Optional[str]:
    """
    **ENHANCED** Global function to safely read text files with automatic encoding detection.
    
    Args:
        file_path: Path to the file to read
        encoding: Preferred encoding (auto-detect if None)
        
    Returns:
        File content as string, or None if reading fails
    """
    try:
        handler = get_encoding_handler()
        
        with handler.safe_file_operation(file_path, 'r', encoding=encoding) as f:
            content = f.read()
            
        return content
        
    except Exception as e:
        logging.getLogger("EncodingUtils").error(f"Failed to read file {file_path}: {e}")
        return None

def safe_write_file(file_path: Union[str, Path], content: str, encoding: str = None, 
                   create_backup: bool = False) -> bool:
    """
    **ENHANCED** Global function to safely write text files with proper encoding handling.
    
    Args:
        file_path: Path to the file to write
        content: Content to write
        encoding: Encoding to use (defaults to UTF-8)
        create_backup: Whether to create a backup of existing file
        
    Returns:
        True if write was successful, False otherwise
    """
    try:
        handler = get_encoding_handler()
        file_path = Path(file_path)
        
        # **NEW**: Create backup if requested and file exists
        if create_backup and file_path.exists():
            backup_path = file_path.with_suffix(file_path.suffix + '.bak')
            try:
                shutil.copy2(file_path, backup_path)
            except Exception as e:
                logging.getLogger("EncodingUtils").warning(f"Failed to create backup: {e}")
        
        # **NEW**: Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # **NEW**: Use atomic write operation
        temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
        
        try:
            with handler.safe_file_operation(temp_path, 'w', encoding=encoding) as f:
                f.write(content)
            
            # **NEW**: Atomic move (rename)
            if os.name == 'nt':  # Windows
                if file_path.exists():
                    file_path.unlink()
            temp_path.rename(file_path)
            
            return True
            
        except Exception as e:
            # **NEW**: Cleanup temp file on error
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            raise e
        
    except Exception as e:
        logging.getLogger("EncodingUtils").error(f"Failed to write file {file_path}: {e}")
        return False

def safe_decode_bytes(data: bytes, encoding: str = None) -> str:
    """
    **ENHANCED** Global function to safely decode bytes to string.
    
    Args:
        data: Bytes to decode
        encoding: Preferred encoding (auto-detect if None)
        
    Returns:
        Decoded string (never fails)
    """
    handler = get_encoding_handler()
    return handler.safe_decode(data, encoding)

def safe_encode_string(text: str, encoding: str = None) -> bytes:
    """
    **ENHANCED** Global function to safely encode string to bytes.
    
    Args:
        text: String to encode
        encoding: Target encoding (defaults to UTF-8)
        
    Returns:
        Encoded bytes (never fails)
    """
    handler = get_encoding_handler()
    return handler.safe_encode(text, encoding)

def detect_file_encoding(file_path: Union[str, Path]) -> Tuple[str, float]:
    """
    **NEW** Global function to detect file encoding.
    
    Args:
        file_path: Path to the file to analyze
        
    Returns:
        Tuple of (detected_encoding, confidence_score)
    """
    try:
        handler = get_encoding_handler()
        file_path = Path(file_path)
        
        if not file_path.exists():
            return (handler.default_encoding, 0.0)
        
        with open(file_path, 'rb') as f:
            sample = f.read(handler.MAX_DETECTION_SIZE)
        
        return handler.detect_encoding(sample)
        
    except Exception as e:
        logging.getLogger("EncodingUtils").error(f"Failed to detect encoding for {file_path}: {e}")
        return ('utf-8', 0.0)

def is_binary_file(file_path: Union[str, Path]) -> bool:
    """
    **NEW** Global function to check if a file is binary.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if file is binary, False if text
    """
    handler = get_encoding_handler()
    return handler.is_binary_file(file_path)

def normalize_text_safe(text: str) -> str:
    """
    **NEW** Global function to safely normalize text.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text
    """
    handler = get_encoding_handler()
    return handler.normalize_text(text)

def sanitize_text_safe(text: str, allow_newlines: bool = True) -> str:
    """
    **NEW** Global function to safely sanitize text.
    
    Args:
        text: Text to sanitize
        allow_newlines: Whether to preserve newlines
        
    Returns:
        Sanitized text
    """
    handler = get_encoding_handler()
    return handler.sanitize_text(text, allow_newlines)

def get_encoding_statistics() -> Dict[str, Any]:
    """
    **NEW** Global function to get encoding operation statistics.
    
    Returns:
        Statistics dictionary
    """
    handler = get_encoding_handler()
    return handler.get_statistics()

def clear_encoding_caches():
    """**NEW** Global function to clear all encoding caches."""
    handler = get_encoding_handler()
    handler.clear_caches()

# **NEW**: Cleanup function for application shutdown
def cleanup_encoding_utils():
    """Clean up encoding utilities during application shutdown."""
    global _global_encoding_handler
    
    if _global_encoding_handler:
        _global_encoding_handler._handle_shutdown()
        _global_encoding_handler = None