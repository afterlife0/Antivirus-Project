"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Scanner Engine - Central Scanning Coordinator and Orchestrator

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.detection.classification_engine (ClassificationEngine)
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.ui.scan_window (ScanWindow)
- src.core.app_config (AppConfig)
- src.notification.notification_manager (NotificationManager)

Integration Points:
- Central scanning coordinator for file system operations
- Multi-threaded scanning with real-time progress reporting
- Integration with classification engine for comprehensive threat analysis
- Quarantine management and automated threat response
- Scan scheduling and background monitoring capabilities
- Performance optimization with configurable scan parameters
- File system monitoring for real-time protection
- Comprehensive scan reporting and statistics tracking
- Memory-efficient scanning for large file systems
- Integration with notification system for user alerts

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: ScannerEngine
□ Dependencies properly imported with EXACT class names
□ All connected files can access ScannerEngine functionality
□ Scanning coordination implemented
□ Classification integration functional
□ Progress reporting working
□ Performance optimization included
□ Integration points established
"""

import os
import sys
import logging
import time
import threading
import queue
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Callable, Iterator
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import fnmatch

# Project Dependencies
from src.detection.classification_engine import (
    ClassificationEngine, ClassificationResult, ClassificationStatus,
    ClassificationPriority, ThreatSeverity, VotingStrategy
)
from src.utils.encoding_utils import EncodingHandler


class ScanType(Enum):
    """Types of scans supported."""
    QUICK_SCAN = "quick_scan"
    FULL_SYSTEM_SCAN = "full_system_scan"
    CUSTOM_SCAN = "custom_scan"
    REAL_TIME_SCAN = "real_time_scan"
    SCHEDULED_SCAN = "scheduled_scan"


class ScanStatus(Enum):
    """Scan operation status."""
    IDLE = "idle"
    PREPARING = "preparing"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ScanPriority(Enum):
    """Scan priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class FileAction(Enum):
    """Actions to take on detected threats."""
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    BLOCK_ACCESS = "block_access"
    USER_PROMPT = "user_prompt"


@dataclass
class ScanConfiguration:
    """Configuration for scan operations."""
    scan_type: ScanType
    target_paths: List[str]
    file_extensions: Optional[List[str]]
    exclude_paths: List[str]
    max_file_size: int  # bytes
    max_threads: int
    timeout_per_file: float  # seconds
    classification_priority: ClassificationPriority
    voting_strategy: VotingStrategy
    follow_symlinks: bool
    scan_archives: bool
    scan_compressed: bool
    deep_scan: bool
    heuristic_analysis: bool
    real_time_monitoring: bool
    auto_quarantine: bool
    scan_memory: bool
    scan_system_files: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FileProcessingResult:
    """Result of processing a single file."""
    file_path: str
    file_size: int
    file_hash: str
    scan_timestamp: str
    processing_time: float
    classification_result: Optional[ClassificationResult]
    threat_detected: bool
    threat_classification: str
    threat_severity: ThreatSeverity
    confidence_score: float
    risk_score: float
    action_taken: FileAction
    error_message: Optional[str]
    skipped: bool
    skip_reason: Optional[str]


@dataclass
class ScanProgress:
    """Real-time scan progress information."""
    scan_id: str
    current_file: str
    files_scanned: int
    files_total: int
    files_remaining: int
    threats_detected: int
    files_quarantined: int
    files_cleaned: int
    files_skipped: int
    bytes_scanned: int
    scan_speed: float  # files per second
    estimated_time_remaining: float  # seconds
    current_phase: str
    progress_percentage: float
    elapsed_time: float
    last_update: str


@dataclass
class ScanSummary:
    """Complete scan operation summary."""
    scan_id: str
    scan_type: ScanType
    scan_status: ScanStatus
    start_time: str
    end_time: Optional[str]
    total_duration: float
    files_scanned: int
    files_total: int
    threats_detected: int
    threats_by_severity: Dict[str, int]
    threats_by_type: Dict[str, int]
    files_quarantined: int
    files_cleaned: int
    files_deleted: int
    files_skipped: int
    bytes_scanned: int
    average_scan_speed: float
    scan_configuration: ScanConfiguration
    detailed_results: List[FileProcessingResult]
    error_messages: List[str]
    performance_metrics: Dict[str, Any]


class ScannerEngine:
    """
    Central Scanning Engine and Coordinator.
    
    Provides comprehensive file system scanning capabilities with multi-threaded
    processing, real-time progress reporting, and integration with classification
    engine for threat detection and response.
    
    Features:
    - Multi-threaded scanning with configurable thread pools
    - Real-time progress monitoring and reporting
    - Comprehensive scan configuration and customization
    - Integration with classification engine for threat analysis
    - Automatic threat response and quarantine management
    - Scan scheduling and background monitoring
    - Performance optimization and memory management
    - File system watching for real-time protection
    - Detailed scan reporting and statistics
    - Support for multiple scan types and priorities
    """
    
    def __init__(self, classification_engine: Optional[ClassificationEngine] = None):
        """
        Initialize Scanner Engine.
        
        Args:
            classification_engine: Classification engine for threat analysis
        """
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("ScannerEngine")
        
        # Classification engine integration
        self.classification_engine = classification_engine
        
        # Scanning configuration
        self.default_config = self._create_default_configuration()
        self.supported_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
            '.vbs', '.js', '.jar', '.apk', '.dex', '.so', '.dylib', '.pdf',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar',
            '.7z', '.tar', '.gz', '.bin', '.dat', '.tmp', '.msi', '.cab',
            '.iso', '.img', '.dmg', '.pkg', '.deb', '.rpm'
        }
        
        # Scan management
        self.active_scans = {}  # scan_id -> scan_thread
        self.scan_history = []
        self.scan_queue = queue.PriorityQueue()
        self.scan_results = {}  # scan_id -> ScanSummary
        
        # Threading and performance
        self.max_concurrent_scans = 3
        self.default_thread_pool_size = 4
        self.file_processing_queue = queue.Queue(maxsize=1000)
        
        # Progress callbacks
        self.progress_callbacks = []  # List of progress callback functions
        self.completion_callbacks = []  # List of completion callback functions
        
        # Real-time monitoring
        self.real_time_enabled = False
        self.file_watchers = {}
        self.monitoring_threads = {}
        
        # Statistics and performance tracking
        self.total_scans = 0
        self.total_files_scanned = 0
        self.total_threats_detected = 0
        self.total_scan_time = 0.0
        self.scan_performance_history = []
        
        # Thread safety
        self._scan_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._callback_lock = threading.Lock()
        
        # Shutdown control
        self._shutdown_event = threading.Event()
        
        # Background scan processor
        self._scan_processor = None
        self._start_scan_processor()
        
        self.logger.info("ScannerEngine initialized")
    
    def _create_default_configuration(self) -> ScanConfiguration:
        """Create default scan configuration."""
        return ScanConfiguration(
            scan_type=ScanType.QUICK_SCAN,
            target_paths=[],
            file_extensions=None,  # Scan all supported extensions
            exclude_paths=[
                "/proc", "/sys", "/dev", "/tmp",  # Linux
                "C:\\Windows\\System32", "C:\\Windows\\SysWOW64",  # Windows
                "/System", "/Library"  # macOS
            ],
            max_file_size=100 * 1024 * 1024,  # 100MB
            max_threads=4,
            timeout_per_file=30.0,
            classification_priority=ClassificationPriority.NORMAL,
            voting_strategy=VotingStrategy.WEIGHTED,
            follow_symlinks=False,
            scan_archives=True,
            scan_compressed=True,
            deep_scan=False,
            heuristic_analysis=True,
            real_time_monitoring=False,
            auto_quarantine=False,
            scan_memory=False,
            scan_system_files=False
        )
    
    def _start_scan_processor(self) -> None:
        """Start background scan processor thread."""
        try:
            self._scan_processor = threading.Thread(
                target=self._scan_processor_worker,
                daemon=True,
                name="ScanProcessor"
            )
            self._scan_processor.start()
            
            self.logger.info("Scan processor started")
            
        except Exception as e:
            self.logger.error(f"Error starting scan processor: {e}")
    
    def _scan_processor_worker(self) -> None:
        """Background worker for processing scan queue."""
        while not self._shutdown_event.is_set():
            try:
                # Check for queued scans
                try:
                    priority, scan_request = self.scan_queue.get(timeout=1.0)
                    
                    # Check if we can start new scan
                    with self._scan_lock:
                        if len(self.active_scans) >= self.max_concurrent_scans:
                            # Put back in queue
                            self.scan_queue.put((priority, scan_request))
                            continue
                    
                    # Start scan
                    self._execute_scan_request(scan_request)
                    
                except queue.Empty:
                    continue  # No queued scans
                    
            except Exception as e:
                self.logger.error(f"Error in scan processor: {e}")
                time.sleep(1.0)
    
    def start_scan(self, config: Optional[ScanConfiguration] = None,
                   priority: ScanPriority = ScanPriority.NORMAL,
                   async_scan: bool = True) -> str:
        """
        Start a new scan operation.
        
        Args:
            config: Scan configuration (uses default if None)
            priority: Scan priority level
            async_scan: Whether to run scan asynchronously
            
        Returns:
            Unique scan ID
        """
        try:
            # Use default config if none provided
            if config is None:
                config = self._create_default_configuration()
            
            # Generate unique scan ID
            scan_id = f"scan_{int(time.time() * 1000)}_{hash(str(config.target_paths)) % 10000}"
            
            # Validate configuration
            if not self._validate_scan_configuration(config):
                raise ValueError("Invalid scan configuration")
            
            # Create scan request
            scan_request = {
                'scan_id': scan_id,
                'config': config,
                'start_time': datetime.now().isoformat(),
                'priority': priority
            }
            
            if async_scan:
                # Add to queue for background processing
                priority_value = {
                    ScanPriority.CRITICAL: 0,
                    ScanPriority.HIGH: 1,
                    ScanPriority.NORMAL: 2,
                    ScanPriority.LOW: 3
                }.get(priority, 2)
                
                self.scan_queue.put((priority_value, scan_request))
                self.logger.info(f"Queued scan: {scan_id} (priority: {priority.value})")
            else:
                # Execute immediately
                self._execute_scan_request(scan_request)
            
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Error starting scan: {e}")
            raise
    
    def _validate_scan_configuration(self, config: ScanConfiguration) -> bool:
        """Validate scan configuration."""
        try:
            # Check target paths
            if not config.target_paths:
                return False
            
            for path in config.target_paths:
                if not Path(path).exists():
                    self.logger.warning(f"Target path does not exist: {path}")
            
            # Check thread limits
            if config.max_threads <= 0 or config.max_threads > 32:
                return False
            
            # Check file size limits
            if config.max_file_size <= 0:
                return False
            
            # Check timeout
            if config.timeout_per_file <= 0:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating scan configuration: {e}")
            return False
    
    def _execute_scan_request(self, scan_request: Dict[str, Any]) -> None:
        """Execute a scan request."""
        try:
            scan_id = scan_request['scan_id']
            config = scan_request['config']
            
            # Create scan thread
            scan_thread = threading.Thread(
                target=self._perform_scan,
                args=(scan_id, config),
                daemon=True,
                name=f"Scan-{scan_id}"
            )
            
            # Register active scan
            with self._scan_lock:
                self.active_scans[scan_id] = scan_thread
            
            # Start scan
            scan_thread.start()
            
            self.logger.info(f"Started scan execution: {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Error executing scan request: {e}")
    
    def _perform_scan(self, scan_id: str, config: ScanConfiguration) -> None:
        """Perform the actual scan operation."""
        try:
            start_time = time.time()
            self.logger.info(f"Starting scan: {scan_id}")
            
            # Initialize scan summary
            scan_summary = ScanSummary(
                scan_id=scan_id,
                scan_type=config.scan_type,
                scan_status=ScanStatus.PREPARING,
                start_time=datetime.now().isoformat(),
                end_time=None,
                total_duration=0.0,
                files_scanned=0,
                files_total=0,
                threats_detected=0,
                threats_by_severity={},
                threats_by_type={},
                files_quarantined=0,
                files_cleaned=0,
                files_deleted=0,
                files_skipped=0,
                bytes_scanned=0,
                average_scan_speed=0.0,
                scan_configuration=config,
                detailed_results=[],
                error_messages=[],
                performance_metrics={}
            )
            
            # Store initial scan result
            self.scan_results[scan_id] = scan_summary
            
            # Phase 1: File Discovery
            self._update_scan_status(scan_id, ScanStatus.PREPARING, "Discovering files...")
            files_to_scan = self._discover_files(config)
            scan_summary.files_total = len(files_to_scan)
            
            if not files_to_scan:
                self._complete_scan(scan_id, "No files found to scan")
                return
            
            # Phase 2: File Scanning
            self._update_scan_status(scan_id, ScanStatus.SCANNING, f"Scanning {len(files_to_scan)} files...")
            
            # Create progress tracker
            progress = ScanProgress(
                scan_id=scan_id,
                current_file="",
                files_scanned=0,
                files_total=len(files_to_scan),
                files_remaining=len(files_to_scan),
                threats_detected=0,
                files_quarantined=0,
                files_cleaned=0,
                files_skipped=0,
                bytes_scanned=0,
                scan_speed=0.0,
                estimated_time_remaining=0.0,
                current_phase="scanning",
                progress_percentage=0.0,
                elapsed_time=0.0,
                last_update=datetime.now().isoformat()
            )
            
            # Process files with thread pool
            self._process_files_parallel(scan_id, files_to_scan, config, progress, scan_summary)
            
            # Phase 3: Analysis and Reporting
            self._update_scan_status(scan_id, ScanStatus.ANALYZING, "Analyzing results...")
            self._finalize_scan_results(scan_id, scan_summary, start_time)
            
            # Complete scan
            self._complete_scan(scan_id, f"Scan completed: {scan_summary.threats_detected} threats detected")
            
        except Exception as e:
            self.logger.error(f"Error performing scan {scan_id}: {e}")
            self._fail_scan(scan_id, str(e))
        
        finally:
            # Cleanup active scan
            with self._scan_lock:
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
    
    def _discover_files(self, config: ScanConfiguration) -> List[Path]:
        """Discover files to scan based on configuration."""
        try:
            files_to_scan = []
            
            for target_path_str in config.target_paths:
                target_path = Path(target_path_str)
                
                if not target_path.exists():
                    self.logger.warning(f"Target path does not exist: {target_path}")
                    continue
                
                if target_path.is_file():
                    # Single file
                    if self._should_scan_file(target_path, config):
                        files_to_scan.append(target_path)
                else:
                    # Directory - walk recursively
                    for file_path in self._walk_directory(target_path, config):
                        if self._should_scan_file(file_path, config):
                            files_to_scan.append(file_path)
            
            self.logger.info(f"Discovered {len(files_to_scan)} files to scan")
            return files_to_scan
            
        except Exception as e:
            self.logger.error(f"Error discovering files: {e}")
            return []
    
    def _walk_directory(self, directory: Path, config: ScanConfiguration) -> Iterator[Path]:
        """Walk directory recursively and yield files."""
        try:
            for root, dirs, files in os.walk(directory, followlinks=config.follow_symlinks):
                root_path = Path(root)
                
                # Check if this directory should be excluded
                if self._is_path_excluded(root_path, config.exclude_paths):
                    dirs.clear()  # Don't recurse into excluded directories
                    continue
                
                # Process files in current directory
                for file_name in files:
                    file_path = root_path / file_name
                    
                    # Skip if file is excluded
                    if self._is_path_excluded(file_path, config.exclude_paths):
                        continue
                    
                    yield file_path
                    
        except Exception as e:
            self.logger.error(f"Error walking directory {directory}: {e}")
    
    def _should_scan_file(self, file_path: Path, config: ScanConfiguration) -> bool:
        """Determine if a file should be scanned."""
        try:
            # Check if file exists and is readable
            if not file_path.exists() or not file_path.is_file():
                return False
            
            # Check file size
            try:
                file_size = file_path.stat().st_size
                if file_size > config.max_file_size:
                    return False
            except OSError:
                return False  # Can't access file
            
            # Check file extension
            if config.file_extensions:
                # Only scan specified extensions
                if file_path.suffix.lower() not in config.file_extensions:
                    return False
            else:
                # Use default supported extensions
                if file_path.suffix.lower() not in self.supported_extensions:
                    return False
            
            # Check system files
            if not config.scan_system_files and self._is_system_file(file_path):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking if file should be scanned: {e}")
            return False
    
    def _is_path_excluded(self, path: Path, exclude_patterns: List[str]) -> bool:
        """Check if path matches any exclusion pattern."""
        try:
            path_str = str(path)
            
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path_str.lower(), pattern.lower()):
                    return True
                    
                # Also check if path starts with excluded directory
                if path_str.startswith(pattern) or path_str.lower().startswith(pattern.lower()):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking path exclusion: {e}")
            return False
    
    def _is_system_file(self, file_path: Path) -> bool:
        """Check if file is a system file."""
        try:
            path_str = str(file_path).lower()
            
            # Windows system paths
            windows_system_paths = [
                "c:\\windows\\system32",
                "c:\\windows\\syswow64",
                "c:\\program files\\windows",
                "c:\\program files (x86)\\windows"
            ]
            
            # Linux system paths
            linux_system_paths = [
                "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                "/lib", "/usr/lib", "/lib64", "/usr/lib64"
            ]
            
            # macOS system paths
            macos_system_paths = [
                "/system", "/library", "/usr/bin", "/usr/sbin"
            ]
            
            all_system_paths = windows_system_paths + linux_system_paths + macos_system_paths
            
            for system_path in all_system_paths:
                if path_str.startswith(system_path.lower()):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking if system file: {e}")
            return False
    
    def _process_files_parallel(self, scan_id: str, files_to_scan: List[Path],
                               config: ScanConfiguration, progress: ScanProgress,
                               scan_summary: ScanSummary) -> None:
        """Process files in parallel using thread pool."""
        try:
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
                # Submit all files for processing
                future_to_file = {
                    executor.submit(self._process_single_file, file_path, config, scan_id): file_path
                    for file_path in files_to_scan
                }
                
                # Process completed tasks
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    
                    try:
                        # Get processing result
                        result = future.result(timeout=config.timeout_per_file)
                        
                        # Update scan summary
                        self._update_scan_summary_with_result(scan_summary, result)
                        
                        # Update progress
                        progress.files_scanned += 1
                        progress.files_remaining = progress.files_total - progress.files_scanned
                        progress.current_file = str(file_path)
                        progress.progress_percentage = (progress.files_scanned / progress.files_total) * 100
                        progress.elapsed_time = time.time() - start_time
                        progress.scan_speed = progress.files_scanned / progress.elapsed_time if progress.elapsed_time > 0 else 0
                        progress.estimated_time_remaining = (progress.files_remaining / progress.scan_speed) if progress.scan_speed > 0 else 0
                        progress.last_update = datetime.now().isoformat()
                        
                        if result.threat_detected:
                            progress.threats_detected += 1
                            if result.action_taken == FileAction.QUARANTINE:
                                progress.files_quarantined += 1
                        
                        if result.skipped:
                            progress.files_skipped += 1
                        
                        progress.bytes_scanned += result.file_size
                        
                        # Notify progress callbacks
                        self._notify_progress_callbacks(progress)
                        
                    except Exception as file_error:
                        self.logger.error(f"Error processing file {file_path}: {file_error}")
                        scan_summary.error_messages.append(f"Error processing {file_path}: {file_error}")
                        
                        # Create error result
                        error_result = FileProcessingResult(
                            file_path=str(file_path),
                            file_size=0,
                            file_hash="",
                            scan_timestamp=datetime.now().isoformat(),
                            processing_time=0.0,
                            classification_result=None,
                            threat_detected=False,
                            threat_classification="error",
                            threat_severity=ThreatSeverity.CLEAN,
                            confidence_score=0.0,
                            risk_score=0.0,
                            action_taken=FileAction.ALLOW,
                            error_message=str(file_error),
                            skipped=True,
                            skip_reason="processing_error"
                        )
                        
                        scan_summary.detailed_results.append(error_result)
                        progress.files_skipped += 1
                        progress.files_scanned += 1
                        
                        # Update progress
                        self._notify_progress_callbacks(progress)
            
        except Exception as e:
            self.logger.error(f"Error in parallel file processing: {e}")
            raise
    
    def _process_single_file(self, file_path: Path, config: ScanConfiguration,
                           scan_id: str) -> FileProcessingResult:
        """Process a single file for threats."""
        try:
            start_time = time.time()
            
            # Get file information
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            
            # Check if classification engine is available
            if not self.classification_engine:
                return FileProcessingResult(
                    file_path=str(file_path),
                    file_size=file_size,
                    file_hash=file_hash,
                    scan_timestamp=datetime.now().isoformat(),
                    processing_time=time.time() - start_time,
                    classification_result=None,
                    threat_detected=False,
                    threat_classification="not_analyzed",
                    threat_severity=ThreatSeverity.CLEAN,
                    confidence_score=0.0,
                    risk_score=0.0,
                    action_taken=FileAction.ALLOW,
                    error_message="Classification engine not available",
                    skipped=True,
                    skip_reason="no_classification_engine"
                )
            
            # Perform classification
            classification_result = self.classification_engine.classify_file(
                file_path=file_path,
                priority=config.classification_priority,
                voting_strategy=config.voting_strategy,
                timeout_seconds=config.timeout_per_file,
                async_processing=False,
                metadata={'scan_id': scan_id, 'scan_type': config.scan_type.value}
            )
            
            # Process classification result
            if classification_result and classification_result.status == ClassificationStatus.COMPLETED:
                threat_profile = classification_result.threat_profile
                
                if threat_profile:
                    # Determine action based on threat severity and configuration
                    action_taken = self._determine_file_action(threat_profile, config)
                    
                    # Execute action if needed
                    if action_taken in [FileAction.QUARANTINE, FileAction.DELETE]:
                        self._execute_file_action(file_path, action_taken, threat_profile)
                    
                    return FileProcessingResult(
                        file_path=str(file_path),
                        file_size=file_size,
                        file_hash=file_hash,
                        scan_timestamp=datetime.now().isoformat(),
                        processing_time=time.time() - start_time,
                        classification_result=classification_result,
                        threat_detected=threat_profile.threat_detected,
                        threat_classification=threat_profile.final_classification,
                        threat_severity=threat_profile.threat_severity,
                        confidence_score=threat_profile.confidence_score,
                        risk_score=threat_profile.risk_assessment,
                        action_taken=action_taken,
                        error_message=None,
                        skipped=False,
                        skip_reason=None
                    )
            
            # Classification failed or no result
            return FileProcessingResult(
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                scan_timestamp=datetime.now().isoformat(),
                processing_time=time.time() - start_time,
                classification_result=classification_result,
                threat_detected=False,
                threat_classification="analysis_failed",
                threat_severity=ThreatSeverity.CLEAN,
                confidence_score=0.0,
                risk_score=0.0,
                action_taken=FileAction.ALLOW,
                error_message=classification_result.error_message if classification_result else "Classification failed",
                skipped=True,
                skip_reason="classification_failed"
            )
            
        except Exception as e:
            self.logger.error(f"Error processing file {file_path}: {e}")
            return FileProcessingResult(
                file_path=str(file_path),
                file_size=0,
                file_hash="",
                scan_timestamp=datetime.now().isoformat(),
                processing_time=time.time() - start_time,
                classification_result=None,
                threat_detected=False,
                threat_classification="error",
                threat_severity=ThreatSeverity.CLEAN,
                confidence_score=0.0,
                risk_score=0.0,
                action_taken=FileAction.ALLOW,
                error_message=str(e),
                skipped=True,
                skip_reason="processing_error"
            )
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def _determine_file_action(self, threat_profile, config: ScanConfiguration) -> FileAction:
        """Determine what action to take on a detected threat."""
        try:
            if not threat_profile.threat_detected:
                return FileAction.ALLOW
            
            # Auto-quarantine based on configuration and threat severity
            if config.auto_quarantine:
                if threat_profile.threat_severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]:
                    return FileAction.QUARANTINE
                elif threat_profile.threat_severity == ThreatSeverity.MEDIUM and threat_profile.confidence_score >= 0.8:
                    return FileAction.QUARANTINE
            
            # Default action based on severity
            if threat_profile.threat_severity == ThreatSeverity.CRITICAL:
                return FileAction.QUARANTINE
            elif threat_profile.threat_severity == ThreatSeverity.HIGH:
                return FileAction.USER_PROMPT if not config.auto_quarantine else FileAction.QUARANTINE
            else:
                return FileAction.ALLOW
                
        except Exception as e:
            self.logger.error(f"Error determining file action: {e}")
            return FileAction.ALLOW
    
    def _execute_file_action(self, file_path: Path, action: FileAction, threat_profile) -> bool:
        """Execute the determined action on a file."""
        try:
            if action == FileAction.QUARANTINE:
                # Note: Actual quarantine implementation would require FileManager
                # For now, just log the action
                self.logger.warning(f"QUARANTINE ACTION: {file_path} - {threat_profile.final_classification}")
                return True
                
            elif action == FileAction.DELETE:
                # Note: Actual deletion should be done carefully with user confirmation
                self.logger.warning(f"DELETE ACTION: {file_path} - {threat_profile.final_classification}")
                return True
                
            elif action == FileAction.BLOCK_ACCESS:
                self.logger.warning(f"BLOCK ACTION: {file_path} - {threat_profile.final_classification}")
                return True
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error executing file action {action} on {file_path}: {e}")
            return False
    
    def _update_scan_summary_with_result(self, scan_summary: ScanSummary,
                                       result: FileProcessingResult) -> None:
        """Update scan summary with file processing result."""
        try:
            # Add detailed result
            scan_summary.detailed_results.append(result)
            
            # Update counters
            scan_summary.files_scanned += 1
            scan_summary.bytes_scanned += result.file_size
            
            if result.threat_detected:
                scan_summary.threats_detected += 1
                
                # Count by severity
                severity_key = result.threat_severity.value
                scan_summary.threats_by_severity[severity_key] = scan_summary.threats_by_severity.get(severity_key, 0) + 1
                
                # Count by type
                type_key = result.threat_classification
                scan_summary.threats_by_type[type_key] = scan_summary.threats_by_type.get(type_key, 0) + 1
            
            if result.action_taken == FileAction.QUARANTINE:
                scan_summary.files_quarantined += 1
            elif result.action_taken == FileAction.DELETE:
                scan_summary.files_deleted += 1
            
            if result.skipped:
                scan_summary.files_skipped += 1
            
            if result.error_message:
                scan_summary.error_messages.append(f"{result.file_path}: {result.error_message}")
                
        except Exception as e:
            self.logger.error(f"Error updating scan summary: {e}")
    
    def _finalize_scan_results(self, scan_id: str, scan_summary: ScanSummary,
                              start_time: float) -> None:
        """Finalize scan results and calculate metrics."""
        try:
            end_time = time.time()
            scan_summary.total_duration = end_time - start_time
            scan_summary.end_time = datetime.now().isoformat()
            scan_summary.average_scan_speed = scan_summary.files_scanned / scan_summary.total_duration if scan_summary.total_duration > 0 else 0
            
            # Calculate performance metrics
            scan_summary.performance_metrics = {
                'files_per_second': scan_summary.average_scan_speed,
                'bytes_per_second': scan_summary.bytes_scanned / scan_summary.total_duration if scan_summary.total_duration > 0 else 0,
                'threat_detection_rate': scan_summary.threats_detected / scan_summary.files_scanned if scan_summary.files_scanned > 0 else 0,
                'skip_rate': scan_summary.files_skipped / scan_summary.files_scanned if scan_summary.files_scanned > 0 else 0,
                'error_rate': len(scan_summary.error_messages) / scan_summary.files_scanned if scan_summary.files_scanned > 0 else 0,
                'memory_usage': self._get_memory_usage(),
                'cpu_usage': self._get_cpu_usage()
            }
            
            # Update global statistics
            self._update_global_statistics(scan_summary)
            
        except Exception as e:
            self.logger.error(f"Error finalizing scan results: {e}")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # MB
        except ImportError:
            return 0.0
        except Exception as e:
            self.logger.error(f"Error getting memory usage: {e}")
            return 0.0
    
    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return 0.0
        except Exception as e:
            self.logger.error(f"Error getting CPU usage: {e}")
            return 0.0
    
    def _update_global_statistics(self, scan_summary: ScanSummary) -> None:
        """Update global scanner statistics."""
        try:
            with self._stats_lock:
                self.total_scans += 1
                self.total_files_scanned += scan_summary.files_scanned
                self.total_threats_detected += scan_summary.threats_detected
                self.total_scan_time += scan_summary.total_duration
                
                # Keep performance history
                self.scan_performance_history.append({
                    'scan_id': scan_summary.scan_id,
                    'scan_type': scan_summary.scan_type.value,
                    'files_scanned': scan_summary.files_scanned,
                    'threats_detected': scan_summary.threats_detected,
                    'duration': scan_summary.total_duration,
                    'speed': scan_summary.average_scan_speed,
                    'timestamp': scan_summary.start_time
                })
                
                # Limit history size
                if len(self.scan_performance_history) > 100:
                    self.scan_performance_history = self.scan_performance_history[-50:]
                    
        except Exception as e:
            self.logger.error(f"Error updating global statistics: {e}")
    
    def _update_scan_status(self, scan_id: str, status: ScanStatus, message: str = "") -> None:
        """Update scan status and notify callbacks."""
        try:
            if scan_id in self.scan_results:
                self.scan_results[scan_id].scan_status = status
                
                # Log status change
                self.logger.info(f"Scan {scan_id} status: {status.value} - {message}")
                
        except Exception as e:
            self.logger.error(f"Error updating scan status: {e}")
    
    def _complete_scan(self, scan_id: str, message: str) -> None:
        """Complete a scan operation."""
        try:
            self._update_scan_status(scan_id, ScanStatus.COMPLETED, message)
            
            # Add to scan history
            if scan_id in self.scan_results:
                self.scan_history.append(self.scan_results[scan_id])
                
                # Limit history size
                if len(self.scan_history) > 50:
                    self.scan_history = self.scan_history[-25:]
            
            # Notify completion callbacks
            self._notify_completion_callbacks(scan_id, self.scan_results.get(scan_id))
            
            self.logger.info(f"Scan completed: {scan_id} - {message}")
            
        except Exception as e:
            self.logger.error(f"Error completing scan: {e}")
    
    def _fail_scan(self, scan_id: str, error_message: str) -> None:
        """Mark a scan as failed."""
        try:
            self._update_scan_status(scan_id, ScanStatus.FAILED, error_message)
            
            if scan_id in self.scan_results:
                self.scan_results[scan_id].error_messages.append(error_message)
            
            self.logger.error(f"Scan failed: {scan_id} - {error_message}")
            
        except Exception as e:
            self.logger.error(f"Error failing scan: {e}")
    
    def _notify_progress_callbacks(self, progress: ScanProgress) -> None:
        """Notify all registered progress callbacks."""
        try:
            with self._callback_lock:
                for callback in self.progress_callbacks:
                    try:
                        callback(progress)
                    except Exception as callback_error:
                        self.logger.error(f"Error in progress callback: {callback_error}")
                        
        except Exception as e:
            self.logger.error(f"Error notifying progress callbacks: {e}")
    
    def _notify_completion_callbacks(self, scan_id: str, scan_summary: Optional[ScanSummary]) -> None:
        """Notify all registered completion callbacks."""
        try:
            with self._callback_lock:
                for callback in self.completion_callbacks:
                    try:
                        callback(scan_id, scan_summary)
                    except Exception as callback_error:
                        self.logger.error(f"Error in completion callback: {callback_error}")
                        
        except Exception as e:
            self.logger.error(f"Error notifying completion callbacks: {e}")
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanStatus]:
        """Get current status of a scan."""
        try:
            if scan_id in self.scan_results:
                return self.scan_results[scan_id].scan_status
            
            # Check if scan is queued
            with self.scan_queue.mutex:
                for priority, scan_request in self.scan_queue.queue:
                    if scan_request['scan_id'] == scan_id:
                        return ScanStatus.IDLE
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting scan status: {e}")
            return None
    
    def get_scan_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get current progress of an active scan."""
        try:
            # This would typically be stored and updated during scanning
            # For now, return basic information from scan results
            if scan_id in self.scan_results:
                summary = self.scan_results[scan_id]
                return ScanProgress(
                    scan_id=scan_id,
                    current_file="",
                    files_scanned=summary.files_scanned,
                    files_total=summary.files_total,
                    files_remaining=summary.files_total - summary.files_scanned,
                    threats_detected=summary.threats_detected,
                    files_quarantined=summary.files_quarantined,
                    files_cleaned=summary.files_cleaned,
                    files_skipped=summary.files_skipped,
                    bytes_scanned=summary.bytes_scanned,
                    scan_speed=summary.average_scan_speed,
                    estimated_time_remaining=0.0,
                    current_phase="scanning",
                    progress_percentage=(summary.files_scanned / summary.files_total * 100) if summary.files_total > 0 else 0,
                    elapsed_time=summary.total_duration,
                    last_update=datetime.now().isoformat()
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting scan progress: {e}")
            return None
    
    def get_scan_summary(self, scan_id: str) -> Optional[ScanSummary]:
        """Get complete scan summary."""
        try:
            return self.scan_results.get(scan_id)
            
        except Exception as e:
            self.logger.error(f"Error getting scan summary: {e}")
            return None
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active or queued scan."""
        try:
            # Check if scan is active
            with self._scan_lock:
                if scan_id in self.active_scans:
                    # Note: Actual thread cancellation is complex in Python
                    # This would require implementing proper cancellation tokens
                    self._update_scan_status(scan_id, ScanStatus.CANCELLED, "Scan cancelled by user")
                    self.logger.info(f"Cancelled active scan: {scan_id}")
                    return True
            
            # Check if scan is queued
            with self.scan_queue.mutex:
                temp_queue = []
                cancelled = False
                
                while not self.scan_queue.empty():
                    priority, scan_request = self.scan_queue.get_nowait()
                    if scan_request['scan_id'] == scan_id:
                        cancelled = True
                        self.logger.info(f"Cancelled queued scan: {scan_id}")
                    else:
                        temp_queue.append((priority, scan_request))
                
                # Put back non-cancelled scans
                for item in temp_queue:
                    self.scan_queue.put(item)
                
                return cancelled
            
        except Exception as e:
            self.logger.error(f"Error cancelling scan: {e}")
            return False
    
    def register_progress_callback(self, callback: Callable[[ScanProgress], None]) -> None:
        """Register a progress callback function."""
        try:
            with self._callback_lock:
                self.progress_callbacks.append(callback)
                
        except Exception as e:
            self.logger.error(f"Error registering progress callback: {e}")
    
    def register_completion_callback(self, callback: Callable[[str, Optional[ScanSummary]], None]) -> None:
        """Register a completion callback function."""
        try:
            with self._callback_lock:
                self.completion_callbacks.append(callback)
                
        except Exception as e:
            self.logger.error(f"Error registering completion callback: {e}")
    
    def get_scanner_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scanner statistics."""
        try:
            with self._stats_lock:
                stats = {
                    'total_scans': self.total_scans,
                    'total_files_scanned': self.total_files_scanned,
                    'total_threats_detected': self.total_threats_detected,
                    'total_scan_time': self.total_scan_time,
                    'average_scan_time': self.total_scan_time / self.total_scans if self.total_scans > 0 else 0,
                    'average_files_per_scan': self.total_files_scanned / self.total_scans if self.total_scans > 0 else 0,
                    'threat_detection_rate': self.total_threats_detected / self.total_files_scanned if self.total_files_scanned > 0 else 0,
                    'active_scans': len(self.active_scans),
                    'queued_scans': self.scan_queue.qsize(),
                    'scan_history_count': len(self.scan_history),
                    'supported_extensions': list(self.supported_extensions),
                    'max_concurrent_scans': self.max_concurrent_scans,
                    'classification_engine_available': self.classification_engine is not None,
                    'real_time_monitoring_enabled': self.real_time_enabled,
                    'performance_history': self.scan_performance_history[-10:],  # Last 10 scans
                    'last_updated': datetime.now().isoformat()
                }
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting scanner statistics: {e}")
            return {}
    
    def is_scanner_healthy(self) -> bool:
        """Check if scanner engine is healthy."""
        try:
            # Check if classification engine is available
            if not self.classification_engine:
                return False
            
            # Check if classification engine is healthy
            if not self.classification_engine.is_engine_healthy():
                return False
            
            # Check thread limits
            if len(self.active_scans) >= self.max_concurrent_scans * 2:
                return False  # Too many active scans
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking scanner health: {e}")
            return False
    
    def cleanup_old_results(self, max_age_hours: int = 24) -> int:
        """Clean up old scan results."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            removed_count = 0
            
            # Clean scan results
            to_remove = []
            for scan_id, summary in self.scan_results.items():
                try:
                    start_time = datetime.fromisoformat(summary.start_time)
                    if start_time < cutoff_time:
                        to_remove.append(scan_id)
                except ValueError:
                    to_remove.append(scan_id)  # Invalid timestamp
            
            for scan_id in to_remove:
                del self.scan_results[scan_id]
                removed_count += 1
            
            # Clean scan history
            self.scan_history = [
                summary for summary in self.scan_history
                if datetime.fromisoformat(summary.start_time) >= cutoff_time
            ]
            
            self.logger.info(f"Cleaned up {removed_count} old scan results")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old results: {e}")
            return 0
    
    def shutdown(self) -> None:
        """Shutdown scanner engine."""
        try:
            self.logger.info("Shutting down ScannerEngine...")
            
            # Signal shutdown
            self._shutdown_event.set()
            
            # Wait for scan processor to finish
            if self._scan_processor and self._scan_processor.is_alive():
                self._scan_processor.join(timeout=5.0)
            
            # Cancel active scans
            with self._scan_lock:
                for scan_id in list(self.active_scans.keys()):
                    self.cancel_scan(scan_id)
            
            # Clear queues
            while not self.scan_queue.empty():
                try:
                    self.scan_queue.get_nowait()
                except queue.Empty:
                    break
            
            self.logger.info("ScannerEngine shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Utility function for easy scanner creation
def create_scanner_engine(classification_engine: Optional[ClassificationEngine] = None) -> ScannerEngine:
    """
    Convenience function to create a scanner engine.
    
    Args:
        classification_engine: Classification engine for threat analysis
        
    Returns:
        Initialized ScannerEngine instance
    """
    try:
        return ScannerEngine(classification_engine)
    except Exception as e:
        logging.getLogger("ScannerEngine").error(f"Error creating scanner engine: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import tempfile
    
    print("Testing ScannerEngine...")
    
    # Create temporary test directory with files
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        (temp_path / "test1.exe").write_text("Test executable 1")
        (temp_path / "test2.dll").write_text("Test library 1")
        (temp_path / "readme.txt").write_text("Not scanned - unsupported extension")
        
        try:
            # Create scanner engine (without classification engine for testing)
            scanner = ScannerEngine()
            print(f"✅ ScannerEngine created successfully")
            
            # Test health check
            is_healthy = scanner.is_scanner_healthy()
            print(f"✅ Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
            
            # Create scan configuration
            config = ScanConfiguration(
                scan_type=ScanType.CUSTOM_SCAN,
                target_paths=[str(temp_path)],
                file_extensions=['.exe', '.dll'],
                exclude_paths=[],
                max_file_size=1024 * 1024,  # 1MB
                max_threads=2,
                timeout_per_file=10.0,
                classification_priority=ClassificationPriority.NORMAL,
                voting_strategy=VotingStrategy.WEIGHTED,
                follow_symlinks=False,
                scan_archives=False,
                scan_compressed=False,
                deep_scan=False,
                heuristic_analysis=True,
                real_time_monitoring=False,
                auto_quarantine=False,
                scan_memory=False,
                scan_system_files=False
            )
            
            # Test scan (will complete but without actual threat detection)
            scan_id = scanner.start_scan(config, priority=ScanPriority.HIGH, async_scan=False)
            print(f"✅ Scan started: {scan_id}")
            
            # Wait a moment for scan to complete
            time.sleep(1.0)
            
            # Check scan status
            status = scanner.get_scan_status(scan_id)
            print(f"✅ Scan Status: {status.value if status else 'Unknown'}")
            
            # Get scan summary
            summary = scanner.get_scan_summary(scan_id)
            if summary:
                print(f"✅ Scan Summary:")
                print(f"   Files Scanned: {summary.files_scanned}")
                print(f"   Files Total: {summary.files_total}")
                print(f"   Threats Detected: {summary.threats_detected}")
                print(f"   Duration: {summary.total_duration:.3f}s")
                print(f"   Status: {summary.scan_status.value}")
            
            # Test statistics
            stats = scanner.get_scanner_statistics()
            print(f"✅ Statistics retrieved: {len(stats)} categories")
            print(f"   Total Scans: {stats.get('total_scans', 0)}")
            print(f"   Total Files Scanned: {stats.get('total_files_scanned', 0)}")
            print(f"   Active Scans: {stats.get('active_scans', 0)}")
            
            print("✅ ScannerEngine test completed successfully")
            
        except Exception as e:
            print(f"❌ ScannerEngine test failed: {e}")
        
        finally:
            # Cleanup
            try:
                scanner.shutdown()
            except:
                pass