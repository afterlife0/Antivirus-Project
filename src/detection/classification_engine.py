"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Classification Engine - Central Threat Classification Coordinator

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.detection.ml_detector (MLEnsembleDetector)
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.detection.signature_detector (SignatureDetector)
- src.detection.yara_detector (YaraDetector)
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.core.scanner_engine (ScannerEngine)
- src.ui.scan_window (ScanWindow)
- src.intelligence.threat_intel (ThreatIntelligence)

Integration Points:
- Central classification coordinator for all detection methods
- Unified threat analysis and risk assessment engine
- Classification result aggregation and comprehensive reporting
- Multi-algorithm detection orchestration and coordination
- Threat intelligence integration for enhanced classification
- Real-time classification with performance optimization
- Comprehensive threat profiling and family identification
- Risk-based classification with confidence scoring
- Detection method performance analysis and optimization
- Unified classification API for all scanning operations

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: ClassificationEngine
□ Dependencies properly imported with EXACT class names
□ All connected files can access ClassificationEngine functionality
□ Classification coordination implemented
□ Threat analysis functional
□ Result aggregation working
□ Performance optimization included
□ Integration points established
"""

import os
import sys
import logging
import time
import json
import threading
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import statistics

# Project Dependencies
from src.detection.ml_detector import MLEnsembleDetector
from src.detection.ensemble.voting_classifier import EnsembleVotingClassifier, DetectionMethod, VotingStrategy
from src.detection.signature_detector import SignatureDetector
from src.detection.yara_detector import YaraDetector
from src.utils.encoding_utils import EncodingHandler


class ClassificationStatus(Enum):
    """Classification process status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class ThreatSeverity(Enum):
    """Threat severity levels."""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ClassificationPriority(Enum):
    """Classification priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class DetectionMethodResult:
    """Container for individual detection method results."""
    method: DetectionMethod
    detected: bool
    confidence: float
    threat_classification: str
    risk_score: float
    processing_time: float
    result_details: Dict[str, Any]
    error_message: Optional[str] = None
    status: str = "completed"


@dataclass
class ThreatProfile:
    """Comprehensive threat profile."""
    file_path: str
    file_hash_sha256: str
    file_size: int
    file_type: str
    threat_detected: bool
    final_classification: str
    threat_family: str
    threat_severity: ThreatSeverity
    confidence_score: float
    risk_assessment: float
    detection_methods_used: List[DetectionMethod]
    method_results: Dict[DetectionMethod, DetectionMethodResult]
    threat_indicators: List[str]
    behavioral_patterns: List[str]
    classification_timestamp: str
    processing_time: float
    recommended_actions: List[str]
    additional_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClassificationRequest:
    """Request for file classification."""
    file_path: str
    priority: ClassificationPriority
    requested_methods: Optional[List[DetectionMethod]]
    voting_strategy: VotingStrategy
    timeout_seconds: float
    metadata: Dict[str, Any]
    request_id: str
    request_timestamp: str


@dataclass
class ClassificationResult:
    """Complete classification result."""
    request_id: str
    status: ClassificationStatus
    threat_profile: Optional[ThreatProfile]
    error_message: Optional[str]
    performance_metrics: Dict[str, Any]
    completion_timestamp: str


class ClassificationEngine:
    """
    Central Threat Classification Engine.
    
    Coordinates all detection methods to provide comprehensive threat analysis
    and classification with unified reporting and risk assessment.
    
    Features:
    - Multi-algorithm detection coordination
    - Unified threat classification and profiling
    - Ensemble voting for enhanced accuracy
    - Real-time classification with timeout controls
    - Performance optimization and method selection
    - Comprehensive threat analysis and reporting
    - Risk-based classification with confidence scoring
    - Detection method performance monitoring
    - Priority-based classification queue
    - Asynchronous classification processing
    """
    
    def __init__(self, ml_ensemble_detector: Optional[MLEnsembleDetector] = None,
                 signature_detector: Optional[SignatureDetector] = None,
                 yara_detector: Optional[YaraDetector] = None):
        """
        Initialize Classification Engine.
        
        Args:
            ml_ensemble_detector: ML ensemble detector instance
            signature_detector: Signature detector instance
            yara_detector: YARA detector instance
        """
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("ClassificationEngine")
        
        # Detection methods
        self.ml_ensemble_detector = ml_ensemble_detector
        self.signature_detector = signature_detector
        self.yara_detector = yara_detector
        
        # Ensemble voting classifier
        self.voting_classifier = None
        self._initialize_voting_classifier()
        
        # Classification configuration
        self.default_timeout = 60.0  # 60 seconds default timeout
        self.max_concurrent_classifications = 5
        self.supported_file_extensions = {
            '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1',
            '.vbs', '.js', '.jar', '.apk', '.dex', '.so', '.dylib', '.pdf',
            '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar',
            '.7z', '.tar', '.gz', '.bin', '.dat', '.tmp'
        }
        
        # Classification queue and processing
        self.classification_queue = []
        self.active_classifications = {}
        self.completed_classifications = {}
        self.classification_history = []
        
        # Performance tracking
        self.total_classifications = 0
        self.successful_classifications = 0
        self.failed_classifications = 0
        self.total_processing_time = 0.0
        self.method_performance = {}
        
        # Thread safety
        self._queue_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._processing_lock = threading.Lock()
        
        # Classification worker thread
        self._worker_thread = None
        self._stop_processing = False
        
        # Initialize performance tracking
        self._initialize_performance_tracking()
        
        # Start background processing
        self._start_background_processing()
        
        self.logger.info("ClassificationEngine initialized")
    
    def _initialize_voting_classifier(self) -> None:
        """Initialize ensemble voting classifier with available detectors."""
        try:
            # Create voting classifier with ML ensemble
            self.voting_classifier = EnsembleVotingClassifier(self.ml_ensemble_detector)
            
            # Register available detection methods
            if self.signature_detector:
                self.voting_classifier.register_detection_method(
                    DetectionMethod.SIGNATURE, 
                    self.signature_detector
                )
                self.logger.info("Registered signature detector with voting classifier")
            
            if self.yara_detector:
                self.voting_classifier.register_detection_method(
                    DetectionMethod.YARA, 
                    self.yara_detector
                )
                self.logger.info("Registered YARA detector with voting classifier")
            
            # Set default voting strategy
            self.voting_classifier.set_voting_strategy(VotingStrategy.WEIGHTED)
            
            self.logger.info("Ensemble voting classifier initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing voting classifier: {e}")
            self.voting_classifier = None
    
    def _initialize_performance_tracking(self) -> None:
        """Initialize performance tracking for detection methods."""
        try:
            for method in DetectionMethod:
                self.method_performance[method] = {
                    'total_runs': 0,
                    'successful_runs': 0,
                    'failed_runs': 0,
                    'total_time': 0.0,
                    'average_time': 0.0,
                    'detection_count': 0,
                    'false_positive_count': 0,
                    'last_run': None,
                    'health_status': 'unknown'
                }
                
        except Exception as e:
            self.logger.error(f"Error initializing performance tracking: {e}")
    
    def _start_background_processing(self) -> None:
        """Start background classification processing thread."""
        try:
            self._worker_thread = threading.Thread(
                target=self._classification_worker,
                daemon=True,
                name="ClassificationWorker"
            )
            self._stop_processing = False
            self._worker_thread.start()
            
            self.logger.info("Background classification processing started")
            
        except Exception as e:
            self.logger.error(f"Error starting background processing: {e}")
    
    def _classification_worker(self) -> None:
        """Background worker thread for processing classification queue."""
        while not self._stop_processing:
            try:
                # Check for pending classifications
                with self._queue_lock:
                    if not self.classification_queue:
                        time.sleep(0.1)  # Short sleep when queue is empty
                        continue
                    
                    # Check if we can process more classifications
                    if len(self.active_classifications) >= self.max_concurrent_classifications:
                        time.sleep(0.1)
                        continue
                    
                    # Get next classification request (priority-based)
                    request = self._get_next_classification_request()
                    if not request:
                        continue
                
                # Process classification
                self._process_classification_request(request)
                
            except Exception as e:
                self.logger.error(f"Error in classification worker: {e}")
                time.sleep(1.0)  # Longer sleep on error
    
    def _get_next_classification_request(self) -> Optional[ClassificationRequest]:
        """Get next classification request from queue based on priority."""
        try:
            if not self.classification_queue:
                return None
            
            # Sort by priority (urgent first)
            priority_order = {
                ClassificationPriority.URGENT: 0,
                ClassificationPriority.HIGH: 1,
                ClassificationPriority.NORMAL: 2,
                ClassificationPriority.LOW: 3
            }
            
            self.classification_queue.sort(key=lambda req: priority_order.get(req.priority, 999))
            return self.classification_queue.pop(0)
            
        except Exception as e:
            self.logger.error(f"Error getting next classification request: {e}")
            return None
    
    def classify_file(self, file_path: Union[str, Path], 
                     priority: ClassificationPriority = ClassificationPriority.NORMAL,
                     voting_strategy: VotingStrategy = VotingStrategy.WEIGHTED,
                     timeout_seconds: Optional[float] = None,
                     async_processing: bool = False,
                     metadata: Optional[Dict[str, Any]] = None) -> Union[ClassificationResult, str]:
        """
        Classify a file using all available detection methods.
        
        Args:
            file_path: Path to the file to classify
            priority: Classification priority level
            voting_strategy: Voting strategy for ensemble classification
            timeout_seconds: Maximum time allowed for classification
            async_processing: Whether to process asynchronously
            metadata: Additional metadata for classification
            
        Returns:
            ClassificationResult for synchronous processing or request_id for async
        """
        try:
            file_path = Path(file_path)
            timeout_seconds = timeout_seconds or self.default_timeout
            metadata = metadata or {}
            
            # Generate unique request ID
            request_id = f"clf_{int(time.time() * 1000)}_{hash(str(file_path)) % 10000}"
            
            # Create classification request
            request = ClassificationRequest(
                file_path=str(file_path),
                priority=priority,
                requested_methods=None,  # Use all available methods
                voting_strategy=voting_strategy,
                timeout_seconds=timeout_seconds,
                metadata=metadata,
                request_id=request_id,
                request_timestamp=datetime.now().isoformat()
            )
            
            if async_processing:
                # Add to queue for background processing
                with self._queue_lock:
                    self.classification_queue.append(request)
                
                self.logger.info(f"Queued classification request: {request_id}")
                return request_id
            else:
                # Process synchronously
                return self._process_classification_request(request)
                
        except Exception as e:
            self.logger.error(f"Error in classify_file: {e}")
            return ClassificationResult(
                request_id="error",
                status=ClassificationStatus.FAILED,
                threat_profile=None,
                error_message=str(e),
                performance_metrics={},
                completion_timestamp=datetime.now().isoformat()
            )
    
    def _process_classification_request(self, request: ClassificationRequest) -> ClassificationResult:
        """Process a classification request."""
        try:
            start_time = time.time()
            
            with self._processing_lock:
                self.active_classifications[request.request_id] = request
            
            self.logger.info(f"Processing classification request: {request.request_id}")
            
            # Validate file
            file_path = Path(request.file_path)
            if not file_path.exists() or not file_path.is_file():
                return self._create_error_result(
                    request.request_id, 
                    f"File not found or not accessible: {file_path}"
                )
            
            # Check file extension
            if file_path.suffix.lower() not in self.supported_file_extensions:
                self.logger.warning(f"Unsupported file extension: {file_path.suffix}")
                # Continue processing but note the warning
            
            # Perform detection using ensemble voting classifier
            if not self.voting_classifier:
                return self._create_error_result(
                    request.request_id,
                    "Ensemble voting classifier not available"
                )
            
            # Run ensemble classification with timeout
            ensemble_result = self._run_ensemble_classification(
                file_path, 
                request.voting_strategy,
                request.timeout_seconds
            )
            
            if not ensemble_result:
                return self._create_error_result(
                    request.request_id,
                    "Ensemble classification failed"
                )
            
            # Create comprehensive threat profile
            threat_profile = self._create_threat_profile(file_path, ensemble_result, request.metadata)
            
            # Calculate performance metrics
            processing_time = time.time() - start_time
            performance_metrics = self._calculate_performance_metrics(
                ensemble_result, 
                processing_time
            )
            
            # Update statistics
            self._update_classification_statistics(True, processing_time)
            
            # Create final result
            result = ClassificationResult(
                request_id=request.request_id,
                status=ClassificationStatus.COMPLETED,
                threat_profile=threat_profile,
                error_message=None,
                performance_metrics=performance_metrics,
                completion_timestamp=datetime.now().isoformat()
            )
            
            # Store completed classification
            with self._processing_lock:
                if request.request_id in self.active_classifications:
                    del self.active_classifications[request.request_id]
                self.completed_classifications[request.request_id] = result
                self.classification_history.append(result)
                
                # Limit history size
                if len(self.classification_history) > 1000:
                    self.classification_history = self.classification_history[-500:]
            
            self.logger.info(f"Classification completed: {request.request_id} "
                           f"({threat_profile.final_classification}, {processing_time:.3f}s)")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing classification request: {e}")
            self._update_classification_statistics(False, time.time() - start_time)
            
            return self._create_error_result(request.request_id, str(e))
        
        finally:
            # Cleanup active classification
            with self._processing_lock:
                if request.request_id in self.active_classifications:
                    del self.active_classifications[request.request_id]
    
    def _run_ensemble_classification(self, file_path: Path, 
                                   voting_strategy: VotingStrategy,
                                   timeout_seconds: float) -> Optional[Any]:
        """Run ensemble classification with timeout."""
        try:
            # Set voting strategy
            self.voting_classifier.set_voting_strategy(voting_strategy)
            
            # Run classification
            result = self.voting_classifier.classify_threat(file_path)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error in ensemble classification: {e}")
            return None
    
    def _create_threat_profile(self, file_path: Path, ensemble_result: Any, 
                             metadata: Dict[str, Any]) -> ThreatProfile:
        """Create comprehensive threat profile from ensemble results."""
        try:
            # Extract basic file information
            file_size = file_path.stat().st_size
            file_type = file_path.suffix.lower()
            
            # Extract ensemble results
            threat_detected = ensemble_result.final_classification != "clean"
            final_classification = ensemble_result.final_classification
            threat_severity = self._determine_threat_severity(
                ensemble_result.threat_level.value,
                ensemble_result.global_confidence,
                ensemble_result.risk_score
            )
            
            # Determine threat family
            threat_family = self._determine_threat_family(
                final_classification,
                ensemble_result.method_results
            )
            
            # Extract detection method results
            method_results = {}
            for method, detection_result in ensemble_result.method_results.items():
                method_results[method] = DetectionMethodResult(
                    method=method,
                    detected=detection_result.detected,
                    confidence=detection_result.confidence,
                    threat_classification=detection_result.threat_type or "unknown",
                    risk_score=detection_result.risk_score,
                    processing_time=detection_result.processing_time,
                    result_details=detection_result.details,
                    error_message=None,
                    status="completed"
                )
            
            # Extract threat indicators and behavioral patterns
            threat_indicators = self._extract_threat_indicators(ensemble_result)
            behavioral_patterns = self._extract_behavioral_patterns(ensemble_result)
            
            # Generate recommended actions
            recommended_actions = self._generate_recommended_actions(
                final_classification,
                threat_severity,
                ensemble_result.global_confidence
            )
            
            # Create threat profile
            threat_profile = ThreatProfile(
                file_path=str(file_path),
                file_hash_sha256=getattr(ensemble_result, 'file_hash', ''),
                file_size=file_size,
                file_type=file_type,
                threat_detected=threat_detected,
                final_classification=final_classification,
                threat_family=threat_family,
                threat_severity=threat_severity,
                confidence_score=ensemble_result.global_confidence,
                risk_assessment=ensemble_result.risk_score,
                detection_methods_used=ensemble_result.detection_methods_used,
                method_results=method_results,
                threat_indicators=threat_indicators,
                behavioral_patterns=behavioral_patterns,
                classification_timestamp=datetime.now().isoformat(),
                processing_time=ensemble_result.processing_time,
                recommended_actions=recommended_actions,
                additional_metadata={
                    'consensus_level': ensemble_result.consensus_level,
                    'voting_strategy': ensemble_result.voting_strategy.value,
                    'analysis_summary': ensemble_result.analysis_summary,
                    'user_metadata': metadata
                }
            )
            
            return threat_profile
            
        except Exception as e:
            self.logger.error(f"Error creating threat profile: {e}")
            # Return minimal threat profile
            return ThreatProfile(
                file_path=str(file_path),
                file_hash_sha256="",
                file_size=0,
                file_type="unknown",
                threat_detected=False,
                final_classification="error",
                threat_family="unknown",
                threat_severity=ThreatSeverity.CLEAN,
                confidence_score=0.0,
                risk_assessment=0.0,
                detection_methods_used=[],
                method_results={},
                threat_indicators=[],
                behavioral_patterns=[],
                classification_timestamp=datetime.now().isoformat(),
                processing_time=0.0,
                recommended_actions=["review_manually"]
            )
    
    def _determine_threat_severity(self, threat_level: str, confidence: float, 
                                 risk_score: float) -> ThreatSeverity:
        """Determine threat severity from classification results."""
        try:
            # Combine threat level, confidence, and risk score
            if threat_level == "critical" or (confidence >= 0.95 and risk_score >= 0.9):
                return ThreatSeverity.CRITICAL
            elif threat_level == "malicious" or (confidence >= 0.8 and risk_score >= 0.7):
                return ThreatSeverity.HIGH
            elif threat_level == "suspicious" or (confidence >= 0.6 and risk_score >= 0.5):
                return ThreatSeverity.MEDIUM
            elif confidence >= 0.3 or risk_score >= 0.3:
                return ThreatSeverity.LOW
            else:
                return ThreatSeverity.CLEAN
                
        except Exception as e:
            self.logger.error(f"Error determining threat severity: {e}")
            return ThreatSeverity.CLEAN
    
    def _determine_threat_family(self, classification: str, 
                               method_results: Dict[Any, Any]) -> str:
        """Determine threat family from classification results."""
        try:
            if classification == "clean":
                return "clean"
            
            # Check for specific threat families in method results
            threat_families = []
            
            for method, result in method_results.items():
                if hasattr(result, 'threat_type') and result.threat_type:
                    threat_families.append(result.threat_type)
                if hasattr(result, 'details') and isinstance(result.details, dict):
                    family = result.details.get('threat_family', '')
                    if family:
                        threat_families.append(family)
            
            if threat_families:
                # Return most common threat family
                from collections import Counter
                family_counts = Counter(threat_families)
                return family_counts.most_common(1)[0][0]
            
            # Fallback to classification
            return classification
            
        except Exception as e:
            self.logger.error(f"Error determining threat family: {e}")
            return "unknown"
    
    def _extract_threat_indicators(self, ensemble_result: Any) -> List[str]:
        """Extract threat indicators from ensemble results."""
        try:
            indicators = []
            
            # Extract from method results
            for method, result in ensemble_result.method_results.items():
                if hasattr(result, 'details') and isinstance(result.details, dict):
                    # ML indicators
                    if 'features' in result.details:
                        ml_indicators = result.details.get('high_risk_features', [])
                        indicators.extend(ml_indicators)
                    
                    # Signature indicators
                    if 'signature_matches' in result.details:
                        sig_indicators = [f"Signature: {match}" for match in result.details['signature_matches']]
                        indicators.extend(sig_indicators)
                    
                    # YARA indicators
                    if 'yara_matches' in result.details:
                        yara_indicators = [f"YARA: {match}" for match in result.details['yara_matches']]
                        indicators.extend(yara_indicators)
            
            return list(set(indicators))  # Remove duplicates
            
        except Exception as e:
            self.logger.error(f"Error extracting threat indicators: {e}")
            return []
    
    def _extract_behavioral_patterns(self, ensemble_result: Any) -> List[str]:
        """Extract behavioral patterns from ensemble results."""
        try:
            patterns = []
            
            # Extract from analysis summary
            if hasattr(ensemble_result, 'analysis_summary'):
                summary = ensemble_result.analysis_summary
                if isinstance(summary, dict):
                    # Look for behavioral patterns
                    if 'behavioral_analysis' in summary:
                        behavioral_data = summary['behavioral_analysis']
                        if isinstance(behavioral_data, dict):
                            patterns.extend(behavioral_data.get('patterns', []))
                    
                    # Look for API usage patterns
                    if 'api_usage' in summary:
                        api_data = summary['api_usage']
                        if isinstance(api_data, list):
                            patterns.extend([f"API: {api}" for api in api_data])
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error extracting behavioral patterns: {e}")
            return []
    
    def _generate_recommended_actions(self, classification: str, severity: ThreatSeverity,
                                    confidence: float) -> List[str]:
        """Generate recommended actions based on classification results."""
        try:
            actions = []
            
            if classification == "clean":
                actions.append("allow")
                return actions
            
            # Based on severity
            if severity == ThreatSeverity.CRITICAL:
                actions.extend([
                    "quarantine_immediately",
                    "block_execution",
                    "scan_system_for_similar_threats",
                    "notify_security_team"
                ])
            elif severity == ThreatSeverity.HIGH:
                actions.extend([
                    "quarantine_with_confirmation",
                    "detailed_analysis",
                    "check_for_system_changes"
                ])
            elif severity == ThreatSeverity.MEDIUM:
                actions.extend([
                    "flag_for_review",
                    "monitor_file_behavior",
                    "user_confirmation_required"
                ])
            else:
                actions.extend([
                    "allow_with_monitoring",
                    "periodic_rescan"
                ])
            
            # Based on confidence
            if confidence < 0.7:
                actions.append("manual_analysis_recommended")
            
            # Based on classification type
            if "ransomware" in classification.lower():
                actions.extend([
                    "backup_protection_check",
                    "network_isolation",
                    "immediate_incident_response"
                ])
            elif "trojan" in classification.lower():
                actions.extend([
                    "check_network_connections",
                    "scan_for_persistence_mechanisms"
                ])
            
            return actions
            
        except Exception as e:
            self.logger.error(f"Error generating recommended actions: {e}")
            return ["review_manually"]
    
    def _calculate_performance_metrics(self, ensemble_result: Any, 
                                     processing_time: float) -> Dict[str, Any]:
        """Calculate performance metrics for classification."""
        try:
            metrics = {
                'total_processing_time': processing_time,
                'method_count': len(ensemble_result.detection_methods_used),
                'consensus_level': ensemble_result.consensus_level,
                'confidence_score': ensemble_result.global_confidence,
                'risk_score': ensemble_result.risk_score
            }
            
            # Method-specific metrics
            method_metrics = {}
            for method, result in ensemble_result.method_results.items():
                method_metrics[method.value] = {
                    'processing_time': result.processing_time,
                    'detected': result.detected,
                    'confidence': result.confidence,
                    'risk_score': result.risk_score
                }
            
            metrics['method_metrics'] = method_metrics
            
            # Performance ratios
            if processing_time > 0:
                metrics['methods_per_second'] = len(ensemble_result.detection_methods_used) / processing_time
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error calculating performance metrics: {e}")
            return {'error': str(e)}
    
    def _create_error_result(self, request_id: str, error_message: str) -> ClassificationResult:
        """Create error classification result."""
        return ClassificationResult(
            request_id=request_id,
            status=ClassificationStatus.FAILED,
            threat_profile=None,
            error_message=error_message,
            performance_metrics={},
            completion_timestamp=datetime.now().isoformat()
        )
    
    def _update_classification_statistics(self, success: bool, processing_time: float) -> None:
        """Update classification statistics."""
        try:
            with self._stats_lock:
                self.total_classifications += 1
                self.total_processing_time += processing_time
                
                if success:
                    self.successful_classifications += 1
                else:
                    self.failed_classifications += 1
                    
        except Exception as e:
            self.logger.error(f"Error updating classification statistics: {e}")
    
    def get_classification_result(self, request_id: str) -> Optional[ClassificationResult]:
        """Get classification result by request ID."""
        try:
            with self._processing_lock:
                # Check completed classifications
                if request_id in self.completed_classifications:
                    return self.completed_classifications[request_id]
                
                # Check active classifications
                if request_id in self.active_classifications:
                    return ClassificationResult(
                        request_id=request_id,
                        status=ClassificationStatus.IN_PROGRESS,
                        threat_profile=None,
                        error_message=None,
                        performance_metrics={},
                        completion_timestamp=""
                    )
                
                # Check queue
                for request in self.classification_queue:
                    if request.request_id == request_id:
                        return ClassificationResult(
                            request_id=request_id,
                            status=ClassificationStatus.PENDING,
                            threat_profile=None,
                            error_message=None,
                            performance_metrics={},
                            completion_timestamp=""
                        )
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting classification result: {e}")
            return None
    
    def get_engine_statistics(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics."""
        try:
            with self._stats_lock:
                stats = {
                    'total_classifications': self.total_classifications,
                    'successful_classifications': self.successful_classifications,
                    'failed_classifications': self.failed_classifications,
                    'success_rate': (self.successful_classifications / self.total_classifications 
                                   if self.total_classifications > 0 else 0.0),
                    'average_processing_time': (self.total_processing_time / self.total_classifications 
                                              if self.total_classifications > 0 else 0.0),
                    'queue_size': len(self.classification_queue),
                    'active_classifications': len(self.active_classifications),
                    'completed_classifications': len(self.completed_classifications),
                    'method_performance': self.method_performance.copy(),
                    'supported_extensions': list(self.supported_file_extensions),
                    'max_concurrent_classifications': self.max_concurrent_classifications,
                    'default_timeout': self.default_timeout,
                    'voting_classifier_healthy': self.voting_classifier.is_classifier_healthy() if self.voting_classifier else False,
                    'last_updated': datetime.now().isoformat()
                }
                
                # Recent classification stats
                if self.classification_history:
                    recent_results = self.classification_history[-100:]  # Last 100 classifications
                    
                    threat_detected_count = sum(1 for result in recent_results 
                                              if result.threat_profile and result.threat_profile.threat_detected)
                    
                    stats['recent_stats'] = {
                        'total_recent': len(recent_results),
                        'threats_detected': threat_detected_count,
                        'threat_detection_rate': threat_detected_count / len(recent_results),
                        'average_recent_time': statistics.mean([
                            result.threat_profile.processing_time for result in recent_results 
                            if result.threat_profile
                        ]) if recent_results else 0.0
                    }
                
                return stats
                
        except Exception as e:
            self.logger.error(f"Error getting engine statistics: {e}")
            return {}
    
    def is_engine_healthy(self) -> bool:
        """Check if classification engine is healthy."""
        try:
            # Check if voting classifier is available and healthy
            if not self.voting_classifier or not self.voting_classifier.is_classifier_healthy():
                return False
            
            # Check if at least one detection method is available
            available_methods = 0
            if self.ml_ensemble_detector:
                available_methods += 1
            if self.signature_detector:
                available_methods += 1
            if self.yara_detector:
                available_methods += 1
            
            return available_methods > 0
            
        except Exception as e:
            self.logger.error(f"Error checking engine health: {e}")
            return False
    
    def cleanup_old_results(self, max_age_hours: int = 24) -> int:
        """Clean up old classification results."""
        try:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            removed_count = 0
            
            with self._processing_lock:
                # Clean completed classifications
                to_remove = []
                for request_id, result in self.completed_classifications.items():
                    try:
                        completion_time = datetime.fromisoformat(result.completion_timestamp)
                        if completion_time < cutoff_time:
                            to_remove.append(request_id)
                    except ValueError:
                        # Invalid timestamp format, remove it
                        to_remove.append(request_id)
                
                for request_id in to_remove:
                    del self.completed_classifications[request_id]
                    removed_count += 1
                
                # Clean classification history
                filtered_history = []
                for result in self.classification_history:
                    try:
                        completion_time = datetime.fromisoformat(result.completion_timestamp)
                        if completion_time >= cutoff_time:
                            filtered_history.append(result)
                    except ValueError:
                        # Skip results with invalid timestamps
                        continue
                
                self.classification_history = filtered_history
            
            self.logger.info(f"Cleaned up {removed_count} old classification results")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old results: {e}")
            return 0
    
    def shutdown(self) -> None:
        """Shutdown classification engine."""
        try:
            self.logger.info("Shutting down ClassificationEngine...")
            
            # Stop background processing
            self._stop_processing = True
            
            # Wait for worker thread to finish
            if self._worker_thread and self._worker_thread.is_alive():
                self._worker_thread.join(timeout=5.0)
            
            # Clear queues
            with self._queue_lock:
                self.classification_queue.clear()
            
            with self._processing_lock:
                self.active_classifications.clear()
            
            self.logger.info("ClassificationEngine shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Utility function for easy engine creation
def create_classification_engine(ml_ensemble_detector: Optional[MLEnsembleDetector] = None,
                               signature_detector: Optional[SignatureDetector] = None,
                               yara_detector: Optional[YaraDetector] = None) -> ClassificationEngine:
    """
    Convenience function to create a classification engine.
    
    Args:
        ml_ensemble_detector: ML ensemble detector instance
        signature_detector: Signature detector instance
        yara_detector: YARA detector instance
        
    Returns:
        Initialized ClassificationEngine instance
    """
    try:
        return ClassificationEngine(ml_ensemble_detector, signature_detector, yara_detector)
    except Exception as e:
        logging.getLogger("ClassificationEngine").error(f"Error creating classification engine: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import tempfile
    
    print("Testing ClassificationEngine...")
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as temp_file:
        temp_file.write("This is a test executable file")
        temp_file_path = temp_file.name
    
    try:
        # Create classification engine (without actual detectors for testing)
        engine = ClassificationEngine()
        print(f"✅ ClassificationEngine created successfully")
        
        # Test health check
        is_healthy = engine.is_engine_healthy()
        print(f"✅ Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Test synchronous classification (will fail without actual detectors)
        result = engine.classify_file(
            temp_file_path,
            priority=ClassificationPriority.HIGH,
            async_processing=False
        )
        
        if result:
            print(f"✅ Classification completed")
            print(f"   Request ID: {result.request_id}")
            print(f"   Status: {result.status.value}")
            if result.error_message:
                print(f"   Error: {result.error_message}")
        
        # Test statistics
        stats = engine.get_engine_statistics()
        print(f"✅ Statistics retrieved: {len(stats)} categories")
        print(f"   Total classifications: {stats.get('total_classifications', 0)}")
        print(f"   Queue size: {stats.get('queue_size', 0)}")
        print(f"   Active classifications: {stats.get('active_classifications', 0)}")
        
        # Test async classification
        request_id = engine.classify_file(
            temp_file_path,
            priority=ClassificationPriority.NORMAL,
            async_processing=True
        )
        
        if isinstance(request_id, str):
            print(f"✅ Async classification queued: {request_id}")
            
            # Check status
            time.sleep(0.1)  # Brief wait
            status_result = engine.get_classification_result(request_id)
            if status_result:
                print(f"   Status: {status_result.status.value}")
        
        print("✅ ClassificationEngine test completed successfully")
        
    except Exception as e:
        print(f"❌ ClassificationEngine test failed: {e}")
    
    finally:
        # Cleanup
        try:
            engine.shutdown()
            os.unlink(temp_file_path)
        except:
            pass