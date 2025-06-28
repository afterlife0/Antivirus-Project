"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Ensemble Voting Classifier - Global Detection Method Coordination

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.detection.ml_detector (MLEnsembleDetector)
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.detection.classification_engine (ClassificationEngine)
- src.core.scanner_engine (ScannerEngine)

Integration Points:
- Coordinates ALL detection methods across the antivirus system
- Manages global voting strategies for cross-method consensus
- Provides final threat classification and risk assessment
- Integrates ML ensemble results with signature and YARA detection
- Handles threat intelligence data integration
- Manages confidence thresholds and decision boundaries
- Provides comprehensive detection result analysis
- Supports multiple voting algorithms for different scenarios
- Handles detection method failures and fallback strategies
- Provides global detection performance monitoring

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: EnsembleVotingClassifier
□ Dependencies properly imported with EXACT class names
□ All connected files can access EnsembleVotingClassifier functionality
□ Global detection coordination implemented
□ Cross-method voting strategies functional
□ Threat classification system working
□ Confidence calculation integrated
□ Performance monitoring included
"""

import os
import sys
import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
import json
import time
import statistics
from datetime import datetime
import threading
from enum import Enum
from dataclasses import dataclass

# Project Dependencies
from src.detection.ml_detector import MLEnsembleDetector
from src.utils.encoding_utils import EncodingHandler


class DetectionMethod(Enum):
    """Enumeration of available detection methods."""
    ML_ENSEMBLE = "ml_ensemble"
    SIGNATURE = "signature"
    YARA = "yara"
    HEURISTIC = "heuristic"
    BEHAVIORAL = "behavioral"
    REPUTATION = "reputation"


class ThreatLevel(Enum):
    """Threat severity levels."""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


class VotingStrategy(Enum):
    """Available voting strategies."""
    MAJORITY = "majority"
    WEIGHTED = "weighted"
    CONSENSUS = "consensus"
    THRESHOLD = "threshold"
    RISK_BASED = "risk_based"
    INTELLIGENCE_WEIGHTED = "intelligence_weighted"


@dataclass
class DetectionResult:
    """Container for individual detection method results."""
    method: DetectionMethod
    detected: bool
    confidence: float
    threat_type: Optional[str]
    risk_score: float
    details: Dict[str, Any]
    processing_time: float
    timestamp: str


@dataclass
class GlobalThreatClassification:
    """Container for final global threat classification."""
    final_classification: str
    threat_level: ThreatLevel
    global_confidence: float
    risk_score: float
    consensus_level: float
    detection_methods_used: List[DetectionMethod]
    method_results: Dict[DetectionMethod, DetectionResult]
    voting_strategy: VotingStrategy
    recommended_action: str
    analysis_summary: Dict[str, Any]
    processing_time: float
    timestamp: str


class EnsembleVotingClassifier:
    """
    Global Detection Ensemble Voting Classifier.
    
    Coordinates all detection methods in the antivirus system and provides
    final threat classification through sophisticated voting algorithms.
    
    Features:
    - Cross-method voting and consensus building
    - Multiple voting strategies for different scenarios
    - Threat intelligence integration
    - Dynamic confidence thresholds
    - Risk-based decision making
    - Performance monitoring across all methods
    - Fallback strategies for method failures
    - Comprehensive threat analysis and reporting
    """
    
    def __init__(self, ml_ensemble_detector: Optional[MLEnsembleDetector] = None):
        """
        Initialize Ensemble Voting Classifier.
        
        Args:
            ml_ensemble_detector: Optional ML ensemble detector instance
        """
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("EnsembleVotingClassifier")
        
        # ML Ensemble Integration
        self.ml_ensemble_detector = ml_ensemble_detector
        
        # Detection method configuration
        self.detection_methods = {}
        self.method_weights = {}
        self.method_performance = {}
        
        # Voting configuration
        self.voting_strategies = {
            VotingStrategy.MAJORITY: self._majority_voting,
            VotingStrategy.WEIGHTED: self._weighted_voting,
            VotingStrategy.CONSENSUS: self._consensus_voting,
            VotingStrategy.THRESHOLD: self._threshold_voting,
            VotingStrategy.RISK_BASED: self._risk_based_voting,
            VotingStrategy.INTELLIGENCE_WEIGHTED: self._intelligence_weighted_voting
        }
        self.default_voting_strategy = VotingStrategy.WEIGHTED
        
        # Classification configuration
        self.threat_classes = [
            "clean", "suspicious", "malware", "ransomware", 
            "trojan", "spyware", "adware", "rootkit", "worm"
        ]
        
        # Confidence thresholds
        self.confidence_thresholds = {
            ThreatLevel.CLEAN: 0.3,
            ThreatLevel.SUSPICIOUS: 0.6,
            ThreatLevel.MALICIOUS: 0.8,
            ThreatLevel.CRITICAL: 0.95
        }
        
        # Risk assessment configuration
        self.risk_weights = {
            DetectionMethod.ML_ENSEMBLE: 0.35,    # High weight for ML consensus
            DetectionMethod.SIGNATURE: 0.25,      # High weight for known signatures
            DetectionMethod.YARA: 0.20,          # Medium-high weight for YARA rules
            DetectionMethod.HEURISTIC: 0.10,     # Medium weight for heuristics
            DetectionMethod.BEHAVIORAL: 0.06,    # Lower weight for behavioral
            DetectionMethod.REPUTATION: 0.04     # Lowest weight for reputation
        }
        
        # Performance tracking
        self.global_classifications = 0
        self.successful_classifications = 0
        self.total_processing_time = 0.0
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize detection methods
        self._initialize_detection_methods()
        
        self.logger.info("EnsembleVotingClassifier initialized")
    
    def _initialize_detection_methods(self) -> None:
        """Initialize available detection methods."""
        try:
            # Initialize method weights (can be adjusted dynamically)
            self.method_weights = self.risk_weights.copy()
            
            # Initialize performance tracking for each method
            for method in DetectionMethod:
                self.method_performance[method] = {
                    'total_detections': 0,
                    'successful_detections': 0,
                    'false_positives': 0,
                    'false_negatives': 0,
                    'average_confidence': 0.0,
                    'average_processing_time': 0.0,
                    'last_detection': None,
                    'health_status': 'healthy'
                }
            
            # Mark ML ensemble as available if provided
            if self.ml_ensemble_detector:
                self.detection_methods[DetectionMethod.ML_ENSEMBLE] = self.ml_ensemble_detector
                self.logger.info("ML Ensemble detector registered")
            
            self.logger.info(f"Detection methods initialized: {len(self.detection_methods)} active")
            
        except Exception as e:
            self.logger.error(f"Error initializing detection methods: {e}")
    
    def register_detection_method(self, method: DetectionMethod, detector_instance: Any) -> bool:
        """
        Register a detection method with the voting classifier.
        
        Args:
            method: Detection method type
            detector_instance: Instance of the detector
            
        Returns:
            True if registration successful, False otherwise
        """
        try:
            self.detection_methods[method] = detector_instance
            self.logger.info(f"Registered detection method: {method.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering detection method {method.value}: {e}")
            return False
    
    def classify_threat(self, file_path: Union[str, Path], 
                       voting_strategy: Optional[VotingStrategy] = None,
                       include_methods: Optional[List[DetectionMethod]] = None) -> Optional[GlobalThreatClassification]:
        """
        Perform global threat classification using all available detection methods.
        
        Args:
            file_path: Path to the file to analyze
            voting_strategy: Voting strategy to use
            include_methods: Specific methods to include (None for all)
            
        Returns:
            Global threat classification result or None if classification fails
        """
        try:
            start_time = time.time()
            voting_strategy = voting_strategy or self.default_voting_strategy
            file_path = Path(file_path)
            
            self.logger.info(f"Starting global threat classification for: {file_path.name}")
            
            # Get detection results from all available methods
            detection_results = self._get_detection_results(file_path, include_methods)
            
            if not detection_results:
                self.logger.error("No detection results available")
                return None
            
            # Apply voting strategy
            voting_result = self._apply_voting_strategy(detection_results, voting_strategy)
            if not voting_result:
                return None
            
            # Determine threat level
            threat_level = self._determine_threat_level(voting_result['global_confidence'], 
                                                      voting_result['risk_score'])
            
            # Generate recommended action
            recommended_action = self._generate_recommended_action(
                voting_result['final_classification'], 
                threat_level, 
                voting_result['global_confidence']
            )
            
            # Calculate processing metrics
            processing_time = time.time() - start_time
            consensus_level = self._calculate_consensus_level(detection_results)
            
            # Create analysis summary
            analysis_summary = self._create_analysis_summary(detection_results, voting_result)
            
            # Update performance tracking
            self._update_global_performance(processing_time, True)
            
            # Create final classification result
            final_result = GlobalThreatClassification(
                final_classification=voting_result['final_classification'],
                threat_level=threat_level,
                global_confidence=voting_result['global_confidence'],
                risk_score=voting_result['risk_score'],
                consensus_level=consensus_level,
                detection_methods_used=[result.method for result in detection_results.values()],
                method_results=detection_results,
                voting_strategy=voting_strategy,
                recommended_action=recommended_action,
                analysis_summary=analysis_summary,
                processing_time=processing_time,
                timestamp=datetime.now().isoformat()
            )
            
            self.logger.info(f"Global classification completed: {final_result.final_classification} "
                           f"(confidence: {final_result.global_confidence:.3f}, "
                           f"threat level: {final_result.threat_level.value})")
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error in global threat classification for {file_path}: {e}")
            self._update_global_performance(0.0, False)
            return None
    
    def _get_detection_results(self, file_path: Path, 
                             include_methods: Optional[List[DetectionMethod]] = None) -> Dict[DetectionMethod, DetectionResult]:
        """Get detection results from all available methods."""
        try:
            detection_results = {}
            methods_to_use = include_methods or list(self.detection_methods.keys())
            
            for method in methods_to_use:
                if method not in self.detection_methods:
                    continue
                
                try:
                    start_time = time.time()
                    result = self._get_method_result(method, file_path)
                    processing_time = time.time() - start_time
                    
                    if result:
                        detection_result = DetectionResult(
                            method=method,
                            detected=result.get('detected', False),
                            confidence=result.get('confidence', 0.0),
                            threat_type=result.get('threat_type', 'unknown'),
                            risk_score=result.get('risk_score', 0.0),
                            details=result.get('details', {}),
                            processing_time=processing_time,
                            timestamp=datetime.now().isoformat()
                        )
                        detection_results[method] = detection_result
                        
                        # Update method performance
                        self._update_method_performance(method, detection_result, True)
                    else:
                        self.logger.warning(f"{method.value} detection failed for {file_path.name}")
                        self._update_method_performance(method, None, False)
                        
                except Exception as method_error:
                    self.logger.error(f"Error in {method.value} detection: {method_error}")
                    self._update_method_performance(method, None, False)
            
            return detection_results
            
        except Exception as e:
            self.logger.error(f"Error getting detection results: {e}")
            return {}
    
    def _get_method_result(self, method: DetectionMethod, file_path: Path) -> Optional[Dict[str, Any]]:
        """Get result from a specific detection method."""
        try:
            detector = self.detection_methods[method]
            
            if method == DetectionMethod.ML_ENSEMBLE:
                # ML Ensemble detection
                ml_result = detector.predict_file(file_path)
                if ml_result:
                    return {
                        'detected': ml_result['ensemble_prediction'] != 'benign',
                        'confidence': ml_result['ensemble_confidence'],
                        'threat_type': ml_result['ensemble_prediction'],
                        'risk_score': ml_result['risk_score'],
                        'details': {
                            'voting_strategy': ml_result['voting_strategy'],
                            'detector_count': ml_result['detector_count'],
                            'consensus_level': ml_result['consensus_level'],
                            'individual_predictions': ml_result['individual_predictions']
                        }
                    }
            
            elif method == DetectionMethod.SIGNATURE:
                # Signature-based detection (placeholder - would integrate with actual detector)
                # signature_result = detector.detect(file_path)
                return {
                    'detected': False,  # Placeholder
                    'confidence': 0.0,
                    'threat_type': 'unknown',
                    'risk_score': 0.0,
                    'details': {'method': 'signature_placeholder'}
                }
            
            elif method == DetectionMethod.YARA:
                # YARA rules detection (placeholder - would integrate with actual detector)
                # yara_result = detector.scan(file_path)
                return {
                    'detected': False,  # Placeholder
                    'confidence': 0.0,
                    'threat_type': 'unknown',
                    'risk_score': 0.0,
                    'details': {'method': 'yara_placeholder'}
                }
            
            elif method == DetectionMethod.HEURISTIC:
                # Heuristic analysis (placeholder - would integrate with actual detector)
                return {
                    'detected': False,  # Placeholder
                    'confidence': 0.0,
                    'threat_type': 'unknown',
                    'risk_score': 0.0,
                    'details': {'method': 'heuristic_placeholder'}
                }
            
            elif method == DetectionMethod.BEHAVIORAL:
                # Behavioral analysis (placeholder - would integrate with actual detector)
                return {
                    'detected': False,  # Placeholder
                    'confidence': 0.0,
                    'threat_type': 'unknown',
                    'risk_score': 0.0,
                    'details': {'method': 'behavioral_placeholder'}
                }
            
            elif method == DetectionMethod.REPUTATION:
                # Reputation-based detection (placeholder - would integrate with actual detector)
                return {
                    'detected': False,  # Placeholder
                    'confidence': 0.0,
                    'threat_type': 'unknown',
                    'risk_score': 0.0,
                    'details': {'method': 'reputation_placeholder'}
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting result from {method.value}: {e}")
            return None
    
    def _apply_voting_strategy(self, detection_results: Dict[DetectionMethod, DetectionResult],
                             strategy: VotingStrategy) -> Optional[Dict[str, Any]]:
        """Apply specified voting strategy to detection results."""
        try:
            if strategy not in self.voting_strategies:
                self.logger.error(f"Unknown voting strategy: {strategy}")
                strategy = self.default_voting_strategy
            
            voting_function = self.voting_strategies[strategy]
            return voting_function(detection_results)
            
        except Exception as e:
            self.logger.error(f"Error applying voting strategy: {e}")
            return None
    
    def _majority_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Majority voting: simple majority rule."""
        try:
            # Count detections
            total_methods = len(detection_results)
            detected_count = sum(1 for result in detection_results.values() if result.detected)
            
            # Determine final classification
            is_threat = detected_count > (total_methods / 2)
            
            # Calculate average confidence and risk score
            avg_confidence = statistics.mean([result.confidence for result in detection_results.values()])
            avg_risk = statistics.mean([result.risk_score for result in detection_results.values()])
            
            # Determine most common threat type among detections
            threat_types = [result.threat_type for result in detection_results.values() if result.detected]
            final_classification = max(set(threat_types), key=threat_types.count) if threat_types else "clean"
            
            return {
                'final_classification': final_classification if is_threat else "clean",
                'global_confidence': avg_confidence,
                'risk_score': avg_risk if is_threat else 0.0,
                'detection_ratio': detected_count / total_methods
            }
            
        except Exception as e:
            self.logger.error(f"Error in majority voting: {e}")
            return None
    
    def _weighted_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Weighted voting: method weights applied to decisions."""
        try:
            weighted_confidence = 0.0
            weighted_risk = 0.0
            total_weight = 0.0
            threat_scores = {}
            
            for method, result in detection_results.items():
                weight = self.method_weights.get(method, 1.0)
                total_weight += weight
                
                # Apply weights to confidence and risk
                weighted_confidence += result.confidence * weight
                weighted_risk += result.risk_score * weight
                
                # Track threat type scores
                if result.detected and result.threat_type:
                    threat_scores[result.threat_type] = threat_scores.get(result.threat_type, 0.0) + weight
            
            # Normalize by total weight
            if total_weight > 0:
                weighted_confidence /= total_weight
                weighted_risk /= total_weight
            
            # Determine final classification
            if threat_scores:
                final_classification = max(threat_scores, key=threat_scores.get)
                # Check if threat score is significant enough
                max_threat_score = threat_scores[final_classification]
                if max_threat_score < (total_weight * 0.3):  # Less than 30% weighted vote
                    final_classification = "clean"
            else:
                final_classification = "clean"
            
            return {
                'final_classification': final_classification,
                'global_confidence': weighted_confidence,
                'risk_score': weighted_risk,
                'threat_scores': threat_scores
            }
            
        except Exception as e:
            self.logger.error(f"Error in weighted voting: {e}")
            return None
    
    def _consensus_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Consensus voting: requires high agreement between methods."""
        try:
            # Require at least 70% agreement for positive detection
            consensus_threshold = 0.7
            
            total_methods = len(detection_results)
            detected_count = sum(1 for result in detection_results.values() if result.detected)
            detection_ratio = detected_count / total_methods
            
            # Calculate confidence-weighted consensus
            confidence_weights = []
            for result in detection_results.values():
                if result.detected:
                    confidence_weights.append(result.confidence)
                else:
                    confidence_weights.append(1.0 - result.confidence)  # Inverted for non-detections
            
            avg_confidence = statistics.mean(confidence_weights) if confidence_weights else 0.0
            
            # Require both ratio and confidence consensus
            is_consensus_threat = (detection_ratio >= consensus_threshold and 
                                 avg_confidence >= consensus_threshold)
            
            # Determine threat type by highest confidence detection
            if is_consensus_threat:
                detected_results = [r for r in detection_results.values() if r.detected]
                if detected_results:
                    best_detection = max(detected_results, key=lambda x: x.confidence)
                    final_classification = best_detection.threat_type
                else:
                    final_classification = "malware"  # Generic classification
            else:
                final_classification = "clean"
            
            # Calculate risk score
            avg_risk = statistics.mean([result.risk_score for result in detection_results.values()])
            
            return {
                'final_classification': final_classification,
                'global_confidence': avg_confidence,
                'risk_score': avg_risk if is_consensus_threat else 0.0,
                'consensus_level': detection_ratio
            }
            
        except Exception as e:
            self.logger.error(f"Error in consensus voting: {e}")
            return None
    
    def _threshold_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Threshold voting: confidence-based thresholds."""
        try:
            # Define confidence thresholds for different threat levels
            high_confidence_threshold = 0.8
            medium_confidence_threshold = 0.6
            
            high_confidence_detections = []
            medium_confidence_detections = []
            
            for result in detection_results.values():
                if result.detected:
                    if result.confidence >= high_confidence_threshold:
                        high_confidence_detections.append(result)
                    elif result.confidence >= medium_confidence_threshold:
                        medium_confidence_detections.append(result)
            
            # Determine classification based on confidence levels
            if high_confidence_detections:
                # Any high-confidence detection triggers classification
                best_detection = max(high_confidence_detections, key=lambda x: x.confidence)
                final_classification = best_detection.threat_type
                global_confidence = best_detection.confidence
            elif len(medium_confidence_detections) >= 2:
                # Multiple medium-confidence detections
                best_detection = max(medium_confidence_detections, key=lambda x: x.confidence)
                final_classification = best_detection.threat_type
                global_confidence = statistics.mean([d.confidence for d in medium_confidence_detections])
            else:
                # Not enough confident detections
                final_classification = "clean"
                avg_clean_confidence = statistics.mean([
                    1.0 - result.confidence if result.detected else result.confidence 
                    for result in detection_results.values()
                ])
                global_confidence = avg_clean_confidence
            
            # Calculate risk score
            if final_classification != "clean":
                detected_results = [r for r in detection_results.values() if r.detected]
                avg_risk = statistics.mean([r.risk_score for r in detected_results]) if detected_results else 0.0
            else:
                avg_risk = 0.0
            
            return {
                'final_classification': final_classification,
                'global_confidence': global_confidence,
                'risk_score': avg_risk,
                'high_confidence_count': len(high_confidence_detections),
                'medium_confidence_count': len(medium_confidence_detections)
            }
            
        except Exception as e:
            self.logger.error(f"Error in threshold voting: {e}")
            return None
    
    def _risk_based_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Risk-based voting: considers risk scores and threat severity."""
        try:
            # Calculate weighted risk score
            total_risk = 0.0
            total_weight = 0.0
            threat_severity = {}
            
            # Risk severity mapping
            severity_weights = {
                "clean": 0.0,
                "suspicious": 0.3,
                "malware": 0.7,
                "ransomware": 1.0,
                "trojan": 0.9,
                "spyware": 0.8,
                "adware": 0.4,
                "rootkit": 0.95,
                "worm": 0.85
            }
            
            for method, result in detection_results.items():
                method_weight = self.method_weights.get(method, 1.0)
                total_weight += method_weight
                
                # Calculate weighted risk
                risk_contribution = result.risk_score * method_weight
                total_risk += risk_contribution
                
                # Track threat severity
                if result.detected and result.threat_type:
                    threat_severity[result.threat_type] = (
                        threat_severity.get(result.threat_type, 0.0) + 
                        severity_weights.get(result.threat_type, 0.5) * method_weight
                    )
            
            # Normalize risk score
            normalized_risk = total_risk / total_weight if total_weight > 0 else 0.0
            
            # Determine classification based on risk and severity
            if threat_severity:
                # Find highest severity threat
                final_classification = max(threat_severity, key=threat_severity.get)
                max_severity_score = threat_severity[final_classification]
                
                # Apply risk threshold
                risk_threshold = 0.5
                if normalized_risk < risk_threshold and max_severity_score < (total_weight * 0.4):
                    final_classification = "clean"
            else:
                final_classification = "clean"
            
            # Calculate global confidence based on risk and consensus
            confidence_from_risk = min(normalized_risk * 2, 1.0)  # Scale risk to confidence
            avg_method_confidence = statistics.mean([r.confidence for r in detection_results.values()])
            global_confidence = (confidence_from_risk + avg_method_confidence) / 2
            
            return {
                'final_classification': final_classification,
                'global_confidence': global_confidence,
                'risk_score': normalized_risk,
                'threat_severity_scores': threat_severity
            }
            
        except Exception as e:
            self.logger.error(f"Error in risk-based voting: {e}")
            return None
    
    def _intelligence_weighted_voting(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> Dict[str, Any]:
        """Intelligence-weighted voting: incorporates threat intelligence data."""
        try:
            # This would integrate with actual threat intelligence systems
            # For now, implementing a sophisticated weighted approach
            
            base_weights = self.method_weights.copy()
            
            # Adjust weights based on recent threat intelligence
            # (In real implementation, this would query threat intelligence APIs)
            intelligence_adjustments = {
                DetectionMethod.ML_ENSEMBLE: 1.1,    # Boost ML during active campaigns
                DetectionMethod.SIGNATURE: 1.2,      # Boost signatures for known threats
                DetectionMethod.YARA: 1.0,          # Standard weight
                DetectionMethod.HEURISTIC: 0.9,     # Reduce heuristics slightly
                DetectionMethod.BEHAVIORAL: 0.8,    # Lower priority
                DetectionMethod.REPUTATION: 1.3     # Boost reputation during outbreaks
            }
            
            # Apply intelligence adjustments
            adjusted_weights = {}
            for method, base_weight in base_weights.items():
                adjustment = intelligence_adjustments.get(method, 1.0)
                adjusted_weights[method] = base_weight * adjustment
            
            # Normalize adjusted weights
            total_adjusted_weight = sum(adjusted_weights.values())
            if total_adjusted_weight > 0:
                for method in adjusted_weights:
                    adjusted_weights[method] /= total_adjusted_weight
            
            # Apply weighted voting with adjusted weights
            weighted_confidence = 0.0
            weighted_risk = 0.0
            threat_scores = {}
            
            for method, result in detection_results.items():
                weight = adjusted_weights.get(method, 0.0)
                
                weighted_confidence += result.confidence * weight
                weighted_risk += result.risk_score * weight
                
                if result.detected and result.threat_type:
                    threat_scores[result.threat_type] = (
                        threat_scores.get(result.threat_type, 0.0) + weight
                    )
            
            # Determine final classification
            if threat_scores:
                final_classification = max(threat_scores, key=threat_scores.get)
                max_threat_score = threat_scores[final_classification]
                
                # Apply intelligence-based threshold
                intelligence_threshold = 0.25  # Lower threshold due to intelligence weighting
                if max_threat_score < intelligence_threshold:
                    final_classification = "clean"
            else:
                final_classification = "clean"
            
            return {
                'final_classification': final_classification,
                'global_confidence': weighted_confidence,
                'risk_score': weighted_risk,
                'intelligence_weights': adjusted_weights,
                'threat_scores': threat_scores
            }
            
        except Exception as e:
            self.logger.error(f"Error in intelligence-weighted voting: {e}")
            return None
    
    def _determine_threat_level(self, confidence: float, risk_score: float) -> ThreatLevel:
        """Determine threat level based on confidence and risk score."""
        try:
            # Combine confidence and risk for threat level assessment
            combined_score = (confidence * 0.6) + (risk_score * 0.4)
            
            if combined_score >= 0.9:
                return ThreatLevel.CRITICAL
            elif combined_score >= 0.7:
                return ThreatLevel.MALICIOUS
            elif combined_score >= 0.4:
                return ThreatLevel.SUSPICIOUS
            else:
                return ThreatLevel.CLEAN
                
        except Exception as e:
            self.logger.error(f"Error determining threat level: {e}")
            return ThreatLevel.CLEAN
    
    def _generate_recommended_action(self, classification: str, threat_level: ThreatLevel, 
                                   confidence: float) -> str:
        """Generate recommended action based on classification and threat level."""
        try:
            if threat_level == ThreatLevel.CRITICAL:
                return "quarantine_immediately"
            elif threat_level == ThreatLevel.MALICIOUS:
                if confidence >= 0.8:
                    return "quarantine_immediately"
                else:
                    return "quarantine_with_user_confirmation"
            elif threat_level == ThreatLevel.SUSPICIOUS:
                if classification in ["ransomware", "trojan", "rootkit"]:
                    return "quarantine_with_user_confirmation"
                else:
                    return "flag_for_review"
            else:
                return "allow"
                
        except Exception as e:
            self.logger.error(f"Error generating recommended action: {e}")
            return "flag_for_review"
    
    def _calculate_consensus_level(self, detection_results: Dict[DetectionMethod, DetectionResult]) -> float:
        """Calculate consensus level among detection methods."""
        try:
            if len(detection_results) <= 1:
                return 1.0
            
            # Count agreement on threat/clean classification
            detected_count = sum(1 for result in detection_results.values() if result.detected)
            clean_count = len(detection_results) - detected_count
            
            # Consensus is the proportion of the majority opinion
            consensus_level = max(detected_count, clean_count) / len(detection_results)
            
            return consensus_level
            
        except Exception as e:
            self.logger.error(f"Error calculating consensus level: {e}")
            return 0.0
    
    def _create_analysis_summary(self, detection_results: Dict[DetectionMethod, DetectionResult],
                               voting_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive analysis summary."""
        try:
            detected_methods = [method.value for method, result in detection_results.items() if result.detected]
            clean_methods = [method.value for method, result in detection_results.items() if not result.detected]
            
            # Calculate confidence statistics
            confidences = [result.confidence for result in detection_results.values()]
            confidence_stats = {
                'mean': statistics.mean(confidences),
                'median': statistics.median(confidences),
                'stdev': statistics.stdev(confidences) if len(confidences) > 1 else 0.0,
                'min': min(confidences),
                'max': max(confidences)
            }
            
            # Processing time statistics
            processing_times = [result.processing_time for result in detection_results.values()]
            time_stats = {
                'total': sum(processing_times),
                'mean': statistics.mean(processing_times),
                'max': max(processing_times)
            }
            
            return {
                'detection_summary': {
                    'total_methods': len(detection_results),
                    'detected_by': detected_methods,
                    'clean_by': clean_methods,
                    'detection_ratio': len(detected_methods) / len(detection_results)
                },
                'confidence_analysis': confidence_stats,
                'performance_metrics': time_stats,
                'voting_details': voting_result,
                'method_contributions': {
                    method.value: {
                        'detected': result.detected,
                        'confidence': result.confidence,
                        'risk_score': result.risk_score,
                        'processing_time': result.processing_time
                    }
                    for method, result in detection_results.items()
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error creating analysis summary: {e}")
            return {}
    
    def _update_method_performance(self, method: DetectionMethod, result: Optional[DetectionResult], 
                                 success: bool) -> None:
        """Update performance metrics for a specific detection method."""
        try:
            with self._lock:
                if method not in self.method_performance:
                    return
                
                perf = self.method_performance[method]
                perf['total_detections'] += 1
                
                if success and result:
                    perf['successful_detections'] += 1
                    
                    # Update averages
                    total_successful = perf['successful_detections']
                    
                    # Update average confidence
                    old_avg_confidence = perf['average_confidence']
                    perf['average_confidence'] = (
                        (old_avg_confidence * (total_successful - 1) + result.confidence) / total_successful
                    )
                    
                    # Update average processing time
                    old_avg_time = perf['average_processing_time']
                    perf['average_processing_time'] = (
                        (old_avg_time * (total_successful - 1) + result.processing_time) / total_successful
                    )
                    
                    perf['last_detection'] = result.timestamp
                
                # Update health status
                success_rate = perf['successful_detections'] / perf['total_detections']
                if success_rate >= 0.9:
                    perf['health_status'] = 'excellent'
                elif success_rate >= 0.7:
                    perf['health_status'] = 'good'
                elif success_rate >= 0.5:
                    perf['health_status'] = 'fair'
                else:
                    perf['health_status'] = 'poor'
                
        except Exception as e:
            self.logger.error(f"Error updating method performance: {e}")
    
    def _update_global_performance(self, processing_time: float, success: bool) -> None:
        """Update global performance metrics."""
        try:
            with self._lock:
                self.global_classifications += 1
                
                if success:
                    self.successful_classifications += 1
                    self.total_processing_time += processing_time
                
        except Exception as e:
            self.logger.error(f"Error updating global performance: {e}")
    
    def get_global_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics for all detection methods."""
        try:
            total_classifications = self.global_classifications
            success_rate = (self.successful_classifications / total_classifications 
                          if total_classifications > 0 else 0.0)
            
            avg_processing_time = (self.total_processing_time / self.successful_classifications 
                                 if self.successful_classifications > 0 else 0.0)
            
            return {
                'global_metrics': {
                    'total_classifications': total_classifications,
                    'successful_classifications': self.successful_classifications,
                    'success_rate': success_rate,
                    'average_processing_time': avg_processing_time
                },
                'method_performance': self.method_performance.copy(),
                'method_weights': self.method_weights.copy(),
                'active_methods': list(self.detection_methods.keys()),
                'voting_strategies': [strategy.value for strategy in VotingStrategy],
                'default_strategy': self.default_voting_strategy.value,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting performance metrics: {e}")
            return {}
    
    def adjust_method_weights(self, performance_based: bool = True) -> bool:
        """Adjust detection method weights based on performance."""
        try:
            if not performance_based:
                return True
            
            with self._lock:
                new_weights = {}
                total_score = 0.0
                
                for method, perf in self.method_performance.items():
                    if perf['total_detections'] > 0:
                        success_rate = perf['successful_detections'] / perf['total_detections']
                        avg_confidence = perf['average_confidence']
                        
                        # Performance score: weighted combination of success rate and confidence
                        score = (success_rate * 0.6) + (avg_confidence * 0.4)
                        new_weights[method] = score
                        total_score += score
                    else:
                        # Default weight for unused methods
                        new_weights[method] = 0.1
                        total_score += 0.1
                
                # Normalize weights
                if total_score > 0:
                    for method in new_weights:
                        self.method_weights[method] = new_weights[method] / total_score
                
                self.logger.info(f"Adjusted method weights: {self.method_weights}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error adjusting method weights: {e}")
            return False
    
    def set_voting_strategy(self, strategy: VotingStrategy) -> bool:
        """Set the default voting strategy."""
        try:
            if strategy in self.voting_strategies:
                self.default_voting_strategy = strategy
                self.logger.info(f"Set default voting strategy to: {strategy.value}")
                return True
            else:
                self.logger.error(f"Unknown voting strategy: {strategy}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting voting strategy: {e}")
            return False
    
    def get_supported_voting_strategies(self) -> List[str]:
        """Get list of supported voting strategies."""
        return [strategy.value for strategy in VotingStrategy]
    
    def is_classifier_healthy(self) -> bool:
        """Check if classifier is healthy enough for classifications."""
        try:
            active_methods = len(self.detection_methods)
            healthy_methods = sum(1 for perf in self.method_performance.values() 
                                if perf['health_status'] in ['excellent', 'good'])
            
            # Require at least 2 active methods with at least 1 healthy
            return active_methods >= 2 and healthy_methods >= 1
            
        except Exception as e:
            self.logger.error(f"Error checking classifier health: {e}")
            return False


# Utility function for easy classifier creation
def create_ensemble_voting_classifier(ml_ensemble_detector: Optional[MLEnsembleDetector] = None) -> EnsembleVotingClassifier:
    """
    Convenience function to create an ensemble voting classifier.
    
    Args:
        ml_ensemble_detector: Optional ML ensemble detector instance
        
    Returns:
        Initialized EnsembleVotingClassifier instance
    """
    try:
        return EnsembleVotingClassifier(ml_ensemble_detector)
    except Exception as e:
        logging.getLogger("EnsembleVotingClassifier").error(f"Error creating voting classifier: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import sys
    
    print("Testing EnsembleVotingClassifier...")
    
    # Create voting classifier
    try:
        classifier = EnsembleVotingClassifier()
        print(f"✅ EnsembleVotingClassifier created successfully")
        
        # Test supported strategies
        strategies = classifier.get_supported_voting_strategies()
        print(f"✅ Supported Voting Strategies: {strategies}")
        
        # Test strategy setting
        success = classifier.set_voting_strategy(VotingStrategy.CONSENSUS)
        print(f"✅ Strategy setting: {'Success' if success else 'Failed'}")
        
        # Test performance metrics
        metrics = classifier.get_global_performance_metrics()
        print(f"✅ Performance Metrics: {len(metrics)} categories")
        
        # Test health check
        is_healthy = classifier.is_classifier_healthy()
        print(f"✅ Classifier Health: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Test weight adjustment
        weight_success = classifier.adjust_method_weights(performance_based=False)
        print(f"✅ Weight Adjustment: {'Success' if weight_success else 'Failed'}")
        
        print("✅ EnsembleVotingClassifier test completed successfully")
        
    except Exception as e:
        print(f"❌ EnsembleVotingClassifier test failed: {e}")