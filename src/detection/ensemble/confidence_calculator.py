"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Confidence Calculator - Detection Confidence Analysis

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.detection.ml_detector (MLEnsembleDetector)
- src.detection.classification_engine (ClassificationEngine)

Integration Points:
- Advanced confidence scoring algorithms
- Statistical confidence analysis
- Multi-model confidence aggregation
- Uncertainty quantification
- Confidence threshold optimization
- False positive/negative rate analysis
- Ensemble prediction confidence assessment
- Bayesian confidence estimation

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: ConfidenceCalculator
□ Dependencies properly imported with EXACT class names
□ All connected files can access ConfidenceCalculator functionality
□ Confidence algorithms implemented
□ Statistical analysis functional
□ Integration points established
"""

import os
import sys
import logging
import numpy as np
import statistics
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
import math

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler


class ConfidenceMethod(Enum):
    """Confidence calculation methods."""
    SIMPLE_AVERAGE = "simple_average"
    WEIGHTED_AVERAGE = "weighted_average"
    BAYESIAN = "bayesian"
    ENTROPY_BASED = "entropy_based"
    VARIANCE_BASED = "variance_based"
    CONSENSUS_BASED = "consensus_based"
    THRESHOLD_BASED = "threshold_based"


class ConfidenceLevel(Enum):
    """Confidence level classifications."""
    VERY_LOW = "very_low"      # 0.0 - 0.3
    LOW = "low"                # 0.3 - 0.5
    MEDIUM = "medium"          # 0.5 - 0.7
    HIGH = "high"              # 0.7 - 0.9
    VERY_HIGH = "very_high"    # 0.9 - 1.0


@dataclass
class ModelPrediction:
    """Container for individual model predictions."""
    model_name: str
    prediction: bool
    confidence: float
    probability_scores: Dict[str, float]
    processing_time: float
    model_weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfidenceAnalysis:
    """Container for confidence analysis results."""
    final_confidence: float
    confidence_level: ConfidenceLevel
    confidence_method: ConfidenceMethod
    individual_confidences: List[float]
    model_predictions: List[ModelPrediction]
    consensus_score: float
    uncertainty_score: float
    variance: float
    entropy: float
    weighted_average: float
    bayesian_confidence: float
    threshold_analysis: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ConfidenceCalculator:
    """
    Advanced confidence calculation system for ensemble detection.
    
    Provides sophisticated confidence analysis including:
    - Multiple confidence calculation methods
    - Statistical confidence analysis
    - Uncertainty quantification
    - Consensus-based scoring
    - Bayesian confidence estimation
    - Entropy-based uncertainty measurement
    - Variance analysis for prediction stability
    - Threshold optimization analysis
    """
    
    def __init__(self):
        """Initialize the confidence calculator."""
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("ConfidenceCalculator")
        
        # Configuration
        self.default_method = ConfidenceMethod.WEIGHTED_AVERAGE
        self.confidence_thresholds = {
            ConfidenceLevel.VERY_LOW: (0.0, 0.3),
            ConfidenceLevel.LOW: (0.3, 0.5),
            ConfidenceLevel.MEDIUM: (0.5, 0.7),
            ConfidenceLevel.HIGH: (0.7, 0.9),
            ConfidenceLevel.VERY_HIGH: (0.9, 1.0)
        }
        
        # Statistical parameters
        self.bayesian_prior = 0.5  # Prior probability
        self.entropy_base = 2      # Base for entropy calculation
        self.variance_weight = 0.1 # Weight for variance in confidence
        
        # Performance tracking
        self.calculation_stats = {
            'total_calculations': 0,
            'method_usage': {method.value: 0 for method in ConfidenceMethod},
            'average_processing_time': 0.0,
            'confidence_distribution': {level.value: 0 for level in ConfidenceLevel}
        }
        
        self.logger.info("ConfidenceCalculator initialized")
    
    def calculate_confidence(self, 
                           model_predictions: List[ModelPrediction],
                           method: Optional[ConfidenceMethod] = None) -> ConfidenceAnalysis:
        """
        Calculate confidence from multiple model predictions.
        
        Args:
            model_predictions: List of model predictions
            method: Confidence calculation method (optional)
            
        Returns:
            ConfidenceAnalysis with detailed confidence information
        """
        try:
            start_time = datetime.now()
            method = method or self.default_method
            
            if not model_predictions:
                return self._create_zero_confidence_analysis(method)
            
            # Extract individual confidences and weights
            confidences = [pred.confidence for pred in model_predictions]
            weights = [pred.model_weight for pred in model_predictions]
            predictions = [pred.prediction for pred in model_predictions]
            
            # Calculate various confidence metrics
            simple_avg = self._calculate_simple_average(confidences)
            weighted_avg = self._calculate_weighted_average(confidences, weights)
            consensus = self._calculate_consensus_score(predictions, confidences)
            uncertainty = self._calculate_uncertainty_score(confidences)
            variance = self._calculate_variance(confidences)
            entropy = self._calculate_entropy(confidences)
            bayesian_conf = self._calculate_bayesian_confidence(confidences, predictions)
            
            # Calculate final confidence based on method
            final_confidence = self._calculate_final_confidence(
                method, confidences, weights, predictions
            )
            
            # Determine confidence level
            confidence_level = self._determine_confidence_level(final_confidence)
            
            # Threshold analysis
            threshold_analysis = self._perform_threshold_analysis(
                model_predictions, final_confidence
            )
            
            # Create analysis result
            analysis = ConfidenceAnalysis(
                final_confidence=final_confidence,
                confidence_level=confidence_level,
                confidence_method=method,
                individual_confidences=confidences,
                model_predictions=model_predictions,
                consensus_score=consensus,
                uncertainty_score=uncertainty,
                variance=variance,
                entropy=entropy,
                weighted_average=weighted_avg,
                bayesian_confidence=bayesian_conf,
                threshold_analysis=threshold_analysis,
                metadata={
                    'calculation_time': (datetime.now() - start_time).total_seconds(),
                    'model_count': len(model_predictions),
                    'method_used': method.value
                }
            )
            
            # Update statistics
            self._update_statistics(method, confidence_level, analysis.metadata['calculation_time'])
            
            self.logger.debug(f"Confidence calculated: {final_confidence:.3f} ({confidence_level.value})")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error calculating confidence: {e}")
            return self._create_zero_confidence_analysis(method or self.default_method)
    
    def _calculate_simple_average(self, confidences: List[float]) -> float:
        """Calculate simple average of confidences."""
        return statistics.mean(confidences) if confidences else 0.0
    
    def _calculate_weighted_average(self, confidences: List[float], weights: List[float]) -> float:
        """Calculate weighted average of confidences."""
        if not confidences or not weights:
            return 0.0
        
        total_weight = sum(weights)
        if total_weight == 0:
            return self._calculate_simple_average(confidences)
        
        weighted_sum = sum(conf * weight for conf, weight in zip(confidences, weights))
        return weighted_sum / total_weight
    
    def _calculate_consensus_score(self, predictions: List[bool], confidences: List[float]) -> float:
        """Calculate consensus score based on prediction agreement."""
        if not predictions:
            return 0.0
        
        # Calculate agreement rate
        positive_count = sum(predictions)
        total_count = len(predictions)
        agreement_rate = max(positive_count, total_count - positive_count) / total_count
        
        # Weight by average confidence
        avg_confidence = statistics.mean(confidences) if confidences else 0.0
        
        return agreement_rate * avg_confidence
    
    def _calculate_uncertainty_score(self, confidences: List[float]) -> float:
        """Calculate uncertainty score (inverse of confidence stability)."""
        if len(confidences) < 2:
            return 0.0
        
        # Use standard deviation as uncertainty measure
        stdev = statistics.stdev(confidences)
        max_possible_stdev = 0.5  # Maximum possible standard deviation for [0,1] range
        
        return min(stdev / max_possible_stdev, 1.0)
    
    def _calculate_variance(self, confidences: List[float]) -> float:
        """Calculate variance of confidences."""
        if len(confidences) < 2:
            return 0.0
        
        return statistics.variance(confidences)
    
    def _calculate_entropy(self, confidences: List[float]) -> float:
        """Calculate entropy-based uncertainty measure."""
        if not confidences:
            return 0.0
        
        # Normalize confidences to probabilities
        total = sum(confidences)
        if total == 0:
            return 0.0
        
        probabilities = [conf / total for conf in confidences]
        
        # Calculate entropy
        entropy = 0.0
        for prob in probabilities:
            if prob > 0:
                entropy -= prob * math.log(prob, self.entropy_base)
        
        # Normalize to [0,1] range
        max_entropy = math.log(len(confidences), self.entropy_base)
        return entropy / max_entropy if max_entropy > 0 else 0.0
    
    def _calculate_bayesian_confidence(self, confidences: List[float], predictions: List[bool]) -> float:
        """Calculate Bayesian confidence estimate."""
        if not confidences or not predictions:
            return self.bayesian_prior
        
        # Simple Bayesian update
        positive_count = sum(predictions)
        total_count = len(predictions)
        
        # Beta distribution parameters (simplified)
        alpha = positive_count + 1
        beta = (total_count - positive_count) + 1
        
        # Beta distribution mean
        bayesian_mean = alpha / (alpha + beta)
        
        # Weight by average confidence
        avg_confidence = statistics.mean(confidences)
        
        return (bayesian_mean + avg_confidence) / 2
    
    def _calculate_final_confidence(self, 
                                  method: ConfidenceMethod,
                                  confidences: List[float],
                                  weights: List[float],
                                  predictions: List[bool]) -> float:
        """Calculate final confidence based on specified method."""
        if method == ConfidenceMethod.SIMPLE_AVERAGE:
            return self._calculate_simple_average(confidences)
        
        elif method == ConfidenceMethod.WEIGHTED_AVERAGE:
            return self._calculate_weighted_average(confidences, weights)
        
        elif method == ConfidenceMethod.BAYESIAN:
            return self._calculate_bayesian_confidence(confidences, predictions)
        
        elif method == ConfidenceMethod.ENTROPY_BASED:
            entropy = self._calculate_entropy(confidences)
            avg_conf = self._calculate_simple_average(confidences)
            return avg_conf * (1 - entropy)  # Lower entropy = higher confidence
        
        elif method == ConfidenceMethod.VARIANCE_BASED:
            variance = self._calculate_variance(confidences)
            avg_conf = self._calculate_simple_average(confidences)
            return avg_conf * (1 - min(variance * self.variance_weight, 1.0))
        
        elif method == ConfidenceMethod.CONSENSUS_BASED:
            return self._calculate_consensus_score(predictions, confidences)
        
        elif method == ConfidenceMethod.THRESHOLD_BASED:
            # Use weighted average with threshold adjustment
            weighted_avg = self._calculate_weighted_average(confidences, weights)
            consensus = self._calculate_consensus_score(predictions, confidences)
            return (weighted_avg + consensus) / 2
        
        else:
            # Default to weighted average
            return self._calculate_weighted_average(confidences, weights)
    
    def _determine_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Determine confidence level from confidence score."""
        for level, (min_val, max_val) in self.confidence_thresholds.items():
            if min_val <= confidence < max_val:
                return level
        
        # Handle edge case for 1.0
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        
        return ConfidenceLevel.VERY_LOW
    
    def _perform_threshold_analysis(self, 
                                  model_predictions: List[ModelPrediction],
                                  final_confidence: float) -> Dict[str, Any]:
        """Perform threshold analysis for optimization."""
        try:
            confidences = [pred.confidence for pred in model_predictions]
            
            if not confidences:
                return {}
            
            # Calculate various threshold statistics
            min_conf = min(confidences)
            max_conf = max(confidences)
            median_conf = statistics.median(confidences)
            q1 = statistics.quantiles(confidences, n=4)[0] if len(confidences) >= 4 else min_conf
            q3 = statistics.quantiles(confidences, n=4)[2] if len(confidences) >= 4 else max_conf
            
            # Optimal threshold estimation (simplified)
            optimal_threshold = median_conf
            
            return {
                'min_confidence': min_conf,
                'max_confidence': max_conf,
                'median_confidence': median_conf,
                'q1_confidence': q1,
                'q3_confidence': q3,
                'optimal_threshold': optimal_threshold,
                'threshold_efficiency': final_confidence / optimal_threshold if optimal_threshold > 0 else 0,
                'confidence_range': max_conf - min_conf,
                'models_above_median': sum(1 for conf in confidences if conf >= median_conf)
            }
            
        except Exception as e:
            self.logger.error(f"Error in threshold analysis: {e}")
            return {}
    
    def _create_zero_confidence_analysis(self, method: ConfidenceMethod) -> ConfidenceAnalysis:
        """Create a zero-confidence analysis for error cases."""
        return ConfidenceAnalysis(
            final_confidence=0.0,
            confidence_level=ConfidenceLevel.VERY_LOW,
            confidence_method=method,
            individual_confidences=[],
            model_predictions=[],
            consensus_score=0.0,
            uncertainty_score=1.0,
            variance=0.0,
            entropy=0.0,
            weighted_average=0.0,
            bayesian_confidence=self.bayesian_prior,
            threshold_analysis={}
        )
    
    def _update_statistics(self, method: ConfidenceMethod, level: ConfidenceLevel, processing_time: float):
        """Update calculation statistics."""
        try:
            self.calculation_stats['total_calculations'] += 1
            self.calculation_stats['method_usage'][method.value] += 1
            self.calculation_stats['confidence_distribution'][level.value] += 1
            
            # Update average processing time
            total = self.calculation_stats['total_calculations']
            current_avg = self.calculation_stats['average_processing_time']
            self.calculation_stats['average_processing_time'] = (
                (current_avg * (total - 1) + processing_time) / total
            )
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get calculation statistics."""
        return self.calculation_stats.copy()
    
    def optimize_thresholds(self, 
                          historical_predictions: List[List[ModelPrediction]],
                          ground_truth: List[bool]) -> Dict[str, float]:
        """
        Optimize confidence thresholds based on historical data.
        
        Args:
            historical_predictions: Historical model predictions
            ground_truth: Actual results for optimization
            
        Returns:
            Dictionary of optimized thresholds
        """
        try:
            if len(historical_predictions) != len(ground_truth):
                raise ValueError("Predictions and ground truth length mismatch")
            
            # Calculate confidence for all historical predictions
            confidence_scores = []
            for predictions in historical_predictions:
                analysis = self.calculate_confidence(predictions)
                confidence_scores.append(analysis.final_confidence)
            
            # Find optimal thresholds (simplified approach)
            optimal_thresholds = {}
            
            for threshold in [0.1, 0.3, 0.5, 0.7, 0.9]:
                tp = fp = tn = fn = 0
                
                for conf, truth in zip(confidence_scores, ground_truth):
                    predicted = conf >= threshold
                    
                    if predicted and truth:
                        tp += 1
                    elif predicted and not truth:
                        fp += 1
                    elif not predicted and not truth:
                        tn += 1
                    else:
                        fn += 1
                
                # Calculate metrics
                precision = tp / (tp + fp) if (tp + fp) > 0 else 0
                recall = tp / (tp + fn) if (tp + fn) > 0 else 0
                f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                
                optimal_thresholds[f"threshold_{threshold}"] = {
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1_score
                }
            
            return optimal_thresholds
            
        except Exception as e:
            self.logger.error(f"Error optimizing thresholds: {e}")
            return {}
    
    def reset_statistics(self):
        """Reset calculation statistics."""
        self.calculation_stats = {
            'total_calculations': 0,
            'method_usage': {method.value: 0 for method in ConfidenceMethod},
            'average_processing_time': 0.0,
            'confidence_distribution': {level.value: 0 for level in ConfidenceLevel}
        }
        self.logger.info("Statistics reset")
