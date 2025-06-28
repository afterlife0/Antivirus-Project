"""
Advanced Multi-Algorithm Antivirus Software
==========================================
ML Ensemble Detector - Multi-Algorithm Machine Learning Detection

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.detection.models.random_forest_detector (RandomForestDetector)
- src.detection.models.svm_detector (SVMDetector)
- src.detection.models.dnn_detector (DNNDetector)
- src.detection.models.xgboost_detector (XGBoostDetector)
- src.detection.models.lightgbm_detector (LightGBMDetector)
- src.core.model_manager (ModelManager)
- src.detection.feature_extractor (FeatureExtractor)
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.core.scanner_engine (ScannerEngine)
- src.detection.classification_engine (ClassificationEngine)

Integration Points:
- Coordinates all 5 ML detection models in ensemble
- Manages weighted voting across RandomForest, SVM, DNN, XGBoost, LightGBM
- Provides unified ML detection interface for scanner engine
- Handles model performance monitoring and health checks
- Implements fallback strategies when individual models fail
- Supports batch processing across all ensemble members
- Calculates ensemble confidence scores and risk assessments
- Manages feature extraction pipeline for all models
- Provides model-specific and ensemble-wide analytics
- Handles dynamic model weight adjustment based on performance

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: MLEnsembleDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access MLEnsembleDetector functionality
□ 5-model ensemble coordination implemented
□ Weighted voting system functional
□ Confidence calculation working
□ Batch processing supported
□ Performance monitoring integrated
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
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Project Dependencies
from src.detection.models.random_forest_detector import RandomForestDetector
from src.detection.models.svm_detector import SVMDetector
from src.detection.models.dnn_detector import DNNDetector
from src.detection.models.xgboost_detector import XGBoostDetector
from src.detection.models.lightgbm_detector import LightGBMDetector
from src.core.model_manager import ModelManager
from src.detection.feature_extractor import FeatureExtractor
from src.utils.encoding_utils import EncodingHandler


class MLEnsembleDetector:
    """
    Multi-Algorithm Machine Learning Ensemble Detector.
    
    Coordinates 5 trained ML models for comprehensive malware detection:
    - Random Forest (tree-based ensemble)
    - SVM (support vector machine)
    - DNN (deep neural network)
    - XGBoost (gradient boosting)
    - LightGBM (light gradient boosting)
    
    Features:
    - Weighted ensemble voting for enhanced accuracy
    - Confidence-based prediction aggregation
    - Performance monitoring and health checks
    - Batch processing optimization
    - Dynamic weight adjustment
    - Fallback detection strategies
    - Model-specific analytics
    - Real-time performance tracking
    """
    
    def __init__(self, model_manager: ModelManager, feature_extractor: FeatureExtractor):
        """
        Initialize ML Ensemble Detector.
        
        Args:
            model_manager: Model management system
            feature_extractor: Feature extraction engine
        """
        self.model_manager = model_manager
        self.feature_extractor = feature_extractor
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("MLEnsembleDetector")
        
        # Initialize individual detectors
        self.detectors = {}
        self.detector_weights = {}
        self.detector_performance = {}
        
        # Ensemble configuration
        self.ensemble_name = "ml_ensemble"
        self.ensemble_version = "1.0.0"
        self.confidence_threshold = 0.6
        self.minimum_detectors = 3  # Minimum detectors required for prediction
        
        # Class names (consistent across all models)
        self.class_names = ["benign", "malware", "ransomware", "trojan", "spyware", "adware"]
        
        # Voting strategies
        self.voting_strategies = {
            'hard': self._hard_voting,
            'soft': self._soft_voting,
            'weighted': self._weighted_voting,
            'confidence_weighted': self._confidence_weighted_voting
        }
        self.default_voting_strategy = 'confidence_weighted'
        
        # Performance tracking
        self.ensemble_predictions = 0
        self.successful_predictions = 0
        self.failed_predictions = 0
        self.total_prediction_time = 0.0
        self.last_health_check = None
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize ensemble
        self._initialize_ensemble()
        
        self.logger.info(f"MLEnsembleDetector initialized - {len(self.detectors)} models loaded")
    
    def _initialize_ensemble(self) -> bool:
        """Initialize all ML detectors in the ensemble."""
        try:
            self.logger.info("Initializing ML ensemble detectors...")
            
            # Initialize each detector
            detector_configs = [
                ('random_forest', RandomForestDetector, 0.20),  # 20% weight
                ('svm', SVMDetector, 0.25),                     # 25% weight
                ('dnn', DNNDetector, 0.20),                     # 20% weight
                ('xgboost', XGBoostDetector, 0.20),             # 20% weight
                ('lightgbm', LightGBMDetector, 0.15)            # 15% weight
            ]
            
            successful_detectors = 0
            
            for detector_name, detector_class, default_weight in detector_configs:
                try:
                    self.logger.info(f"Initializing {detector_name} detector...")
                    
                    # Create detector instance
                    detector = detector_class(self.model_manager, self.feature_extractor)
                    
                    # Verify detector is functional
                    if detector.is_model_loaded():
                        self.detectors[detector_name] = detector
                        self.detector_weights[detector_name] = default_weight
                        self.detector_performance[detector_name] = {
                            'predictions': 0,
                            'successful': 0,
                            'failed': 0,
                            'average_time': 0.0,
                            'average_confidence': 0.0,
                            'last_prediction': None,
                            'health_status': 'healthy'
                        }
                        successful_detectors += 1
                        self.logger.info(f"✅ {detector_name} detector initialized successfully")
                    else:
                        self.logger.warning(f"❌ {detector_name} detector failed to load model")
                        
                except Exception as e:
                    self.logger.error(f"❌ Error initializing {detector_name} detector: {e}")
            
            # Normalize weights if some detectors failed
            if successful_detectors > 0:
                self._normalize_weights()
                self.logger.info(f"Ensemble initialized: {successful_detectors}/5 detectors loaded")
                return True
            else:
                self.logger.error("No detectors loaded successfully")
                return False
                
        except Exception as e:
            self.logger.error(f"Error initializing ensemble: {e}")
            return False
    
    def _normalize_weights(self) -> None:
        """Normalize detector weights to sum to 1.0."""
        try:
            total_weight = sum(self.detector_weights.values())
            if total_weight > 0:
                for detector_name in self.detector_weights:
                    self.detector_weights[detector_name] /= total_weight
                
                self.logger.debug(f"Normalized weights: {self.detector_weights}")
            
        except Exception as e:
            self.logger.error(f"Error normalizing weights: {e}")
    
    def predict_file(self, file_path: Union[str, Path], 
                    voting_strategy: str = None) -> Optional[Dict[str, Any]]:
        """
        Predict malware classification for a single file using ensemble.
        
        Args:
            file_path: Path to the file to analyze
            voting_strategy: Voting strategy to use
            
        Returns:
            Ensemble prediction result or None if prediction fails
        """
        try:
            if not self.detectors:
                self.logger.error("No detectors available for prediction")
                return None
            
            start_time = time.time()
            voting_strategy = voting_strategy or self.default_voting_strategy
            
            self.logger.info(f"Starting ensemble prediction for: {Path(file_path).name}")
            
            # Get predictions from all available detectors
            detector_predictions = self._get_detector_predictions(file_path)
            
            if not detector_predictions:
                self.logger.error("No detector predictions available")
                return None
            
            # Check minimum detector requirement
            if len(detector_predictions) < self.minimum_detectors:
                self.logger.warning(f"Only {len(detector_predictions)} detectors available, minimum is {self.minimum_detectors}")
            
            # Apply voting strategy
            ensemble_result = self._apply_voting_strategy(detector_predictions, voting_strategy)
            if not ensemble_result:
                return None
            
            # Calculate ensemble metrics
            prediction_time = time.time() - start_time
            ensemble_confidence = self._calculate_ensemble_confidence(detector_predictions)
            consensus_level = self._calculate_consensus_level(detector_predictions)
            
            # Update performance tracking
            self._update_ensemble_performance(prediction_time, True)
            
            # Prepare final result
            final_result = {
                'file_path': str(file_path),
                'file_name': Path(file_path).name,
                'ensemble_prediction': ensemble_result['predicted_class'],
                'ensemble_confidence': ensemble_confidence,
                'consensus_level': consensus_level,
                'risk_score': ensemble_result.get('risk_score', 0.0),
                'voting_strategy': voting_strategy,
                'detectors_used': list(detector_predictions.keys()),
                'detector_count': len(detector_predictions),
                'individual_predictions': {
                    name: {
                        'predicted_class': pred['predicted_class'],
                        'confidence': pred['confidence'],
                        'risk_score': pred.get('risk_score', 0.0)
                    }
                    for name, pred in detector_predictions.items()
                },
                'detector_weights': self.detector_weights.copy(),
                'class_probabilities': ensemble_result.get('class_probabilities', {}),
                'prediction_time': prediction_time,
                'ensemble_method': 'ml_ensemble',
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info(f"Ensemble prediction completed: {final_result['ensemble_prediction']} "
                           f"(confidence: {ensemble_confidence:.3f}, consensus: {consensus_level:.3f})")
            
            return final_result
            
        except Exception as e:
            self.logger.error(f"Error in ensemble prediction for {file_path}: {e}")
            self._update_ensemble_performance(0.0, False)
            return None
    
    def predict_batch(self, file_paths: List[Union[str, Path]], 
                     voting_strategy: str = None,
                     max_workers: int = 4) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Predict malware classification for multiple files using ensemble.
        
        Args:
            file_paths: List of file paths to analyze
            voting_strategy: Voting strategy to use
            max_workers: Maximum number of worker threads
            
        Returns:
            Dictionary mapping file paths to prediction results
        """
        try:
            if not self.detectors:
                self.logger.error("No detectors available for batch prediction")
                return {}
            
            results = {}
            voting_strategy = voting_strategy or self.default_voting_strategy
            
            self.logger.info(f"Starting ensemble batch prediction for {len(file_paths)} files")
            
            # Use ThreadPoolExecutor for parallel processing
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit prediction tasks
                future_to_file = {
                    executor.submit(self.predict_file, file_path, voting_strategy): file_path 
                    for file_path in file_paths
                }
                
                # Collect results
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results[str(file_path)] = result
                    except Exception as file_error:
                        self.logger.error(f"Error predicting {file_path}: {file_error}")
                        results[str(file_path)] = None
            
            successful_predictions = sum(1 for v in results.values() if v is not None)
            self.logger.info(f"Batch prediction completed: {successful_predictions}/{len(file_paths)} successful")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in batch prediction: {e}")
            return {}
    
    def _get_detector_predictions(self, file_path: Union[str, Path]) -> Dict[str, Dict[str, Any]]:
        """Get predictions from all available detectors."""
        try:
            detector_predictions = {}
            
            for detector_name, detector in self.detectors.items():
                try:
                    start_time = time.time()
                    prediction = detector.predict_file(file_path)
                    prediction_time = time.time() - start_time
                    
                    if prediction:
                        detector_predictions[detector_name] = prediction
                        
                        # Update detector performance
                        self._update_detector_performance(detector_name, prediction_time, 
                                                        prediction.get('confidence', 0.0), True)
                    else:
                        self.logger.warning(f"{detector_name} failed to predict {Path(file_path).name}")
                        self._update_detector_performance(detector_name, 0.0, 0.0, False)
                        
                except Exception as detector_error:
                    self.logger.error(f"Error in {detector_name} prediction: {detector_error}")
                    self._update_detector_performance(detector_name, 0.0, 0.0, False)
            
            return detector_predictions
            
        except Exception as e:
            self.logger.error(f"Error getting detector predictions: {e}")
            return {}
    
    def _apply_voting_strategy(self, detector_predictions: Dict[str, Dict[str, Any]], 
                             strategy: str) -> Optional[Dict[str, Any]]:
        """Apply specified voting strategy to detector predictions."""
        try:
            if strategy not in self.voting_strategies:
                self.logger.error(f"Unknown voting strategy: {strategy}")
                strategy = self.default_voting_strategy
            
            voting_function = self.voting_strategies[strategy]
            return voting_function(detector_predictions)
            
        except Exception as e:
            self.logger.error(f"Error applying voting strategy: {e}")
            return None
    
    def _hard_voting(self, detector_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Hard voting: majority class wins."""
        try:
            # Count votes for each class
            class_votes = {}
            for prediction in detector_predictions.values():
                predicted_class = prediction['predicted_class']
                class_votes[predicted_class] = class_votes.get(predicted_class, 0) + 1
            
            # Find majority class
            majority_class = max(class_votes, key=class_votes.get)
            majority_count = class_votes[majority_class]
            
            # Calculate confidence as proportion of votes
            confidence = majority_count / len(detector_predictions)
            
            # Calculate risk score
            benign_votes = class_votes.get('benign', 0)
            risk_score = 1.0 - (benign_votes / len(detector_predictions))
            
            return {
                'predicted_class': majority_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'class_probabilities': {
                    class_name: count / len(detector_predictions)
                    for class_name, count in class_votes.items()
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error in hard voting: {e}")
            return None
    
    def _soft_voting(self, detector_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Soft voting: average class probabilities."""
        try:
            # Aggregate class probabilities
            aggregated_probs = {}
            
            for prediction in detector_predictions.values():
                class_probs = prediction.get('class_probabilities', {})
                if not class_probs:
                    # Fallback: use confidence for predicted class
                    predicted_class = prediction['predicted_class']
                    confidence = prediction['confidence']
                    class_probs = {predicted_class: confidence}
                    # Distribute remaining probability
                    remaining_prob = 1.0 - confidence
                    other_classes = [c for c in self.class_names if c != predicted_class]
                    for other_class in other_classes:
                        class_probs[other_class] = remaining_prob / len(other_classes)
                
                # Aggregate probabilities
                for class_name, prob in class_probs.items():
                    aggregated_probs[class_name] = aggregated_probs.get(class_name, 0.0) + prob
            
            # Average probabilities
            num_detectors = len(detector_predictions)
            for class_name in aggregated_probs:
                aggregated_probs[class_name] /= num_detectors
            
            # Find predicted class and confidence
            predicted_class = max(aggregated_probs, key=aggregated_probs.get)
            confidence = aggregated_probs[predicted_class]
            
            # Calculate risk score
            benign_prob = aggregated_probs.get('benign', 0.5)
            risk_score = 1.0 - benign_prob
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'class_probabilities': aggregated_probs
            }
            
        except Exception as e:
            self.logger.error(f"Error in soft voting: {e}")
            return None
    
    def _weighted_voting(self, detector_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Weighted voting: detector weights applied to probabilities."""
        try:
            # Aggregate weighted class probabilities
            weighted_probs = {}
            total_weight = 0.0
            
            for detector_name, prediction in detector_predictions.items():
                weight = self.detector_weights.get(detector_name, 1.0)
                total_weight += weight
                
                class_probs = prediction.get('class_probabilities', {})
                if not class_probs:
                    # Fallback: use confidence for predicted class
                    predicted_class = prediction['predicted_class']
                    confidence = prediction['confidence']
                    class_probs = {predicted_class: confidence}
                    # Distribute remaining probability
                    remaining_prob = 1.0 - confidence
                    other_classes = [c for c in self.class_names if c != predicted_class]
                    for other_class in other_classes:
                        class_probs[other_class] = remaining_prob / len(other_classes)
                
                # Apply weights
                for class_name, prob in class_probs.items():
                    weighted_probs[class_name] = weighted_probs.get(class_name, 0.0) + (prob * weight)
            
            # Normalize by total weight
            if total_weight > 0:
                for class_name in weighted_probs:
                    weighted_probs[class_name] /= total_weight
            
            # Find predicted class and confidence
            predicted_class = max(weighted_probs, key=weighted_probs.get)
            confidence = weighted_probs[predicted_class]
            
            # Calculate risk score
            benign_prob = weighted_probs.get('benign', 0.5)
            risk_score = 1.0 - benign_prob
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'class_probabilities': weighted_probs
            }
            
        except Exception as e:
            self.logger.error(f"Error in weighted voting: {e}")
            return None
    
    def _confidence_weighted_voting(self, detector_predictions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Confidence-weighted voting: higher confidence predictions get more weight."""
        try:
            # Aggregate confidence-weighted class probabilities
            weighted_probs = {}
            total_confidence_weight = 0.0
            
            for detector_name, prediction in detector_predictions.items():
                base_weight = self.detector_weights.get(detector_name, 1.0)
                confidence_weight = prediction.get('confidence', 0.5)
                combined_weight = base_weight * confidence_weight
                total_confidence_weight += combined_weight
                
                class_probs = prediction.get('class_probabilities', {})
                if not class_probs:
                    # Fallback: use confidence for predicted class
                    predicted_class = prediction['predicted_class']
                    confidence = prediction['confidence']
                    class_probs = {predicted_class: confidence}
                    # Distribute remaining probability
                    remaining_prob = 1.0 - confidence
                    other_classes = [c for c in self.class_names if c != predicted_class]
                    for other_class in other_classes:
                        class_probs[other_class] = remaining_prob / len(other_classes)
                
                # Apply combined weights
                for class_name, prob in class_probs.items():
                    weighted_probs[class_name] = weighted_probs.get(class_name, 0.0) + (prob * combined_weight)
            
            # Normalize by total confidence weight
            if total_confidence_weight > 0:
                for class_name in weighted_probs:
                    weighted_probs[class_name] /= total_confidence_weight
            
            # Find predicted class and confidence
            predicted_class = max(weighted_probs, key=weighted_probs.get)
            confidence = weighted_probs[predicted_class]
            
            # Calculate risk score
            benign_prob = weighted_probs.get('benign', 0.5)
            risk_score = 1.0 - benign_prob
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'class_probabilities': weighted_probs
            }
            
        except Exception as e:
            self.logger.error(f"Error in confidence-weighted voting: {e}")
            return None
    
    def _calculate_ensemble_confidence(self, detector_predictions: Dict[str, Dict[str, Any]]) -> float:
        """Calculate overall ensemble confidence."""
        try:
            if not detector_predictions:
                return 0.0
            
            # Calculate average confidence weighted by detector weights
            total_weighted_confidence = 0.0
            total_weight = 0.0
            
            for detector_name, prediction in detector_predictions.items():
                weight = self.detector_weights.get(detector_name, 1.0)
                confidence = prediction.get('confidence', 0.0)
                
                total_weighted_confidence += confidence * weight
                total_weight += weight
            
            if total_weight > 0:
                return total_weighted_confidence / total_weight
            else:
                return 0.0
                
        except Exception as e:
            self.logger.error(f"Error calculating ensemble confidence: {e}")
            return 0.0
    
    def _calculate_consensus_level(self, detector_predictions: Dict[str, Dict[str, Any]]) -> float:
        """Calculate consensus level among detectors."""
        try:
            if len(detector_predictions) <= 1:
                return 1.0
            
            # Count predictions for each class
            class_counts = {}
            for prediction in detector_predictions.values():
                predicted_class = prediction['predicted_class']
                class_counts[predicted_class] = class_counts.get(predicted_class, 0) + 1
            
            # Calculate consensus as proportion of majority
            majority_count = max(class_counts.values())
            consensus_level = majority_count / len(detector_predictions)
            
            return consensus_level
            
        except Exception as e:
            self.logger.error(f"Error calculating consensus level: {e}")
            return 0.0
    
    def _update_detector_performance(self, detector_name: str, prediction_time: float,
                                   confidence: float, success: bool) -> None:
        """Update performance metrics for a specific detector."""
        try:
            with self._lock:
                if detector_name not in self.detector_performance:
                    return
                
                perf = self.detector_performance[detector_name]
                
                # Update counts
                perf['predictions'] += 1
                if success:
                    perf['successful'] += 1
                else:
                    perf['failed'] += 1
                
                # Update averages
                if success:
                    # Update average time
                    total_time = perf['average_time'] * (perf['successful'] - 1) + prediction_time
                    perf['average_time'] = total_time / perf['successful']
                    
                    # Update average confidence
                    total_confidence = perf['average_confidence'] * (perf['successful'] - 1) + confidence
                    perf['average_confidence'] = total_confidence / perf['successful']
                
                # Update health status
                success_rate = perf['successful'] / perf['predictions']
                if success_rate >= 0.8:
                    perf['health_status'] = 'healthy'
                elif success_rate >= 0.5:
                    perf['health_status'] = 'degraded'
                else:
                    perf['health_status'] = 'unhealthy'
                
                perf['last_prediction'] = datetime.now().isoformat()
                
        except Exception as e:
            self.logger.error(f"Error updating detector performance: {e}")
    
    def _update_ensemble_performance(self, prediction_time: float, success: bool) -> None:
        """Update ensemble performance metrics."""
        try:
            with self._lock:
                self.ensemble_predictions += 1
                
                if success:
                    self.successful_predictions += 1
                    self.total_prediction_time += prediction_time
                else:
                    self.failed_predictions += 1
                
        except Exception as e:
            self.logger.error(f"Error updating ensemble performance: {e}")
    
    def get_ensemble_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of the ensemble."""
        try:
            # Calculate ensemble metrics
            total_predictions = self.ensemble_predictions
            success_rate = self.successful_predictions / total_predictions if total_predictions > 0 else 0.0
            average_prediction_time = (self.total_prediction_time / self.successful_predictions 
                                     if self.successful_predictions > 0 else 0.0)
            
            # Determine overall health
            if success_rate >= 0.9 and len(self.detectors) >= 4:
                overall_health = 'excellent'
            elif success_rate >= 0.8 and len(self.detectors) >= 3:
                overall_health = 'good'
            elif success_rate >= 0.6 and len(self.detectors) >= 2:
                overall_health = 'fair'
            else:
                overall_health = 'poor'
            
            return {
                'overall_health': overall_health,
                'total_detectors': len(self.detectors),
                'active_detectors': [name for name, perf in self.detector_performance.items() 
                                   if perf['health_status'] in ['healthy', 'degraded']],
                'ensemble_metrics': {
                    'total_predictions': total_predictions,
                    'successful_predictions': self.successful_predictions,
                    'failed_predictions': self.failed_predictions,
                    'success_rate': success_rate,
                    'average_prediction_time': average_prediction_time
                },
                'detector_performance': self.detector_performance.copy(),
                'detector_weights': self.detector_weights.copy(),
                'last_health_check': datetime.now().isoformat(),
                'minimum_detectors': self.minimum_detectors,
                'voting_strategy': self.default_voting_strategy
            }
            
        except Exception as e:
            self.logger.error(f"Error getting health status: {e}")
            return {'overall_health': 'error', 'error': str(e)}
    
    def adjust_detector_weights(self, performance_based: bool = True) -> bool:
        """Adjust detector weights based on performance."""
        try:
            if not performance_based:
                return True
            
            with self._lock:
                # Calculate new weights based on success rate and confidence
                new_weights = {}
                total_score = 0.0
                
                for detector_name, perf in self.detector_performance.items():
                    if perf['predictions'] > 0:
                        success_rate = perf['successful'] / perf['predictions']
                        avg_confidence = perf['average_confidence']
                        
                        # Combined score: success rate and confidence
                        score = (success_rate * 0.7) + (avg_confidence * 0.3)
                        new_weights[detector_name] = score
                        total_score += score
                    else:
                        new_weights[detector_name] = 0.1  # Minimal weight for unused detectors
                        total_score += 0.1
                
                # Normalize weights
                if total_score > 0:
                    for detector_name in new_weights:
                        self.detector_weights[detector_name] = new_weights[detector_name] / total_score
                
                self.logger.info(f"Adjusted detector weights: {self.detector_weights}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error adjusting detector weights: {e}")
            return False
    
    def get_detector_status(self, detector_name: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific detector."""
        try:
            if detector_name not in self.detectors:
                return None
            
            detector = self.detectors[detector_name]
            performance = self.detector_performance.get(detector_name, {})
            
            return {
                'name': detector_name,
                'loaded': detector.is_model_loaded(),
                'weight': self.detector_weights.get(detector_name, 0.0),
                'performance': performance,
                'model_info': detector.get_model_info() if hasattr(detector, 'get_model_info') else {}
            }
            
        except Exception as e:
            self.logger.error(f"Error getting detector status: {e}")
            return None
    
    def reload_detector(self, detector_name: str) -> bool:
        """Reload a specific detector."""
        try:
            if detector_name not in self.detectors:
                self.logger.error(f"Detector not found: {detector_name}")
                return False
            
            detector = self.detectors[detector_name]
            
            # Attempt to reload
            if hasattr(detector, 'reload_model'):
                success = detector.reload_model()
                if success:
                    # Reset performance metrics
                    self.detector_performance[detector_name] = {
                        'predictions': 0,
                        'successful': 0,
                        'failed': 0,
                        'average_time': 0.0,
                        'average_confidence': 0.0,
                        'last_prediction': None,
                        'health_status': 'healthy'
                    }
                    self.logger.info(f"Successfully reloaded {detector_name} detector")
                    return True
                else:
                    self.logger.error(f"Failed to reload {detector_name} detector")
                    return False
            else:
                self.logger.warning(f"Detector {detector_name} does not support reloading")
                return False
                
        except Exception as e:
            self.logger.error(f"Error reloading detector {detector_name}: {e}")
            return False
    
    def is_ensemble_healthy(self) -> bool:
        """Check if ensemble is healthy enough for predictions."""
        try:
            healthy_detectors = sum(1 for perf in self.detector_performance.values() 
                                  if perf['health_status'] in ['healthy', 'degraded'])
            
            return healthy_detectors >= self.minimum_detectors
            
        except Exception as e:
            self.logger.error(f"Error checking ensemble health: {e}")
            return False
    
    def get_supported_voting_strategies(self) -> List[str]:
        """Get list of supported voting strategies."""
        return list(self.voting_strategies.keys())
    
    def set_voting_strategy(self, strategy: str) -> bool:
        """Set default voting strategy."""
        try:
            if strategy in self.voting_strategies:
                self.default_voting_strategy = strategy
                self.logger.info(f"Set default voting strategy to: {strategy}")
                return True
            else:
                self.logger.error(f"Unknown voting strategy: {strategy}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting voting strategy: {e}")
            return False


# Utility function for easy ensemble access
def create_ml_ensemble_detector(model_manager: ModelManager, 
                              feature_extractor: FeatureExtractor) -> MLEnsembleDetector:
    """
    Convenience function to create an ML ensemble detector.
    
    Args:
        model_manager: Model management system
        feature_extractor: Feature extraction engine
        
    Returns:
        Initialized MLEnsembleDetector instance
    """
    try:
        return MLEnsembleDetector(model_manager, feature_extractor)
    except Exception as e:
        logging.getLogger("MLEnsembleDetector").error(f"Error creating ensemble detector: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import sys
    
    # Mock dependencies for testing
    class MockModelManager:
        def get_model_path(self, model_name):
            return f"models/{model_name}/{model_name}_model.pkl"
        
        def get_model_config_path(self, model_name):
            return f"models/{model_name}/{model_name}_config.json"
    
    class MockFeatureExtractor:
        def get_feature_count(self):
            return 714
        
        def get_feature_names(self):
            return [f"feature_{i}" for i in range(714)]
        
        def extract_features(self, file_path):
            return {f"feature_{i}": np.random.rand() for i in range(714)}
        
        def validate_feature_vector(self, features):
            return len(features) == 714
    
    print("Testing MLEnsembleDetector...")
    
    # Create mock dependencies
    mock_model_manager = MockModelManager()
    mock_feature_extractor = MockFeatureExtractor()
    
    # Create ensemble detector
    try:
        ensemble = MLEnsembleDetector(mock_model_manager, mock_feature_extractor)
        print(f"✅ MLEnsembleDetector created successfully")
        
        # Test health status
        health_status = ensemble.get_ensemble_health_status()
        print(f"✅ Health Status: {health_status['overall_health']}")
        print(f"   Total Detectors: {health_status['total_detectors']}")
        print(f"   Active Detectors: {len(health_status['active_detectors'])}")
        
        # Test voting strategies
        strategies = ensemble.get_supported_voting_strategies()
        print(f"✅ Supported Voting Strategies: {strategies}")
        
        # Test detector status
        for detector_name in ensemble.detectors.keys():
            status = ensemble.get_detector_status(detector_name)
            if status:
                print(f"✅ {detector_name}: {'Loaded' if status['loaded'] else 'Not Loaded'} "
                      f"(weight: {status['weight']:.3f})")
        
        # Test ensemble health check
        is_healthy = ensemble.is_ensemble_healthy()
        print(f"✅ Ensemble Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        print("✅ MLEnsembleDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ MLEnsembleDetector test failed: {e}")