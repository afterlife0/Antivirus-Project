"""
Advanced Multi-Algorithm Antivirus Software
==========================================
SVM Detector - Support Vector Machine Malware Detection

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.core.model_manager (ModelManager)
- src.detection.feature_extractor (FeatureExtractor)
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.detection.ml_detector (MLEnsembleDetector)
- src.detection.ensemble.voting_classifier (EnsembleVotingClassifier)
- src.detection.classification_engine (ClassificationEngine)

Integration Points:
- Loads trained SVM model with feature scaling from ModelManager
- Uses FeatureExtractor for file feature extraction
- Performs malware classification with SVM-specific preprocessing
- Provides prediction results to ensemble voting system
- Supports model retraining and updates
- Handles feature scaling and normalization (critical for SVM)
- Provides decision function scores for confidence calculation
- Supports batch prediction for multiple files

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: SVMDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access SVMDetector functionality
□ SVM model loading implemented
□ Feature extraction integration working
□ Malware classification with confidence scoring
□ Ensemble integration functional
"""

import os
import sys
import logging
import pickle
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
import json
import joblib
from datetime import datetime
import time
import warnings

# ML/Scientific imports
try:
    from sklearn.svm import SVC
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.preprocessing import RobustScaler
    import pandas as pd
    
    # Suppress sklearn warnings for cleaner output
    warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')
    
except ImportError as e:
    logging.error(f"Required ML libraries not installed: {e}")
    raise ImportError("Please install scikit-learn and pandas: pip install scikit-learn pandas")

# Project Dependencies
from src.core.model_manager import ModelManager
from src.detection.feature_extractor import FeatureExtractor
from src.utils.encoding_utils import EncodingHandler


class SVMDetector:
    """
    Support Vector Machine-based malware detection system.
    
    Implements machine learning-based malware detection using SVM algorithm
    with ensemble capabilities and confidence scoring.
    
    Features:
    - Trained SVM model loading and management
    - Feature scaling and normalization (critical for SVM performance)
    - Multi-class malware classification
    - Decision function-based confidence scoring
    - Probability calibration for better confidence estimates
    - Batch processing capabilities
    - Model performance monitoring
    - Integration with ensemble voting system
    """
    
    def __init__(self, model_manager: ModelManager, feature_extractor: FeatureExtractor):
        """
        Initialize SVM detector.
        
        Args:
            model_manager: Model management system
            feature_extractor: Feature extraction engine
        """
        self.model_manager = model_manager
        self.feature_extractor = feature_extractor
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("SVMDetector")
        
        # Model components
        self.model = None
        self.scaler = None
        self.calibrated_model = None  # For probability calibration
        self.model_config = None
        self.feature_names = None
        self.class_names = ["benign", "malware", "ransomware", "trojan", "spyware", "adware"]
        
        # Performance tracking
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.model_accuracy = 0.0
        self.last_updated = None
        
        # Model configuration
        self.model_name = "svm"
        self.model_version = "1.0.0"
        self.confidence_threshold = 0.5
        self.decision_threshold = 0.0  # SVM decision function threshold
        self.use_probability = True  # Use probability estimates
        
        # SVM-specific configuration
        self.kernel_type = "rbf"
        self.gamma = "scale"
        self.C = 1.0
        self.class_weight = "balanced"
        
        # Initialize model
        self._initialize_model()
        
        self.logger.info(f"SVMDetector initialized - Model: {self.model_name} v{self.model_version}")
    
    def _initialize_model(self) -> bool:
        """Initialize the SVM model and components."""
        try:
            self.logger.info("Initializing SVM model...")
            
            # Load model configuration
            config_loaded = self._load_model_config()
            if not config_loaded:
                self.logger.warning("Failed to load model configuration, using defaults")
                self._create_default_config()
            
            # Load trained model
            model_loaded = self._load_trained_model()
            if not model_loaded:
                self.logger.warning("Failed to load trained model, creating default model")
                self._create_default_model()
            
            # Load feature scaler (CRITICAL for SVM)
            scaler_loaded = self._load_feature_scaler()
            if not scaler_loaded:
                self.logger.warning("Feature scaler not found, creating default scaler")
                self._create_default_scaler()
            
            # Load calibrated model for better probability estimates
            self._load_calibrated_model()
            
            # Validate model compatibility
            if not self._validate_model_compatibility():
                self.logger.error("Model compatibility validation failed")
                return False
            
            self.logger.info("SVM model initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing SVM model: {e}")
            return False
    
    def _load_model_config(self) -> bool:
        """Load model configuration from file."""
        try:
            config_path = self.model_manager.get_model_config_path(self.model_name)
            if not config_path or not Path(config_path).exists():
                self.logger.warning(f"Model config not found: {config_path}")
                return False
            
            with open(config_path, 'r', encoding='utf-8') as f:
                self.model_config = json.load(f)
            
            # Extract configuration values
            self.model_version = self.model_config.get('version', self.model_version)
            self.confidence_threshold = self.model_config.get('confidence_threshold', self.confidence_threshold)
            self.class_names = self.model_config.get('class_names', self.class_names)
            
            # SVM-specific parameters
            hyperparams = self.model_config.get('hyperparameters', {})
            self.kernel_type = hyperparams.get('kernel', self.kernel_type)
            self.gamma = hyperparams.get('gamma', self.gamma)
            self.C = hyperparams.get('C', self.C)
            self.class_weight = hyperparams.get('class_weight', self.class_weight)
            
            self.logger.info(f"Loaded SVM config: {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model config: {e}")
            return False
    
    def _create_default_config(self) -> None:
        """Create default model configuration."""
        self.model_config = {
            'name': self.model_name,
            'version': self.model_version,
            'algorithm': 'Support Vector Machine',
            'confidence_threshold': self.confidence_threshold,
            'class_names': self.class_names,
            'feature_count': 714,  # **CORRECTED**: Your trained models use 714 features
            'hyperparameters': {
                'kernel': self.kernel_type,
                'gamma': self.gamma,
                'C': self.C,
                'class_weight': self.class_weight,
                'probability': True,  # Enable probability estimates
                'random_state': 42
            },
            'scaling': {
                'method': 'RobustScaler',  # **CORRECTED**: Your training uses RobustScaler
                'quantile_range': [25.0, 75.0],  # **CORRECTED**: 25th to 75th percentile
                'centering': 'median',  # **CORRECTED**: Uses median instead of mean
                'unit_variance': False  # **CORRECTED**: Uses IQR instead of std dev
            },
            'created_date': datetime.now().isoformat(),
            'training_accuracy': 0.0,
            'validation_accuracy': 0.0
        }
        
        self.logger.info("Created default SVM configuration with RobustScaler")

    def _load_trained_model(self) -> bool:
        """Load the trained SVM model."""
        try:
            model_path = self.model_manager.get_model_path(self.model_name)
            if not model_path or not Path(model_path).exists():
                self.logger.warning(f"Trained model not found: {model_path}")
                return False
            
            # Load model using joblib (recommended for scikit-learn models)
            self.model = joblib.load(model_path)
            
            # Validate model type
            if not isinstance(self.model, (SVC, CalibratedClassifierCV)):
                self.logger.error(f"Invalid model type: {type(self.model)}")
                return False
            
            # Extract model information
            if hasattr(self.model, 'classes_'):
                self.class_names = list(self.model.classes_)
            elif hasattr(self.model, 'base_estimator') and hasattr(self.model.base_estimator, 'classes_'):
                self.class_names = list(self.model.base_estimator.classes_)
            
            self.logger.info(f"Loaded trained SVM model from: {model_path}")
            self.logger.info(f"Model type: {type(self.model).__name__}")
            self.logger.info(f"Model classes: {len(self.class_names)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading trained model: {e}")
            return False
    
    def _create_default_model(self) -> None:
        """Create a default SVM model for testing."""
        try:
            # Create default model with hyperparameters from config
            hyperparams = self.model_config.get('hyperparameters', {})
            
            self.model = SVC(
                kernel=hyperparams.get('kernel', 'rbf'),
                gamma=hyperparams.get('gamma', 'scale'),
                C=hyperparams.get('C', 1.0),
                class_weight=hyperparams.get('class_weight', 'balanced'),
                probability=hyperparams.get('probability', True),
                random_state=hyperparams.get('random_state', 42)
            )
            
            # Create dummy training data for initialization
            n_features = self.model_config.get('feature_count', 714)  # **CORRECTED**
            X_dummy = np.random.rand(200, n_features)  # More samples for SVM
            y_dummy = np.random.randint(0, len(self.class_names), 200)
            
            # Fit model with dummy data
            self.model.fit(X_dummy, y_dummy)
            
            self.logger.warning("Created default SVM model with dummy data")
            self.logger.warning("Model should be replaced with properly trained model")
            
        except Exception as e:
            self.logger.error(f"Error creating default model: {e}")
            self.model = None
    
    def _load_feature_scaler(self) -> bool:
        """Load feature scaler (CRITICAL for SVM performance)."""
        try:
            scaler_path = self.model_manager.get_model_path(f"{self.model_name}_scaler")
            if not scaler_path or not Path(scaler_path).exists():
                self.logger.warning("Feature scaler not found")
                return False
            
            self.scaler = joblib.load(scaler_path)
            self.logger.info(f"Loaded feature scaler from: {scaler_path}")
            self.logger.info(f"Scaler type: {type(self.scaler).__name__}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading feature scaler: {e}")
            return False
    
    def _create_default_scaler(self) -> None:
        """Create default feature scaler for SVM."""
        try:
            # **CORRECTED**: Use RobustScaler to match training data preprocessing
            scaling_config = self.model_config.get('scaling', {})
            scaling_method = scaling_config.get('method', 'RobustScaler')
            
            if scaling_method == 'RobustScaler':
                quantile_range = scaling_config.get('quantile_range', [25.0, 75.0])
                self.scaler = RobustScaler(quantile_range=tuple(quantile_range))
                self.logger.info(f"Using RobustScaler with quantile range: {quantile_range}")
            elif scaling_method == 'MinMaxScaler':
                feature_range = scaling_config.get('feature_range', (0, 1))
                self.scaler = MinMaxScaler(feature_range=feature_range)
            else:
                # Fallback to StandardScaler
                self.scaler = StandardScaler()
                self.logger.warning("Fallback to StandardScaler - may cause performance degradation")
            
            # Create dummy data to fit scaler
            n_features = self.model_config.get('feature_count', 714)
            X_dummy = np.random.rand(100, n_features)
            
            # Fit scaler with dummy data
            self.scaler.fit(X_dummy)
            
            self.logger.warning(f"Created default {scaling_method} with dummy data")
            self.logger.warning("Scaler should be replaced with properly fitted scaler from training")
            
        except Exception as e:
            self.logger.error(f"Error creating default scaler: {e}")
            self.scaler = None
    
    def _load_calibrated_model(self) -> bool:
        """Load calibrated model for better probability estimates."""
        try:
            calibrated_path = self.model_manager.get_model_path(f"{self.model_name}_calibrated")
            if not calibrated_path or not Path(calibrated_path).exists():
                self.logger.debug("Calibrated model not found, using base model probabilities")
                return False
            
            self.calibrated_model = joblib.load(calibrated_path)
            self.logger.info(f"Loaded calibrated SVM model from: {calibrated_path}")
            return True
            
        except Exception as e:
            self.logger.debug(f"Error loading calibrated model: {e}")
            return False
    
    def _validate_model_compatibility(self) -> bool:
        """Validate model compatibility with feature extractor."""
        try:
            if not self.model:
                return False
            
            # Check feature count compatibility
            expected_features = self.feature_extractor.get_feature_count()
            
            # Get model feature count (handle different model types)
            if hasattr(self.model, 'n_features_in_'):
                model_features = self.model.n_features_in_
            elif hasattr(self.model, 'base_estimator') and hasattr(self.model.base_estimator, 'n_features_in_'):
                model_features = self.model.base_estimator.n_features_in_
            else:
                self.logger.warning("Cannot determine model feature count")
                model_features = expected_features  # Assume compatibility
            
            if expected_features != model_features:
                self.logger.error(f"Feature count mismatch: expected {expected_features}, model has {model_features}")
                return False
            
            # Check scaler compatibility
            if self.scaler:
                if hasattr(self.scaler, 'n_features_in_'):
                    scaler_features = self.scaler.n_features_in_
                    if expected_features != scaler_features:
                        self.logger.error(f"Scaler feature count mismatch: expected {expected_features}, scaler has {scaler_features}")
                        return False
            
            # Check class compatibility
            if len(self.class_names) == 0:
                self.logger.error("No class names defined")
                return False
            
            self.logger.info(f"Model compatibility validated: {model_features} features, {len(self.class_names)} classes")
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating model compatibility: {e}")
            return False
    
    def predict_file(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """
        Predict malware classification for a single file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Prediction result dictionary or None if prediction fails
        """
        try:
            if not self.model:
                self.logger.error("Model not loaded")
                return None
            
            start_time = time.time()
            
            # Extract features from file
            features = self.feature_extractor.extract_features(file_path)
            if not features:
                self.logger.error(f"Failed to extract features from: {file_path}")
                return None
            
            # Validate feature vector
            if not self.feature_extractor.validate_feature_vector(features):
                self.logger.error(f"Invalid feature vector for: {file_path}")
                return None
            
            # Convert features to numpy array
            feature_vector = self._prepare_feature_vector(features)
            if feature_vector is None:
                return None
            
            # Make prediction
            prediction_result = self._predict_features(feature_vector)
            if not prediction_result:
                return None
            
            # Add file information
            prediction_result['file_path'] = str(file_path)
            prediction_result['file_name'] = Path(file_path).name
            prediction_result['model_name'] = self.model_name
            prediction_result['model_version'] = self.model_version
            
            # Update performance tracking
            prediction_time = time.time() - start_time
            self._update_performance_metrics(prediction_time)
            
            prediction_result['prediction_time'] = prediction_time
            
            self.logger.info(f"Prediction completed for {Path(file_path).name}: {prediction_result['predicted_class']} ({prediction_result['confidence']:.3f})")
            
            return prediction_result
            
        except Exception as e:
            self.logger.error(f"Error predicting file {file_path}: {e}")
            return None
    
    def predict_batch(self, file_paths: List[Union[str, Path]]) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Predict malware classification for multiple files.
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            Dictionary mapping file paths to prediction results
        """
        try:
            if not self.model:
                self.logger.error("Model not loaded")
                return {}
            
            results = {}
            
            self.logger.info(f"Starting batch prediction for {len(file_paths)} files")
            
            for i, file_path in enumerate(file_paths):
                try:
                    result = self.predict_file(file_path)
                    results[str(file_path)] = result
                    
                    # Log progress
                    if (i + 1) % 10 == 0:
                        self.logger.info(f"Processed {i + 1}/{len(file_paths)} files")
                        
                except Exception as file_error:
                    self.logger.error(f"Error processing file {file_path}: {file_error}")
                    results[str(file_path)] = None
            
            successful_predictions = sum(1 for v in results.values() if v is not None)
            self.logger.info(f"Batch prediction completed: {successful_predictions}/{len(file_paths)} successful")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in batch prediction: {e}")
            return {}
    
    def _prepare_feature_vector(self, features: Dict[str, float]) -> Optional[np.ndarray]:
        """Prepare feature vector for model prediction."""
        try:
            # Get expected feature names
            expected_features = self.feature_extractor.get_feature_names()
            
            # Create feature vector in correct order
            feature_vector = np.array([features[feature_name] for feature_name in expected_features])
            
            # Reshape for single prediction
            feature_vector = feature_vector.reshape(1, -1)
            
            # Apply feature scaling (CRITICAL for SVM)
            if self.scaler:
                feature_vector = self.scaler.transform(feature_vector)
            else:
                self.logger.warning("No feature scaler available - SVM performance may be poor")
            
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preparing feature vector: {e}")
            return None
    
    def _predict_features(self, feature_vector: np.ndarray) -> Optional[Dict[str, Any]]:
        """Make prediction using prepared feature vector."""
        try:
            # Choose model for prediction (calibrated if available)
            prediction_model = self.calibrated_model if self.calibrated_model else self.model
            
            # Get prediction
            prediction = prediction_model.predict(feature_vector)
            
            # Extract results
            predicted_class_idx = prediction[0]
            predicted_class = self.class_names[predicted_class_idx]
            
            # Get probabilities (if available)
            class_probabilities = {}
            confidence = 0.5  # Default confidence
            
            if hasattr(prediction_model, 'predict_proba'):
                try:
                    probabilities = prediction_model.predict_proba(feature_vector)
                    confidence = float(probabilities[0][predicted_class_idx])
                    
                    # Create class probability dictionary
                    class_probabilities = {
                        class_name: float(prob) 
                        for class_name, prob in zip(self.class_names, probabilities[0])
                    }
                except Exception as prob_error:
                    self.logger.debug(f"Error getting probabilities: {prob_error}")
            
            # Get decision function scores (SVM-specific)
            decision_scores = {}
            if hasattr(self.model, 'decision_function'):
                try:
                    if isinstance(self.model, SVC):
                        decision_values = self.model.decision_function(feature_vector)
                        if len(self.class_names) == 2:
                            # Binary classification
                            decision_scores = {
                                'decision_value': float(decision_values[0])
                            }
                        else:
                            # Multi-class classification
                            decision_scores = {
                                f'decision_{i}': float(val) 
                                for i, val in enumerate(decision_values[0])
                            }
                except Exception as decision_error:
                    self.logger.debug(f"Error getting decision scores: {decision_error}")
            
            # Determine if prediction is confident enough
            is_confident = confidence >= self.confidence_threshold
            
            # Calculate risk score (probability of being malicious)
            benign_prob = class_probabilities.get('benign', 0.5)
            risk_score = 1.0 - benign_prob
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'is_confident': is_confident,
                'class_probabilities': class_probabilities,
                'decision_scores': decision_scores,
                'prediction_method': 'svm',
                'threshold_used': self.confidence_threshold,
                'kernel_used': self.kernel_type
            }
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return None
    
    def get_support_vectors_info(self) -> Optional[Dict[str, Any]]:
        """
        Get support vector information from the SVM model.
        
        Returns:
            Dictionary with support vector statistics
        """
        try:
            if not self.model:
                return None
            
            # Get base SVM model (handle calibrated classifier)
            svm_model = self.model
            if isinstance(self.model, CalibratedClassifierCV):
                if hasattr(self.model, 'base_estimator'):
                    svm_model = self.model.base_estimator
                elif hasattr(self.model, 'calibrated_classifiers_'):
                    # Get first calibrated classifier's base estimator
                    svm_model = self.model.calibrated_classifiers_[0].base_estimator
            
            if not isinstance(svm_model, SVC):
                return None
            
            support_info = {
                'n_support_vectors': svm_model.n_support_.tolist() if hasattr(svm_model, 'n_support_') else [],
                'total_support_vectors': int(svm_model.support_vectors_.shape[0]) if hasattr(svm_model, 'support_vectors_') else 0,
                'kernel': svm_model.kernel,
                'gamma': svm_model.gamma,
                'C': svm_model.C,
                'class_weight': svm_model.class_weight
            }
            
            self.logger.info(f"Retrieved support vector info: {support_info['total_support_vectors']} support vectors")
            return support_info
            
        except Exception as e:
            self.logger.error(f"Error getting support vector info: {e}")
            return None
    
    def _update_performance_metrics(self, prediction_time: float) -> None:
        """Update performance tracking metrics."""
        try:
            self.prediction_count += 1
            self.total_prediction_time += prediction_time
            
            # Log performance periodically
            if self.prediction_count % 100 == 0:
                avg_time = self.total_prediction_time / self.prediction_count
                self.logger.info(f"Performance: {self.prediction_count} predictions, avg time: {avg_time:.3f}s")
                
        except Exception as e:
            self.logger.debug(f"Error updating performance metrics: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get comprehensive model information."""
        try:
            avg_prediction_time = (
                self.total_prediction_time / self.prediction_count 
                if self.prediction_count > 0 else 0.0
            )
            
            # Get model parameters
            model_params = {}
            if self.model:
                base_model = self.model
                if isinstance(self.model, CalibratedClassifierCV):
                    if hasattr(self.model, 'base_estimator'):
                        base_model = self.model.base_estimator
                    elif hasattr(self.model, 'calibrated_classifiers_'):
                        base_model = self.model.calibrated_classifiers_[0].base_estimator
                
                if isinstance(base_model, SVC):
                    model_params = {
                        'kernel': base_model.kernel,
                        'gamma': base_model.gamma,
                        'C': base_model.C,
                        'class_weight': base_model.class_weight,
                        'probability': base_model.probability
                    }
            
            model_info = {
                'name': self.model_name,
                'version': self.model_version,
                'algorithm': 'Support Vector Machine',
                'status': 'loaded' if self.model else 'not_loaded',
                'feature_count': self._get_model_feature_count(),
                'class_count': len(self.class_names),
                'class_names': self.class_names,
                'confidence_threshold': self.confidence_threshold,
                'has_scaler': self.scaler is not None,
                'has_calibrated_model': self.calibrated_model is not None,
                'scaler_type': type(self.scaler).__name__ if self.scaler else None,
                'performance': {
                    'prediction_count': self.prediction_count,
                    'total_prediction_time': self.total_prediction_time,
                    'average_prediction_time': avg_prediction_time
                },
                'model_parameters': model_params
            }
            
            # Add support vector info
            support_info = self.get_support_vectors_info()
            if support_info:
                model_info['support_vectors'] = support_info
            
            return model_info
            
        except Exception as e:
            self.logger.error(f"Error getting model info: {e}")
            return {'name': self.model_name, 'status': 'error', 'error': str(e)}
    
    def _get_model_feature_count(self) -> int:
        """Get the number of features the model expects."""
        try:
            if not self.model:
                return 0
            
            if hasattr(self.model, 'n_features_in_'):
                return self.model.n_features_in_
            elif hasattr(self.model, 'base_estimator') and hasattr(self.model.base_estimator, 'n_features_in_'):
                return self.model.base_estimator.n_features_in_
            else:
                return 0
                
        except Exception:
            return 0
    
    def reload_model(self) -> bool:
        """Reload the model from disk."""
        try:
            self.logger.info("Reloading SVM model...")
            
            # Reset model components
            self.model = None
            self.scaler = None
            self.calibrated_model = None
            self.model_config = None
            
            # Reinitialize
            success = self._initialize_model()
            
            if success:
                self.logger.info("Model reloaded successfully")
            else:
                self.logger.error("Failed to reload model")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error reloading model: {e}")
            return False
    
    def is_model_loaded(self) -> bool:
        """Check if model is properly loaded."""
        return self.model is not None
    
    def get_supported_file_types(self) -> List[str]:
        """Get list of supported file types for analysis."""
        return ['.exe', '.dll', '.sys', '.ocx', '.scr', '.com', '.pif', '.bat', '.cmd']
    
    def validate_file_for_analysis(self, file_path: Union[str, Path]) -> bool:
        """Validate if file can be analyzed by this detector."""
        try:
            file_path = Path(file_path)
            
            # Check file existence
            if not file_path.exists():
                return False
            
            # Check file extension
            if file_path.suffix.lower() not in self.get_supported_file_types():
                return False
            
            # Check file size (avoid very large files)
            file_size = file_path.stat().st_size
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                self.logger.warning(f"File too large for analysis: {file_size} bytes")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error validating file {file_path}: {e}")
            return False


# Utility function for easy model access
def create_svm_detector(model_manager: ModelManager, feature_extractor: FeatureExtractor) -> SVMDetector:
    """
    Convenience function to create an SVM detector.
    
    Args:
        model_manager: Model management system
        feature_extractor: Feature extraction engine
        
    Returns:
        Initialized SVMDetector instance
    """
    try:
        return SVMDetector(model_manager, feature_extractor)
    except Exception as e:
        logging.getLogger("SVMDetector").error(f"Error creating detector: {e}")
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
            return 714  # **CORRECTED**
        
        def get_feature_names(self):
            return [f"feature_{i}" for i in range(714)]  # **CORRECTED**
        
        def extract_features(self, file_path):
            return {f"feature_{i}": np.random.rand() for i in range(714)}  # **CORRECTED**
        
        def validate_feature_vector(self, features):
            return len(features) == 714  # **CORRECTED**
    
    print("Testing SVMDetector...")
    
    # Create mock dependencies
    mock_model_manager = MockModelManager()
    mock_feature_extractor = MockFeatureExtractor()
    
    # Create detector
    try:
        detector = SVMDetector(mock_model_manager, mock_feature_extractor)
        print(f"✅ SVMDetector created successfully")
        
        # Test model info
        model_info = detector.get_model_info()
        print(f"✅ Model Info: {model_info['name']} - Status: {model_info['status']}")
        print(f"   Scaler: {model_info['scaler_type']}")
        print(f"   Calibrated: {model_info['has_calibrated_model']}")
        
        # Test support vector info (if model loaded)
        if detector.is_model_loaded():
            support_info = detector.get_support_vectors_info()
            if support_info:
                print(f"✅ Support Vectors: {support_info['total_support_vectors']}")
                print(f"   Kernel: {support_info['kernel']}")
        
        print("✅ SVMDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ SVMDetector test failed: {e}")