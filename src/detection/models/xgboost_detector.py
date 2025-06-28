"""
Advanced Multi-Algorithm Antivirus Software
==========================================
XGBoost Detector - Gradient Boosting Malware Detection

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
- Loads trained XGBoost model (gradient boosting trees)
- Uses FeatureExtractor for file feature extraction (714 features)
- Applies RobustScaler with (25.0, 75.0) quantile range for preprocessing
- Performs malware classification with gradient boosting
- Provides prediction results to ensemble voting system
- Supports feature importance analysis and ranking
- Implements SHAP values for model interpretability
- Supports batch prediction for multiple files
- Handles tree-based prediction with confidence scoring
- Provides model performance metrics and monitoring

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: XGBoostDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access XGBoostDetector functionality
□ XGBoost model loading implemented
□ Feature extraction integration working
□ RobustScaler integration with correct parameters
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
import time
import warnings
from datetime import datetime

# XGBoost imports
try:
    import xgboost as xgb
    from xgboost import XGBClassifier, DMatrix
    
    # Suppress XGBoost warnings for cleaner output
    warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')
    
except ImportError as e:
    logging.error(f"XGBoost not installed: {e}")
    raise ImportError("Please install XGBoost: pip install xgboost")

# Scientific computing imports
try:
    from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import pandas as pd
    import joblib
    
except ImportError as e:
    logging.error(f"Required ML libraries not installed: {e}")
    raise ImportError("Please install scikit-learn and pandas: pip install scikit-learn pandas")

# Optional SHAP for model interpretability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logging.warning("SHAP not installed - model interpretability features disabled")

# Project Dependencies
from src.core.model_manager import ModelManager
from src.detection.feature_extractor import FeatureExtractor
from src.utils.encoding_utils import EncodingHandler


class XGBoostDetector:
    """
    XGBoost-based malware detection system.
    
    Implements gradient boosting-based malware detection using XGBoost
    with ensemble capabilities and advanced tree-based techniques.
    
    Features:
    - Trained XGBoost model loading and management
    - Gradient boosting tree ensemble
    - Feature importance analysis and ranking
    - SHAP values for model interpretability (if available)
    - Multi-class malware classification
    - Confidence scoring with probability estimates
    - Batch processing capabilities
    - Model performance monitoring
    - Integration with ensemble voting system
    - Tree-based feature selection
    """
    
    def __init__(self, model_manager: ModelManager, feature_extractor: FeatureExtractor):
        """
        Initialize XGBoost detector.
        
        Args:
            model_manager: Model management system
            feature_extractor: Feature extraction engine
        """
        self.model_manager = model_manager
        self.feature_extractor = feature_extractor
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("XGBoostDetector")
        
        # Model components
        self.model = None
        self.scaler = None
        self.model_config = None
        self.feature_names = None
        self.class_names = ["benign", "malware", "ransomware", "trojan", "spyware", "adware"]
        
        # Performance tracking
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.model_accuracy = 0.0
        self.last_updated = None
        
        # Model configuration
        self.model_name = "xgboost"
        self.model_version = "1.0.0"
        self.confidence_threshold = 0.5
        
        # XGBoost-specific configuration
        self.n_estimators = 100
        self.max_depth = 6
        self.learning_rate = 0.1
        self.subsample = 0.8
        self.colsample_bytree = 0.8
        self.random_state = 42
        self.n_jobs = -1  # Use all available cores
        self.objective = 'multi:softprob'  # Multi-class probability output
        
        # Feature importance and interpretability
        self.feature_importances = None
        self.shap_explainer = None if not SHAP_AVAILABLE else None
        
        # Initialize model
        self._initialize_model()
        
        self.logger.info(f"XGBoostDetector initialized - Model: {self.model_name} v{self.model_version}")
        self.logger.info(f"SHAP interpretability: {'Available' if SHAP_AVAILABLE else 'Not available'}")
    
    def _initialize_model(self) -> bool:
        """Initialize the XGBoost model and components."""
        try:
            self.logger.info("Initializing XGBoost model...")
            
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
            
            # Load feature scaler
            scaler_loaded = self._load_feature_scaler()
            if not scaler_loaded:
                self.logger.warning("Feature scaler not found, creating default scaler")
                self._create_default_scaler()
            
            # Initialize SHAP explainer if available
            if SHAP_AVAILABLE and self.model:
                self._initialize_shap_explainer()
            
            # Validate model compatibility
            if not self._validate_model_compatibility():
                self.logger.error("Model compatibility validation failed")
                return False
            
            self.logger.info("XGBoost model initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing XGBoost model: {e}")
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
            
            # XGBoost-specific parameters
            hyperparams = self.model_config.get('hyperparameters', {})
            self.n_estimators = hyperparams.get('n_estimators', self.n_estimators)
            self.max_depth = hyperparams.get('max_depth', self.max_depth)
            self.learning_rate = hyperparams.get('learning_rate', self.learning_rate)
            self.subsample = hyperparams.get('subsample', self.subsample)
            self.colsample_bytree = hyperparams.get('colsample_bytree', self.colsample_bytree)
            self.random_state = hyperparams.get('random_state', self.random_state)
            self.n_jobs = hyperparams.get('n_jobs', self.n_jobs)
            self.objective = hyperparams.get('objective', self.objective)
            
            self.logger.info(f"Loaded XGBoost config: {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model config: {e}")
            return False
    
    def _create_default_config(self) -> None:
        """Create default model configuration."""
        self.model_config = {
            'name': self.model_name,
            'version': self.model_version,
            'algorithm': 'XGBoost',
            'confidence_threshold': self.confidence_threshold,
            'class_names': self.class_names,
            'feature_count': 714,  # CORRECTED: Your trained models use 714 features
            'hyperparameters': {
                'n_estimators': self.n_estimators,
                'max_depth': self.max_depth,
                'learning_rate': self.learning_rate,
                'subsample': self.subsample,
                'colsample_bytree': self.colsample_bytree,
                'random_state': self.random_state,
                'n_jobs': self.n_jobs,
                'objective': self.objective,
                'eval_metric': 'mlogloss',
                'tree_method': 'hist',  # Faster training
                'grow_policy': 'depthwise'
            },
            'scaling': {
                'method': 'RobustScaler',  # **CORRECTED**: Your training uses RobustScaler
                'quantile_range': [25.0, 75.0],  # **CORRECTED**: 25th to 75th percentile
                'centering': 'median',  # **CORRECTED**: Uses median instead of mean
                'unit_variance': False  # **CORRECTED**: Uses IQR instead of std dev
            },
            'feature_selection': {
                'use_feature_importance': True,
                'importance_threshold': 0.001,
                'max_features': None
            },
            'interpretability': {
                'use_shap': SHAP_AVAILABLE,
                'shap_sample_size': 100
            },
            'created_date': datetime.now().isoformat(),
            'training_accuracy': 0.0,
            'validation_accuracy': 0.0
        }
        
        self.logger.info("Created default XGBoost configuration with RobustScaler")
    
    def _load_trained_model(self) -> bool:
        """Load the trained XGBoost model."""
        try:
            model_path = self.model_manager.get_model_path(self.model_name)
            if not model_path or not Path(model_path).exists():
                self.logger.warning(f"Trained model not found: {model_path}")
                return False
            
            # Load XGBoost model using joblib or pickle
            self.model = joblib.load(model_path)
            
            # Validate loaded model
            if not hasattr(self.model, 'predict_proba'):
                self.logger.error("Loaded model does not support probability prediction")
                return False
            
            # Extract feature importance if available
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importances = self.model.feature_importances_
                self.logger.info("Feature importances loaded from model")
            
            # Get model parameters
            if hasattr(self.model, 'get_params'):
                model_params = self.model.get_params()
                self.logger.info(f"Model parameters: n_estimators={model_params.get('n_estimators', 'unknown')}")
            
            self.logger.info(f"Loaded trained XGBoost model from: {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading trained model: {e}")
            return False
    
    def _create_default_model(self) -> None:
        """Create a default XGBoost model for testing."""
        try:
            # Create default XGBoost classifier
            self.model = XGBClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=self.learning_rate,
                subsample=self.subsample,
                colsample_bytree=self.colsample_bytree,
                random_state=self.random_state,
                n_jobs=self.n_jobs,
                objective=self.objective,
                eval_metric='mlogloss',
                tree_method='hist'
            )
            
            # Create dummy training data for initialization
            n_features = self.model_config.get('feature_count', 714)
            X_dummy = np.random.rand(200, n_features)  # More samples for XGBoost
            y_dummy = np.random.randint(0, len(self.class_names), 200)
            
            # Fit model with dummy data
            self.model.fit(X_dummy, y_dummy)
            
            # Extract feature importance
            self.feature_importances = self.model.feature_importances_
            
            self.logger.warning("Created default XGBoost model with dummy data")
            self.logger.warning("Model should be replaced with properly trained model")
            self.logger.info(f"Default model: {self.n_estimators} estimators, max_depth={self.max_depth}")
            
        except Exception as e:
            self.logger.error(f"Error creating default model: {e}")
            self.model = None
    
    def _load_feature_scaler(self) -> bool:
        """Load feature scaler for preprocessing."""
        try:
            scaler_path = self.model_manager.get_model_path(f"{self.model_name}_scaler")
            if not scaler_path or not Path(scaler_path).exists():
                self.logger.warning("Feature scaler not found")
                return False
            
            # Load scaler using joblib
            self.scaler = joblib.load(scaler_path)
            
            self.logger.info(f"Loaded feature scaler from: {scaler_path}")
            self.logger.info(f"Scaler type: {type(self.scaler).__name__}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading feature scaler: {e}")
            return False
    
    def _create_default_scaler(self) -> None:
        """Create default feature scaler for XGBoost."""
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
    
    def _initialize_shap_explainer(self) -> None:
        """Initialize SHAP explainer for model interpretability."""
        try:
            if not SHAP_AVAILABLE or not self.model:
                return
            
            # Create a small sample for SHAP background
            n_features = self.model_config.get('feature_count', 714)
            shap_sample_size = self.model_config.get('interpretability', {}).get('shap_sample_size', 100)
            
            # Create background data for SHAP
            background_data = np.random.rand(shap_sample_size, n_features)
            
            # Initialize SHAP TreeExplainer for XGBoost
            self.shap_explainer = shap.TreeExplainer(self.model, background_data)
            
            self.logger.info(f"SHAP explainer initialized with {shap_sample_size} background samples")
            
        except Exception as e:
            self.logger.warning(f"Error initializing SHAP explainer: {e}")
            self.shap_explainer = None
    
    def _validate_model_compatibility(self) -> bool:
        """Validate model compatibility with feature extractor."""
        try:
            if not self.model:
                return False
            
            # Check feature count compatibility
            expected_features = self.feature_extractor.get_feature_count()
            
            # For XGBoost, check n_features_in_ if available
            if hasattr(self.model, 'n_features_in_'):
                model_features = self.model.n_features_in_
                if expected_features != model_features:
                    self.logger.error(f"Feature count mismatch: expected {expected_features}, model expects {model_features}")
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
            
            # For XGBoost, check classes_ if available
            if hasattr(self.model, 'classes_'):
                model_classes = len(self.model.classes_)
                if len(self.class_names) != model_classes:
                    self.logger.warning(f"Class count mismatch: config has {len(self.class_names)}, model has {model_classes}")
                    # Adjust class names to match model
                    self.class_names = [f"class_{i}" for i in range(model_classes)]
            
            self.logger.info(f"Model compatibility validated: {expected_features} features, {len(self.class_names)} classes")
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
            
            # Extract features for all files first
            all_features = []
            valid_files = []
            
            for file_path in file_paths:
                try:
                    features = self.feature_extractor.extract_features(file_path)
                    if features and self.feature_extractor.validate_feature_vector(features):
                        all_features.append(features)
                        valid_files.append(file_path)
                    else:
                        results[str(file_path)] = None
                except Exception as file_error:
                    self.logger.error(f"Error extracting features from {file_path}: {file_error}")
                    results[str(file_path)] = None
            
            if not all_features:
                self.logger.warning("No valid feature vectors extracted for batch prediction")
                return results
            
            # Prepare feature matrix for batch prediction
            feature_matrix = self._prepare_feature_matrix(all_features)
            if feature_matrix is None:
                self.logger.error("Failed to prepare feature matrix for batch prediction")
                return results
            
            # Perform batch prediction
            batch_predictions = self._predict_features_batch(feature_matrix)
            if batch_predictions is None:
                self.logger.error("Batch prediction failed")
                return results
            
            # Assign predictions to files
            for file_path, prediction in zip(valid_files, batch_predictions):
                if prediction:
                    prediction['file_path'] = str(file_path)
                    prediction['file_name'] = Path(file_path).name
                    prediction['model_name'] = self.model_name
                    prediction['model_version'] = self.model_version
                
                results[str(file_path)] = prediction
            
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
            
            # Apply feature scaling
            if self.scaler:
                feature_vector = self.scaler.transform(feature_vector)
            else:
                self.logger.warning("No feature scaler available - XGBoost performance may be suboptimal")
            
            # Ensure correct data type
            feature_vector = feature_vector.astype(np.float32)
            
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preparing feature vector: {e}")
            return None
    
    def _prepare_feature_matrix(self, all_features: List[Dict[str, float]]) -> Optional[np.ndarray]:
        """Prepare feature matrix for batch prediction."""
        try:
            # Get expected feature names
            expected_features = self.feature_extractor.get_feature_names()
            
            # Create feature matrix
            feature_matrix = np.zeros((len(all_features), len(expected_features)), dtype=np.float32)
            
            for i, features in enumerate(all_features):
                for j, feature_name in enumerate(expected_features):
                    feature_matrix[i, j] = features[feature_name]
            
            # Apply feature scaling
            if self.scaler:
                feature_matrix = self.scaler.transform(feature_matrix)
            else:
                self.logger.warning("No feature scaler available - XGBoost performance may be suboptimal")
            
            return feature_matrix
            
        except Exception as e:
            self.logger.error(f"Error preparing feature matrix: {e}")
            return None
    
    def _predict_features(self, feature_vector: np.ndarray) -> Optional[Dict[str, Any]]:
        """Make prediction using prepared feature vector."""
        try:
            # Get prediction probabilities
            probabilities = self.model.predict_proba(feature_vector)[0]
            
            # Get predicted class
            predicted_class_idx = np.argmax(probabilities)
            predicted_class = self.class_names[predicted_class_idx]
            confidence = float(probabilities[predicted_class_idx])
            
            # Create class probability dictionary
            class_probabilities = {
                class_name: float(prob) 
                for class_name, prob in zip(self.class_names, probabilities)
            }
            
            # Calculate risk score (probability of being malicious)
            benign_prob = class_probabilities.get('benign', 0.5)
            risk_score = 1.0 - benign_prob
            
            # Determine if prediction is confident enough
            is_confident = confidence >= self.confidence_threshold
            
            # Get feature importance for this prediction (top N features)
            feature_importance_info = self._get_prediction_feature_importance(feature_vector)
            
            # Get SHAP values if available
            shap_values = self._get_shap_values(feature_vector) if self.shap_explainer else None
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'is_confident': is_confident,
                'class_probabilities': class_probabilities,
                'feature_importance': feature_importance_info,
                'shap_values': shap_values,
                'prediction_method': 'xgboost',
                'threshold_used': self.confidence_threshold,
                'n_estimators': self.n_estimators
            }
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return None
    
    def _predict_features_batch(self, feature_matrix: np.ndarray) -> Optional[List[Dict[str, Any]]]:
        """Make batch predictions using prepared feature matrix."""
        try:
            # Get batch prediction probabilities
            batch_probabilities = self.model.predict_proba(feature_matrix)
            
            batch_results = []
            
            for i, probabilities in enumerate(batch_probabilities):
                # Get predicted class
                predicted_class_idx = np.argmax(probabilities)
                predicted_class = self.class_names[predicted_class_idx]
                confidence = float(probabilities[predicted_class_idx])
                
                # Create class probability dictionary
                class_probabilities = {
                    class_name: float(prob) 
                    for class_name, prob in zip(self.class_names, probabilities)
                }
                
                # Calculate risk score
                benign_prob = class_probabilities.get('benign', 0.5)
                risk_score = 1.0 - benign_prob
                
                # Determine confidence
                is_confident = confidence >= self.confidence_threshold
                
                # Get feature importance for this sample
                sample_vector = feature_matrix[i:i+1]
                feature_importance_info = self._get_prediction_feature_importance(sample_vector)
                
                batch_results.append({
                    'predicted_class': predicted_class,
                    'confidence': confidence,
                    'risk_score': risk_score,
                    'is_confident': is_confident,
                    'class_probabilities': class_probabilities,
                    'feature_importance': feature_importance_info,
                    'prediction_method': 'xgboost',
                    'threshold_used': self.confidence_threshold,
                    'n_estimators': self.n_estimators
                })
            
            return batch_results
            
        except Exception as e:
            self.logger.error(f"Error making batch predictions: {e}")
            return None
    
    def _get_prediction_feature_importance(self, feature_vector: np.ndarray, top_n: int = 10) -> Optional[Dict[str, Any]]:
        """Get feature importance information for a prediction."""
        try:
            if self.feature_importances is None:
                return None
            
            # Get feature names
            feature_names = self.feature_extractor.get_feature_names()
            
            # Get top N most important features
            top_indices = np.argsort(self.feature_importances)[-top_n:][::-1]
            
            top_features = []
            for idx in top_indices:
                if idx < len(feature_names):
                    feature_name = feature_names[idx]
                    importance = float(self.feature_importances[idx])
                    value = float(feature_vector[0, idx]) if feature_vector.shape[1] > idx else 0.0
                    
                    top_features.append({
                        'name': feature_name,
                        'importance': importance,
                        'value': value,
                        'rank': int(np.where(np.argsort(self.feature_importances)[::-1] == idx)[0][0] + 1)
                    })
            
            return {
                'top_features': top_features,
                'total_features': len(self.feature_importances),
                'importance_type': 'gain'  # XGBoost default
            }
            
        except Exception as e:
            self.logger.debug(f"Error getting feature importance: {e}")
            return None
    
    def _get_shap_values(self, feature_vector: np.ndarray) -> Optional[Dict[str, Any]]:
        """Get SHAP values for model interpretability."""
        try:
            if not self.shap_explainer:
                return None
            
            # Calculate SHAP values
            shap_values = self.shap_explainer.shap_values(feature_vector)
            
            # For multi-class, shap_values is a list of arrays
            if isinstance(shap_values, list):
                # Use the SHAP values for the predicted class
                predicted_class_idx = np.argmax(self.model.predict_proba(feature_vector)[0])
                if predicted_class_idx < len(shap_values):
                    shap_values_for_class = shap_values[predicted_class_idx][0]
                else:
                    shap_values_for_class = shap_values[0][0]
            else:
                shap_values_for_class = shap_values[0]
            
            # Get feature names
            feature_names = self.feature_extractor.get_feature_names()
            
            # Get top positive and negative SHAP values
            top_n = 5
            positive_indices = np.argsort(shap_values_for_class)[-top_n:][::-1]
            negative_indices = np.argsort(shap_values_for_class)[:top_n]
            
            top_positive = []
            for idx in positive_indices:
                if idx < len(feature_names) and shap_values_for_class[idx] > 0:
                    top_positive.append({
                        'feature': feature_names[idx],
                        'shap_value': float(shap_values_for_class[idx]),
                        'feature_value': float(feature_vector[0, idx])
                    })
            
            top_negative = []
            for idx in negative_indices:
                if idx < len(feature_names) and shap_values_for_class[idx] < 0:
                    top_negative.append({
                        'feature': feature_names[idx],
                        'shap_value': float(shap_values_for_class[idx]),
                        'feature_value': float(feature_vector[0, idx])
                    })
            
            return {
                'top_positive_contributions': top_positive,
                'top_negative_contributions': top_negative,
                'base_value': float(self.shap_explainer.expected_value[predicted_class_idx] if isinstance(self.shap_explainer.expected_value, list) else self.shap_explainer.expected_value),
                'prediction_class': self.class_names[predicted_class_idx]
            }
            
        except Exception as e:
            self.logger.debug(f"Error calculating SHAP values: {e}")
            return None
    
    def get_feature_importance_ranking(self, top_n: int = 20) -> Optional[List[Dict[str, Any]]]:
        """
        Get feature importance ranking for the model.
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            List of feature importance information
        """
        try:
            if self.feature_importances is None:
                self.logger.warning("Feature importances not available")
                return None
            
            # Get feature names
            feature_names = self.feature_extractor.get_feature_names()
            
            # Sort features by importance
            importance_indices = np.argsort(self.feature_importances)[::-1]
            
            feature_ranking = []
            for i, idx in enumerate(importance_indices[:top_n]):
                if idx < len(feature_names):
                    feature_ranking.append({
                        'rank': i + 1,
                        'feature_name': feature_names[idx],
                        'importance': float(self.feature_importances[idx]),
                        'importance_percentage': float(self.feature_importances[idx] / np.sum(self.feature_importances) * 100)
                    })
            
            return feature_ranking
            
        except Exception as e:
            self.logger.error(f"Error getting feature importance ranking: {e}")
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
                if hasattr(self.model, 'get_params'):
                    params = self.model.get_params()
                    model_params = {
                        'n_estimators': params.get('n_estimators', self.n_estimators),
                        'max_depth': params.get('max_depth', self.max_depth),
                        'learning_rate': params.get('learning_rate', self.learning_rate),
                        'subsample': params.get('subsample', self.subsample),
                        'colsample_bytree': params.get('colsample_bytree', self.colsample_bytree),
                        'objective': params.get('objective', self.objective),
                        'n_jobs': params.get('n_jobs', self.n_jobs)
                    }
                
                if hasattr(self.model, 'n_features_in_'):
                    model_params['n_features_in'] = self.model.n_features_in_
            
            model_info = {
                'name': self.model_name,
                'version': self.model_version,
                'algorithm': 'XGBoost',
                'status': 'loaded' if self.model else 'not_loaded',
                'feature_count': self._get_model_feature_count(),
                'class_count': len(self.class_names),
                'class_names': self.class_names,
                'confidence_threshold': self.confidence_threshold,
                'has_scaler': self.scaler is not None,
                'scaler_type': type(self.scaler).__name__ if self.scaler else None,
                'has_feature_importance': self.feature_importances is not None,
                'shap_available': self.shap_explainer is not None,
                'performance': {
                    'prediction_count': self.prediction_count,
                    'total_prediction_time': self.total_prediction_time,
                    'average_prediction_time': avg_prediction_time
                },
                'model_parameters': model_params
            }
            
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
            
            # Fallback to config
            return self.model_config.get('feature_count', 714)
                
        except Exception:
            return 714  # Default to expected feature count
    
    def reload_model(self) -> bool:
        """Reload the model from disk."""
        try:
            self.logger.info("Reloading XGBoost model...")
            
            # Reset model components
            self.model = None
            self.scaler = None
            self.model_config = None
            self.feature_importances = None
            self.shap_explainer = None
            
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
def create_xgboost_detector(model_manager: ModelManager, feature_extractor: FeatureExtractor) -> XGBoostDetector:
    """
    Convenience function to create an XGBoost detector.
    
    Args:
        model_manager: Model management system
        feature_extractor: Feature extraction engine
        
    Returns:
        Initialized XGBoostDetector instance
    """
    try:
        return XGBoostDetector(model_manager, feature_extractor)
    except Exception as e:
        logging.getLogger("XGBoostDetector").error(f"Error creating detector: {e}")
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
    
    print("Testing XGBoostDetector...")
    
    # Create mock dependencies
    mock_model_manager = MockModelManager()
    mock_feature_extractor = MockFeatureExtractor()
    
    # Create detector
    try:
        detector = XGBoostDetector(mock_model_manager, mock_feature_extractor)
        print(f"✅ XGBoostDetector created successfully")
        
        # Test model info
        model_info = detector.get_model_info()
        print(f"✅ Model Info: {model_info['name']} - Status: {model_info['status']}")
        print(f"   Scaler: {model_info['scaler_type']}")
        print(f"   Feature Importance: {model_info['has_feature_importance']}")
        print(f"   SHAP Available: {model_info['shap_available']}")
        
        # Test feature importance ranking
        if detector.is_model_loaded():
            importance_ranking = detector.get_feature_importance_ranking(top_n=5)
            if importance_ranking:
                print(f"✅ Feature Importance Ranking: Top 5 features")
                for item in importance_ranking[:3]:
                    print(f"   {item['rank']}. {item['feature_name']}: {item['importance']:.4f}")
        
        print("✅ XGBoostDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ XGBoostDetector test failed: {e}")