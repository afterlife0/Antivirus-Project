"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Random Forest Detector - ML-Based Malware Detection

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
- Loads trained Random Forest model from ModelManager
- Uses FeatureExtractor for file feature extraction
- Performs malware classification with confidence scoring
- Provides prediction results to ensemble voting system
- Supports model retraining and updates
- Handles model-specific preprocessing
- Provides feature importance analysis
- Supports batch prediction for multiple files

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: RandomForestDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access RandomForestDetector functionality
□ Random Forest model loading implemented
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
from sklearn.preprocessing import RobustScaler, MinMaxScaler

# ML/Scientific imports
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
except ImportError as e:
    logging.error(f"Required ML libraries not installed: {e}")
    raise ImportError("Please install scikit-learn and pandas: pip install scikit-learn pandas")

# Project Dependencies
from src.core.model_manager import ModelManager
from src.detection.feature_extractor import FeatureExtractor
from src.utils.encoding_utils import EncodingHandler
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler


class RandomForestDetector:
    """
    Random Forest-based malware detection system.
    
    Implements machine learning-based malware detection using Random Forest algorithm
    with ensemble capabilities and confidence scoring.
    
    Features:
    - Trained Random Forest model loading and management
    - File feature extraction and preprocessing
    - Multi-class malware classification
    - Confidence scoring for predictions
    - Feature importance analysis
    - Batch processing capabilities
    - Model performance monitoring
    - Integration with ensemble voting system
    """
    
    def __init__(self, model_manager: ModelManager, feature_extractor: FeatureExtractor):
        """
        Initialize Random Forest detector.
        
        Args:
            model_manager: Model management system
            feature_extractor: Feature extraction engine
        """
        self.model_manager = model_manager
        self.feature_extractor = feature_extractor
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("RandomForestDetector")
        
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
        self.model_name = "random_forest"
        self.model_version = "1.0.0"
        self.confidence_threshold = 0.5
        self.min_samples_for_prediction = 1
        
        # Initialize model
        self._initialize_model()
        
        self.logger.info(f"RandomForestDetector initialized - Model: {self.model_name} v{self.model_version}")
    
    def _initialize_model(self) -> bool:
        """Initialize the Random Forest model and components."""
        try:
            self.logger.info("Initializing Random Forest model...")
            
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
            
            # Load feature scaler if available
            self._load_feature_scaler()
            
            # Validate model compatibility
            if not self._validate_model_compatibility():
                self.logger.error("Model compatibility validation failed")
                return False
            
            self.logger.info("Random Forest model initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing Random Forest model: {e}")
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
            
            self.logger.info(f"Loaded Random Forest config: {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model config: {e}")
            return False
    
    def _create_default_config(self) -> None:
        """Create default model configuration."""
        self.model_config = {
            'name': self.model_name,
            'version': self.model_version,
            'algorithm': 'Random Forest',
            'confidence_threshold': self.confidence_threshold,
            'class_names': self.class_names,
            'feature_count': 714,  # **CORRECTED**: Your trained models use 714 features
            'hyperparameters': {
                'n_estimators': 100,
                'max_depth': 20,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
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
        
        self.logger.info("Created default Random Forest configuration with RobustScaler")

    def _create_default_scaler(self) -> None:
        """Create default feature scaler for Random Forest."""
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

    def _load_trained_model(self) -> bool:
        """Load the trained Random Forest model."""
        try:
            model_path = self.model_manager.get_model_path(self.model_name)
            if not model_path or not Path(model_path).exists():
                self.logger.warning(f"Trained model not found: {model_path}")
                return False
            
            # Load model using joblib (recommended for scikit-learn models)
            self.model = joblib.load(model_path)
            
            # Validate model type
            if not isinstance(self.model, RandomForestClassifier):
                self.logger.error(f"Invalid model type: {type(self.model)}")
                return False
            
            # Extract model information
            self.feature_names = getattr(self.model, 'feature_names_in_', None)
            if hasattr(self.model, 'classes_'):
                self.class_names = list(self.model.classes_)
            
            self.logger.info(f"Loaded trained Random Forest model from: {model_path}")
            self.logger.info(f"Model features: {self.model.n_features_in_}")
            self.logger.info(f"Model classes: {len(self.class_names)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading trained model: {e}")
            return False
    
    def _create_default_model(self) -> None:
        """Create a default Random Forest model for testing."""
        try:
            # Create default model with hyperparameters from config
            hyperparams = self.model_config.get('hyperparameters', {})
            
            self.model = RandomForestClassifier(
                n_estimators=hyperparams.get('n_estimators', 100),
                max_depth=hyperparams.get('max_depth', 20),
                min_samples_split=hyperparams.get('min_samples_split', 5),
                min_samples_leaf=hyperparams.get('min_samples_leaf', 2),
                random_state=hyperparams.get('random_state', 42),
                n_jobs=-1  # Use all available cores
            )
            
            # Create dummy training data for initialization
            n_features = self.model_config.get('feature_count', 714)  # **CORRECTED**
            X_dummy = np.random.rand(100, n_features)
            y_dummy = np.random.randint(0, len(self.class_names), 100)
            
            # Fit model with dummy data
            self.model.fit(X_dummy, y_dummy)
            
            self.logger.warning("Created default Random Forest model with dummy data")
            self.logger.warning("Model should be replaced with properly trained model")
            
        except Exception as e:
            self.logger.error(f"Error creating default model: {e}")
            self.model = None
    
    def _load_feature_scaler(self) -> bool:
        """Load feature scaler if available."""
        try:
            scaler_path = self.model_manager.get_model_path(f"{self.model_name}_scaler")
            if not scaler_path or not Path(scaler_path).exists():
                self.logger.debug("Feature scaler not found, using raw features")
                return False
            
            self.scaler = joblib.load(scaler_path)
            self.logger.info(f"Loaded feature scaler from: {scaler_path}")
            return True
            
        except Exception as e:
            self.logger.debug(f"Error loading feature scaler: {e}")
            return False
    
    def _validate_model_compatibility(self) -> bool:
        """Validate model compatibility with feature extractor."""
        try:
            if not self.model:
                return False
            
            # Check feature count compatibility
            expected_features = self.feature_extractor.get_feature_count()
            model_features = self.model.n_features_in_
            
            if expected_features != model_features:
                self.logger.error(f"Feature count mismatch: expected {expected_features}, model has {model_features}")
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
            
            # Apply feature scaling if available
            if self.scaler:
                feature_vector = self.scaler.transform(feature_vector)
            
            return feature_vector
            
        except Exception as e:
            self.logger.error(f"Error preparing feature vector: {e}")
            return None
    
    def _predict_features(self, feature_vector: np.ndarray) -> Optional[Dict[str, Any]]:
        """Make prediction using prepared feature vector."""
        try:
            # Get prediction and probabilities
            prediction = self.model.predict(feature_vector)
            probabilities = self.model.predict_proba(feature_vector)
            
            # Extract results
            predicted_class_idx = prediction[0]
            predicted_class = self.class_names[predicted_class_idx]
            confidence = float(probabilities[0][predicted_class_idx])
            
            # Create class probability dictionary
            class_probabilities = {
                class_name: float(prob) 
                for class_name, prob in zip(self.class_names, probabilities[0])
            }
            
            # Determine if prediction is confident enough
            is_confident = confidence >= self.confidence_threshold
            
            # Calculate risk score (probability of being malicious)
            benign_prob = class_probabilities.get('benign', 0.0)
            risk_score = 1.0 - benign_prob
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'is_confident': is_confident,
                'class_probabilities': class_probabilities,
                'prediction_method': 'random_forest',
                'threshold_used': self.confidence_threshold
            }
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return None
    
    def get_feature_importance(self, top_n: int = 20) -> Optional[Dict[str, float]]:
        """
        Get feature importance from the trained model.
        
        Args:
            top_n: Number of top features to return
            
        Returns:
            Dictionary of feature names and their importance scores
        """
        try:
            if not self.model or not hasattr(self.model, 'feature_importances_'):
                self.logger.error("Model not loaded or doesn't support feature importance")
                return None
            
            # Get feature names and importances
            feature_names = self.feature_extractor.get_feature_names()
            feature_importances = self.model.feature_importances_
            
            # Create feature-importance pairs
            feature_importance_pairs = list(zip(feature_names, feature_importances))
            
            # Sort by importance (descending)
            feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)
            
            # Get top N features
            top_features = feature_importance_pairs[:top_n]
            
            # Convert to dictionary
            importance_dict = {feature: importance for feature, importance in top_features}
            
            self.logger.info(f"Retrieved top {len(importance_dict)} feature importances")
            return importance_dict
            
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {e}")
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
            
            model_info = {
                'name': self.model_name,
                'version': self.model_version,
                'algorithm': 'Random Forest',
                'status': 'loaded' if self.model else 'not_loaded',
                'feature_count': self.model.n_features_in_ if self.model else 0,
                'class_count': len(self.class_names),
                'class_names': self.class_names,
                'confidence_threshold': self.confidence_threshold,
                'has_scaler': self.scaler is not None,
                'performance': {
                    'prediction_count': self.prediction_count,
                    'total_prediction_time': self.total_prediction_time,
                    'average_prediction_time': avg_prediction_time
                },
                'model_parameters': {
                    'n_estimators': self.model.n_estimators if self.model else 0,
                    'max_depth': self.model.max_depth if self.model else 0,
                    'min_samples_split': self.model.min_samples_split if self.model else 0,
                    'min_samples_leaf': self.model.min_samples_leaf if self.model else 0
                } if self.model else {}
            }
            
            return model_info
            
        except Exception as e:
            self.logger.error(f"Error getting model info: {e}")
            return {'name': self.model_name, 'status': 'error', 'error': str(e)}
    
    def reload_model(self) -> bool:
        """Reload the model from disk."""
        try:
            self.logger.info("Reloading Random Forest model...")
            
            # Reset model components
            self.model = None
            self.scaler = None
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
def create_random_forest_detector(model_manager: ModelManager, feature_extractor: FeatureExtractor) -> RandomForestDetector:
    """
    Convenience function to create a Random Forest detector.
    
    Args:
        model_manager: Model management system
        feature_extractor: Feature extraction engine
        
    Returns:
        Initialized RandomForestDetector instance
    """
    try:
        return RandomForestDetector(model_manager, feature_extractor)
    except Exception as e:
        logging.getLogger("RandomForestDetector").error(f"Error creating detector: {e}")
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
            return {f"feature_{i}": 0.5 for i in range(714)}  # **CORRECTED**
        
        def validate_feature_vector(self, features):
            return len(features) == 714  # **CORRECTED**
    
    print("Testing RandomForestDetector...")
    
    # Create mock dependencies
    mock_model_manager = MockModelManager()
    mock_feature_extractor = MockFeatureExtractor()
    
    # Create detector
    try:
        detector = RandomForestDetector(mock_model_manager, mock_feature_extractor)
        print(f"✅ RandomForestDetector created successfully")
        
        # Test model info
        model_info = detector.get_model_info()
        print(f"✅ Model Info: {model_info['name']} - Status: {model_info['status']}")
        
        # Test feature importance (if model loaded)
        if detector.is_model_loaded():
            importance = detector.get_feature_importance(top_n=5)
            if importance:
                print(f"✅ Top 5 feature importances: {list(importance.keys())}")
        
        print("✅ RandomForestDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ RandomForestDetector test failed: {e}")