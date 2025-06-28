"""
Advanced Multi-Algorithm Antivirus Software
==========================================
DNN Detector - Deep Neural Network Malware Detection

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
- Loads trained Deep Neural Network model (TensorFlow/Keras)
- Uses FeatureExtractor for file feature extraction (714 features)
- Performs malware classification with deep learning
- Provides prediction results to ensemble voting system
- Supports GPU/CPU acceleration and optimization
- Handles model checkpointing and restoration
- Provides layer-wise analysis and interpretation
- Supports batch prediction for multiple files
- Implements dropout and regularization for inference

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: DNNDetector
□ Dependencies properly imported with EXACT class names
□ All connected files can access DNNDetector functionality
□ DNN model loading implemented
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
import time
import warnings
from datetime import datetime

# Deep Learning imports
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, callbacks, optimizers
    from tensorflow.keras.models import load_model, Sequential, Model
    from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input
    from tensorflow.keras.utils import to_categorical
    import tensorflow.keras.backend as K
    
    # Suppress TensorFlow warnings for cleaner output
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore', category=UserWarning, module='tensorflow')
    
    # Set TensorFlow to use CPU by default (can be overridden)
    tf.config.set_visible_devices([], 'GPU')  # Disable GPU by default
    
except ImportError as e:
    logging.error(f"TensorFlow not installed: {e}")
    raise ImportError("Please install TensorFlow: pip install tensorflow")

# Scientific computing imports
try:
    from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler  # **ADDED RobustScaler**
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import pandas as pd
    
except ImportError as e:
    logging.error(f"Required ML libraries not installed: {e}")
    raise ImportError("Please install scikit-learn and pandas: pip install scikit-learn pandas")

# Project Dependencies
from src.core.model_manager import ModelManager
from src.detection.feature_extractor import FeatureExtractor
from src.utils.encoding_utils import EncodingHandler


class DNNDetector:
    """
    Deep Neural Network-based malware detection system.
    
    Implements deep learning-based malware detection using TensorFlow/Keras
    with ensemble capabilities and advanced neural network techniques.
    
    Features:
    - Trained DNN model loading and management
    - Multi-layer neural network architecture
    - Feature normalization and preprocessing
    - GPU/CPU acceleration support
    - Multi-class malware classification
    - Confidence scoring with softmax probabilities
    - Batch processing capabilities
    - Model performance monitoring
    - Integration with ensemble voting system
    - Layer-wise analysis and interpretation
    """
    
    def __init__(self, model_manager: ModelManager, feature_extractor: FeatureExtractor):
        """
        Initialize DNN detector.
        
        Args:
            model_manager: Model management system
            feature_extractor: Feature extraction engine
        """
        self.model_manager = model_manager
        self.feature_extractor = feature_extractor
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("DNNDetector")
        
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
        self.model_name = "dnn"
        self.model_version = "1.0.0"
        self.confidence_threshold = 0.5
        self.use_gpu = False  # Default to CPU
        
        # DNN-specific configuration
        self.input_dim = 714  # CORRECTED: Expected feature count
        self.hidden_layers = [512, 256, 128, 64]  # Default architecture
        self.dropout_rate = 0.3
        self.activation = 'relu'
        self.output_activation = 'softmax'
        self.optimizer = 'adam'
        self.batch_size = 32
        
        # TensorFlow session configuration
        self.session_config = None
        
        # Initialize model
        self._initialize_model()
        
        self.logger.info(f"DNNDetector initialized - Model: {self.model_name} v{self.model_version}")
        self.logger.info(f"Using device: {'GPU' if self.use_gpu else 'CPU'}")
    
    def _initialize_model(self) -> bool:
        """Initialize the DNN model and components."""
        try:
            self.logger.info("Initializing DNN model...")
            
            # Configure TensorFlow session
            self._configure_tensorflow()
            
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
            
            # Validate model compatibility
            if not self._validate_model_compatibility():
                self.logger.error("Model compatibility validation failed")
                return False
            
            self.logger.info("DNN model initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing DNN model: {e}")
            return False
    
    def _configure_tensorflow(self) -> None:
        """Configure TensorFlow session and device settings."""
        try:
            # Configure memory growth for GPU (if available)
            gpus = tf.config.experimental.list_physical_devices('GPU')
            if gpus and self.use_gpu:
                try:
                    # Allow memory growth
                    for gpu in gpus:
                        tf.config.experimental.set_memory_growth(gpu, True)
                    self.logger.info(f"Configured {len(gpus)} GPU(s) with memory growth")
                except RuntimeError as e:
                    self.logger.warning(f"GPU configuration failed: {e}")
                    self.use_gpu = False
            else:
                # Force CPU usage
                tf.config.set_visible_devices([], 'GPU')
                self.logger.info("Configured for CPU usage")
            
            # Set threading configuration for better CPU performance
            tf.config.threading.set_inter_op_parallelism_threads(0)  # Use all available cores
            tf.config.threading.set_intra_op_parallelism_threads(0)
            
        except Exception as e:
            self.logger.warning(f"Error configuring TensorFlow: {e}")
    
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
            
            # DNN-specific parameters
            architecture = self.model_config.get('architecture', {})
            self.input_dim = architecture.get('input_dim', self.input_dim)
            self.hidden_layers = architecture.get('hidden_layers', self.hidden_layers)
            self.dropout_rate = architecture.get('dropout_rate', self.dropout_rate)
            self.activation = architecture.get('activation', self.activation)
            self.output_activation = architecture.get('output_activation', self.output_activation)
            self.optimizer = architecture.get('optimizer', self.optimizer)
            self.batch_size = architecture.get('batch_size', self.batch_size)
            
            # Device configuration
            self.use_gpu = self.model_config.get('use_gpu', self.use_gpu)
            
            self.logger.info(f"Loaded DNN config: {config_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model config: {e}")
            return False
    
    def _create_default_config(self) -> None:
        """Create default model configuration."""
        self.model_config = {
            'name': self.model_name,
            'version': self.model_version,
            'algorithm': 'Deep Neural Network',
            'confidence_threshold': self.confidence_threshold,
            'class_names': self.class_names,
            'feature_count': self.input_dim,
            'architecture': {
                'input_dim': self.input_dim,
                'hidden_layers': self.hidden_layers,
                'dropout_rate': self.dropout_rate,
                'activation': self.activation,
                'output_activation': self.output_activation,
                'optimizer': self.optimizer,
                'batch_size': self.batch_size
            },
            'training': {
                'epochs': 100,
                'early_stopping_patience': 10,
                'learning_rate': 0.001,
                'validation_split': 0.2
            },
            'scaling': {
                'method': 'RobustScaler',  # **CORRECTED**: Your training uses RobustScaler
                'quantile_range': [25.0, 75.0],  # **CORRECTED**: 25th to 75th percentile
                'centering': 'median',  # **CORRECTED**: Uses median instead of mean
                'unit_variance': False  # **CORRECTED**: Uses IQR instead of std dev
            },
            'use_gpu': self.use_gpu,
            'created_date': datetime.now().isoformat(),
            'training_accuracy': 0.0,
            'validation_accuracy': 0.0
        }
        
        self.logger.info("Created default DNN configuration with RobustScaler")

    def _create_default_model(self) -> None:
        """Create a default DNN model for testing."""
        try:
            # Create default model architecture
            model = Sequential()
            
            # Input layer
            model.add(Input(shape=(self.input_dim,)))
            
            # Hidden layers
            for i, hidden_size in enumerate(self.hidden_layers):
                model.add(Dense(hidden_size, activation=self.activation, name=f'hidden_{i+1}'))
                model.add(BatchNormalization())
                model.add(Dropout(self.dropout_rate))
            
            # Output layer
            model.add(Dense(len(self.class_names), activation=self.output_activation, name='output'))
            
            # Compile model
            model.compile(
                optimizer=self.optimizer,
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
            
            # Initialize with random weights (model is already initialized)
            self.model = model
            
            self.logger.warning("Created default DNN model with random weights")
            self.logger.warning("Model should be replaced with properly trained model")
            self.logger.info(f"Default model architecture: {[self.input_dim] + self.hidden_layers + [len(self.class_names)]}")
            
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
            
            # Load scaler using pickle/joblib
            import joblib
            self.scaler = joblib.load(scaler_path)
            
            self.logger.info(f"Loaded feature scaler from: {scaler_path}")
            self.logger.info(f"Scaler type: {type(self.scaler).__name__}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading feature scaler: {e}")
            return False
    
    def _create_default_scaler(self) -> None:
        """Create default feature scaler for DNN."""
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
    
    def _validate_model_compatibility(self) -> bool:
        """Validate model compatibility with feature extractor."""
        try:
            if not self.model:
                return False
            
            # Check feature count compatibility
            expected_features = self.feature_extractor.get_feature_count()
            model_input_dim = self.model.input_shape[1]
            
            if expected_features != model_input_dim:
                self.logger.error(f"Feature count mismatch: expected {expected_features}, model expects {model_input_dim}")
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
            
            model_output_dim = self.model.output_shape[1]
            if len(self.class_names) != model_output_dim:
                self.logger.warning(f"Class count mismatch: config has {len(self.class_names)}, model outputs {model_output_dim}")
                # Adjust class names to match model
                self.class_names = [f"class_{i}" for i in range(model_output_dim)]
            
            self.logger.info(f"Model compatibility validated: {model_input_dim} features, {model_output_dim} classes")
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
                self.logger.warning("No feature scaler available - DNN performance may be poor")
            
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
                self.logger.warning("No feature scaler available - DNN performance may be poor")
            
            return feature_matrix
            
        except Exception as e:
            self.logger.error(f"Error preparing feature matrix: {e}")
            return None
    
    def _predict_features(self, feature_vector: np.ndarray) -> Optional[Dict[str, Any]]:
        """Make prediction using prepared feature vector."""
        try:
            # Get prediction probabilities
            probabilities = self.model.predict(feature_vector, verbose=0)[0]
            
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
            
            # Get additional DNN-specific information
            layer_activations = self._get_layer_activations(feature_vector) if hasattr(self, '_get_layer_activations') else {}
            
            return {
                'predicted_class': predicted_class,
                'confidence': confidence,
                'risk_score': risk_score,
                'is_confident': is_confident,
                'class_probabilities': class_probabilities,
                'layer_activations': layer_activations,
                'prediction_method': 'dnn',
                'threshold_used': self.confidence_threshold,
                'model_architecture': f"{len(self.model.layers)} layers"
            }
            
        except Exception as e:
            self.logger.error(f"Error making prediction: {e}")
            return None
    
    def _predict_features_batch(self, feature_matrix: np.ndarray) -> Optional[List[Dict[str, Any]]]:
        """Make batch predictions using prepared feature matrix."""
        try:
            # Get batch prediction probabilities
            batch_probabilities = self.model.predict(feature_matrix, 
                                                   batch_size=self.batch_size, 
                                                   verbose=0)
            
            batch_results = []
            
            for probabilities in batch_probabilities:
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
                
                batch_results.append({
                    'predicted_class': predicted_class,
                    'confidence': confidence,
                    'risk_score': risk_score,
                    'is_confident': is_confident,
                    'class_probabilities': class_probabilities,
                    'prediction_method': 'dnn',
                    'threshold_used': self.confidence_threshold,
                    'model_architecture': f"{len(self.model.layers)} layers"
                })
            
            return batch_results
            
        except Exception as e:
            self.logger.error(f"Error making batch predictions: {e}")
            return None
    
    def get_model_summary(self) -> Optional[str]:
        """
        Get detailed model architecture summary.
        
        Returns:
            Model summary string or None if model not loaded
        """
        try:
            if not self.model:
                return None
            
            # Capture model summary
            summary_lines = []
            self.model.summary(print_fn=lambda x: summary_lines.append(x))
            
            return '\n'.join(summary_lines)
            
        except Exception as e:
            self.logger.error(f"Error getting model summary: {e}")
            return None
    
    def get_layer_info(self) -> Optional[List[Dict[str, Any]]]:
        """
        Get information about each layer in the model.
        
        Returns:
            List of layer information dictionaries
        """
        try:
            if not self.model:
                return None
            
            layer_info = []
            
            for i, layer in enumerate(self.model.layers):
                info = {
                    'layer_index': i,
                    'layer_name': layer.name,
                    'layer_type': type(layer).__name__,
                    'output_shape': layer.output_shape,
                    'trainable_params': layer.count_params() if hasattr(layer, 'count_params') else 0,
                    'activation': getattr(layer, 'activation', None).__name__ if hasattr(layer, 'activation') and layer.activation else None
                }
                
                # Add layer-specific information
                if hasattr(layer, 'units'):
                    info['units'] = layer.units
                if hasattr(layer, 'rate'):
                    info['dropout_rate'] = layer.rate
                
                layer_info.append(info)
            
            return layer_info
            
        except Exception as e:
            self.logger.error(f"Error getting layer info: {e}")
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
                model_params = {
                    'total_layers': len(self.model.layers),
                    'input_shape': self.model.input_shape,
                    'output_shape': self.model.output_shape,
                    'total_params': self.model.count_params(),
                    'trainable_params': sum([layer.count_params() for layer in self.model.layers if layer.trainable]),
                    'architecture': self.hidden_layers,
                    'activation': self.activation,
                    'optimizer': self.optimizer,
                    'dropout_rate': self.dropout_rate
                }
            
            model_info = {
                'name': self.model_name,
                'version': self.model_version,
                'algorithm': 'Deep Neural Network',
                'status': 'loaded' if self.model else 'not_loaded',
                'feature_count': self._get_model_feature_count(),
                'class_count': len(self.class_names),
                'class_names': self.class_names,
                'confidence_threshold': self.confidence_threshold,
                'has_scaler': self.scaler is not None,
                'scaler_type': type(self.scaler).__name__ if self.scaler else None,
                'use_gpu': self.use_gpu,
                'device': 'GPU' if self.use_gpu else 'CPU',
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
            
            return self.model.input_shape[1]
                
        except Exception:
            return 0
    
    def enable_gpu(self) -> bool:
        """
        Enable GPU acceleration if available.
        
        Returns:
            True if GPU enabled successfully, False otherwise
        """
        try:
            gpus = tf.config.experimental.list_physical_devices('GPU')
            if not gpus:
                self.logger.warning("No GPUs available")
                return False
            
            # Enable GPU
            tf.config.set_visible_devices(gpus, 'GPU')
            
            # Configure memory growth
            for gpu in gpus:
                tf.config.experimental.set_memory_growth(gpu, True)
            
            self.use_gpu = True
            self.logger.info(f"GPU acceleration enabled: {len(gpus)} GPU(s)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error enabling GPU: {e}")
            return False
    
    def disable_gpu(self) -> None:
        """Disable GPU acceleration and use CPU only."""
        try:
            tf.config.set_visible_devices([], 'GPU')
            self.use_gpu = False
            self.logger.info("GPU acceleration disabled, using CPU")
            
        except Exception as e:
            self.logger.error(f"Error disabling GPU: {e}")
    
    def reload_model(self) -> bool:
        """Reload the model from disk."""
        try:
            self.logger.info("Reloading DNN model...")
            
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

    # Add missing _load_trained_model method:
    def _load_trained_model(self) -> bool:
        """Load the trained DNN model."""
        try:
            model_path = self.model_manager.get_model_path(self.model_name)
            if not model_path or not Path(model_path).exists():
                self.logger.warning(f"Trained model not found: {model_path}")
                return False
            
            # Load Keras model
            self.model = load_model(model_path, compile=False)  # Don't compile for inference
            
            # Recompile with inference settings
            self.model.compile(
                optimizer=self.optimizer,
                loss='categorical_crossentropy',
                metrics=['accuracy']
            )
            
            # Validate model architecture
            if len(self.model.layers) == 0:
                self.logger.error("Loaded model has no layers")
                return False
            
            self.logger.info(f"Loaded trained DNN model from: {model_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading trained model: {e}")
            return False
        

# Utility function for easy model access
def create_dnn_detector(model_manager: ModelManager, feature_extractor: FeatureExtractor) -> DNNDetector:
    """
    Convenience function to create a DNN detector.
    
    Args:
        model_manager: Model management system
        feature_extractor: Feature extraction engine
        
    Returns:
        Initialized DNNDetector instance
    """
    try:
        return DNNDetector(model_manager, feature_extractor)
    except Exception as e:
        logging.getLogger("DNNDetector").error(f"Error creating detector: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import sys
    
    # Mock dependencies for testing
    class MockModelManager:
        def get_model_path(self, model_name):
            return f"models/{model_name}/{model_name}_model.h5"
        
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
    
    print("Testing DNNDetector...")
    
    # Create mock dependencies
    mock_model_manager = MockModelManager()
    mock_feature_extractor = MockFeatureExtractor()
    
    # Create detector
    try:
        detector = DNNDetector(mock_model_manager, mock_feature_extractor)
        print(f"✅ DNNDetector created successfully")
        
        # Test model info
        model_info = detector.get_model_info()
        print(f"✅ Model Info: {model_info['name']} - Status: {model_info['status']}")
        print(f"   Device: {model_info['device']}")
        print(f"   Scaler: {model_info['scaler_type']}")
        
        # Test model summary (if model loaded)
        if detector.is_model_loaded():
            summary = detector.get_model_summary()
            if summary:
                print(f"✅ Model Summary available ({len(summary.split('\\n'))} lines)")
            
            layer_info = detector.get_layer_info()
            if layer_info:
                print(f"✅ Layer Info: {len(layer_info)} layers")
                print(f"   Architecture: {[info['layer_type'] for info in layer_info[:3]]}...")
        
        # Test GPU availability
        gpu_available = detector.enable_gpu()
        print(f"✅ GPU Available: {gpu_available}")
        
        print("✅ DNNDetector test completed successfully")
        
    except Exception as e:
        print(f"❌ DNNDetector test failed: {e}")