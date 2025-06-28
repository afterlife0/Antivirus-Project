"""
Deep Neural Network Model Implementation for EMBER2018 Malware Detection
Independent robust DNN implementation with hyperparameter tuning

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (independent model using TensorFlow/Keras only)

Connected Components (files that import from this module):
- trainer.py (imports DNNModel class)

Integration Points:
- Provides Deep Neural Network model implementation for malware detection
- NUMERICAL-ONLY training on processed EMBER2018 features
- Comprehensive hyperparameter tuning capabilities
- Multi-core processing support for large datasets
- Complete evaluation metrics calculation
- Model persistence and serialization
- Training history tracking with callbacks

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: DNNModel
□ Independent implementation (no custom dependencies)
□ Hyperparameter tuning implemented
□ NUMERICAL-ONLY training verified
□ Comprehensive metrics implemented
□ Memory optimization implemented
"""

import os
import sys
import time
import warnings
import pickle
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union

import numpy as np
import pandas as pd
import psutil

# TensorFlow and Keras imports
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, Input
    from tensorflow.keras.optimizers import Adam, SGD, RMSprop
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
    from tensorflow.keras.regularizers import l1, l2, l1_l2
    from tensorflow.keras.utils import to_categorical
    TENSORFLOW_AVAILABLE = True
    
    # Configure TensorFlow logging
    tf.get_logger().setLevel('ERROR')
    tf.autograph.set_verbosity(0)
    
except ImportError:
    print("❌ CRITICAL ERROR: TensorFlow not available")
    TENSORFLOW_AVAILABLE = False
    sys.exit(1)

# Scikit-learn for metrics and preprocessing
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score, log_loss, roc_auc_score, precision_recall_curve, auc,
    precision_score, recall_score, f1_score, confusion_matrix, classification_report,
    roc_curve, average_precision_score
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

# Suppress warnings
warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# Optional Bayesian optimization
try:
    import optuna
    from optuna.samplers import TPESampler
    OPTUNA_AVAILABLE = True
except ImportError:
    OPTUNA_AVAILABLE = False

try:
    from hyperopt import hp, fmin, tpe, Trials, STATUS_OK
    HYPEROPT_AVAILABLE = True
except ImportError:
    HYPEROPT_AVAILABLE = False

try:
    from skopt import gp_minimize
    from skopt.space import Real, Integer, Categorical
    SKOPT_AVAILABLE = True
except ImportError:
    SKOPT_AVAILABLE = False

# Default hyperparameter grid for DNN
DNN_PARAM_GRID = {
    'hidden_layers': [
        (64,), (128,), (256,), (512,),
        (64, 32), (128, 64), (256, 128), (512, 256),
        (128, 64, 32), (256, 128, 64), (512, 256, 128),
        (256, 128, 64, 32), (512, 256, 128, 64)
    ],
    'learning_rate': [0.0001, 0.001, 0.01, 0.1],
    'batch_size': [16, 32, 64, 128, 256],
    'dropout_rate': [0.0, 0.1, 0.2, 0.3, 0.5],
    'activation': ['relu', 'tanh', 'sigmoid', 'elu'],
    'optimizer': ['adam', 'sgd', 'rmsprop'],
    'l1_reg': [0.0, 0.001, 0.01],
    'l2_reg': [0.0, 0.001, 0.01],
    'batch_normalization': [True, False]
}

# Reduced parameter grid for faster tuning
DNN_PARAM_GRID_FAST = {
    'hidden_layers': [(64,), (128,), (128, 64), (256, 128)],
    'learning_rate': [0.001, 0.01],
    'batch_size': [32, 64, 128],
    'dropout_rate': [0.0, 0.2, 0.5],
    'activation': ['relu', 'tanh'],
    'optimizer': ['adam', 'sgd'],
    'l1_reg': [0.0, 0.001],
    'l2_reg': [0.0, 0.001],
    'batch_normalization': [True, False]
}

# Hyperparameter search spaces for different optimization methods
DNN_HYPEROPT_SPACE = {
    'hidden_layers': hp.choice('hidden_layers', [
        (64,), (128,), (256,), (128, 64), (256, 128), (256, 128, 64)
    ]),
    'learning_rate': hp.loguniform('learning_rate', np.log(0.0001), np.log(0.1)),
    'batch_size': hp.choice('batch_size', [16, 32, 64, 128]),
    'dropout_rate': hp.uniform('dropout_rate', 0.0, 0.5),
    'activation': hp.choice('activation', ['relu', 'tanh', 'elu']),
    'optimizer': hp.choice('optimizer', ['adam', 'sgd', 'rmsprop']),
    'l1_reg': hp.loguniform('l1_reg', np.log(0.0001), np.log(0.01)),
    'l2_reg': hp.loguniform('l2_reg', np.log(0.0001), np.log(0.01)),
    'batch_normalization': hp.choice('batch_normalization', [True, False])
}

DNN_OPTUNA_SPACE = {
    'hidden_layers': ('categorical', [
        (64,), (128,), (256,), (128, 64), (256, 128), (256, 128, 64)
    ]),
    'learning_rate': ('log_uniform', 0.0001, 0.1),
    'batch_size': ('categorical', [16, 32, 64, 128]),
    'dropout_rate': ('uniform', 0.0, 0.5),
    'activation': ('categorical', ['relu', 'tanh', 'elu']),
    'optimizer': ('categorical', ['adam', 'sgd', 'rmsprop']),
    'l1_reg': ('log_uniform', 0.0001, 0.01),
    'l2_reg': ('log_uniform', 0.0001, 0.01),
    'batch_normalization': ('categorical', [True, False])
}

class DNNModel:
    """
    Independent robust Deep Neural Network implementation with hyperparameter tuning
    
    Features:
    - Multiple DNN architectures (shallow, deep, wide networks)
    - Comprehensive hyperparameter tuning (Grid, Random, Bayesian)
    - Multi-core processing support
    - Memory-efficient training for large datasets
    - Complete evaluation metrics calculation
    - Model persistence and serialization
    - Cross-validation with detailed results
    - Training history tracking with callbacks
    - Early stopping and learning rate scheduling
    - Regularization techniques (Dropout, L1/L2, Batch Normalization)
    """
    
    def __init__(self, random_state: int = 42, n_cores: int = -1, memory_limit: float = 4.0):
        """
        Initialize DNN model with configuration
        
        Args:
            random_state: Random seed for reproducibility
            n_cores: Number of CPU cores to use (-1 for all)
            memory_limit: Memory limit in GB for training
        """
        self.random_state = random_state
        self.n_cores = n_cores if n_cores > 0 else -1
        self.memory_limit = memory_limit
        
        # Set random seeds for reproducibility
        np.random.seed(random_state)
        tf.random.set_seed(random_state)
        
        # Configure TensorFlow
        self._configure_tensorflow()
        
        # Model components
        self.model = None
        self.label_encoder = None
        self.scaler = None
        self.is_fitted = False
        
        # Hyperparameter tuning results
        self.best_params = {}
        self.best_score = 0.0
        self.cv_results = {}
        self.hyperparameter_tuning_results = {}
        self.search_history = []
        
        # Training metrics and history
        self.training_history = {
            'training_time': 0.0,
            'validation_scores': [],
            'history': None,
            'callbacks_used': [],
            'model_complexity': {}
        }
        
        # Default parameter grids
        self.default_param_grid = DNN_PARAM_GRID
        self.fast_param_grid = DNN_PARAM_GRID_FAST
        
        # Memory tracking
        self.initial_memory = self._get_memory_usage()
        self.memory_usage = {}
        
        print(f"🧠 Deep Neural Network Model initialized:")
        print(f"   🎲 Random state: {self.random_state}")
        print(f"   🔧 CPU cores: {self.n_cores}")
        print(f"   💾 Memory limit: {self.memory_limit}GB")
        print(f"   🖥️ TensorFlow version: {tf.__version__}")
        print(f"   📊 Hyperparameter grid size: {self._calculate_grid_size(self.default_param_grid)}")
    
    def _configure_tensorflow(self):
        """Configure TensorFlow settings for optimal performance"""
        try:
            # Configure GPU if available
            gpus = tf.config.experimental.list_physical_devices('GPU')
            if gpus:
                print(f"🚀 GPU detected: {len(gpus)} device(s)")
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
            else:
                print("💻 Using CPU for training")
            
            # Configure CPU threading
            if self.n_cores > 0:
                tf.config.threading.set_intra_op_parallelism_threads(self.n_cores)
                tf.config.threading.set_inter_op_parallelism_threads(self.n_cores)
            
        except Exception as e:
            print(f"⚠️ TensorFlow configuration warning: {e}")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in GB"""
        try:
            return psutil.Process().memory_info().rss / (1024**3)
        except Exception:
            return 0.0
    
    def _monitor_memory(self, operation: str, start_memory: float = None) -> None:
        """Monitor memory usage for an operation"""
        current_memory = self._get_memory_usage()
        if start_memory is None:
            start_memory = self.initial_memory
        
        self.memory_usage[operation] = {
            'current_gb': current_memory,
            'delta_gb': current_memory - start_memory,
            'timestamp': time.time()
        }
        
        # Check memory limit
        if current_memory > self.memory_limit:
            print(f"⚠️ Memory usage ({current_memory:.2f}GB) exceeds limit ({self.memory_limit}GB)")
    
    def _calculate_grid_size(self, param_grid: Dict[str, List]) -> int:
        """Calculate total number of parameter combinations"""
        size = 1
        for param_values in param_grid.values():
            size *= len(param_values)
        return size
    
    def _validate_input_data(self, X: pd.DataFrame, y: pd.Series = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Validate and prepare input data for training/prediction
        
        Args:
            X: Feature matrix
            y: Target vector (optional)
            
        Returns:
            Tuple of (X_array, y_array) as numpy arrays
        """
        try:
            # Validate feature matrix
            if not isinstance(X, (pd.DataFrame, np.ndarray)):
                raise ValueError("X must be pandas DataFrame or numpy array")
            
            # Convert to numpy array
            if isinstance(X, pd.DataFrame):
                # Ensure no string columns remain
                string_cols = X.select_dtypes(include=['object', 'string']).columns
                if len(string_cols) > 0:
                    raise ValueError(f"String columns found in features: {string_cols.tolist()}")
                X_array = X.values.astype(np.float32)
            else:
                X_array = X.astype(np.float32)
            
            # Check for missing values
            if np.isnan(X_array).any():
                print("⚠️ Missing values detected in features - filling with 0")
                X_array = np.nan_to_num(X_array, nan=0.0)
            
            # Check for infinite values
            if np.isinf(X_array).any():
                print("⚠️ Infinite values detected in features - clipping")
                X_array = np.clip(X_array, -1e10, 1e10)
            
            # Validate target vector if provided
            y_array = None
            if y is not None:
                if isinstance(y, pd.Series):
                    y_array = y.values
                else:
                    y_array = np.array(y)
                
                # Encode labels if necessary
                if self.label_encoder is None:
                    unique_labels = np.unique(y_array)
                    if len(unique_labels) > 2:
                        print(f"📊 Multi-class problem detected: {len(unique_labels)} classes")
                    
                    # Check if labels need encoding
                    if not np.issubdtype(y_array.dtype, np.integer):
                        self.label_encoder = LabelEncoder()
                        y_array = self.label_encoder.fit_transform(y_array)
                        print(f"🔤 Labels encoded: {dict(zip(self.label_encoder.classes_, self.label_encoder.transform(self.label_encoder.classes_)))}")
                else:
                    if not np.issubdtype(y_array.dtype, np.integer):
                        y_array = self.label_encoder.transform(y_array)
                
                # Convert to appropriate format for neural network
                n_classes = len(np.unique(y_array))
                if n_classes > 2:
                    # Multi-class: convert to categorical
                    y_array = to_categorical(y_array, num_classes=n_classes)
                else:
                    # Binary: keep as is but ensure float32
                    y_array = y_array.astype(np.float32)
            
            print(f"✅ Data validation completed: X shape {X_array.shape}, y shape {y_array.shape if y_array is not None else 'None'}")
            return X_array, y_array
            
        except Exception as e:
            print(f"❌ Data validation failed: {e}")
            raise
    
    def _create_base_model(self, input_shape: int, n_classes: int, **params) -> Model:
        """
        Create base DNN model with specified parameters
        
        Args:
            input_shape: Number of input features
            n_classes: Number of output classes
            **params: DNN parameters
            
        Returns:
            Configured Keras model
        """
        try:
            # Set default parameters
            default_params = {
                'hidden_layers': (128, 64),
                'learning_rate': 0.001,
                'dropout_rate': 0.2,
                'activation': 'relu',
                'optimizer': 'adam',
                'l1_reg': 0.0,
                'l2_reg': 0.001,
                'batch_normalization': True
            }
            
            # Update with provided parameters
            model_params = {**default_params, **params}
            
            # Build model architecture
            inputs = Input(shape=(input_shape,), name='input')
            x = inputs
            
            # Add hidden layers
            for i, units in enumerate(model_params['hidden_layers']):
                # Dense layer with regularization
                regularizer = None
                if model_params['l1_reg'] > 0 and model_params['l2_reg'] > 0:
                    regularizer = l1_l2(l1=model_params['l1_reg'], l2=model_params['l2_reg'])
                elif model_params['l1_reg'] > 0:
                    regularizer = l1(model_params['l1_reg'])
                elif model_params['l2_reg'] > 0:
                    regularizer = l2(model_params['l2_reg'])
                
                x = Dense(
                    units,
                    activation=model_params['activation'],
                    kernel_regularizer=regularizer,
                    name=f'dense_{i+1}'
                )(x)
                
                # Batch normalization
                if model_params['batch_normalization']:
                    x = BatchNormalization(name=f'batch_norm_{i+1}')(x)
                
                # Dropout
                if model_params['dropout_rate'] > 0:
                    x = Dropout(model_params['dropout_rate'], name=f'dropout_{i+1}')(x)
            
            # Output layer
            if n_classes > 2:
                # Multi-class
                outputs = Dense(n_classes, activation='softmax', name='output')(x)
                loss = 'categorical_crossentropy'
                metrics = ['accuracy']
            else:
                # Binary
                outputs = Dense(1, activation='sigmoid', name='output')(x)
                loss = 'binary_crossentropy'
                metrics = ['accuracy']
            
            # Create model
            model = Model(inputs=inputs, outputs=outputs, name='dnn_classifier')
            
            # Configure optimizer
            if model_params['optimizer'] == 'adam':
                optimizer = Adam(learning_rate=model_params['learning_rate'])
            elif model_params['optimizer'] == 'sgd':
                optimizer = SGD(learning_rate=model_params['learning_rate'], momentum=0.9)
            elif model_params['optimizer'] == 'rmsprop':
                optimizer = RMSprop(learning_rate=model_params['learning_rate'])
            else:
                optimizer = Adam(learning_rate=model_params['learning_rate'])
            
            # Compile model
            model.compile(
                optimizer=optimizer,
                loss=loss,
                metrics=metrics
            )
            
            return model
            
        except Exception as e:
            print(f"❌ Error creating DNN model: {e}")
            raise
    
    def _create_callbacks(self, patience: int = 10, min_delta: float = 0.001) -> List:
        """
        Create training callbacks for better training control
        
        Args:
            patience: Patience for early stopping
            min_delta: Minimum change for early stopping
            
        Returns:
            List of Keras callbacks
        """
        callbacks = []
        
        try:
            # Early stopping
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=patience,
                min_delta=min_delta,
                restore_best_weights=True,
                verbose=0
            )
            callbacks.append(early_stopping)
            
            # Learning rate reduction
            lr_reduction = ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=patience//2,
                min_lr=1e-7,
                verbose=0
            )
            callbacks.append(lr_reduction)
            
            self.training_history['callbacks_used'] = [
                'EarlyStopping', 'ReduceLROnPlateau'
            ]
            
        except Exception as e:
            print(f"⚠️ Callback creation warning: {e}")
        
        return callbacks
    
    def _calculate_comprehensive_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                       y_pred_proba: np.ndarray, n_classes: int) -> Dict[str, float]:
        """
        Calculate comprehensive metrics for model evaluation
        **ADDED**: Essential method for comprehensive metrics calculation
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Predicted probabilities
            n_classes: Number of classes
            
        Returns:
            Dictionary of comprehensive metrics
        """
        try:
            # Basic metrics
            accuracy = accuracy_score(y_true, y_pred)
            
            # Classification metrics with different averaging strategies
            if n_classes > 2:  # Multiclass
                precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
                precision_micro = precision_score(y_true, y_pred, average='micro', zero_division=0)
                precision_weighted = precision_score(y_true, y_pred, average='weighted', zero_division=0)
                
                recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
                recall_micro = recall_score(y_true, y_pred, average='micro', zero_division=0)
                recall_weighted = recall_score(y_true, y_pred, average='weighted', zero_division=0)
                
                f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
                f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
                f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
                
                # For multiclass, use one-vs-rest approach for AUC
                try:
                    auc_roc = roc_auc_score(y_true, y_pred_proba, multi_class='ovr', average='weighted')
                except Exception:
                    auc_roc = 0.0
                
                auc_pr = 0.0  # Placeholder for multiclass PR-AUC
                
            else:  # Binary classification
                precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
                precision_micro = precision_score(y_true, y_pred, average='micro', zero_division=0)
                precision_weighted = precision_score(y_true, y_pred, average='weighted', zero_division=0)
                
                recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
                recall_micro = recall_score(y_true, y_pred, average='micro', zero_division=0)
                recall_weighted = recall_score(y_true, y_pred, average='weighted', zero_division=0)
                
                f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
                f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
                f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
                
                # ROC curve and AUC for binary classification
                try:
                    if y_pred_proba.ndim > 1 and y_pred_proba.shape[1] > 1:
                        y_pred_proba_positive = y_pred_proba[:, 1]  # Positive class probabilities
                    else:
                        y_pred_proba_positive = y_pred_proba.ravel()
                    
                    fpr, tpr, roc_thresholds = roc_curve(y_true, y_pred_proba_positive)
                    auc_roc = auc(fpr, tpr)
                    
                    # Precision-Recall curve and AUC
                    precision_curve, recall_curve, pr_thresholds = precision_recall_curve(y_true, y_pred_proba_positive)
                    auc_pr = auc(recall_curve, precision_curve)
                    
                except Exception as e:
                    print(f"⚠️ AUC calculation warning: {e}")
                    auc_roc = 0.0
                    auc_pr = 0.0
            
            # Log loss
            try:
                if n_classes > 2:
                    # Multiclass log loss
                    log_loss_val = log_loss(y_true, y_pred_proba, labels=np.unique(y_true))
                else:
                    # Binary log loss
                    if y_pred_proba.ndim > 1 and y_pred_proba.shape[1] > 1:
                        log_loss_val = log_loss(y_true, y_pred_proba[:, 1])
                    else:
                        log_loss_val = log_loss(y_true, y_pred_proba.ravel())
            except Exception as e:
                print(f"⚠️ Log loss calculation warning: {e}")
                log_loss_val = 0.0
            
            # Confusion matrix
            try:
                cm = confusion_matrix(y_true, y_pred)
            except Exception:
                cm = np.array([[0]])
            
            # Compile comprehensive metrics
            metrics = {
                'accuracy': float(accuracy),
                'precision_macro': float(precision_macro),
                'precision_micro': float(precision_micro),
                'precision_weighted': float(precision_weighted),
                'recall_macro': float(recall_macro),
                'recall_micro': float(recall_micro),
                'recall_weighted': float(recall_weighted),
                'f1_macro': float(f1_macro),
                'f1_micro': float(f1_micro),
                'f1_weighted': float(f1_weighted),
                'auc_roc': float(auc_roc),
                'auc_pr': float(auc_pr),
                'log_loss': float(log_loss_val),
                'confusion_matrix': cm.tolist()
            }
            
            # Add curve data for binary classification visualization
            if n_classes == 2:
                try:
                    if y_pred_proba.ndim > 1 and y_pred_proba.shape[1] > 1:
                        y_pred_proba_positive = y_pred_proba[:, 1]
                    else:
                        y_pred_proba_positive = y_pred_proba.ravel()
                    
                    fpr, tpr, roc_thresholds = roc_curve(y_true, y_pred_proba_positive)
                    precision_curve, recall_curve, pr_thresholds = precision_recall_curve(y_true, y_pred_proba_positive)
                    
                    metrics['roc_curve'] = (fpr.tolist(), tpr.tolist(), roc_thresholds.tolist())
                    metrics['pr_curve'] = (precision_curve.tolist(), recall_curve.tolist(), pr_thresholds.tolist())
                except Exception as e:
                    print(f"⚠️ ROC/PR curve data warning: {e}")
            
            return metrics
            
        except Exception as e:
            print(f"❌ Comprehensive metrics calculation failed: {e}")
            # Return default metrics structure
            return {
                'accuracy': 0.0, 'precision_macro': 0.0, 'precision_micro': 0.0, 'precision_weighted': 0.0,
                'recall_macro': 0.0, 'recall_micro': 0.0, 'recall_weighted': 0.0,
                'f1_macro': 0.0, 'f1_micro': 0.0, 'f1_weighted': 0.0,
                'auc_roc': 0.0, 'auc_pr': 0.0, 'log_loss': 0.0, 'confusion_matrix': []
            }
    
    def train(self, X_train: pd.DataFrame, y_train: pd.Series, 
              X_val: pd.DataFrame = None, y_val: pd.Series = None,
              config: Dict[str, Any] = None, use_hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Train DNN model with optional hyperparameter tuning
        
        Args:
            X_train: Training features
            y_train: Training labels
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            config: Training configuration
            use_hyperparameter_tuning: Enable hyperparameter tuning
            
        Returns:
            Dictionary with training results and metrics
        """
        try:
            print("🚀 Starting DNN training...")
            training_start = time.time()
            self._monitor_memory("training_start")
            
            # Validate and prepare data
            X_train_array, y_train_array = self._validate_input_data(X_train, y_train)
            
            if X_val is not None and y_val is not None:
                X_val_array, y_val_array = self._validate_input_data(X_val, y_val)
            else:
                X_val_array, y_val_array = None, None
            
            # Scale features for neural network
            if self.scaler is None:
                self.scaler = StandardScaler()
                X_train_scaled = self.scaler.fit_transform(X_train_array)
            else:
                X_train_scaled = self.scaler.transform(X_train_array)
            
            if X_val_array is not None:
                X_val_scaled = self.scaler.transform(X_val_array)
            else:
                X_val_scaled = None
            
            # Configure training
            if config is None:
                config = {}
            
            # Get data dimensions
            input_shape = X_train_scaled.shape[1]
            n_classes = len(np.unique(y_train)) if len(y_train_array.shape) == 1 else y_train_array.shape[1]
            
            # Perform hyperparameter tuning if requested
            if use_hyperparameter_tuning:
                print("🔧 Performing hyperparameter tuning...")
                tuning_results = self.hyperparameter_tuning(
                    X_train, y_train,
                    param_grid=config.get('param_grid'),
                    method=config.get('hyperparameter_method', 'grid'),
                    cv_folds=config.get('hyperparameter_cv', 3),
                    scoring=config.get('hyperparameter_scoring', 'f1_weighted'),
                    timeout_minutes=config.get('hyperparameter_timeout', 30),
                    n_iter=config.get('n_iter', 20)
                )
                
                # Use best parameters
                best_params = tuning_results['best_parameters']
                print(f"🎯 Best parameters: {best_params}")
                
            else:
                # Use default or provided parameters
                best_params = config.get('model_params', {
                    'hidden_layers': (128, 64),
                    'learning_rate': 0.001,
                    'batch_size': 64,
                    'dropout_rate': 0.2,
                    'activation': 'relu',
                    'optimizer': 'adam',
                    'l1_reg': 0.0,
                    'l2_reg': 0.001,
                    'batch_normalization': True
                })
                print(f"🎯 Using parameters: {best_params}")
            
            # Create and train model
            print("🏋️ Training DNN model...")
            self.model = self._create_base_model(input_shape, n_classes, **best_params)
            
            # Create callbacks
            callbacks = self._create_callbacks(
                patience=config.get('early_stopping_patience', 10),
                min_delta=config.get('early_stopping_min_delta', 0.001)
            )
            
            # Training parameters
            epochs = config.get('epochs', 100)
            batch_size = best_params.get('batch_size', 64)
            verbose = config.get('verbose', 0)
            
            # Prepare validation data
            validation_data = None
            if X_val_scaled is not None and y_val_array is not None:
                validation_data = (X_val_scaled, y_val_array)
            
            fit_start = time.time()
            
            # Train model
            history = self.model.fit(
                X_train_scaled, y_train_array,
                epochs=epochs,
                batch_size=batch_size,
                validation_data=validation_data,
                callbacks=callbacks,
                verbose=verbose
            )
            
            fit_time = time.time() - fit_start
            
            self.is_fitted = True
            self.best_params = best_params
            
            print(f"✅ Model training completed in {fit_time:.2f}s")
            self._monitor_memory("training_complete")
            
            # Calculate training metrics
            print("📊 Calculating training metrics...")
            train_pred_proba = self.model.predict(X_train_scaled, verbose=0)
            train_pred = self._convert_predictions(train_pred_proba, n_classes)
            
            # Convert y_train back to original format for metrics
            y_train_original = y_train.values if hasattr(y_train, 'values') else y_train
            if self.label_encoder is not None:
                y_train_for_metrics = y_train_original
            else:
                y_train_for_metrics = y_train_original
            
            train_metrics = self._calculate_comprehensive_metrics(
                y_train_for_metrics, train_pred, train_pred_proba, n_classes
            )
            
            # Calculate validation metrics if validation data provided
            val_metrics = {}
            if X_val_scaled is not None and y_val_array is not None:
                print("📊 Calculating validation metrics...")
                val_pred_proba = self.model.predict(X_val_scaled, verbose=0)
                val_pred = self._convert_predictions(val_pred_proba, n_classes)
                
                # Convert y_val back to original format for metrics
                y_val_original = y_val.values if hasattr(y_val, 'values') else y_val
                if self.label_encoder is not None:
                    y_val_for_metrics = y_val_original
                else:
                    y_val_for_metrics = y_val_original
                
                val_metrics = self._calculate_comprehensive_metrics(
                    y_val_for_metrics, val_pred, val_pred_proba, n_classes
                )
            
            # Store training history
            total_training_time = time.time() - training_start
            self.training_history.update({
                'training_time': total_training_time,
                'fit_time': fit_time,
                'tuning_time': tuning_results.get('tuning_time', 0.0) if use_hyperparameter_tuning else 0.0,
                'validation_scores': [val_metrics.get('f1_weighted', 0.0)] if val_metrics else [],
                'history': {
                    'loss': history.history.get('loss', []),
                    'accuracy': history.history.get('accuracy', []),
                    'val_loss': history.history.get('val_loss', []),
                    'val_accuracy': history.history.get('val_accuracy', [])
                },
                'model_complexity': {
                    'hidden_layers': best_params.get('hidden_layers', (128, 64)),
                    'total_params': self.model.count_params(),
                    'trainable_params': sum([tf.keras.backend.count_params(w) for w in self.model.trainable_weights]),
                    'layers': len(self.model.layers),
                    'input_shape': input_shape,
                    'n_classes': n_classes
                }
            })
            
            # Prepare results
            results = {
                'model_name': 'dnn',
                'training_time': total_training_time,
                'fit_time': fit_time,
                'best_parameters': best_params,
                'train_metrics': train_metrics,
                'validation_metrics': val_metrics,
                'training_history': self.training_history['history'],
                'model_complexity': self.training_history['model_complexity'],
                'hyperparameter_tuning': tuning_results if use_hyperparameter_tuning else {'enabled': False},
                'memory_usage': self.memory_usage,
                'dataset_info': {
                    'n_samples': len(X_train),
                    'n_features': X_train.shape[1],
                    'n_classes': n_classes,
                    'class_distribution': dict(zip(*np.unique(y_train_for_metrics, return_counts=True)))
                }
            }
            
            print(f"🎉 DNN training completed successfully!")
            print(f"⏱️ Total time: {total_training_time:.2f}s")
            print(f"📊 Training accuracy: {train_metrics['accuracy']:.4f}")
            if val_metrics:
                print(f"📊 Validation accuracy: {val_metrics['accuracy']:.4f}")
            print(f"🧠 Model parameters: {self.model.count_params():,}")
            
            return results
            
        except Exception as e:
            print(f"❌ DNN training failed: {e}")
            raise
    
    def _convert_predictions(self, pred_proba: np.ndarray, n_classes: int) -> np.ndarray:
        """
        Convert probability predictions to class predictions
        
        Args:
            pred_proba: Probability predictions
            n_classes: Number of classes
            
        Returns:
            Class predictions
        """
        if n_classes > 2:
            # Multi-class: argmax
            predictions = np.argmax(pred_proba, axis=1)
        else:
            # Binary: threshold at 0.5
            predictions = (pred_proba.ravel() > 0.5).astype(int)
        
        return predictions
    
    def predict(self, X_test: pd.DataFrame) -> np.ndarray:
        """
        Make predictions on test data
        
        Args:
            X_test: Test features
            
        Returns:
            Predicted labels
        """
        try:
            if not self.is_fitted:
                raise ValueError("Model must be trained before making predictions")
            
            print("🔮 Making predictions...")
            X_test_array, _ = self._validate_input_data(X_test)
            
            # Scale features
            X_test_scaled = self.scaler.transform(X_test_array)
            
            # Get predictions
            pred_proba = self.model.predict(X_test_scaled, verbose=0)
            
            # Determine number of classes
            if len(pred_proba.shape) > 1 and pred_proba.shape[1] > 1:
                n_classes = pred_proba.shape[1]
            else:
                n_classes = 2
            
            predictions = self._convert_predictions(pred_proba, n_classes)
            
            # Decode labels if necessary
            if self.label_encoder is not None:
                predictions = self.label_encoder.inverse_transform(predictions)
            
            print(f"✅ Predictions completed: {len(predictions)} samples")
            return predictions
            
        except Exception as e:
            print(f"❌ Prediction failed: {e}")
            raise
    
    def predict_proba(self, X_test: pd.DataFrame) -> np.ndarray:
        """
        Predict class probabilities for test data
        
        Args:
            X_test: Test features
            
        Returns:
            Class probabilities
        """
        try:
            if not self.is_fitted:
                raise ValueError("Model must be trained before making predictions")
            
            print("🔮 Predicting probabilities...")
            X_test_array, _ = self._validate_input_data(X_test)
            
            # Scale features
            X_test_scaled = self.scaler.transform(X_test_array)
            
            # Get probability predictions
            probabilities = self.model.predict(X_test_scaled, verbose=0)
            
            # For binary classification, ensure 2D output
            if len(probabilities.shape) == 1 or probabilities.shape[1] == 1:
                prob_positive = probabilities.ravel()
                prob_negative = 1 - prob_positive
                probabilities = np.column_stack([prob_negative, prob_positive])
            
            print(f"✅ Probability predictions completed: {probabilities.shape}")
            return probabilities
            
        except Exception as e:
            print(f"❌ Probability prediction failed: {e}")
            raise
    
    def evaluate(self, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, float]:
        """
        Comprehensive model evaluation with all required metrics including ROC/PR curves
        **ENHANCED**: Added ROC curve and Precision-Recall curve data
        """
        try:
            # Make predictions
            y_pred = self.predict(X_test)
            y_pred_proba = self.predict_proba(X_test)
            
            # Basic metrics
            accuracy = accuracy_score(y_test, y_pred)
            
            # Classification report
            if len(np.unique(y_test)) > 2:  # Multiclass
                precision_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
                precision_micro = precision_score(y_test, y_pred, average='micro', zero_division=0)
                precision_weighted = precision_score(y_test, y_pred, average='weighted', zero_division=0)
                
                recall_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
                recall_micro = recall_score(y_test, y_pred, average='micro', zero_division=0)
                recall_weighted = recall_score(y_test, y_pred, average='weighted', zero_division=0)
                
                f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
                f1_micro = f1_score(y_test, y_pred, average='micro', zero_division=0)
                f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
                
                # For multiclass, use one-vs-rest approach
                auc_roc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', average='weighted')
                auc_pr = 0.0  # Placeholder for multiclass PR-AUC
                
            else:  # Binary classification
                precision_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
                precision_micro = precision_score(y_test, y_pred, average='micro', zero_division=0)
                precision_weighted = precision_score(y_test, y_pred, average='weighted', zero_division=0)
                
                recall_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
                recall_micro = recall_score(y_test, y_pred, average='micro', zero_division=0)
                recall_weighted = recall_score(y_test, y_pred, average='weighted', zero_division=0)
                
                f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
                f1_micro = f1_score(y_test, y_pred, average='micro', zero_division=0)
                f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)
                
                # ROC curve and AUC
                if y_pred_proba.ndim > 1 and y_pred_proba.shape[1] > 1:
                    y_pred_proba_positive = y_pred_proba[:, 1]  # Positive class probabilities
                else:
                    y_pred_proba_positive = y_pred_proba.ravel()
                
                fpr, tpr, roc_thresholds = roc_curve(y_test, y_pred_proba_positive)
                auc_roc = auc(fpr, tpr)
                
                # Precision-Recall curve and AUC
                precision_curve, recall_curve, pr_thresholds = precision_recall_curve(y_test, y_pred_proba_positive)
                auc_pr = auc(recall_curve, precision_curve)
            
            # Log loss
            try:
                if len(np.unique(y_test)) > 2:
                    log_loss_val = log_loss(y_test, y_pred_proba, labels=np.unique(y_test))
                else:
                    log_loss_val = log_loss(y_test, y_pred_proba_positive)
            except Exception:
                log_loss_val = 0.0
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # Return comprehensive metrics
            metrics = {
                'accuracy': float(accuracy),
                'precision_macro': float(precision_macro),
                'precision_micro': float(precision_micro), 
                'precision_weighted': float(precision_weighted),
                'recall_macro': float(recall_macro),
                'recall_micro': float(recall_micro),
                'recall_weighted': float(recall_weighted),
                'f1_macro': float(f1_macro),
                'f1_micro': float(f1_micro),
                'f1_weighted': float(f1_weighted),
                'auc_roc': float(auc_roc),
                'auc_pr': float(auc_pr),
                'log_loss': float(log_loss_val),
                'confusion_matrix': cm.tolist()
            }
            
            # **NEW**: Add curve data for visualization
            if len(np.unique(y_test)) == 2:  # Binary classification
                metrics['roc_curve'] = (fpr.tolist(), tpr.tolist(), roc_thresholds.tolist())
                metrics['pr_curve'] = (precision_curve.tolist(), recall_curve.tolist(), pr_thresholds.tolist())
            
            return metrics
            
        except Exception as e:
            print(f"❌ Evaluation failed: {e}")
            return {
                'accuracy': 0.0, 'precision_macro': 0.0, 'precision_micro': 0.0, 'precision_weighted': 0.0,
                'recall_macro': 0.0, 'recall_micro': 0.0, 'recall_weighted': 0.0,
                'f1_macro': 0.0, 'f1_micro': 0.0, 'f1_weighted': 0.0,
                'auc_roc': 0.0, 'auc_pr': 0.0, 'log_loss': 0.0, 'confusion_matrix': []
            }
    
    def get_feature_importance(self) -> np.ndarray:
        """
        Get feature importance (limited for neural networks)
        
        Returns:
            Feature importance array or None if not available
        """
        try:
            if not self.is_fitted:
                print("⚠️ Model not fitted - cannot get feature importance")
                return None
            
            # For neural networks, feature importance is not directly available
            # We can compute input layer weights as a proxy
            if hasattr(self.model, 'layers') and len(self.model.layers) > 0:
                first_layer = self.model.layers[0]
                if hasattr(first_layer, 'get_weights'):
                    weights = first_layer.get_weights()
                    if len(weights) > 0:
                        # Use absolute mean of input weights as importance
                        importance = np.mean(np.abs(weights[0]), axis=1)
                        print(f"✅ Feature importance approximated: {len(importance)} features")
                        return importance
            
            print("⚠️ Feature importance not available for neural networks")
            return None
                
        except Exception as e:
            print(f"❌ Feature importance extraction failed: {e}")
            return None
    
    def cross_validate(self, X: pd.DataFrame, y: pd.Series, cv_folds: int = 3) -> Dict[str, Any]:
        """
        Perform cross-validation with comprehensive metrics (simplified for neural networks)
        
        Args:
            X: Features
            y: Labels
            cv_folds: Number of cross-validation folds
            
        Returns:
            Cross-validation results
        """
        try:
            print(f"🔄 Performing {cv_folds}-fold cross-validation...")
            
            # Prepare data
            X_array, y_array = self._validate_input_data(X, y)
            
            # Scale features
            if self.scaler is None:
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X_array)
            else:
                X_scaled = self.scaler.transform(X_array)
            
            # Get original labels for metrics
            y_original = y.values if hasattr(y, 'values') else y
            
            # Use stratified k-fold
            skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
            
            # Results storage
            results = {
                'cv_folds': cv_folds,
                'mean_scores': {},
                'std_scores': {},
                'detailed_scores': {}
            }
            
            fold_scores = {
                'accuracy': [],
                'precision_weighted': [],
                'recall_weighted': [],
                'f1_weighted': [],
                'auc_roc': []
            }
            
            # Perform cross-validation manually
            for fold, (train_idx, val_idx) in enumerate(skf.split(X_scaled, y_original)):
                print(f"  Fold {fold + 1}/{cv_folds}...")
                
                # Split data
                X_train_fold = X_scaled[train_idx]
                X_val_fold = X_scaled[val_idx]
                y_train_fold = y_array[train_idx] if len(y_array.shape) > 1 else y_original[train_idx]
                y_val_fold = y_original[val_idx]
                
                # Get dimensions
                input_shape = X_train_fold.shape[1]
                n_classes = len(np.unique(y_original))
                
                # Create and train model for this fold
                fold_model = self._create_base_model(input_shape, n_classes, **self.best_params)
                
                # Train with minimal epochs for CV
                fold_model.fit(
                    X_train_fold, y_train_fold,
                    epochs=20,  # Reduced epochs for CV
                    batch_size=64,
                    verbose=0
                )
                
                # Make predictions
                val_pred_proba = fold_model.predict(X_val_fold, verbose=0)
                val_pred = self._convert_predictions(val_pred_proba, n_classes)
                
                # Calculate metrics
                fold_scores['accuracy'].append(accuracy_score(y_val_fold, val_pred))
                fold_scores['precision_weighted'].append(precision_score(y_val_fold, val_pred, average='weighted', zero_division=0))
                fold_scores['recall_weighted'].append(recall_score(y_val_fold, val_pred, average='weighted', zero_division=0))
                fold_scores['f1_weighted'].append(f1_score(y_val_fold, val_pred, average='weighted', zero_division=0))
                
                # AUC (if binary classification)
                try:
                    if n_classes == 2:
                        fold_scores['auc_roc'].append(roc_auc_score(y_val_fold, val_pred_proba[:, 1]))
                    else:
                        fold_scores['auc_roc'].append(roc_auc_score(y_val_fold, val_pred_proba, multi_class='ovr', average='weighted'))
                except:
                    fold_scores['auc_roc'].append(0.0)
            
            # Calculate summary statistics
            for metric, scores in fold_scores.items():
                results['mean_scores'][f'{metric}_test'] = np.mean(scores)
                results['std_scores'][f'{metric}_test'] = np.std(scores)
                results['detailed_scores'][f'{metric}_test'] = scores
            
            print("✅ Cross-validation completed")
            return results
            
        except Exception as e:
            print(f"❌ Cross-validation failed: {e}")
            return {'error': str(e)}
    
    def hyperparameter_tuning(self, X_train: pd.DataFrame, y_train: pd.Series,
                             param_grid: Dict[str, Any] = None, method: str = 'random',
                             cv_folds: int = 3, scoring: str = 'f1_weighted',
                             timeout_minutes: int = 60, n_iter: int = 20) -> Dict[str, Any]:
        """
        Comprehensive hyperparameter tuning with multiple methods
        
        Args:
            X_train: Training features
            y_train: Training labels
            param_grid: Parameter grid (optional)
            method: Tuning method ('grid', 'random', 'bayesian')
            cv_folds: Cross-validation folds
            scoring: Scoring metric
            timeout_minutes: Maximum time limit
            n_iter: Number of iterations for random/bayesian search
            
        Returns:
            Hyperparameter tuning results
        """
        try:
            print(f"🔧 Starting hyperparameter tuning using {method} method...")
            tuning_start = time.time()
            
            # Prepare data
            X_array, y_array = self._validate_input_data(X_train, y_train)
            
            # Scale features
            if self.scaler is None:
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X_array)
            else:
                X_scaled = self.scaler.transform(X_array)
            
            # Get original labels
            y_original = y_train.values if hasattr(y_train, 'values') else y_train
            
            # Use provided or default parameter grid
            if param_grid is None:
                # Choose grid based on dataset size for efficiency
                if len(X_train) > 10000:
                    param_grid = self.fast_param_grid
                    print("📊 Using fast parameter grid for large dataset")
                else:
                    param_grid = self.default_param_grid
                    print("📊 Using full parameter grid")
            
            # Get dimensions
            input_shape = X_scaled.shape[1]
            n_classes = len(np.unique(y_original))
            
            results = {
                'method': method,
                'param_grid': param_grid,
                'cv_folds': cv_folds,
                'scoring': scoring,
                'timeout_minutes': timeout_minutes,
                'tuning_time': 0.0,
                'best_parameters': {},
                'best_score': 0.0,
                'cv_results': {},
                'search_history': []
            }
            
            best_score = 0.0
            best_params = {}
            search_results = []
            
            if method in ['grid', 'random']:
                # Manual grid/random search for neural networks
                import itertools
                from random import sample
                
                # Generate parameter combinations
                param_names = list(param_grid.keys())
                param_values = list(param_grid.values())
                all_combinations = list(itertools.product(*param_values))
                
                if method == 'random' and len(all_combinations) > n_iter:
                    # Random sampling
                    combinations = sample(all_combinations, n_iter)
                    print(f"🎲 Random search with {len(combinations)} combinations...")
                else:
                    # Grid search (or all combinations if less than n_iter)
                    combinations = all_combinations[:n_iter] if method == 'random' else all_combinations
                    print(f"🔍 Grid search over {len(combinations)} combinations...")
                
                # Evaluate each combination
                for i, param_combo in enumerate(combinations):
                    if time.time() - tuning_start > timeout_minutes * 60:
                        print(f"⏰ Timeout reached, stopping search...")
                        break
                    
                    # Create parameter dictionary
                    params = dict(zip(param_names, param_combo))
                    
                    try:
                        # Perform cross-validation
                        cv_scores = []
                        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
                        
                        for train_idx, val_idx in skf.split(X_scaled, y_original):
                            X_train_cv = X_scaled[train_idx]
                            X_val_cv = X_scaled[val_idx]
                            y_train_cv = y_array[train_idx] if len(y_array.shape) > 1 else y_original[train_idx]
                            y_val_cv = y_original[val_idx]
                            
                            # Create and train model
                            cv_model = self._create_base_model(input_shape, n_classes, **params)
                            cv_model.fit(X_train_cv, y_train_cv, epochs=10, batch_size=params.get('batch_size', 64), verbose=0)
                            
                            # Evaluate
                            val_pred_proba = cv_model.predict(X_val_cv, verbose=0)
                            val_pred = self._convert_predictions(val_pred_proba, n_classes)
                            
                            if scoring == 'f1_weighted':
                                score = f1_score(y_val_cv, val_pred, average='weighted', zero_division=0)
                            elif scoring == 'accuracy':
                                score = accuracy_score(y_val_cv, val_pred)
                            else:
                                score = f1_score(y_val_cv, val_pred, average='weighted', zero_division=0)
                            
                            cv_scores.append(score)
                        
                        mean_score = np.mean(cv_scores)
                        search_results.append({'params': params, 'score': mean_score, 'cv_scores': cv_scores})
                        
                        if mean_score > best_score:
                            best_score = mean_score
                            best_params = params
                        
                        print(f"  Combination {i+1}/{len(combinations)}: {mean_score:.4f}")
                        
                    except Exception as e:
                        print(f"  ⚠️ Failed combination {i+1}: {e}")
                        continue
                
            elif method == 'bayesian' and OPTUNA_AVAILABLE:
                # Bayesian optimization with Optuna
                print(f"🧠 Bayesian optimization with {n_iter} trials...")
                
                def objective(trial):
                    # Sample parameters
                    params = {}
                    for param, config in DNN_OPTUNA_SPACE.items():
                        if config[0] == 'log_uniform':
                            params[param] = trial.suggest_loguniform(param, config[1], config[2])
                        elif config[0] == 'uniform':
                            params[param] = trial.suggest_uniform(param, config[1], config[2])
                        elif config[0] == 'categorical':
                            params[param] = trial.suggest_categorical(param, config[1])
                        elif config[0] == 'int':
                            params[param] = trial.suggest_int(param, config[1], config[2])
                    
                    try:
                        # Perform simplified cross-validation
                        cv_scores = []
                        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
                        
                        for train_idx, val_idx in skf.split(X_scaled, y_original):
                            X_train_cv = X_scaled[train_idx]
                            X_val_cv = X_scaled[val_idx]
                            y_train_cv = y_array[train_idx] if len(y_array.shape) > 1 else y_original[train_idx]
                            y_val_cv = y_original[val_idx]
                            
                            # Create and train model
                            cv_model = self._create_base_model(input_shape, n_classes, **params)
                            cv_model.fit(X_train_cv, y_train_cv, epochs=5, batch_size=params.get('batch_size', 64), verbose=0)
                            
                            # Evaluate
                            val_pred_proba = cv_model.predict(X_val_cv, verbose=0)
                            val_pred = self._convert_predictions(val_pred_proba, n_classes)
                            
                            score = f1_score(y_val_cv, val_pred, average='weighted', zero_division=0)
                            cv_scores.append(score)
                        
                        return np.mean(cv_scores)
                    
                    except Exception:
                        return 0.0
                
                study = optuna.create_study(
                    direction='maximize',
                    sampler=TPESampler(seed=self.random_state)
                )
                
                study.optimize(objective, n_trials=n_iter, timeout=timeout_minutes*60)
                
                best_params = study.best_params
                best_score = study.best_value
                search_results = [{'params': trial.params, 'score': trial.value} 
                                for trial in study.trials if trial.value is not None]
                
            else:
                # Fallback to random search
                print("⚠️ Advanced optimization not available, using random search")
                return self.hyperparameter_tuning(
                    X_train, y_train, param_grid, 'random', cv_folds, scoring, timeout_minutes, n_iter
                )
            
            # Store results
            tuning_time = time.time() - tuning_start
            results.update({
                'tuning_time': tuning_time,
                'best_parameters': best_params,
                'best_score': best_score,
                'cv_results': {
                    'search_results': search_results
                }
            })
            
            self.best_params = best_params
            self.best_score = best_score
            self.cv_results = results['cv_results']
            self.hyperparameter_tuning_results = results
            
            print(f"✅ Hyperparameter tuning completed in {tuning_time:.2f}s")
            print(f"🎯 Best score: {best_score:.4f}")
            print(f"🎯 Best parameters: {best_params}")
            
            return results
            
        except Exception as e:
            print(f"❌ Hyperparameter tuning failed: {e}")
            return {'error': str(e), 'best_parameters': {}, 'best_score': 0.0}
    
    def save_model(self, filepath: str) -> bool:
        """
        Save trained model to file
        
        Args:
            filepath: Path to save the model
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.is_fitted:
                print("⚠️ No trained model to save")
                return False
            
            # Create directory if it doesn't exist
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Save Keras model
            model_path = filepath.with_suffix('.h5')
            self.model.save(model_path)
            
            # Save additional metadata
            metadata_path = filepath.with_suffix('.pkl')
            model_data = {
                'label_encoder': self.label_encoder,
                'scaler': self.scaler,
                'best_params': self.best_params,
                'training_history': self.training_history,
                'hyperparameter_tuning_results': self.hyperparameter_tuning_results,
                'model_info': {
                    'model_type': 'dnn',
                    'random_state': self.random_state,
                    'timestamp': datetime.now().isoformat()
                }
            }
            
            joblib.dump(model_data, metadata_path)
            print(f"✅ Model saved to {model_path} and {metadata_path}")
            return True
            
        except Exception as e:
            print(f"❌ Model saving failed: {e}")
            return False
    
    def load_model(self, filepath: str) -> bool:
        """
        Load model from file
        
        Args:
            filepath: Path to load the model from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            filepath = Path(filepath)
            model_path = filepath.with_suffix('.h5')
            metadata_path = filepath.with_suffix('.pkl')
            
            if not model_path.exists() or not metadata_path.exists():
                print(f"❌ Model files not found: {model_path} or {metadata_path}")
                return False
            
            # Load Keras model
            self.model = keras.models.load_model(model_path)
            
            # Load metadata
            model_data = joblib.load(metadata_path)
            
            self.label_encoder = model_data.get('label_encoder')
            self.scaler = model_data.get('scaler')
            self.best_params = model_data.get('best_params', {})
            self.training_history = model_data.get('training_history', {})
            self.hyperparameter_tuning_results = model_data.get('hyperparameter_tuning_results', {})
            self.is_fitted = True
            
            print(f"✅ Model loaded from {model_path} and {metadata_path}")
            return True
            
        except Exception as e:
            print(f"❌ Model loading failed: {e}")
            return False
    
    def get_training_history(self) -> Dict[str, List[float]]:
        """Get training history"""
        return self.training_history.copy()
    
    def save_hyperparameter_results(self, filepath: str) -> bool:
        """
        Save hyperparameter tuning results to file
        
        Args:
            filepath: Path to save results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.hyperparameter_tuning_results:
                print("⚠️ No hyperparameter tuning results to save")
                return False
            
            # Create directory if it doesn't exist
            filepath = Path(filepath)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Save as JSON for readability
            json_path = filepath.with_suffix('.json')
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(self.hyperparameter_tuning_results, f, indent=2, default=str)
            
            # Also save as pickle for complete data preservation
            pkl_path = filepath.with_suffix('.pkl')
            joblib.dump(self.hyperparameter_tuning_results, pkl_path)
            
            print(f"✅ Hyperparameter results saved to {json_path} and {pkl_path}")
            return True
            
        except Exception as e:
            print(f"❌ Hyperparameter results saving failed: {e}")
            return False

# Main execution for testing
if __name__ == "__main__":
    print("🧠 Deep Neural Network Model - Standalone Testing")
    print("=" * 60)
    
    try:
        # Initialize model
        dnn_model = DNNModel(random_state=42, n_cores=4, memory_limit=8.0)
        
        # Create sample data for testing
        print("\n📊 Creating sample data for testing...")
        np.random.seed(42)
        n_samples = 1000
        n_features = 50
        
        # Generate synthetic numerical data
        X_sample = np.random.randn(n_samples, n_features).astype(np.float32)
        y_sample = np.random.randint(0, 2, n_samples)  # Binary classification
        
        # Convert to pandas
        feature_names = [f'feature_{i}' for i in range(n_features)]
        X_df = pd.DataFrame(X_sample, columns=feature_names)
        y_series = pd.Series(y_sample, name='target')
        
        print(f"✅ Sample data created: {X_df.shape} features, {len(y_series)} samples")
        
        # Test basic training without hyperparameter tuning
        print("\n🏋️ Testing basic training...")
        config = {
            'epochs': 20,
            'verbose': 1,
            'model_params': {
                'hidden_layers': (64, 32),
                'learning_rate': 0.001,
                'batch_size': 32,
                'dropout_rate': 0.2,
                'activation': 'relu',
                'optimizer': 'adam'
            }
        }
        
        # Split data for validation
        split_idx = int(0.8 * len(X_df))
        X_train = X_df.iloc[:split_idx]
        y_train = y_series.iloc[:split_idx]
        X_val = X_df.iloc[split_idx:]
        y_val = y_series.iloc[split_idx:]
        
        # Train model
        results = dnn_model.train(
            X_train, y_train, X_val, y_val,
            config=config, use_hyperparameter_tuning=False
        )
        
        print(f"\n✅ Basic training completed!")
        print(f"   Training accuracy: {results['train_metrics']['accuracy']:.4f}")
        print(f"   Validation accuracy: {results['validation_metrics']['accuracy']:.4f}")
        print(f"   Training time: {results['training_time']:.2f}s")
        print(f"   Model parameters: {results['model_complexity']['total_params']:,}")
        
        # Test predictions
        print("\n🔮 Testing predictions...")
        predictions = dnn_model.predict(X_val)
        probabilities = dnn_model.predict_proba(X_val)
        
        print(f"✅ Predictions completed:")
        print(f"   Predictions shape: {predictions.shape}")
        print(f"   Probabilities shape: {probabilities.shape}")
        print(f"   Sample predictions: {predictions[:5]}")
        
        # Test evaluation
        print("\n📊 Testing evaluation...")
        eval_metrics = dnn_model.evaluate(X_val, y_val)
        
        print(f"✅ Evaluation completed:")
        print(f"   Accuracy: {eval_metrics['accuracy']:.4f}")
        print(f"   F1 Score: {eval_metrics['f1_weighted']:.4f}")
        print(f"   AUC ROC: {eval_metrics['auc_roc']:.4f}")
        
        # Test model saving
        print("\n💾 Testing model saving...")
        save_path = "outputs/models/test_dnn_model"
        Path("outputs/models").mkdir(parents=True, exist_ok=True)
        
        if dnn_model.save_model(save_path):
            print("✅ Model saved successfully")
        else:
            print("❌ Model saving failed")
        
        # Test hyperparameter tuning (quick test)
        print("\n🔧 Testing hyperparameter tuning (quick)...")
        
        # Use a very small parameter grid for testing
        test_param_grid = {
            'hidden_layers': [(32,), (64,)],
            'learning_rate': [0.001, 0.01],
            'batch_size': [32, 64],
            'dropout_rate': [0.0, 0.2],
            'activation': ['relu', 'tanh'],
            'optimizer': ['adam'],
            'l1_reg': [0.0],
            'l2_reg': [0.001],
            'batch_normalization': [True]
        }
        
        tuning_config = {
            'param_grid': test_param_grid,
            'hyperparameter_method': 'random',
            'hyperparameter_cv': 2,
            'hyperparameter_scoring': 'f1_weighted',
            'hyperparameter_timeout': 5,  # 5 minutes timeout
            'n_iter': 4,  # Test only 4 combinations
            'epochs': 5   # Reduced epochs for quick testing
        }
        
        # Create new model instance for tuning test
        dnn_tuning_model = DNNModel(random_state=42, n_cores=2, memory_limit=8.0)
        
        tuning_results = dnn_tuning_model.train(
            X_train, y_train,
            config=tuning_config,
            use_hyperparameter_tuning=True
        )
        
        print(f"✅ Hyperparameter tuning test completed!")
        print(f"   Best score: {tuning_results['hyperparameter_tuning']['best_score']:.4f}")
        print(f"   Best parameters: {tuning_results['hyperparameter_tuning']['best_parameters']}")
        print(f"   Tuning time: {tuning_results['hyperparameter_tuning']['tuning_time']:.2f}s")
        
        # Test cross-validation
        print("\n🔄 Testing cross-validation...")
        cv_results = dnn_model.cross_validate(X_train, y_train, cv_folds=3)
        
        if 'error' not in cv_results:
            print(f"✅ Cross-validation completed:")
            print(f"   Mean accuracy: {cv_results['mean_scores'].get('accuracy_test', 0):.4f}")
            print(f"   Mean F1 score: {cv_results['mean_scores'].get('f1_weighted_test', 0):.4f}")
        else:
            print(f"⚠️ Cross-validation had issues: {cv_results['error']}")
        
        # Test feature importance (limited for DNN)
        print("\n🎯 Testing feature importance...")
        importance = dnn_model.get_feature_importance()
        if importance is not None:
            print(f"✅ Feature importance extracted: {len(importance)} features")
            print(f"   Top 5 features: {np.argsort(importance)[-5:]}")
        else:
            print("ℹ️ Feature importance not available for neural networks")
        
        # Test hyperparameter results saving
        if dnn_tuning_model.hyperparameter_tuning_results:
            print("\n💾 Testing hyperparameter results saving...")
            hp_save_path = "outputs/hyperparameter_results/test_dnn_hyperparams"
            Path("outputs/hyperparameter_results").mkdir(parents=True, exist_ok=True)
            
            if dnn_tuning_model.save_hyperparameter_results(hp_save_path):
                print("✅ Hyperparameter results saved successfully")
            else:
                print("❌ Hyperparameter results saving failed")
        
        print(f"\n🎉 All DNN model tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Testing failed with error: {e}")
        import traceback
        traceback.print_exc()
        
    print("\n🧠 Deep Neural Network Model testing completed.")
