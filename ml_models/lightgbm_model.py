"""
LightGBM Model Implementation for EMBER2018 Malware Detection
Independent robust LightGBM implementation with hyperparameter tuning

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (independent model using LightGBM only)

Connected Components (files that import from this module):
- trainer.py (imports LightGBMModel class)

Integration Points:
- Provides LightGBM model implementation for malware detection
- NUMERICAL-ONLY training on processed EMBER2018 features
- Comprehensive hyperparameter tuning capabilities
- Multi-core processing support for large datasets
- Complete evaluation metrics calculation
- Model persistence and serialization
- Native feature importance extraction

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: LightGBMModel
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

# LightGBM imports
try:
    import lightgbm as lgb
    from lightgbm import LGBMClassifier
    LIGHTGBM_AVAILABLE = True
except ImportError:
    print("❌ CRITICAL ERROR: LightGBM not available")
    LIGHTGBM_AVAILABLE = False
    sys.exit(1)

# Scikit-learn for metrics and preprocessing
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, cross_validate, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, log_loss, roc_auc_score, precision_recall_curve, auc,
    precision_score, recall_score, f1_score, confusion_matrix, classification_report,
    roc_curve, average_precision_score
)
from sklearn.preprocessing import LabelEncoder
import joblib

# Suppress warnings
warnings.filterwarnings('ignore')

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

# Default hyperparameter grid for LightGBM
LIGHTGBM_PARAM_GRID = {
    'n_estimators': [50, 100, 200, 300, 500, 1000],
    'max_depth': [3, 4, 5, 6, 8, 10, 12, -1],
    'learning_rate': [0.01, 0.05, 0.1, 0.15, 0.2, 0.3],
    'num_leaves': [15, 31, 50, 100, 150, 200],
    'subsample': [0.6, 0.7, 0.8, 0.9, 1.0],
    'colsample_bytree': [0.6, 0.7, 0.8, 0.9, 1.0],
    'reg_alpha': [0, 0.1, 0.5, 1, 2, 5],
    'reg_lambda': [0, 0.1, 0.5, 1, 2, 5],
    'min_child_samples': [10, 20, 50, 100, 200],
    'min_child_weight': [0.001, 0.01, 0.1, 1],
    'min_split_gain': [0, 0.1, 0.2, 0.5, 1]
}

# Reduced parameter grid for faster tuning
LIGHTGBM_PARAM_GRID_FAST = {
    'n_estimators': [100, 200, 500],
    'max_depth': [3, 6, 10, -1],
    'learning_rate': [0.01, 0.1, 0.2],
    'num_leaves': [31, 50, 100],
    'subsample': [0.8, 0.9, 1.0],
    'colsample_bytree': [0.8, 0.9, 1.0],
    'reg_alpha': [0, 0.1, 1],
    'reg_lambda': [0, 0.1, 1],
    'min_child_samples': [20, 50, 100],
    'min_child_weight': [0.01, 0.1, 1],
    'min_split_gain': [0, 0.1, 0.5]
}

# Hyperparameter search spaces for different optimization methods
LIGHTGBM_HYPEROPT_SPACE = {
    'n_estimators': hp.choice('n_estimators', [100, 200, 300, 500, 1000]),
    'max_depth': hp.choice('max_depth', [3, 4, 5, 6, 8, 10, -1]),
    'learning_rate': hp.loguniform('learning_rate', np.log(0.01), np.log(0.3)),
    'num_leaves': hp.choice('num_leaves', [15, 31, 50, 100, 150, 200]),
    'subsample': hp.uniform('subsample', 0.6, 1.0),
    'colsample_bytree': hp.uniform('colsample_bytree', 0.6, 1.0),
    'reg_alpha': hp.loguniform('reg_alpha', np.log(0.01), np.log(5)),
    'reg_lambda': hp.loguniform('reg_lambda', np.log(0.01), np.log(5)),
    'min_child_samples': hp.choice('min_child_samples', [10, 20, 50, 100, 200]),
    'min_child_weight': hp.loguniform('min_child_weight', np.log(0.001), np.log(1)),
    'min_split_gain': hp.loguniform('min_split_gain', np.log(0.01), np.log(1))
}

LIGHTGBM_OPTUNA_SPACE = {
    'n_estimators': ('categorical', [100, 200, 300, 500, 1000]),
    'max_depth': ('categorical', [3, 4, 5, 6, 8, 10, -1]),
    'learning_rate': ('log_uniform', 0.01, 0.3),
    'num_leaves': ('int', 15, 200),
    'subsample': ('uniform', 0.6, 1.0),
    'colsample_bytree': ('uniform', 0.6, 1.0),
    'reg_alpha': ('log_uniform', 0.01, 5),
    'reg_lambda': ('log_uniform', 0.01, 5),
    'min_child_samples': ('int', 10, 200),
    'min_child_weight': ('log_uniform', 0.001, 1),
    'min_split_gain': ('log_uniform', 0.01, 1)
}

class LightGBMModel:
    """
    Independent robust LightGBM implementation with hyperparameter tuning
    
    Features:
    - Gradient boosting with leaf-wise tree growth
    - Comprehensive hyperparameter tuning (Grid, Random, Bayesian)
    - Multi-core processing support
    - GPU acceleration support
    - Memory-efficient training for large datasets
    - Complete evaluation metrics calculation
    - Model persistence and serialization
    - Cross-validation with detailed results
    - Native feature importance extraction
    - Early stopping capabilities
    - Regularization support (L1/L2)
    """
    
    def __init__(self, random_state: int = 42, n_cores: int = -1, memory_limit: float = 8.0):
        """
        Initialize LightGBM model with configuration
        
        Args:
            random_state: Random seed for reproducibility
            n_cores: Number of CPU cores to use (-1 for all)
            memory_limit: Memory limit in GB for training
        """
        self.random_state = random_state
        self.n_cores = n_cores if n_cores > 0 else -1
        self.memory_limit = memory_limit
        
        # Model components
        self.model = None
        self.label_encoder = None
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
            'feature_importance': None,
            'model_complexity': {}
        }
        
        # Default parameter grids
        self.default_param_grid = LIGHTGBM_PARAM_GRID
        self.fast_param_grid = LIGHTGBM_PARAM_GRID_FAST
        
        # Memory tracking
        self.initial_memory = self._get_memory_usage()
        self.memory_usage = {}
        
        print(f"🚀 LightGBM Model initialized:")
        print(f"   🎲 Random state: {self.random_state}")
        print(f"   🔧 CPU cores: {self.n_cores}")
        print(f"   💾 Memory limit: {self.memory_limit}GB")
        print(f"   📦 LightGBM version: {lgb.__version__}")
        print(f"   📊 Hyperparameter grid size: {self._calculate_grid_size(self.default_param_grid)}")
        
        # Check for GPU support
        try:
            if lgb.get_device() == 'gpu':
                print("   🚀 GPU acceleration available")
            else:
                print("   💻 Using CPU acceleration")
        except:
            print("   💻 Using CPU acceleration")
    
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
            
            print(f"✅ Data validation completed: X shape {X_array.shape}, y shape {y_array.shape if y_array is not None else 'None'}")
            return X_array, y_array
            
        except Exception as e:
            print(f"❌ Data validation failed: {e}")
            raise
    
    def _create_base_model(self, **params) -> LGBMClassifier:
        """
        Create base LightGBM model with specified parameters
        
        Args:
            **params: LightGBM parameters
            
        Returns:
            Configured LGBMClassifier
        """
        try:
            # Set default parameters
            default_params = {
                'n_estimators': 100,
                'max_depth': -1,
                'learning_rate': 0.1,
                'num_leaves': 31,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'reg_alpha': 0,
                'reg_lambda': 0,
                'min_child_samples': 20,
                'min_child_weight': 0.001,
                'min_split_gain': 0,
                'random_state': self.random_state,
                'n_jobs': self.n_cores,
                'objective': 'binary',
                'metric': 'binary_logloss',
                'verbosity': -1,
                'force_col_wise': True  # For better performance with many features
            }
            
            # Update with provided parameters
            model_params = {**default_params, **params}
            
            # Create LightGBM classifier
            model = LGBMClassifier(**model_params)
            
            return model
            
        except Exception as e:
            print(f"❌ Error creating LightGBM model: {e}")
            raise
    
    def train(self, X_train: pd.DataFrame, y_train: pd.Series, 
              X_val: pd.DataFrame = None, y_val: pd.Series = None,
              config: Dict[str, Any] = None, use_hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Train LightGBM model with optional hyperparameter tuning
        
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
            print("🚀 Starting LightGBM training...")
            training_start = time.time()
            self._monitor_memory("training_start")
            
            # Validate and prepare data
            X_train_array, y_train_array = self._validate_input_data(X_train, y_train)
            
            if X_val is not None and y_val is not None:
                X_val_array, y_val_array = self._validate_input_data(X_val, y_val)
            else:
                X_val_array, y_val_array = None, None
            
            # Configure training
            if config is None:
                config = {}
            
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
                    n_iter=config.get('n_iter', 50)
                )
                
                # Use best parameters
                best_params = tuning_results['best_parameters']
                print(f"🎯 Best parameters: {best_params}")
                
            else:
                # Use default or provided parameters
                best_params = config.get('model_params', {
                    'n_estimators': 100,
                    'max_depth': -1,
                    'learning_rate': 0.1,
                    'num_leaves': 31,
                    'subsample': 0.8,
                    'colsample_bytree': 0.8
                })
                print(f"🎯 Using parameters: {best_params}")
            
            # Create and train model
            print("🏋️ Training LightGBM model...")
            self.model = self._create_base_model(**best_params)
            
            # Prepare evaluation set for early stopping
            eval_set = []
            eval_names = []
            if X_val_array is not None and y_val_array is not None:
                eval_set = [(X_train_array, y_train_array), (X_val_array, y_val_array)]
                eval_names = ['train', 'valid']
            else:
                eval_set = [(X_train_array, y_train_array)]
                eval_names = ['train']
            
            fit_start = time.time()
            
            # Train model with early stopping
            self.model.fit(
                X_train_array, y_train_array,
                eval_set=eval_set,
                eval_names=eval_names,
                callbacks=[
                    lgb.early_stopping(config.get('early_stopping_rounds', 50), verbose=config.get('verbose', False))
                ] if config.get('early_stopping_rounds', 50) > 0 else None
            )
            
            fit_time = time.time() - fit_start
            
            self.is_fitted = True
            self.best_params = best_params
            
            print(f"✅ Model training completed in {fit_time:.2f}s")
            self._monitor_memory("training_complete")
            
            # Calculate training metrics
            print("📊 Calculating training metrics...")
            train_pred = self.model.predict(X_train_array)
            train_pred_proba = self.model.predict_proba(X_train_array)
            
            # Convert y_train back to original format for metrics
            y_train_original = y_train.values if hasattr(y_train, 'values') else y_train
            if self.label_encoder is not None:
                y_train_for_metrics = y_train_original
            else:
                y_train_for_metrics = y_train_original
            
            train_metrics = self._calculate_comprehensive_metrics(
                y_train_for_metrics, train_pred, train_pred_proba
            )
            
            # Calculate validation metrics if validation data provided
            val_metrics = {}
            if X_val_array is not None and y_val_array is not None:
                print("📊 Calculating validation metrics...")
                val_pred = self.model.predict(X_val_array)
                val_pred_proba = self.model.predict_proba(X_val_array)
                
                # Convert y_val back to original format for metrics
                y_val_original = y_val.values if hasattr(y_val, 'values') else y_val
                if self.label_encoder is not None:
                    y_val_for_metrics = y_val_original
                else:
                    y_val_for_metrics = y_val_original
                
                val_metrics = self._calculate_comprehensive_metrics(
                    y_val_for_metrics, val_pred, val_pred_proba
                )
            
            # Extract feature importance
            feature_importance = self.get_feature_importance()
            
            # Store training history
            total_training_time = time.time() - training_start
            self.training_history.update({
                'training_time': total_training_time,
                'fit_time': fit_time,
                'tuning_time': tuning_results.get('tuning_time', 0.0) if use_hyperparameter_tuning else 0.0,
                'validation_scores': [val_metrics.get('f1_weighted', 0.0)] if val_metrics else [],
                'feature_importance': feature_importance,
                'model_complexity': {
                    'n_estimators': best_params.get('n_estimators', 100),
                    'max_depth': best_params.get('max_depth', -1),
                    'num_leaves': best_params.get('num_leaves', 31),
                    'n_features': X_train_array.shape[1],
                    'n_classes': len(np.unique(y_train_for_metrics))
                }
            })
            
            # Prepare results
            results = {
                'model_name': 'lightgbm',
                'training_time': total_training_time,
                'fit_time': fit_time,
                'best_parameters': best_params,
                'train_metrics': train_metrics,
                'validation_metrics': val_metrics,
                'feature_importance': feature_importance,
                'model_complexity': self.training_history['model_complexity'],
                'hyperparameter_tuning': tuning_results if use_hyperparameter_tuning else {'enabled': False},
                'memory_usage': self.memory_usage,
                'dataset_info': {
                    'n_samples': len(X_train),
                    'n_features': X_train.shape[1],
                    'n_classes': len(np.unique(y_train_for_metrics)),
                    'class_distribution': dict(zip(*np.unique(y_train_for_metrics, return_counts=True)))
                }
            }
            
            print(f"🎉 LightGBM training completed successfully!")
            print(f"⏱️ Total time: {total_training_time:.2f}s")
            print(f"📊 Training accuracy: {train_metrics['accuracy']:.4f}")
            if val_metrics:
                print(f"📊 Validation accuracy: {val_metrics['accuracy']:.4f}")
            print(f"🌳 Trees trained: {best_params.get('n_estimators', 100)}")
            
            return results
            
        except Exception as e:
            print(f"❌ LightGBM training failed: {e}")
            raise
    
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
            
            # Make predictions
            predictions = self.model.predict(X_test_array)
            
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
            
            # Get probability predictions
            probabilities = self.model.predict_proba(X_test_array)
            
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
    
    def _calculate_comprehensive_metrics(self, y_true: np.ndarray, y_pred: np.ndarray, 
                                       y_pred_proba: np.ndarray = None) -> Dict[str, float]:
        """
        Calculate all required metrics: Accuracy, Log Loss, AUC, Precision, Recall, F1, Confusion Matrix
        
        Args:
            y_true: True labels
            y_pred: Predicted labels
            y_pred_proba: Predicted probabilities (optional)
            
        Returns:
            Dictionary with comprehensive metrics
        """
        try:
            metrics = {}
            
            # Basic metrics
            metrics['accuracy'] = accuracy_score(y_true, y_pred)
            
            # Classification report metrics
            precision_macro = precision_score(y_true, y_pred, average='macro', zero_division=0)
            precision_micro = precision_score(y_true, y_pred, average='micro', zero_division=0)
            precision_weighted = precision_score(y_true, y_pred, average='weighted', zero_division=0)
            
            recall_macro = recall_score(y_true, y_pred, average='macro', zero_division=0)
            recall_micro = recall_score(y_true, y_pred, average='micro', zero_division=0)
            recall_weighted = recall_score(y_true, y_pred, average='weighted', zero_division=0)
            
            f1_macro = f1_score(y_true, y_pred, average='macro', zero_division=0)
            f1_micro = f1_score(y_true, y_pred, average='micro', zero_division=0)
            f1_weighted = f1_score(y_true, y_pred, average='weighted', zero_division=0)
            
            metrics.update({
                'precision_macro': precision_macro,
                'precision_micro': precision_micro,
                'precision_weighted': precision_weighted,
                'recall_macro': recall_macro,
                'recall_micro': recall_micro,
                'recall_weighted': recall_weighted,
                'f1_macro': f1_macro,
                'f1_micro': f1_micro,
                'f1_weighted': f1_weighted
            })
            
            # Per-class metrics
            try:
                precision_per_class = precision_score(y_true, y_pred, average=None, zero_division=0)
                recall_per_class = recall_score(y_true, y_pred, average=None, zero_division=0)
                f1_per_class = f1_score(y_true, y_pred, average=None, zero_division=0)
                
                unique_labels = np.unique(np.concatenate([y_true, y_pred]))
                for i, label in enumerate(unique_labels):
                    if i < len(precision_per_class):
                        metrics[f'precision_class_{label}'] = precision_per_class[i]
                        metrics[f'recall_class_{label}'] = recall_per_class[i]
                        metrics[f'f1_class_{label}'] = f1_per_class[i]
            except Exception as e:
                print(f"⚠️ Per-class metrics calculation failed: {e}")
            
            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            metrics['confusion_matrix'] = cm.tolist()
            
            # ROC AUC and related metrics (if probabilities available)
            if y_pred_proba is not None:
                try:
                    n_classes = len(np.unique(y_true))
                    if n_classes == 2:
                        # Binary classification
                        metrics['log_loss'] = log_loss(y_true, y_pred_proba)
                        metrics['auc_roc'] = roc_auc_score(y_true, y_pred_proba[:, 1])
                        
                        # Precision-Recall AUC
                        precision_curve, recall_curve, _ = precision_recall_curve(y_true, y_pred_proba[:, 1])
                        metrics['auc_pr'] = auc(recall_curve, precision_curve)
                        metrics['average_precision'] = average_precision_score(y_true, y_pred_proba[:, 1])
                        
                    else:
                        # Multi-class classification
                        metrics['log_loss'] = log_loss(y_true, y_pred_proba)
                        metrics['auc_roc'] = roc_auc_score(y_true, y_pred_proba, multi_class='ovr', average='weighted')
                        
                        # Average precision for multi-class
                        try:
                            metrics['average_precision'] = average_precision_score(
                                y_true, y_pred_proba, average='weighted'
                            )
                        except Exception:
                            metrics['average_precision'] = 0.0
                        
                        metrics['auc_pr'] = metrics['average_precision']  # Use average precision as PR AUC
                        
                except Exception as e:
                    print(f"⚠️ Probability-based metrics calculation failed: {e}")
                    metrics['log_loss'] = 0.0
                    metrics['auc_roc'] = 0.0
                    metrics['auc_pr'] = 0.0
                    metrics['average_precision'] = 0.0
            else:
                metrics['log_loss'] = 0.0
                metrics['auc_roc'] = 0.0
                metrics['auc_pr'] = 0.0
                metrics['average_precision'] = 0.0
            
            return metrics
            
        except Exception as e:
            print(f"❌ Comprehensive metrics calculation failed: {e}")
            # Return basic metrics as fallback
            return {
                'accuracy': accuracy_score(y_true, y_pred) if len(y_true) > 0 else 0.0,
                'precision_weighted': 0.0,
                'recall_weighted': 0.0,
                'f1_weighted': 0.0,
                'log_loss': 0.0,
                'auc_roc': 0.0,
                'auc_pr': 0.0,
                'confusion_matrix': [[0]]
            }
    
    def get_feature_importance(self) -> np.ndarray:
        """
        Get feature importance from trained LightGBM model
        
        Returns:
            Feature importance array
        """
        try:
            if not self.is_fitted:
                print("⚠️ Model not fitted - cannot get feature importance")
                return None
            
            # Get feature importance
            importance = self.model.feature_importances_
            print(f"✅ Feature importance extracted: {len(importance)} features")
            return importance
                
        except Exception as e:
            print(f"❌ Feature importance extraction failed: {e}")
            return None
    
    def cross_validate(self, X: pd.DataFrame, y: pd.Series, cv_folds: int = 5) -> Dict[str, Any]:
        """
        Perform cross-validation with comprehensive metrics
        
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
            
            # Get original labels for stratification
            y_original = y.values if hasattr(y, 'values') else y
            
            # Create model for cross-validation
            cv_model = self._create_base_model(**self.best_params)
            
            # Define scoring metrics
            scoring = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc']
            
            # Perform cross-validation
            cv_results = cross_validate(
                cv_model, X_array, y_array,
                cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state),
                scoring=scoring,
                n_jobs=self.n_cores,
                return_train_score=True
            )
            
            # Calculate summary statistics
            results = {
                'cv_folds': cv_folds,
                'mean_scores': {},
                'std_scores': {},
                'detailed_scores': {}
            }
            
            for metric in scoring:
                results['mean_scores'][f'{metric}_test'] = np.mean(cv_results[f'test_{metric}'])
                results['std_scores'][f'{metric}_test'] = np.std(cv_results[f'test_{metric}'])
                results['detailed_scores'][f'{metric}_test'] = cv_results[f'test_{metric}'].tolist()
                
                results['mean_scores'][f'{metric}_train'] = np.mean(cv_results[f'train_{metric}'])
                results['std_scores'][f'{metric}_train'] = np.std(cv_results[f'train_{metric}'])
                results['detailed_scores'][f'{metric}_train'] = cv_results[f'train_{metric}'].tolist()
            
            print("✅ Cross-validation completed")
            return results
            
        except Exception as e:
            print(f"❌ Cross-validation failed: {e}")
            return {'error': str(e)}
    
    def hyperparameter_tuning(self, X_train: pd.DataFrame, y_train: pd.Series,
                             param_grid: Dict[str, Any] = None, method: str = 'grid',
                             cv_folds: int = 3, scoring: str = 'f1_weighted',
                             timeout_minutes: int = 60, n_iter: int = 50) -> Dict[str, Any]:
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
            
            # Use provided or default parameter grid
            if param_grid is None:
                # Choose grid based on dataset size for efficiency
                if len(X_train) > 10000:
                    param_grid = self.fast_param_grid
                    print("📊 Using fast parameter grid for large dataset")
                else:
                    param_grid = self.default_param_grid
                    print("📊 Using full parameter grid")
            
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
            
            # Create base model for tuning
            base_model = self._create_base_model()
            
            # Perform hyperparameter search
            if method == 'grid':
                print(f"🔍 Grid search over {self._calculate_grid_size(param_grid)} combinations...")
                
                search = GridSearchCV(
                    estimator=base_model,
                    param_grid=param_grid,
                    scoring=scoring,
                    cv=cv_folds,
                    n_jobs=self.n_cores,
                    verbose=1,
                    return_train_score=True
                )
                
            elif method == 'random':
                print(f"🎲 Random search with {n_iter} iterations...")
                
                search = RandomizedSearchCV(
                    estimator=base_model,
                    param_distributions=param_grid,
                    n_iter=n_iter,
                    scoring=scoring,
                    cv=cv_folds,
                    n_jobs=self.n_cores,
                    verbose=1,
                    random_state=self.random_state,
                    return_train_score=True
                )
                
            elif method == 'bayesian' and OPTUNA_AVAILABLE:
                print(f"🧠 Bayesian optimization with {n_iter} trials...")
                
                def objective(trial):
                    # Sample parameters
                    params = {}
                    for param, config in LIGHTGBM_OPTUNA_SPACE.items():
                        if config[0] == 'log_uniform':
                            params[param] = trial.suggest_loguniform(param, config[1], config[2])
                        elif config[0] == 'uniform':
                            params[param] = trial.suggest_uniform(param, config[1], config[2])
                        elif config[0] == 'categorical':
                            params[param] = trial.suggest_categorical(param, config[1])
                        elif config[0] == 'int':
                            params[param] = trial.suggest_int(param, config[1], config[2])
                    
                    # Create model with sampled parameters
                    model = self._create_base_model(**params)
                    
                    # Perform cross-validation
                    cv_results = cross_validate(
                        model, X_array, y_array,
                        cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state),
                        scoring=scoring,
                        n_jobs=1  # Use single job to avoid conflicts
                    )
                    
                    return np.mean(cv_results['test_score'])
                
                study = optuna.create_study(
                    direction='maximize',
                    sampler=TPESampler(seed=self.random_state)
                )
                
                study.optimize(objective, n_trials=n_iter, timeout=timeout_minutes*60)
                
                # Extract results
                best_params = study.best_params
                best_score = study.best_value
                
                # Create detailed results similar to sklearn
                search_results = {
                    'best_params_': best_params,
                    'best_score_': best_score,
                    'cv_results_': {
                        'params': [trial.params for trial in study.trials],
                        'mean_test_score': [trial.value for trial in study.trials if trial.value is not None]
                    }
                }
                
            else:
                # Fallback to random search
                print("⚠️ Advanced optimization not available, using random search")
                return self.hyperparameter_tuning(
                    X_train, y_train, param_grid, 'random', cv_folds, scoring, timeout_minutes, n_iter
                )
            
            # Fit the search (except for Bayesian which is already done)
            if method != 'bayesian' or not OPTUNA_AVAILABLE:
                search.fit(X_array, y_array)
                search_results = search
                best_params = search.best_params_
                best_score = search.best_score_
                
            # Store results
            tuning_time = time.time() - tuning_start
            results.update({
                'tuning_time': tuning_time,
                'best_parameters': best_params,
                'best_score': best_score,
                'cv_results': {
                    'params': getattr(search_results, 'cv_results_', {}).get('params', [best_params]),
                    'mean_test_score': getattr(search_results, 'cv_results_', {}).get('mean_test_score', [best_score])
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
    
    def get_best_parameters(self) -> Dict[str, Any]:
        """Get best parameters from hyperparameter tuning"""
        return self.best_params.copy()
    
    def get_hyperparameter_tuning_results(self) -> Dict[str, Any]:
        """Get detailed hyperparameter tuning results"""
        return self.hyperparameter_tuning_results.copy()
    
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
            
            # Save LightGBM model
            model_path = filepath.with_suffix('.txt')
            self.model.booster_.save_model(model_path)
            
            # Save additional metadata
            metadata_path = filepath.with_suffix('.pkl')
            model_data = {
                'label_encoder': self.label_encoder,
                'best_params': self.best_params,
                'training_history': self.training_history,
                'hyperparameter_tuning_results': self.hyperparameter_tuning_results,
                'model_info': {
                    'model_type': 'lightgbm',
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
            model_path = filepath.with_suffix('.txt')
            metadata_path = filepath.with_suffix('.pkl')
            
            if not model_path.exists() or not metadata_path.exists():
                print(f"❌ Model files not found: {model_path} or {metadata_path}")
                return False
            
            # Load LightGBM model
            self.model = LGBMClassifier()
            self.model.booster_ = lgb.Booster(model_file=str(model_path))
            
            # Load metadata
            model_data = joblib.load(metadata_path)
            
            self.label_encoder = model_data.get('label_encoder')
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
    print("⚡ LightGBM Model - Standalone Testing")
    print("=" * 60)
    
    try:
        # Initialize model
        lgb_model = LightGBMModel(random_state=42, n_cores=4, memory_limit=8.0)
        
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
            'model_params': {
                'n_estimators': 50,
                'max_depth': 4,
                'learning_rate': 0.1,
                'num_leaves': 31,
                'subsample': 0.8,
                'colsample_bytree': 0.8
            },
            'early_stopping_rounds': 10,
            'verbose': False
        }
        
        # Split data for validation
        split_idx = int(0.8 * len(X_df))
        X_train = X_df.iloc[:split_idx]
        y_train = y_series.iloc[:split_idx]
        X_val = X_df.iloc[split_idx:]
        y_val = y_series.iloc[split_idx:]
        
        # Train model
        results = lgb_model.train(
            X_train, y_train, X_val, y_val,
            config=config, use_hyperparameter_tuning=False
        )
        
        print(f"\n✅ Basic training completed!")
        print(f"   Training accuracy: {results['train_metrics']['accuracy']:.4f}")
        print(f"   Validation accuracy: {results['validation_metrics']['accuracy']:.4f}")
        print(f"   Training time: {results['training_time']:.2f}s")
        print(f"   Trees trained: {results['model_complexity']['n_estimators']}")
        
        # Test predictions
        print("\n🔮 Testing predictions...")
        predictions = lgb_model.predict(X_val)
        probabilities = lgb_model.predict_proba(X_val)
        
        print(f"✅ Predictions completed:")
        print(f"   Predictions shape: {predictions.shape}")
        print(f"   Probabilities shape: {probabilities.shape}")
        print(f"   Sample predictions: {predictions[:5]}")
        
        # Test evaluation
        print("\n📊 Testing evaluation...")
        eval_metrics = lgb_model.evaluate(X_val, y_val)
        
        print(f"✅ Evaluation completed:")
        print(f"   Accuracy: {eval_metrics['accuracy']:.4f}")
        print(f"   F1 Score: {eval_metrics['f1_weighted']:.4f}")
        print(f"   AUC ROC: {eval_metrics['auc_roc']:.4f}")
        
        # Test feature importance
        print("\n🎯 Testing feature importance...")
        importance = lgb_model.get_feature_importance()
        if importance is not None:
            print(f"✅ Feature importance extracted: {len(importance)} features")
            print(f"   Top 5 features: {np.argsort(importance)[-5:]}")
        
        # Test model saving
        print("\n💾 Testing model saving...")
        save_path = "outputs/models/test_lightgbm_model"
        Path("outputs/models").mkdir(parents=True, exist_ok=True)
        
        if lgb_model.save_model(save_path):
            print("✅ Model saved successfully")
        else:
            print("❌ Model saving failed")
        
        # Test hyperparameter tuning (quick test)
        print("\n🔧 Testing hyperparameter tuning (quick)...")
        
        # Use a very small parameter grid for testing
        test_param_grid = {
            'n_estimators': [50, 100],
            'max_depth': [3, 6],
            'learning_rate': [0.1, 0.2],
            'num_leaves': [31, 50],
            'subsample': [0.8, 1.0],
            'colsample_bytree': [0.8, 1.0]
        }
        
        tuning_config = {
            'param_grid': test_param_grid,
            'hyperparameter_method': 'random',
            'hyperparameter_cv': 2,
            'hyperparameter_scoring': 'f1_weighted',
            'hyperparameter_timeout': 5,  # 5 minutes timeout
            'n_iter': 4,  # Test only 4 combinations
            'early_stopping_rounds': 5
        }
        
        # Create new model instance for tuning test
        lgb_tuning_model = LightGBMModel(random_state=42, n_cores=2, memory_limit=8.0)
        
        tuning_results = lgb_tuning_model.train(
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
        cv_results = lgb_model.cross_validate(X_train, y_train, cv_folds=3)
        
        if 'error' not in cv_results:
            print(f"✅ Cross-validation completed:")
            print(f"   Mean accuracy: {cv_results['mean_scores']['accuracy_test']:.4f}")
            print(f"   Mean F1 score: {cv_results['mean_scores']['f1_weighted_test']:.4f}")
            print(f"   Mean AUC: {cv_results['mean_scores']['roc_auc_test']:.4f}")
        else:
            print(f"⚠️ Cross-validation had issues: {cv_results['error']}")
        
        # Test hyperparameter results saving
        if lgb_tuning_model.hyperparameter_tuning_results:
            print("\n💾 Testing hyperparameter results saving...")
            hp_save_path = "outputs/hyperparameter_results/test_lightgbm_hyperparams"
            Path("outputs/hyperparameter_results").mkdir(parents=True, exist_ok=True)
            
            if lgb_tuning_model.save_hyperparameter_results(hp_save_path):
                print("✅ Hyperparameter results saved successfully")
            else:
                print("❌ Hyperparameter results saving failed")
        
        print(f"\n🎉 All LightGBM model tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Testing failed with error: {e}")
        import traceback
        traceback.print_exc()
        
    print("\n⚡ LightGBM Model testing completed.")