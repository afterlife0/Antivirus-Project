"""
Random Forest Model Implementation for EMBER2018 Malware Detection
Independent robust Random Forest implementation with hyperparameter tuning

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (independent model using standard libraries only)

Connected Components (files that import from this module):
- trainer.py (imports RandomForestModel class)

Integration Points:
- Provides Random Forest model implementation for malware detection
- NUMERICAL-ONLY training on processed EMBER2018 features
- Comprehensive hyperparameter tuning capabilities
- Multi-core processing support for large datasets
- Complete evaluation metrics calculation
- Model persistence and serialization
- Native feature importance extraction

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: RandomForestModel
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV, cross_validate, StratifiedKFold
from sklearn.metrics import (
    accuracy_score, log_loss, roc_auc_score, precision_recall_curve, auc,
    precision_score, recall_score, f1_score, confusion_matrix, classification_report,
    roc_curve, average_precision_score
)
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight
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

# Default hyperparameter grid for Random Forest
RANDOM_FOREST_PARAM_GRID = {
    'n_estimators': [50, 100, 200, 300, 500, 800],
    'max_depth': [None, 10, 20, 30, 40, 50],
    'min_samples_split': [2, 5, 10, 15, 20],
    'min_samples_leaf': [1, 2, 4, 6, 8],
    'max_features': ['sqrt', 'log2', None, 0.3, 0.5, 0.7],
    'bootstrap': [True, False],
    'class_weight': [None, 'balanced', 'balanced_subsample'],
    'criterion': ['gini', 'entropy'],
    'max_samples': [None, 0.5, 0.7, 0.9]
}

# Reduced parameter grid for faster tuning
RANDOM_FOREST_PARAM_GRID_FAST = {
    'n_estimators': [100, 200, 500],
    'max_depth': [None, 10, 30],
    'min_samples_split': [2, 10],
    'min_samples_leaf': [1, 4],
    'max_features': ['sqrt', 'log2'],
    'bootstrap': [True, False],
    'class_weight': [None, 'balanced']
}

# Hyperparameter search spaces for different optimization methods
RANDOM_FOREST_HYPEROPT_SPACE = {
    'n_estimators': hp.choice('n_estimators', [50, 100, 200, 500, 800]),
    'max_depth': hp.choice('max_depth', [None, 10, 20, 30, 50]),
    'min_samples_split': hp.choice('min_samples_split', [2, 5, 10, 20]),
    'min_samples_leaf': hp.choice('min_samples_leaf', [1, 2, 4, 8]),
    'max_features': hp.choice('max_features', ['sqrt', 'log2', None]),
    'bootstrap': hp.choice('bootstrap', [True, False]),
    'class_weight': hp.choice('class_weight', [None, 'balanced', 'balanced_subsample']),
    'criterion': hp.choice('criterion', ['gini', 'entropy'])
}

RANDOM_FOREST_OPTUNA_SPACE = {
    'n_estimators': ('int', 50, 1000),
    'max_depth': ('categorical', [None, 10, 20, 30, 40, 50]),
    'min_samples_split': ('int', 2, 20),
    'min_samples_leaf': ('int', 1, 10),
    'max_features': ('categorical', ['sqrt', 'log2', None]),
    'bootstrap': ('categorical', [True, False]),
    'class_weight': ('categorical', [None, 'balanced', 'balanced_subsample']),
    'criterion': ('categorical', ['gini', 'entropy'])
}

class RandomForestModel:
    """
    Independent robust Random Forest implementation with hyperparameter tuning
    
    Features:
    - Multiple Random Forest configurations (trees, depth, sampling)
    - Comprehensive hyperparameter tuning (Grid, Random, Bayesian)
    - Multi-core processing support
    - Memory-efficient training for large datasets
    - Complete evaluation metrics calculation
    - Model persistence and serialization
    - Cross-validation with detailed results
    - Native feature importance extraction
    - Out-of-bag score calculation
    """
    
    def __init__(self, random_state: int = 42, n_cores: int = -1, memory_limit: float = 4.0):
        """
        Initialize Random Forest model with configuration
        
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
            'oob_score': None,
            'model_complexity': {}
        }
        
        # Default parameter grids
        self.default_param_grid = RANDOM_FOREST_PARAM_GRID
        self.fast_param_grid = RANDOM_FOREST_PARAM_GRID_FAST
        
        # Memory tracking
        self.initial_memory = self._get_memory_usage()
        self.memory_usage = {}
        
        print(f"🌲 Random Forest Model initialized:")
        print(f"   🎲 Random state: {self.random_state}")
        print(f"   🔧 CPU cores: {self.n_cores}")
        print(f"   💾 Memory limit: {self.memory_limit}GB")
        print(f"   📊 Hyperparameter grid size: {self._calculate_grid_size(self.default_param_grid)}")
    
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
                X_array = X.values
            else:
                X_array = X
            
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
    
    def _create_base_model(self, **params) -> RandomForestClassifier:
        """
        Create base Random Forest model with specified parameters
        
        Args:
            **params: Random Forest parameters
            
        Returns:
            Configured RandomForestClassifier model
        """
        try:
            # Set default parameters
            model_params = {
                'random_state': self.random_state,
                'n_jobs': self.n_cores,
                'oob_score': True,  # Enable out-of-bag scoring
                'verbose': 0,  # Suppress verbose output
                'warm_start': False,  # Don't reuse solution of previous call
            }
            
            # Update with provided parameters
            model_params.update(params)
            
            # Handle special parameter validation
            if 'max_samples' in model_params and not model_params.get('bootstrap', True):
                # max_samples only works with bootstrap=True
                del model_params['max_samples']
            
            return RandomForestClassifier(**model_params)
            
        except Exception as e:
            print(f"❌ Error creating Random Forest model: {e}")
            raise
    
    def train(self, X_train: pd.DataFrame, y_train: pd.Series, 
              X_val: pd.DataFrame = None, y_val: pd.Series = None,
              config: Dict[str, Any] = None, use_hyperparameter_tuning: bool = False) -> Dict[str, Any]:
        """
        Train Random Forest model with optional hyperparameter tuning
        
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
            print("🚀 Starting Random Forest training...")
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
                    'max_depth': None,
                    'min_samples_split': 2,
                    'min_samples_leaf': 1,
                    'max_features': 'sqrt',
                    'bootstrap': True,
                    'class_weight': 'balanced'
                })
                print(f"🎯 Using parameters: {best_params}")
            
            # Create and train model
            print("🏋️ Training Random Forest model...")
            self.model = self._create_base_model(**best_params)
            
            fit_start = time.time()
            self.model.fit(X_train_array, y_train_array)
            fit_time = time.time() - fit_start
            
            self.is_fitted = True
            self.best_params = best_params
            
            print(f"✅ Model training completed in {fit_time:.2f}s")
            self._monitor_memory("training_complete")
            
            # Calculate training metrics
            print("📊 Calculating training metrics...")
            train_pred = self.model.predict(X_train_array)
            train_pred_proba = self.model.predict_proba(X_train_array)
            
            train_metrics = self._calculate_comprehensive_metrics(
                y_train_array, train_pred, train_pred_proba
            )
            
            # Calculate validation metrics if validation data provided
            val_metrics = {}
            if X_val_array is not None and y_val_array is not None:
                print("📊 Calculating validation metrics...")
                val_pred = self.model.predict(X_val_array)
                val_pred_proba = self.model.predict_proba(X_val_array)
                
                val_metrics = self._calculate_comprehensive_metrics(
                    y_val_array, val_pred, val_pred_proba
                )
            
            # Get out-of-bag score if available
            oob_score = getattr(self.model, 'oob_score_', None)
            if oob_score is not None:
                print(f"📊 Out-of-bag score: {oob_score:.4f}")
            
            # Extract feature importance
            feature_importance = self.get_feature_importance()
            
            # Store training history
            total_training_time = time.time() - training_start
            self.training_history.update({
                'training_time': total_training_time,
                'fit_time': fit_time,
                'tuning_time': tuning_results.get('tuning_time', 0.0) if use_hyperparameter_tuning else 0.0,
                'validation_scores': [val_metrics.get('f1_weighted', 0.0)] if val_metrics else [],
                'feature_importance': feature_importance.tolist() if feature_importance is not None else None,
                'oob_score': oob_score,
                'model_complexity': {
                    'n_estimators': best_params.get('n_estimators', 100),
                    'max_depth': best_params.get('max_depth', None),
                    'n_features': X_train.shape[1],
                    'n_classes': len(np.unique(y_train_array))
                }
            })
            
            # Prepare results
            results = {
                'model_name': 'random_forest',
                'training_time': total_training_time,
                'fit_time': fit_time,
                'best_parameters': best_params,
                'train_metrics': train_metrics,
                'validation_metrics': val_metrics,
                'oob_score': oob_score,
                'feature_importance': feature_importance.tolist() if feature_importance is not None else None,
                'model_complexity': self.training_history['model_complexity'],
                'hyperparameter_tuning': tuning_results if use_hyperparameter_tuning else {'enabled': False},
                'memory_usage': self.memory_usage,
                'dataset_info': {
                    'n_samples': len(X_train),
                    'n_features': X_train.shape[1],
                    'n_classes': len(np.unique(y_train_array)),
                    'class_distribution': dict(zip(*np.unique(y_train_array, return_counts=True)))
                }
            }
            
            print(f"🎉 Random Forest training completed successfully!")
            print(f"⏱️ Total time: {total_training_time:.2f}s")
            print(f"📊 Training accuracy: {train_metrics['accuracy']:.4f}")
            if val_metrics:
                print(f"📊 Validation accuracy: {val_metrics['accuracy']:.4f}")
            if oob_score:
                print(f"📊 Out-of-bag score: {oob_score:.4f}")
            
            return results
            
        except Exception as e:
            print(f"❌ Random Forest training failed: {e}")
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
            
            # Decode predictions if necessary for metric calculation
            if self.label_encoder is not None:
                y_pred_decoded = self.label_encoder.inverse_transform(y_pred) if len(y_pred.shape) == 1 else y_pred
                y_true_decoded = self.label_encoder.inverse_transform(y_true) if len(y_true.shape) == 1 else y_true
            else:
                y_pred_decoded = y_pred
                y_true_decoded = y_true
            
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
        Get feature importance (native to Random Forest)
        
        Returns:
            Feature importance array
        """
        try:
            if not self.is_fitted:
                print("⚠️ Model not fitted - cannot get feature importance")
                return None
            
            if hasattr(self.model, 'feature_importances_'):
                importance = self.model.feature_importances_
                print(f"✅ Feature importance extracted: {len(importance)} features")
                return importance
            else:
                print("⚠️ Feature importance not available")
                return None
                
        except Exception as e:
            print(f"❌ Feature importance extraction failed: {e}")
            return None
    
    def get_oob_score(self) -> float:
        """
        Get out-of-bag score if available
        
        Returns:
            Out-of-bag score or None if not available
        """
        try:
            if not self.is_fitted:
                print("⚠️ Model not fitted - cannot get OOB score")
                return None
            
            if hasattr(self.model, 'oob_score_'):
                oob_score = self.model.oob_score_
                print(f"✅ Out-of-bag score: {oob_score:.4f}")
                return oob_score
            else:
                print("⚠️ Out-of-bag score not available (bootstrap=False)")
                return None
                
        except Exception as e:
            print(f"❌ OOB score extraction failed: {e}")
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
            
            if not self.is_fitted:
                print("⚠️ Using default parameters for cross-validation")
                model = self._create_base_model()
            else:
                model = self.model
            
            # Prepare data
            X_array, y_array = self._validate_input_data(X, y)
            
            # Define scoring metrics
            scoring = [
                'accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted',
                'roc_auc_ovr_weighted'
            ]
            
            # Perform cross-validation
            cv_results = cross_validate(
                model, X_array, y_array,
                cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state),
                scoring=scoring,
                return_train_score=True,
                n_jobs=self.n_cores
            )
            
            # Calculate summary statistics
            results = {
                'cv_folds': cv_folds,
                'mean_scores': {},
                'std_scores': {},
                'detailed_scores': {}
            }
            
            for metric in scoring:
                test_scores = cv_results[f'test_{metric}']
                train_scores = cv_results[f'train_{metric}']
                
                results['mean_scores'][f'{metric}_test'] = np.mean(test_scores)
                results['mean_scores'][f'{metric}_train'] = np.mean(train_scores)
                results['std_scores'][f'{metric}_test'] = np.std(test_scores)
                results['std_scores'][f'{metric}_train'] = np.std(train_scores)
                results['detailed_scores'][f'{metric}_test'] = test_scores.tolist()
                results['detailed_scores'][f'{metric}_train'] = train_scores.tolist()
            
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
            
            # Create base model
            base_model = self._create_base_model()
            
            # Configure cross-validation
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
            
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
            
            if method == 'grid':
                # Grid search
                print(f"🔍 Grid search over {self._calculate_grid_size(param_grid)} combinations...")
                
                search = GridSearchCV(
                    base_model, param_grid,
                    cv=cv, scoring=scoring,
                    n_jobs=self.n_cores,
                    verbose=1,
                    return_train_score=True
                )
                
                search.fit(X_array, y_array)
                
                results.update({
                    'best_parameters': search.best_params_,
                    'best_score': search.best_score_,
                    'cv_results': {
                        'mean_test_score': search.cv_results_['mean_test_score'].tolist(),
                        'std_test_score': search.cv_results_['std_test_score'].tolist(),
                        'params': search.cv_results_['params']
                    }
                })
                
            elif method == 'random':
                # Random search
                print(f"🎲 Random search with {n_iter} iterations...")
                
                search = RandomizedSearchCV(
                    base_model, param_grid,
                    n_iter=n_iter, cv=cv, scoring=scoring,
                    n_jobs=self.n_cores,
                    random_state=self.random_state,
                    verbose=1,
                    return_train_score=True
                )
                
                search.fit(X_array, y_array)
                
                results.update({
                    'best_parameters': search.best_params_,
                    'best_score': search.best_score_,
                    'cv_results': {
                        'mean_test_score': search.cv_results_['mean_test_score'].tolist(),
                        'std_test_score': search.cv_results_['std_test_score'].tolist(),
                        'params': search.cv_results_['params']
                    }
                })
                
            elif method == 'bayesian' and OPTUNA_AVAILABLE:
                # Bayesian optimization with Optuna
                print(f"🧠 Bayesian optimization with {n_iter} trials...")
                
                def objective(trial):
                    # Sample parameters
                    params = {}
                    for param, config in RANDOM_FOREST_OPTUNA_SPACE.items():
                        if config[0] == 'int':
                            params[param] = trial.suggest_int(param, config[1], config[2])
                        elif config[0] == 'categorical':
                            params[param] = trial.suggest_categorical(param, config[1])
                        elif config[0] == 'float':
                            params[param] = trial.suggest_float(param, config[1], config[2])
                    
                    # Create and evaluate model
                    model = self._create_base_model(**params)
                    
                    # Cross-validation
                    scores = cross_validate(model, X_array, y_array, cv=cv, scoring=scoring, n_jobs=1)
                    return np.mean(scores['test_score'])
                
                study = optuna.create_study(
                    direction='maximize',
                    sampler=TPESampler(seed=self.random_state)
                )
                
                study.optimize(objective, n_trials=n_iter, timeout=timeout_minutes*60)
                
                results.update({
                    'best_parameters': study.best_params,
                    'best_score': study.best_value,
                    'cv_results': {
                        'trials': [{'params': trial.params, 'value': trial.value} 
                                 for trial in study.trials if trial.value is not None]
                    }
                })
                
            else:
                # Fallback to grid search
                print("⚠️ Bayesian optimization not available, using grid search")
                return self.hyperparameter_tuning(
                    X_train, y_train, param_grid, 'grid', cv_folds, scoring, timeout_minutes, n_iter
                )
            
            # Store results
            tuning_time = time.time() - tuning_start
            results['tuning_time'] = tuning_time
            
            self.best_params = results['best_parameters']
            self.best_score = results['best_score']
            self.cv_results = results['cv_results']
            self.hyperparameter_tuning_results = results
            
            print(f"✅ Hyperparameter tuning completed in {tuning_time:.2f}s")
            print(f"🎯 Best score: {results['best_score']:.4f}")
            print(f"🎯 Best parameters: {results['best_parameters']}")
            
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
        Save trained model to file with ANTIVIRUS SYSTEM COMPATIBILITY
        **FIXED**: Now saves in format compatible with ModelUtils loading
        
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
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            # **CRITICAL FIX**: Determine save format based on file extension and system requirements
            if filepath.endswith('.pkl'):
                # **ANTIVIRUS SYSTEM COMPATIBILITY**: Save ONLY the sklearn model with pickle protocol 4
                print(f"💾 Saving Random Forest model in pickle format for antivirus compatibility...")
                
                try:
                    # Save ONLY the trained sklearn model (not the wrapper)
                    with open(filepath, 'wb') as f:
                        pickle.dump(self.model, f, protocol=4)
                    print(f"✅ Random Forest model saved in compatible pickle format: {filepath}")
                    
                    # **ADDITIONAL**: Save metadata if available (separate file)
                    metadata_path = filepath.replace('_model.pkl', '_metadata.pkl')
                    metadata = {
                        'label_encoder': self.label_encoder,
                        'best_params': self.best_params,
                        'training_history': self.training_history,
                        'model_info': {
                            'model_type': 'random_forest',
                            'random_state': self.random_state,
                            'timestamp': datetime.now().isoformat(),
                            'n_estimators': getattr(self.model, 'n_estimators', 0),
                            'max_depth': getattr(self.model, 'max_depth', None),
                            'n_features_in': getattr(self.model, 'n_features_in_', 0),
                            'n_classes': getattr(self.model, 'n_classes_', 0)
                        }
                    }
                    
                    with open(metadata_path, 'wb') as f:
                        pickle.dump(metadata, f, protocol=4)
                    print(f"✅ Random Forest metadata saved: {metadata_path}")
                    
                except Exception as pickle_error:
                    print(f"❌ Pickle save failed: {pickle_error}")
                    return False
                    
            elif filepath.endswith('.joblib'):
                # **JOBLIB FORMAT**: Save complete model data (for backward compatibility)
                print(f"💾 Saving Random Forest model in joblib format...")
                
                model_data = {
                    'model': self.model,
                    'label_encoder': self.label_encoder,
                    'best_params': self.best_params,
                    'training_history': self.training_history,
                    'hyperparameter_tuning_results': self.hyperparameter_tuning_results,
                    'model_info': {
                        'model_type': 'random_forest',
                        'sklearn_version': '1.3.0+',
                        'file_format': 'joblib_pickle',
                        'random_state': self.random_state,
                        'timestamp': datetime.now().isoformat(),
                        'n_estimators': getattr(self.model, 'n_estimators', 0),
                        'max_depth': getattr(self.model, 'max_depth', None),
                        'n_features_in': getattr(self.model, 'n_features_in_', 0),
                        'n_classes': getattr(self.model, 'n_classes_', 0)
                    }
                }
                
                joblib.dump(model_data, filepath, compress=3)
                print(f"✅ Complete model data saved in joblib format: {filepath}")
                
            else:
                # **DEFAULT**: Use pickle format for maximum compatibility
                print(f"💾 Using default pickle format for: {filepath}")
                with open(filepath, 'wb') as f:
                    pickle.dump(self.model, f, protocol=4)
            
            # **VERIFICATION**: Test loading immediately after saving
            print("🧪 Verifying saved model can be loaded...")
            try:
                if filepath.endswith('.pkl'):
                    with open(filepath, 'rb') as f:
                        test_model = pickle.load(f)
                        
                    # Quick functionality test
                    if hasattr(test_model, 'predict') and hasattr(test_model, 'predict_proba'):
                        print("✅ Saved model verification successful - compatible with antivirus system")
                        
                        # Test with sample data if available
                        if hasattr(test_model, 'n_features_in_') and test_model.n_features_in_ > 0:
                            sample_data = np.random.random((1, test_model.n_features_in_))
                            test_pred = test_model.predict(sample_data)
                            test_proba = test_model.predict_proba(sample_data)
                            print(f"✅ Model functionality test passed - predictions: {test_pred.shape}, probabilities: {test_proba.shape}")
                    else:
                        print("⚠️ Saved model missing required methods")
                        
                elif filepath.endswith('.joblib'):
                    test_data = joblib.load(filepath)
                    test_model = test_data['model']
                    if hasattr(test_model, 'predict') and hasattr(test_model, 'predict_proba'):
                        print("✅ Saved model verification successful")
                    else:
                        print("⚠️ Saved model missing required methods")
                        
            except Exception as verify_error:
                print(f"⚠️ Model verification failed: {verify_error}")
                print("⚠️ Model saved but may have compatibility issues")
            
            # **FILE SIZE REPORTING**
            try:
                file_size = Path(filepath).stat().st_size / (1024*1024)  # Size in MB
                print(f"✅ Random Forest model saved successfully:")
                print(f"   📁 File path: {filepath}")
                print(f"   📊 File size: {file_size:.2f} MB")
                print(f"   🌳 Trees: {getattr(self.model, 'n_estimators', 'unknown')}")
                print(f"   📏 Features: {getattr(self.model, 'n_features_in_', 'unknown')}")
            except Exception:
                print(f"✅ Random Forest model saved to: {filepath}")
            
            return True
            
        except Exception as e:
            print(f"❌ Model saving failed: {e}")
            return False
    

    def load_model(self, filepath: str) -> bool:
        """
        Load model from file with enhanced compatibility
        **FIXED**: Handle both .pkl and .joblib formats automatically
        
        Args:
            filepath: Path to load the model from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # **ENHANCED**: Auto-detect file format and extension
            filepath = str(filepath)
            original_path = filepath
            
            # Try multiple path variations
            possible_paths = [
                filepath,
                filepath + '.pkl',
                filepath + '.joblib',
                filepath.replace('.joblib', '.pkl'),
                filepath.replace('.pkl', '.joblib')
            ]
            
            actual_path = None
            for path in possible_paths:
                if Path(path).exists():
                    actual_path = path
                    break
            
            if actual_path is None:
                print(f"❌ Model file not found. Tried paths:")
                for path in possible_paths:
                    print(f"   - {path}")
                return False
            
            print(f"📥 Loading Random Forest model from {actual_path}")
            
            try:
                # **ENHANCED**: Try loading with different methods based on file content
                if actual_path.endswith('.pkl'):
                    # **ANTIVIRUS SYSTEM COMPATIBLE**: Direct pickle load
                    print("🔧 Loading as antivirus-compatible pickle format...")
                    with open(actual_path, 'rb') as f:
                        loaded_data = pickle.load(f)
                    
                    # Check if it's just the model or wrapped data
                    if hasattr(loaded_data, 'predict') and hasattr(loaded_data, 'predict_proba'):
                        # Direct sklearn model - antivirus system format
                        self.model = loaded_data
                        self.label_encoder = None
                        self.best_params = {}
                        self.training_history = {}
                        self.hyperparameter_tuning_results = {}
                        print("✅ Loaded sklearn RandomForestClassifier directly (antivirus format)")
                        
                        # Try to load metadata from separate file
                        metadata_path = actual_path.replace('_model.pkl', '_metadata.pkl')
                        if Path(metadata_path).exists():
                            try:
                                with open(metadata_path, 'rb') as f:
                                    metadata = pickle.load(f)
                                self.label_encoder = metadata.get('label_encoder')
                                self.best_params = metadata.get('best_params', {})
                                self.training_history = metadata.get('training_history', {})
                                print("✅ Loaded metadata from separate file")
                            except Exception as meta_error:
                                print(f"⚠️ Could not load metadata: {meta_error}")
                                
                    elif isinstance(loaded_data, dict) and 'model' in loaded_data:
                        # Wrapped format
                        self.model = loaded_data['model']
                        self.label_encoder = loaded_data.get('label_encoder')
                        self.best_params = loaded_data.get('best_params', {})
                        self.training_history = loaded_data.get('training_history', {})
                        self.hyperparameter_tuning_results = loaded_data.get('hyperparameter_tuning_results', {})
                        print("✅ Loaded wrapped Random Forest model from pickle")
                    else:
                        print(f"⚠️ Unexpected pickle content type: {type(loaded_data)}")
                        return False
                        
                elif actual_path.endswith('.joblib'):
                    # **JOBLIB FORMAT**: Load with joblib
                    print("🔧 Loading as joblib format...")
                    loaded_data = joblib.load(actual_path)
                    
                    if hasattr(loaded_data, 'predict') and hasattr(loaded_data, 'predict_proba'):
                        # Direct model
                        self.model = loaded_data
                        self.label_encoder = None
                        self.best_params = {}
                        self.training_history = {}
                        self.hyperparameter_tuning_results = {}
                        print("✅ Loaded sklearn RandomForestClassifier directly from joblib")
                    elif isinstance(loaded_data, dict) and 'model' in loaded_data:
                        # Wrapped format
                        self.model = loaded_data['model']
                        self.label_encoder = loaded_data.get('label_encoder')
                        self.best_params = loaded_data.get('best_params', {})
                        self.training_history = loaded_data.get('training_history', {})
                        self.hyperparameter_tuning_results = loaded_data.get('hyperparameter_tuning_results', {})
                        print("✅ Loaded wrapped Random Forest model from joblib")
                    else:
                        print(f"⚠️ Unexpected joblib content type: {type(loaded_data)}")
                        return False
                else:
                    # **FALLBACK**: Try both methods
                    print("🔧 Unknown format, trying multiple loading methods...")
                    
                    # Try pickle first
                    try:
                        with open(actual_path, 'rb') as f:
                            loaded_data = pickle.load(f)
                        print("✅ Loaded with pickle")
                    except Exception:
                        # Try joblib
                        try:
                            loaded_data = joblib.load(actual_path)
                            print("✅ Loaded with joblib")
                        except Exception as final_error:
                            print(f"❌ Could not load with any method: {final_error}")
                            return False
                    
                    # Process loaded data
                    if hasattr(loaded_data, 'predict'):
                        self.model = loaded_data
                        self.label_encoder = None
                        self.best_params = {}
                        self.training_history = {}
                        print("✅ Loaded direct model")
                    elif isinstance(loaded_data, dict) and 'model' in loaded_data:
                        self.model = loaded_data['model']
                        self.label_encoder = loaded_data.get('label_encoder')
                        self.best_params = loaded_data.get('best_params', {})
                        self.training_history = loaded_data.get('training_history', {})
                        print("✅ Loaded wrapped model")
                
            except Exception as load_error:
                print(f"❌ Loading failed with error: {load_error}")
                return False
            
            # **VALIDATION**: Verify loaded model
            if self.model is None:
                print("❌ No model loaded")
                return False
            
            if not hasattr(self.model, 'predict') or not hasattr(self.model, 'predict_proba'):
                print("❌ Loaded model missing required methods")
                return False
            
            self.is_fitted = True
            
            # **FUNCTIONALITY TEST**: Quick test if possible
            try:
                if hasattr(self.model, 'n_features_in_') and self.model.n_features_in_ > 0:
                    test_data = np.random.random((1, self.model.n_features_in_))
                    test_pred = self.model.predict(test_data)
                    test_proba = self.model.predict_proba(test_data)
                    print(f"✅ Model functionality verified - can predict")
            except Exception as test_error:
                print(f"⚠️ Model functionality test failed: {test_error}")
            
            # Display model info
            print(f"✅ Random Forest model loaded successfully:")
            print(f"   📁 Source file: {actual_path}")
            print(f"   🌳 Trees: {getattr(self.model, 'n_estimators', 'unknown')}")
            print(f"   📏 Features: {getattr(self.model, 'n_features_in_', 'unknown')}")
            print(f"   🎯 Classes: {getattr(self.model, 'n_classes_', 'unknown')}")
            print(f"   📅 Has metadata: {'Yes' if self.best_params else 'No'}")
            
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
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            
            # Save results as JSON
            with open(filepath, 'w') as f:
                json.dump(self.hyperparameter_tuning_results, f, indent=2, default=str)
            
            print(f"✅ Hyperparameter results saved to {filepath}")
            return True
            
        except Exception as e:
            print(f"❌ Hyperparameter results saving failed: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get comprehensive model information"""
        info = {
            'model_type': 'random_forest',
            'is_fitted': self.is_fitted,
            'random_state': self.random_state,
            'n_cores': self.n_cores,
            'memory_limit': self.memory_limit,
            'best_parameters': self.best_params,
            'training_history': self.training_history,
            'memory_usage': self.memory_usage
        }
        
        if self.is_fitted and self.model:
            info.update({
                'n_estimators': getattr(self.model, 'n_estimators', 0),
                'max_depth': getattr(self.model, 'max_depth', None),
                'n_features_in': getattr(self.model, 'n_features_in_', 0),
                'n_classes': getattr(self.model, 'n_classes_', 0),
                'oob_score': getattr(self.model, 'oob_score_', None)
            })
        else:
            info.update({
                'n_estimators': 0,
                'max_depth': None,
                'n_features_in': 0,
                'n_classes': 0,
                'oob_score': None
            })
        
        return info
    
    def __str__(self) -> str:
        """String representation of the model"""
        if self.is_fitted:
            return f"RandomForestModel(fitted=True, n_estimators={getattr(self.model, 'n_estimators', 'unknown')}, max_depth={getattr(self.model, 'max_depth', 'unknown')})"
        else:
            return f"RandomForestModel(fitted=False, random_state={self.random_state})"
    
    def __repr__(self) -> str:
        """Detailed representation of the model"""
        return self.__str__()


# Utility functions for testing and validation

def test_random_forest_model(X_sample: pd.DataFrame = None, y_sample: pd.Series = None, 
                            use_hyperparameter_tuning: bool = False) -> bool:
    """
    Test Random Forest model functionality
    
    Args:
        X_sample: Sample features (optional)
        y_sample: Sample labels (optional)
        use_hyperparameter_tuning: Test hyperparameter tuning
        
    Returns:
        True if test successful, False otherwise
    """
    try:
        print("🧪 Testing Random Forest Model...")
        
        # Create sample data if not provided
        if X_sample is None or y_sample is None:
            print("📊 Creating sample data...")
            np.random.seed(42)
            n_samples, n_features = 1000, 20
            X_sample = pd.DataFrame(
                np.random.randn(n_samples, n_features),
                columns=[f'feature_{i}' for i in range(n_features)]
            )
            y_sample = pd.Series(np.random.choice([0, 1], n_samples))
        
        # Initialize model
        model = RandomForestModel(random_state=42, n_cores=2)
        
        # Test training
        print("🏋️ Testing training...")
        results = model.train(
            X_sample[:800], y_sample[:800],
            X_sample[800:], y_sample[800:],
            use_hyperparameter_tuning=use_hyperparameter_tuning
        )
        
        # Test predictions
        print("🔮 Testing predictions...")
        predictions = model.predict(X_sample[800:])
        probabilities = model.predict_proba(X_sample[800:])
        
        # Test evaluation
        print("📊 Testing evaluation...")
        metrics = model.evaluate(X_sample[800:], y_sample[800:])
        
        # Test feature importance
        print("🔍 Testing feature importance...")
        feature_importance = model.get_feature_importance()
        
        # Test OOB score
        print("🎯 Testing OOB score...")
        oob_score = model.get_oob_score()
        
        # Test cross-validation
        print("🔄 Testing cross-validation...")
        cv_results = model.cross_validate(X_sample[:500], y_sample[:500], cv_folds=3)
        
        # Test model persistence
        print("💾 Testing model persistence...")
        save_path = "test_random_forest_model.pkl"
        model.save_model(save_path)
        
        new_model = RandomForestModel()
        loaded_successfully = new_model.load_model(save_path)
        
        # Cleanup
        if Path(save_path).exists():
            Path(save_path).unlink()
        
        print("✅ Random Forest Model test completed successfully!")
        print(f"📊 Test results:")
        print(f"   - Training accuracy: {results['train_metrics']['accuracy']:.4f}")
        print(f"   - Validation accuracy: {results['validation_metrics']['accuracy']:.4f}")
        print(f"   - Predictions shape: {predictions.shape}")
        print(f"   - Probabilities shape: {probabilities.shape}")
        print(f"   - Feature importance shape: {feature_importance.shape if feature_importance is not None else 'None'}")
        print(f"   - OOB score: {oob_score if oob_score is not None else 'None'}")
        print(f"   - Model saved and loaded: {loaded_successfully}")
        
        return True
        
    except Exception as e:
        print(f"❌ Random Forest Model test failed: {e}")
        return False


if __name__ == "__main__":
    # Run tests if executed directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Random Forest Model")
    parser.add_argument('--test', action='store_true', help='Run comprehensive tests')
    parser.add_argument('--hyperparameter-tuning', action='store_true', 
                       help='Test hyperparameter tuning (slower)')
    
    args = parser.parse_args()
    
    if args.test:
        success = test_random_forest_model(use_hyperparameter_tuning=args.hyperparameter_tuning)
        sys.exit(0 if success else 1)
    else:
        # Interactive mode
        print("Random Forest Model ready for import")
        print("Usage: from random_forest import RandomForestModel")