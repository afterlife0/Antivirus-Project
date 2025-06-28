"""
EMBER2018 Data Preprocessor for Malware Detection ML Training
Comprehensive data preprocessing with NUMERICAL-ONLY training focus

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- data_loader.py (imports DataLoader)

Connected Components (files that import from this module):
- None (saves processed NUMERICAL data to files for trainer.py)

Integration Points:
- Uses DataLoader for memory-efficient data loading
- Separates string and numerical columns (NUMERICAL-ONLY training)
- Saves processed data to files for independent trainer.py access
- **NOW SAVES STRING DATA**: Saves separated string datasets for analysis
- Comprehensive argument parsing for preprocessing options
- Memory-efficient processing with chunked operations

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: DataPreprocessor
□ String column separation implemented (from preprocessor_demo.py)
□ NUMERICAL-ONLY training data preparation
□ STRING DATA SAVING implemented
□ Memory optimization implemented
□ Argument parsing functional
"""

import os
import sys
import gc
import time
import logging
import argparse
import warnings
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Union

import numpy as np
import pandas as pd
import psutil
import pickle
import json

# Suppress warnings
warnings.filterwarnings('ignore')

# Import DataLoader
try:
    from data_loader import DataLoader
    DATA_LOADER_AVAILABLE = True
except ImportError:
    print("❌ CRITICAL ERROR: data_loader.py not found")
    DATA_LOADER_AVAILABLE = False
    sys.exit(1)

# Preprocessing libraries
try:
    from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
    from sklearn.feature_selection import SelectKBest, mutual_info_classif, VarianceThreshold
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    print("❌ CRITICAL ERROR: scikit-learn not available")
    SKLEARN_AVAILABLE = False
    sys.exit(1)

# Imbalanced learning (optional)
try:
    from imblearn.over_sampling import SMOTE, ADASYN, BorderlineSMOTE
    from imblearn.under_sampling import TomekLinks, EditedNearestNeighbours
    from imblearn.combine import SMOTETomek, SMOTEENN
    IMBALANCED_LEARN_AVAILABLE = True
except ImportError:
    IMBALANCED_LEARN_AVAILABLE = False
    print("⚠️ WARNING: imbalanced-learn not available. Install with: pip install imbalanced-learn")

class DataPreprocessor:
    """
    Comprehensive data preprocessor with configurable options for EMBER2018
    
    Features:
    - Memory-efficient data loading using DataLoader
    - Complete string column separation (NUMERICAL-ONLY training)
    - **STRING DATA SAVING**: Saves separated string datasets for analysis
    - Configurable preprocessing pipeline
    - Data balancing with multiple strategies
    - Robust feature scaling and selection
    - Comprehensive argument parsing
    - Memory monitoring and optimization
    - Saves processed data for independent trainer access
    """
    
    def __init__(self, data_loader: DataLoader, config: Dict[str, Any]):
        """
        Initialize DataPreprocessor with DataLoader instance and configuration
        
        Args:
            data_loader: DataLoader instance for memory-efficient loading
            config: Configuration dictionary with preprocessing options
        """
        self.data_loader = data_loader
        self.config = config
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Memory tracking
        self.initial_memory = self._get_memory_usage()
        self.memory_usage = {}
        
        # Processing components
        self.scaler = None
        self.balancer = None
        self.feature_selector = None
        self.outlier_detector = None
        self.variance_selector = None
        
        # Data storage
        self.feature_names = None
        self.excluded_string_columns = []
        self.string_column_names = []  # Track actual string column names for saving
        
        # Processing statistics
        self.stats = {
            'original_samples': 0,
            'processed_samples': {'train': 0, 'val': 0, 'test': 0},
            'original_features': 0,
            'processed_features': 0,
            'string_columns_removed': 0,
            'string_columns_saved': 0,  # New stat for saved string columns
            'outliers_removed': 0,
            'class_distribution_before': {},
            'class_distribution_after': {},
            'processing_time': {},
            'memory_usage': {}
        }
        
        # String columns to ALWAYS drop (from preprocessor_demo.py)
        self.STRING_COLUMNS_TO_DROP = {
            # Metadata columns
            'sha256', 'md5', 'appeared', 'avclass',
            
            # PE Header string columns
            'header_coff_machine',           # Contains 'I386'
            'header_coff_characteristics',   # Contains flag strings  
            'header_optional_subsystem',     # Contains 'WINDOWS_GUI' etc.
            'header_optional_dll_characteristics',  # Contains characteristics
            'header_optional_magic',         # Contains 'PE32'
            
            # Section names (0-9)
            'section_0_name', 'section_1_name', 'section_2_name', 'section_3_name', 'section_4_name',
            'section_5_name', 'section_6_name', 'section_7_name', 'section_8_name', 'section_9_name',
            
            # Section properties
            'section_0_props', 'section_1_props', 'section_2_props', 'section_3_props', 'section_4_props',
            'section_5_props', 'section_6_props', 'section_7_props', 'section_8_props', 'section_9_props',
            'section_entry',
            
            # Import DLL names (0-9)
            'imports_dll_0', 'imports_dll_1', 'imports_dll_2', 'imports_dll_3', 'imports_dll_4',
            'imports_dll_5', 'imports_dll_6', 'imports_dll_7', 'imports_dll_8', 'imports_dll_9',
            
            # Data directory names (0-14)
            'datadir_0_name', 'datadir_1_name', 'datadir_2_name', 'datadir_3_name', 'datadir_4_name',
            'datadir_5_name', 'datadir_6_name', 'datadir_7_name', 'datadir_8_name', 'datadir_9_name',
            'datadir_10_name', 'datadir_11_name', 'datadir_12_name', 'datadir_13_name', 'datadir_14_name'
        }
        
        # Multi-class handling configuration
        self.class_handling_strategy = config.get('class_handling', 'keep_all')
        self.unknown_class_value = config.get('unknown_class_value', -1)
        
        # Class mapping and statistics
        self.original_class_distribution = {}
        self.final_class_distribution = {}
        self.class_mapping = {}
        
        self.logger.info("📋 DataPreprocessor initialized")
        self.logger.info(f"🔧 Configuration: {len(config)} parameters")
        self.logger.info(f"💾 Initial memory: {self.initial_memory:.2f}GB")
        self.logger.info(f"🚫 String columns to drop: {len(self.STRING_COLUMNS_TO_DROP)}")
        self.logger.info(f"💾 String data saving: {'enabled' if config.get('save_string_data', True) else 'disabled'}")
        self.logger.info(f"🎯 Class handling strategy: {self.class_handling_strategy}")
        self.logger.info(f"🔍 Unknown class value: {self.unknown_class_value}")
        
    def _setup_logger(self) -> logging.Logger:
        """Setup logger with memory tracking"""
        logger = logging.getLogger("data_preprocessor")
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            
        return logger
        
    def _get_memory_usage(self) -> float:
        """Get current memory usage in GB"""
        try:
            return psutil.Process().memory_info().rss / (1024**3)
        except Exception:
            return 0.0
            
    def _monitor_memory(self, operation: str) -> None:
        """Monitor memory usage for an operation"""
        current_memory = self._get_memory_usage()
        memory_delta = current_memory - self.initial_memory
        self.memory_usage[operation] = {
            'current_gb': current_memory,
            'delta_gb': memory_delta,
            'timestamp': time.time()
        }
        
    def separate_columns(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Separate string and numerical columns
        
        Args:
            data: Input DataFrame
            
        Returns:
            Tuple of (numerical_data, string_data)
        """
        try:
            self.logger.info("🔄 Separating string and numerical columns...")
            start_time = time.time()
            
            original_columns = len(data.columns)
            
            # Step 1: Explicitly drop known string columns
            self.logger.info("🚫 Dropping known string columns...")
            columns_to_drop = [col for col in self.STRING_COLUMNS_TO_DROP if col in data.columns]
            
            if columns_to_drop:
                data_cleaned = data.drop(columns=columns_to_drop)
                self.logger.info(f"Dropped {len(columns_to_drop)} known string columns")
                self.excluded_string_columns.extend(columns_to_drop)
            else:
                data_cleaned = data.copy()
                self.logger.info("No known string columns found to drop")
            
            # Step 2: Select numerical types only
            self.logger.info("🔢 Selecting numerical columns...")
            numerical_data = data_cleaned.select_dtypes(include=[np.number]).copy()
            
            # Step 3: Add back label column if it exists and was removed
            if 'label' in data.columns and 'label' not in numerical_data.columns:
                numerical_data['label'] = data['label']
                self.logger.info("Added back 'label' column")
            
            # Step 4: Additional validation for remaining columns
            self.logger.info("✅ Validating remaining columns for numeric content...")
            validated_columns = []
            
            for col in numerical_data.columns:
                if col == 'label':
                    validated_columns.append(col)
                    continue
                    
                try:
                    # Sample check for string patterns
                    sample = numerical_data[col].dropna().head(20)
                    if len(sample) == 0:
                        continue
                        
                    # Check for string-like patterns
                    has_string_patterns = any(
                        isinstance(val, str) or
                        (isinstance(val, (int, float)) and 
                         not pd.isna(val) and 
                         str(val).count('-') > 1) or
                        (str(val).replace('.', '').replace('-', '').replace('e', '').replace('+', '').isalpha())
                        for val in sample
                    )
                    
                    if has_string_patterns:
                        self.logger.info(f"Excluding column '{col}' - contains string patterns")
                        self.excluded_string_columns.append(col)
                        continue
                        
                    # Try numeric conversion
                    pd.to_numeric(sample, errors='raise')
                    validated_columns.append(col)
                    
                except (ValueError, TypeError) as e:
                    self.logger.info(f"Excluding column '{col}' - conversion error")
                    self.excluded_string_columns.append(col)
                    continue
            
            # Step 5: Create final numerical dataset
            numerical_data_final = numerical_data[validated_columns].copy()
            
            # Step 6: Force convert to numeric and handle NaN
            for col in numerical_data_final.columns:
                if col != 'label':
                    numerical_data_final[col] = pd.to_numeric(numerical_data_final[col], errors='coerce')
            
            # Fill NaN values
            numerical_data_final = numerical_data_final.fillna(0)
            
            # Step 7: Create string data (excluded columns for saving)
            string_columns = list(set(data.columns) - set(numerical_data_final.columns))
            string_data = data[string_columns].copy() if string_columns else pd.DataFrame()
            
            # Store string column names for metadata
            self.string_column_names = string_columns
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['column_separation'] = processing_time
            self.stats['string_columns_removed'] = len(string_columns)
            self.stats['string_columns_saved'] = len(string_columns) if self.config.get('save_string_data', True) else 0
            
            self.logger.info(f"✅ Column separation completed in {processing_time:.2f}s")
            self.logger.info(f"📊 Original columns: {original_columns}")
            self.logger.info(f"📊 Numerical columns: {len(numerical_data_final.columns)}")
            self.logger.info(f"📊 String columns excluded: {len(string_columns)}")
            self.logger.info(f"💾 String columns to save: {len(string_columns) if self.config.get('save_string_data', True) else 0}")
            
            return numerical_data_final, string_data
            
        except Exception as e:
            self.logger.error(f"Error in column separation: {e}")
            raise
    
    def prepare_numerical_training_data(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Prepare ONLY numerical data for training (exclude all string columns)
        **MODIFIED**: Now returns both numerical and string data
        
        Args:
            data: Input DataFrame
            
        Returns:
            Tuple of (numerical_data, string_data) for training
        """
        try:
            self.logger.info("🎯 Preparing NUMERICAL-ONLY training data...")
            start_time = time.time()
            
            # Separate columns first
            numerical_data, string_data = self.separate_columns(data)
            
            # Verify no string data remains in numerical dataset
            string_cols = numerical_data.select_dtypes(include=['object', 'string']).columns
            if len(string_cols) > 0:
                self.logger.warning(f"Found remaining string columns: {string_cols.tolist()}")
                numerical_data = numerical_data.drop(columns=string_cols)
                self.logger.info("Dropped remaining string columns")
            
            # Final validation - ensure all columns are numeric
            for col in numerical_data.columns:
                if col != 'label':
                    if not pd.api.types.is_numeric_dtype(numerical_data[col]):
                        self.logger.warning(f"Converting non-numeric column '{col}' to numeric")
                        numerical_data[col] = pd.to_numeric(numerical_data[col], errors='coerce')
            
            # Handle any remaining NaN values
            if numerical_data.isnull().any().any():
                nan_count = numerical_data.isnull().sum().sum()
                self.logger.info(f"Filling {nan_count} remaining NaN values with 0")
                numerical_data = numerical_data.fillna(0)
            
            # Store feature names (excluding label)
            feature_columns = [col for col in numerical_data.columns if col != 'label']
            self.feature_names = feature_columns
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['numerical_preparation'] = processing_time
            
            self.logger.info(f"✅ Numerical training data prepared in {processing_time:.2f}s")
            self.logger.info(f"📊 Final numerical shape: {numerical_data.shape}")
            self.logger.info(f"📊 Features: {len(feature_columns)}")
            self.logger.info(f"📊 String data shape: {string_data.shape}")
            
            return numerical_data, string_data
            
        except Exception as e:
            self.logger.error(f"Error preparing numerical training data: {e}")
            raise
    
    def handle_missing_values(self, data: pd.DataFrame, strategy: str = 'smart') -> pd.DataFrame:
        """
        Handle null and zero values gracefully
        
        Args:
            data: Input DataFrame
            strategy: Strategy for handling missing values ('drop', 'fill', 'smart')
            
        Returns:
            DataFrame with handled missing values
        """
        try:
            self.logger.info(f"🔧 Handling missing values with '{strategy}' strategy...")
            start_time = time.time()
            
            initial_shape = data.shape
            
            if strategy == 'drop':
                # Drop rows with any missing values
                data_clean = data.dropna()
                
            elif strategy == 'fill':
                # Fill with median for numerical columns
                data_clean = data.copy()
                for col in data_clean.columns:
                    if col != 'label' and data_clean[col].dtype in [np.float64, np.int64]:
                        data_clean[col] = data_clean[col].fillna(data_clean[col].median())
                        
            elif strategy == 'smart':
                # Smart handling: remove features with >90% missing, fill others
                data_clean = data.copy()
                
                # Remove features with too many missing values
                missing_threshold = 0.9
                for col in data_clean.columns:
                    if col != 'label':
                        missing_ratio = data_clean[col].isnull().sum() / len(data_clean)
                        if missing_ratio > missing_threshold:
                            data_clean = data_clean.drop(columns=[col])
                            self.logger.info(f"Dropped feature '{col}' - {missing_ratio:.1%} missing")
                
                # Fill remaining missing values with median
                for col in data_clean.columns:
                    if col != 'label' and data_clean[col].dtype in [np.float64, np.int64]:
                        if data_clean[col].isnull().any():
                            fill_value = data_clean[col].median()
                            data_clean[col] = data_clean[col].fillna(fill_value)
                            
            else:
                self.logger.warning(f"Unknown strategy '{strategy}', using 'smart'")
                return self.handle_missing_values(data, 'smart')
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['missing_values'] = processing_time
            
            self.logger.info(f"✅ Missing values handled in {processing_time:.2f}s")
            self.logger.info(f"📊 Shape: {initial_shape} → {data_clean.shape}")
            
            return data_clean
            
        except Exception as e:
            self.logger.error(f"Error handling missing values: {e}")
            raise
    
    def analyze_class_distribution(self, data: pd.DataFrame, target_col: str = 'label') -> Dict[str, Any]:
        """
        Analyze class distribution in the dataset
        **NEW**: Comprehensive multi-class analysis
        
        Args:
            data: Input DataFrame
            target_col: Target column name
            
        Returns:
            Dictionary with class distribution analysis
        """
        try:
            if target_col not in data.columns:
                self.logger.warning(f"Target column '{target_col}' not found")
                return {}
            
            self.logger.info("🔍 Analyzing class distribution...")
            
            # Get class distribution
            unique_classes, class_counts = np.unique(data[target_col], return_counts=True)
            class_dist = dict(zip(unique_classes, class_counts))
            
            # Calculate percentages
            total_samples = len(data)
            class_percentages = {
                cls: (count / total_samples) * 100 
                for cls, count in class_dist.items()
            }
            
            # Identify class types
            class_analysis = {
                'total_samples': total_samples,
                'unique_classes': unique_classes.tolist(),
                'class_counts': class_dist,
                'class_percentages': class_percentages,
                'is_binary': len(unique_classes) == 2,
                'is_multiclass': len(unique_classes) > 2,
                'has_unknown_class': self.unknown_class_value in unique_classes,
                'class_imbalance_ratio': max(class_counts) / min(class_counts) if len(class_counts) > 1 else 1.0
            }
            
            # Log analysis
            self.logger.info(f"📊 Total samples: {total_samples}")
            self.logger.info(f"📊 Unique classes: {unique_classes.tolist()}")
            self.logger.info(f"📊 Class distribution: {class_dist}")
            self.logger.info(f"📊 Class percentages: {dict((k, f'{v:.2f}%') for k, v in class_percentages.items())}")
            self.logger.info(f"📊 Classification type: {'Binary' if class_analysis['is_binary'] else 'Multi-class'}")
            self.logger.info(f"📊 Has unknown class (-1): {class_analysis['has_unknown_class']}")
            self.logger.info(f"📊 Class imbalance ratio: {class_analysis['class_imbalance_ratio']:.2f}")
            
            # Warnings for potential issues
            if class_analysis['class_imbalance_ratio'] > 10:
                self.logger.warning(f"⚠️ High class imbalance detected (ratio: {class_analysis['class_imbalance_ratio']:.2f})")
                self.logger.warning("Consider enabling data balancing with --use-balancing")
            
            if class_analysis['has_unknown_class']:
                unknown_percentage = class_percentages.get(self.unknown_class_value, 0)
                self.logger.info(f"🔍 Unknown class (-1) represents {unknown_percentage:.2f}% of data")
                if unknown_percentage > 50:
                    self.logger.warning("⚠️ Unknown class represents majority of data - consider class handling strategy")
            
            self.original_class_distribution = class_analysis
            return class_analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing class distribution: {e}")
            return {}

    def handle_multiclass_data(self, data: pd.DataFrame, target_col: str = 'label') -> pd.DataFrame:
        """
        Handle multi-class data according to specified strategy
        **FIXED**: Better class preservation and validation
        
        Args:
            data: Input DataFrame
            target_col: Target column name
            
        Returns:
            Processed DataFrame according to class handling strategy
        """
        try:
            self.logger.info(f"🎯 Applying class handling strategy: {self.class_handling_strategy}")
            start_time = time.time()
            
            initial_shape = data.shape
            
            # **CRITICAL**: Analyze input data first
            if target_col not in data.columns:
                raise ValueError(f"Target column '{target_col}' not found in data")
            
            # Get original class distribution
            original_classes = np.unique(data[target_col])
            original_dist = dict(zip(*np.unique(data[target_col], return_counts=True)))
            
            self.logger.info(f"📊 Input data - Classes: {original_classes}, Distribution: {original_dist}")
            
            # **SAFETY CHECK**: Ensure we have multiple classes before processing
            if len(original_classes) < 2:
                self.logger.warning(f"⚠️ Input data has only {len(original_classes)} class(es): {original_classes}")
                self.logger.warning("⚠️ Switching to 'keep_all' strategy to preserve data")
                self.class_handling_strategy = 'keep_all'
            
            if self.class_handling_strategy == 'keep_all':
                # Keep all classes as-is
                processed_data = data.copy()
                self.logger.info("✅ Keeping all classes unchanged")
                
            elif self.class_handling_strategy == 'remove_unknown':
                # **ENHANCED**: Only remove unknown if we have enough other samples
                mask = data[target_col] != self.unknown_class_value
                remaining_samples = mask.sum()
                removed_samples = initial_shape[0] - remaining_samples
                
                # Check if we have enough samples in each remaining class
                remaining_data = data[mask]
                remaining_classes = np.unique(remaining_data[target_col])
                remaining_dist = dict(zip(*np.unique(remaining_data[target_col], return_counts=True)))
                
                self.logger.info(f"📊 After removing unknown - Classes: {remaining_classes}, Distribution: {remaining_dist}")
                
                # **SAFETY CHECK**: Ensure we still have multiple classes
                if len(remaining_classes) < 2:
                    self.logger.warning(f"⚠️ Removing unknown would leave only {len(remaining_classes)} class(es)")
                    self.logger.warning("⚠️ Switching to 'keep_all' strategy to preserve classification")
                    processed_data = data.copy()
                    self.class_handling_strategy = 'keep_all'  # Update strategy
                elif remaining_samples < initial_shape[0] * 0.1:  # Less than 10% remaining
                    self.logger.warning(f"⚠️ Removing unknown would leave only {remaining_samples} samples ({remaining_samples/initial_shape[0]:.1%})")
                    self.logger.warning("⚠️ Switching to 'keep_all' strategy to preserve data")
                    processed_data = data.copy()
                    self.class_handling_strategy = 'keep_all'  # Update strategy
                else:
                    processed_data = remaining_data.copy()
                    self.logger.info(f"✅ Removed {removed_samples} samples with unknown class ({self.unknown_class_value})")
                
            elif self.class_handling_strategy == 'binary_unknown_as_malware':
                # Convert unknown (-1) to malware (1) for binary classification
                processed_data = data.copy()
                mask = processed_data[target_col] == self.unknown_class_value
                processed_data.loc[mask, target_col] = 1
                converted_count = mask.sum()
                self.logger.info(f"✅ Converted {converted_count} unknown samples to malware class (1)")
                
            elif self.class_handling_strategy == 'binary_unknown_as_benign':
                # Convert unknown (-1) to benign (0) for binary classification
                processed_data = data.copy()
                mask = processed_data[target_col] == self.unknown_class_value
                processed_data.loc[mask, target_col] = 0
                converted_count = mask.sum()
                self.logger.info(f"✅ Converted {converted_count} unknown samples to benign class (0)")
                
            elif self.class_handling_strategy == 'relabel_sequential':
                # Relabel classes to sequential integers (0, 1, 2, ...)
                processed_data = data.copy()
                unique_classes = sorted(processed_data[target_col].unique())
                class_mapping = {old_class: new_class for new_class, old_class in enumerate(unique_classes)}
                processed_data[target_col] = processed_data[target_col].map(class_mapping)
                self.class_mapping = class_mapping
                self.logger.info(f"✅ Relabeled classes: {class_mapping}")
                
            else:
                self.logger.warning(f"Unknown class handling strategy '{self.class_handling_strategy}', keeping all classes")
                processed_data = data.copy()
            
            # **FINAL VALIDATION**: Ensure we have multiple classes
            final_classes = np.unique(processed_data[target_col])
            final_dist = dict(zip(*np.unique(processed_data[target_col], return_counts=True)))
            
            self.logger.info(f"📊 Final data - Classes: {final_classes}, Distribution: {final_dist}")
            
            if len(final_classes) < 2:
                raise ValueError(
                    f"CRITICAL: After '{self.class_handling_strategy}' processing, data contains only {len(final_classes)} class(es): {final_classes}\n"
                    f"Final distribution: {final_dist}\n"
                    f"Original distribution: {original_dist}\n"
                    f"Cannot proceed with classification! Check your data source."
                )
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['class_handling'] = processing_time
            
            # Analyze final class distribution
            final_analysis = self.analyze_class_distribution(processed_data, target_col)
            self.final_class_distribution = final_analysis
            
            self.logger.info(f"✅ Class handling completed in {processing_time:.2f}s")
            self.logger.info(f"📊 Shape: {initial_shape} → {processed_data.shape}")
            self.logger.info(f"📊 Class preservation: {len(final_classes)}/{len(original_classes)} classes retained")
            
            return processed_data
            
        except Exception as e:
            self.logger.error(f"Error handling multi-class data: {e}")
            raise

    def balance_data(self, data: pd.DataFrame, target_col: str, method: str = 'smote') -> pd.DataFrame:
        """
        Balance dataset using specified method
        **ENHANCED**: Better multi-class support with validation
        """
        try:
            if not IMBALANCED_LEARN_AVAILABLE or method == 'none':
                self.logger.info("⚠️ Skipping data balancing")
                return data
                
            self.logger.info(f"⚖️ Balancing data using '{method}' method...")
            start_time = time.time()
            
            # Separate features and target
            X = data.drop(columns=[target_col])
            y = data[target_col]
            
            # Check class distribution before balancing
            unique_before, counts_before = np.unique(y, return_counts=True)
            self.stats['class_distribution_before'] = dict(zip(unique_before, counts_before))
            self.logger.info(f"Before balancing: {dict(zip(unique_before, counts_before))}")
            
            # Validate minimum samples per class for SMOTE-based methods
            min_samples = min(counts_before)
            if method in ['smote', 'adasyn', 'borderline'] and min_samples < 6:
                self.logger.warning(f"⚠️ Minimum class has only {min_samples} samples, switching to random oversampling")
                method = 'random'
            
            # Apply balancing
            if method == 'smote':
                # Adjust k_neighbors for small classes
                k_neighbors = min(5, min_samples - 1) if min_samples > 1 else 1
                balancer = SMOTE(random_state=42, k_neighbors=k_neighbors)
            elif method == 'adasyn':
                k_neighbors = min(5, min_samples - 1) if min_samples > 1 else 1
                balancer = ADASYN(random_state=42, n_neighbors=k_neighbors)
            elif method == 'borderline':
                k_neighbors = min(5, min_samples - 1) if min_samples > 1 else 1
                balancer = BorderlineSMOTE(random_state=42, k_neighbors=k_neighbors)
            elif method == 'random':
                # Simple random oversampling
                from sklearn.utils import resample
                max_count = max(counts_before)
                balanced_dfs = []
                for class_val in unique_before:
                    class_data = data[data[target_col] == class_val]
                    if len(class_data) < max_count:
                        resampled = resample(class_data, n_samples=max_count, random_state=42)
                        balanced_dfs.append(resampled)
                    else:
                        balanced_dfs.append(class_data)
                balanced_data = pd.concat(balanced_dfs, ignore_index=True)
                
                processing_time = time.time() - start_time
                self.stats['processing_time']['balancing'] = processing_time
                
                unique_after, counts_after = np.unique(balanced_data[target_col], return_counts=True)
                self.stats['class_distribution_after'] = dict(zip(unique_after, counts_after))
                
                self.logger.info(f"✅ Data balanced in {processing_time:.2f}s")
                self.logger.info(f"After balancing: {dict(zip(unique_after, counts_after))}")
                
                return balanced_data
            else:
                self.logger.warning(f"Unknown balancing method '{method}', skipping")
                return data
            
            # Apply SMOTE-based balancing
            try:
                X_balanced, y_balanced = balancer.fit_resample(X, y)
                
                # Combine back into DataFrame
                balanced_data = pd.DataFrame(X_balanced, columns=X.columns)
                balanced_data[target_col] = y_balanced
                
            except Exception as e:
                self.logger.warning(f"SMOTE balancing failed: {e}, switching to random oversampling")
                return self.balance_data(data, target_col, 'random')
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['balancing'] = processing_time
            
            # Check class distribution after balancing
            unique_after, counts_after = np.unique(y_balanced, return_counts=True)
            self.stats['class_distribution_after'] = dict(zip(unique_after, counts_after))
            
            self.logger.info(f"✅ Data balanced in {processing_time:.2f}s")
            self.logger.info(f"After balancing: {dict(zip(unique_after, counts_after))}")
            
            return balanced_data
            
        except Exception as e:
            self.logger.error(f"Error balancing data: {e}")
            return data

    def robust_feature_scaling(self, data: pd.DataFrame) -> Tuple[pd.DataFrame, object]:
        """
        Robust feature scaling with outlier handling
        
        Args:
            data: Input DataFrame
            
        Returns:
            Tuple of (scaled_data, fitted_scaler)
        """
        try:
            scaling_method = self.config.get('scaling_method', 'robust')
            self.logger.info(f"📏 Applying {scaling_method} feature scaling...")
            start_time = time.time()
            
            # Separate features and target
            feature_cols = [col for col in data.columns if col != 'label']
            X = data[feature_cols]
            
            # Initialize scaler
            if scaling_method == 'robust':
                scaler = RobustScaler(quantile_range=(25.0, 75.0))
            elif scaling_method == 'standard':
                scaler = StandardScaler(with_mean=True, with_std=True)
            elif scaling_method == 'minmax':
                scaler = MinMaxScaler(feature_range=(0, 1))
            else:
                self.logger.warning(f"Unknown scaling method '{scaling_method}', using robust")
                scaler = RobustScaler()
            
            # Fit and transform
            X_scaled = scaler.fit_transform(X)
            
            # Create scaled DataFrame
            scaled_data = pd.DataFrame(X_scaled, columns=feature_cols, index=data.index)
            if 'label' in data.columns:
                scaled_data['label'] = data['label']
            
            self.scaler = scaler
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['scaling'] = processing_time
            
            self.logger.info(f"✅ Feature scaling completed in {processing_time:.2f}s")
            
            return scaled_data, scaler
            
        except Exception as e:
            self.logger.error(f"Error in feature scaling: {e}")
            raise
    
    def save_string_datasets(self, train_string: pd.DataFrame, test_string: pd.DataFrame, 
                           val_string: pd.DataFrame, output_path: Path) -> Dict[str, str]:
        """
        Save string datasets to files
        
        Args:
            train_string: Training string data
            test_string: Test string data
            val_string: Validation string data
            output_path: Output directory path
            
        Returns:
            Dictionary with paths to saved string files
        """
        try:
            self.logger.info("💾 Saving string datasets...")
            start_time = time.time()
            
            string_files = {}
            
            # Save string datasets if they have data
            if not train_string.empty:
                train_string_path = output_path / "train_string_data.parquet"
                train_string.to_parquet(train_string_path, index=False)
                string_files['train_string'] = str(train_string_path)
                self.logger.info(f"Saved training string data: {train_string.shape}")
            
            if not test_string.empty:
                test_string_path = output_path / "test_string_data.parquet" 
                test_string.to_parquet(test_string_path, index=False)
                string_files['test_string'] = str(test_string_path)
                self.logger.info(f"Saved test string data: {test_string.shape}")
            
            if not val_string.empty:
                val_string_path = output_path / "val_string_data.parquet"
                val_string.to_parquet(val_string_path, index=False)
                string_files['val_string'] = str(val_string_path)
                self.logger.info(f"Saved validation string data: {val_string.shape}")
            
            # Save string column metadata
            string_metadata = {
                'string_columns': self.string_column_names,
                'excluded_string_columns': self.excluded_string_columns,
                'string_column_count': len(self.string_column_names),
                'string_data_shapes': {
                    'train': train_string.shape,
                    'test': test_string.shape, 
                    'val': val_string.shape
                },
                'timestamp': datetime.now().isoformat()
            }
            
            string_metadata_path = output_path / "string_data_metadata.json"
            with open(string_metadata_path, 'w') as f:
                json.dump(string_metadata, f, indent=2, default=str)
            
            string_files['string_metadata'] = str(string_metadata_path)
            
            processing_time = time.time() - start_time
            self.stats['processing_time']['string_saving'] = processing_time
            
            self.logger.info(f"✅ String datasets saved in {processing_time:.2f}s")
            self.logger.info(f"📊 String files created: {len(string_files)}")
            
            return string_files
            
        except Exception as e:
            self.logger.error(f"Error saving string datasets: {e}")
            return {}
    
    def preprocess_and_save(self, output_dir: str = "outputs/processed_data") -> Dict[str, str]:
        """
        Complete preprocessing pipeline with save functionality
        **ENHANCED**: Better class validation and data preservation
        """
        try:
            self.logger.info("🚀 Starting complete preprocessing pipeline...")
            pipeline_start = time.time()
            
            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Step 1: Load data using DataLoader
            self.logger.info("📥 Loading data using DataLoader...")
            self._monitor_memory("start_loading")
            
            # Load training data
            train_data = self.data_loader.load_train_data(
                chunk_size=self.config.get('chunk_size', 10000),
                nrows=self.config.get('subset_size')
            )
            
            # **CRITICAL**: Validate input data immediately
            if 'label' in train_data.columns:
                input_classes = np.unique(train_data['label'])
                input_dist = dict(zip(*np.unique(train_data['label'], return_counts=True)))
                self.logger.info(f"📊 Input training data - Classes: {input_classes}, Distribution: {input_dist}")
                
                if len(input_classes) < 2:
                    raise ValueError(
                        f"CRITICAL: Input training data contains only {len(input_classes)} class(es): {input_classes}\n"
                        f"Distribution: {input_dist}\n"
                        f"Cannot proceed with classification. Check your source data!"
                    )
            else:
                self.logger.warning("⚠️ No 'label' column found in training data")
            
            # Load test data if available
            try:
                test_data = self.data_loader.load_test_data(
                    chunk_size=self.config.get('chunk_size', 10000),
                    nrows=self.config.get('subset_size')
                )
                
                # Validate test data
                if test_data is not None and 'label' in test_data.columns:
                    test_classes = np.unique(test_data['label'])
                    test_dist = dict(zip(*np.unique(test_data['label'], return_counts=True)))
                    self.logger.info(f"📊 Input test data - Classes: {test_classes}, Distribution: {test_dist}")
                    
            except Exception as e:
                self.logger.warning(f"Could not load test data: {e}")
                test_data = None
            
            self._monitor_memory("data_loaded")
            
            # Step 2: Analyze class distribution BEFORE any processing
            self.logger.info("🔍 Analyzing class distribution...")
            if 'label' in train_data.columns:
                self.analyze_class_distribution(train_data, 'label')
            
            # Step 3: Handle multi-class data with enhanced validation
            self.logger.info("🎯 Handling multi-class data...")
            train_data = self.handle_multiclass_data(train_data, 'label')
            
            if test_data is not None and 'label' in test_data.columns:
                test_data = self.handle_multiclass_data(test_data, 'label')
            
            # Step 4: Prepare numerical training data AND string data
            self.logger.info("🔢 Preparing numerical training data and string data...")
            train_numerical, train_string = self.prepare_numerical_training_data(train_data)
            
            # **ENHANCED**: Validate numerical data has labels
            if 'label' not in train_numerical.columns:
                raise ValueError("CRITICAL: Label column lost during numerical data preparation!")
            
            # Validate we still have multiple classes after numerical preparation
            num_classes = np.unique(train_numerical['label'])
            num_dist = dict(zip(*np.unique(train_numerical['label'], return_counts=True)))
            self.logger.info(f"📊 Numerical training data - Classes: {num_classes}, Distribution: {num_dist}")
            
            if len(num_classes) < 2:
                raise ValueError(
                    f"CRITICAL: Numerical training data contains only {len(num_classes)} class(es): {num_classes}\n"
                    f"Distribution: {num_dist}\n"
                    f"Data lost during numerical preparation!"
                )
            
            if test_data is not None:
                test_numerical, test_string = self.prepare_numerical_training_data(test_data)
                
                # Ensure same features in both datasets
                common_features = list(set(train_numerical.columns) & set(test_numerical.columns))
                if 'label' not in common_features:
                    common_features.append('label')  # Always keep label
                
                train_numerical = train_numerical[common_features]
                test_numerical = test_numerical[common_features]
                
                # Validate test data after processing
                if 'label' in test_numerical.columns:
                    test_num_classes = np.unique(test_numerical['label'])
                    test_num_dist = dict(zip(*np.unique(test_numerical['label'], return_counts=True)))
                    self.logger.info(f"📊 Numerical test data - Classes: {test_num_classes}, Distribution: {test_num_dist}")
                
                # Ensure same string columns
                if not train_string.empty and not test_string.empty:
                    common_string_cols = list(set(train_string.columns) & set(test_string.columns))
                    train_string = train_string[common_string_cols] if common_string_cols else pd.DataFrame()
                    test_string = test_string[common_string_cols] if common_string_cols else pd.DataFrame()
            else:
                # Split training data - ensure stratification works with final classes
                try:
                    # **ENHANCED**: Better stratification
                    stratify_labels = train_numerical['label'] if 'label' in train_numerical.columns else None
                    
                    # Check if stratification is possible
                    if stratify_labels is not None:
                        label_counts = stratify_labels.value_counts()
                        min_class_count = label_counts.min()
                        test_size = self.config.get('test_split', 0.2)
                        min_required = int(1 / test_size) + 1  # Minimum samples needed for stratification
                        
                        if min_class_count < min_required:
                            self.logger.warning(f"⚠️ Minimum class has only {min_class_count} samples, cannot stratify")
                            stratify_labels = None
                    
                    train_numerical, test_numerical = train_test_split(
                        train_numerical, 
                        test_size=test_size,
                        random_state=42,
                        stratify=stratify_labels
                    )
                    
                    if stratify_labels is not None:
                        self.logger.info("✅ Stratified split successful")
                    else:
                        self.logger.info("✅ Random split applied")
                        
                except ValueError as e:
                    self.logger.warning(f"Stratified split failed: {e}, using random split")
                    train_numerical, test_numerical = train_test_split(
                        train_numerical, 
                        test_size=self.config.get('test_split', 0.2),
                        random_state=42
                    )
                
                # **VALIDATION**: Check split results
                for split_name, split_data in [("train", train_numerical), ("test", test_numerical)]:
                    if 'label' in split_data.columns:
                        split_classes = np.unique(split_data['label'])
                        split_dist = dict(zip(*np.unique(split_data['label'], return_counts=True)))
                        self.logger.info(f"📊 {split_name.title()} split - Classes: {split_classes}, Distribution: {split_dist}")
                        
                        if len(split_classes) < 2:
                            self.logger.warning(f"⚠️ {split_name.title()} split has only {len(split_classes)} class(es)")
                
                # Split string data if available
                if not train_string.empty:
                    try:
                        train_string_split, test_string_split = train_test_split(
                            train_string,
                            test_size=self.config.get('test_split', 0.2),
                            random_state=42
                        )
                        train_string = train_string_split
                        test_string = test_string_split
                    except Exception as e:
                        self.logger.warning(f"String data split failed: {e}")
                        test_string = pd.DataFrame()
                else:
                    test_string = pd.DataFrame()
            
            # Continue with rest of preprocessing...
            self.stats['original_samples'] = len(train_numerical) + len(test_numerical)
            self.stats['original_features'] = len([col for col in train_numerical.columns if col != 'label'])
            
            # Step 5: Handle missing values
            if self.config.get('handle_missing', True):
                self.logger.info("🔧 Handling missing values...")
                train_numerical = self.handle_missing_values(
                    train_numerical, 
                    self.config.get('missing_strategy', 'smart')
                )
                test_numerical = self.handle_missing_values(
                    test_numerical, 
                    self.config.get('missing_strategy', 'smart')
                )
            
            # Step 6: Feature scaling
            if self.config.get('use_scaling', True):
                self.logger.info("📏 Applying feature scaling...")
                train_scaled, fitted_scaler = self.robust_feature_scaling(train_numerical)
                
                # Apply same scaling to test data
                feature_cols = [col for col in test_numerical.columns if col != 'label']
                test_features = test_numerical[feature_cols]
                test_scaled_features = fitted_scaler.transform(test_features)
                
                test_scaled = pd.DataFrame(test_scaled_features, columns=feature_cols, index=test_numerical.index)
                if 'label' in test_numerical.columns:
                    test_scaled['label'] = test_numerical['label']
                    
                train_numerical = train_scaled
                test_numerical = test_scaled
            
            # Step 7: Split training data into train/validation
            self.logger.info("📊 Creating train/validation split...")
            
            # **ENHANCED**: Better validation split with class preservation
            try:
                val_stratify = train_numerical['label'] if 'label' in train_numerical.columns else None
                
                # Check stratification feasibility
                if val_stratify is not None:
                    val_label_counts = val_stratify.value_counts()
                    val_min_class_count = val_label_counts.min()
                    val_test_size = self.config.get('validation_split', 0.2)
                    val_min_required = int(1 / val_test_size) + 1
                    
                    if val_min_class_count < val_min_required:
                        self.logger.warning(f"⚠️ Cannot stratify validation split, minimum class has {val_min_class_count} samples")
                        val_stratify = None
                
                train_final, val_final = train_test_split(
                    train_numerical,
                    test_size=val_test_size,
                    random_state=42,
                    stratify=val_stratify
                )
                
                # Validate splits
                for val_split_name, val_split_data in [("final_train", train_final), ("validation", val_final)]:
                    if 'label' in val_split_data.columns:
                        val_split_classes = np.unique(val_split_data['label'])
                        val_split_dist = dict(zip(*np.unique(val_split_data['label'], return_counts=True)))
                        self.logger.info(f"📊 {val_split_name.title()} - Classes: {val_split_classes}, Distribution: {val_split_dist}")
                        
            except Exception as e:
                self.logger.warning(f"Validation split failed: {e}")
                # Use a simple split if stratification fails
                train_final, val_final = train_test_split(
                    train_numerical,
                    test_size=self.config.get('validation_split', 0.2),
                    random_state=42
                )
            
            # Split string data for validation if available
            if not train_string.empty:
                train_string_final, val_string_final = train_test_split(
                    train_string,
                    test_size=self.config.get('validation_split', 0.2),
                    random_state=42
                )
            else:
                train_string_final = pd.DataFrame()
                val_string_final = pd.DataFrame()
            
            # Step 8: Apply data balancing (only on training set)
            if self.config.get('use_balancing', False):
                self.logger.info("⚖️ Applying data balancing to training set...")
                
                # Check if balancing is needed and possible
                if 'label' in train_final.columns:
                    balance_classes = np.unique(train_final['label'])
                    balance_dist = dict(zip(*np.unique(train_final['label'], return_counts=True)))
                    self.logger.info(f"📊 Pre-balance - Classes: {balance_classes}, Distribution: {balance_dist}")
                    
                    if len(balance_classes) >= 2:
                        train_final = self.balance_data(
                            train_final,
                            'label',
                            self.config.get('balancing_method', 'smote')
                        )
                        
                        # Validate post-balance
                        post_balance_classes = np.unique(train_final['label'])
                        post_balance_dist = dict(zip(*np.unique(train_final['label'], return_counts=True)))
                        self.logger.info(f"📊 Post-balance - Classes: {post_balance_classes}, Distribution: {post_balance_dist}")
                    else:
                        self.logger.warning("⚠️ Cannot balance data - insufficient classes")
            
            # Update statistics
            self.stats['processed_samples']['train'] = len(train_final)
            self.stats['processed_samples']['val'] = len(val_final)
            self.stats['processed_samples']['test'] = len(test_numerical)
            self.stats['processed_features'] = len([col for col in train_final.columns if col != 'label'])
            
            # **FINAL VALIDATION**: Ensure all datasets have multiple classes before saving
            datasets_to_validate = [
                ("Final Training", train_final),
                ("Final Validation", val_final),
                ("Final Test", test_numerical)
            ]
            
            for dataset_name, dataset in datasets_to_validate:
                if 'label' in dataset.columns:
                    final_classes = np.unique(dataset['label'])
                    final_dist = dict(zip(*np.unique(dataset['label'], return_counts=True)))
                    self.logger.info(f"📊 {dataset_name} - Classes: {final_classes}, Distribution: {final_dist}")
                    
                    if len(final_classes) < 2:
                        raise ValueError(
                            f"CRITICAL: {dataset_name} dataset contains only {len(final_classes)} class(es): {final_classes}\n"
                            f"Distribution: {final_dist}\n"
                            f"Cannot save dataset for classification!"
                        )
            
            # Step 9: Save processed numerical datasets
            self.logger.info("💾 Saving processed numerical datasets...")
            saved_files = {}
            
            # **ENHANCED**: Save with better naming and validation
            train_path = output_path / "train_data.parquet"  # Use consistent naming
            val_path = output_path / "val_data.parquet" 
            test_path = output_path / "test_data.parquet"
            
            # Save with validation
            for save_name, save_path, save_data in [
                ("train", train_path, train_final),
                ("validation", val_path, val_final), 
                ("test", test_path, test_numerical)
            ]:
                try:
                    save_data.to_parquet(save_path, index=False)
                    saved_files[save_name] = str(save_path)
                    
                    # Validate saved file
                    saved_check = pd.read_parquet(save_path)
                    if 'label' in saved_check.columns:
                        saved_classes = np.unique(saved_check['label'])
                        saved_dist = dict(zip(*np.unique(saved_check['label'], return_counts=True)))
                        self.logger.info(f"✅ Saved {save_name} - Shape: {saved_check.shape}, Classes: {saved_classes}, Distribution: {saved_dist}")
                    else:
                        self.logger.warning(f"⚠️ Saved {save_name} file missing 'label' column")
                        
                except Exception as e:
                    self.logger.error(f"❌ Failed to save {save_name} data: {e}")
                    raise
            
            # Step 10: Save string datasets if enabled
            if self.config.get('save_string_data', True):
                string_files = self.save_string_datasets(
                    train_string_final, 
                    test_string if not test_string.empty else pd.DataFrame(),
                    val_string_final,
                    output_path
                )
                saved_files.update(string_files)
            
            # Step 11: Save preprocessing components and metadata
            components = {
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'excluded_string_columns': self.excluded_string_columns,
                'string_column_names': self.string_column_names,
                'config': self.config,
                'stats': self.stats,
                'class_mapping': self.class_mapping,
                'final_class_distribution': self.final_class_distribution
            }
            
            components_path = output_path / "preprocessing_components.pkl"
            with open(components_path, 'wb') as f:
                pickle.dump(components, f)
            saved_files['components'] = str(components_path)
            
            # Enhanced metadata with class validation info
            metadata = {
                'preprocessing_config': self.config,
                'statistics': self.stats,
                'file_paths': saved_files,
                'timestamp': datetime.now().isoformat(),
                'feature_names': self.feature_names,
                'excluded_columns': self.excluded_string_columns,
                'string_columns': self.string_column_names,
                'string_data_saved': self.config.get('save_string_data', True),
                'class_handling_strategy': self.class_handling_strategy,
                'final_class_distribution': self.final_class_distribution,
                'class_mapping': self.class_mapping,
                'validation_passed': True  # Mark as validated
            }
            
            metadata_path = output_path / "preprocessing_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2, default=str)
            saved_files['metadata'] = str(metadata_path)
            
            pipeline_time = time.time() - pipeline_start
            self.stats['processing_time']['total_pipeline'] = pipeline_time
            
            self.logger.info(f"✅ Preprocessing pipeline completed in {pipeline_time:.2f}s")
            self.logger.info(f"📁 Files saved to: {output_dir}")
            self.logger.info(f"💾 String data saved: {'Yes' if self.config.get('save_string_data', True) else 'No'}")
            self.logger.info(f"🎯 Class handling strategy: {self.class_handling_strategy}")
            self.logger.info(f"✅ All datasets validated with multiple classes")
            
            return saved_files
            
        except Exception as e:
            self.logger.error(f"Error in preprocessing pipeline: {e}")
            raise
    
    def generate_preprocessing_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive preprocessing report
        **MODIFIED**: Now includes string data information
        
        Returns:
            Dictionary containing detailed preprocessing report
        """
        try:
            self.logger.info("📊 Generating preprocessing report...")
            
            report = {
                'summary': {
                    'total_processing_time': sum(self.stats['processing_time'].values()),
                    'original_samples': self.stats['original_samples'],
                    'processed_samples': self.stats['processed_samples'],
                    'original_features': self.stats['original_features'],
                    'processed_features': self.stats['processed_features'],
                    'string_columns_removed': self.stats['string_columns_removed'],
                    'string_columns_saved': self.stats['string_columns_saved'],
                    'outliers_removed': self.stats['outliers_removed']
                },
                'class_distribution': {
                    'before_balancing': self.stats['class_distribution_before'],
                    'after_balancing': self.stats['class_distribution_after']
                },
                'processing_times': self.stats['processing_time'],
                'memory_usage': self.memory_usage,
                'configuration': self.config,
                'feature_info': {
                    'selected_features': self.feature_names,
                    'excluded_string_columns': self.excluded_string_columns
                },
                'string_data_info': {
                    'string_columns': self.string_column_names,
                    'string_data_saved': self.config.get('save_string_data', True),
                    'string_columns_count': len(self.string_column_names)
                }
            }
            
            self.logger.info("✅ Preprocessing report generated")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating preprocessing report: {e}")
            return {}


def create_config_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """
    Create configuration dictionary from command line arguments
    **ENHANCED**: Now includes multi-class handling options
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Configuration dictionary
    """
    config = {
        'subset_size': args.subset_size,
        'use_preprocessing': args.use_preprocessing,
        'use_balancing': args.use_balancing,
        'balancing_method': args.balancing_method,
        'missing_strategy': args.missing_strategy,
        'chunk_size': args.chunk_size,
        'output_dir': args.output_dir,
        'random_seed': args.random_seed,
        'memory_limit': args.memory_limit,
        'n_cores': args.n_cores,
        'scaling_method': args.feature_scaling,
        'outlier_handling': args.outlier_handling,
        'save_string_data': args.save_string_data,
        'validation_split': 0.2,
        'test_split': 0.2,
        'use_scaling': True,
        'handle_missing': True,
        
        # **NEW**: Multi-class handling options
        'class_handling': args.class_handling,
        'unknown_class_value': args.unknown_class_value
    }
    
    return config


def main():
    """Main function with argument parsing for preprocessing"""
    parser = argparse.ArgumentParser(description="EMBER2018 Data Preprocessing Pipeline with Multi-Class Support")
    
    # Data loading arguments
    parser.add_argument('--data-dir', type=str, default="data/ember2018_parquet",
                       help='Directory containing EMBER2018 parquet files')
    parser.add_argument('--subset-size', type=int, default=None,
                       help='Number of samples to use (default: all)')
    parser.add_argument('--chunk-size', type=int, default=10000,
                       help='Chunk size for memory efficiency (default: 10000)')
    
    # Preprocessing arguments
    parser.add_argument('--use-preprocessing', action='store_true', default=True,
                       help='Enable/disable preprocessing (default: True)')
    parser.add_argument('--use-balancing', action='store_true', default=False,
                       help='Enable/disable data balancing (default: False)')
    parser.add_argument('--balancing-method', type=str, default='smote',
                       choices=['smote', 'adasyn', 'borderline', 'random', 'none'],
                       help='Balancing method (default: smote)')
    parser.add_argument('--missing-strategy', type=str, default='smart',
                       choices=['drop', 'fill', 'smart'],
                       help='Missing value strategy (default: smart)')
    parser.add_argument('--feature-scaling', type=str, default='robust',
                       choices=['standard', 'robust', 'minmax'],
                       help='Feature scaling method (default: robust)')
    parser.add_argument('--outlier-handling', action='store_true', default=True,
                       help='Enable outlier detection and handling (default: True)')
    
    # String data arguments **NEW**
    parser.add_argument('--save-string-data', action='store_true', default=True,
                       help='Save separated string datasets (default: True)')
    parser.add_argument('--no-save-string-data', dest='save_string_data', action='store_false',
                       help='Disable saving string datasets')
    
    # Output arguments
    parser.add_argument('--output-dir', type=str, default="outputs/processed_data",
                       help='Output directory for processed data')
    parser.add_argument('--report-level', type=str, default='detailed',
                       choices=['basic', 'detailed', 'comprehensive'],
                       help='Report detail level (default: detailed)')
    
    # System arguments
    parser.add_argument('--random-seed', type=int, default=42,
                       help='Random seed for reproducibility (default: 42)')
    parser.add_argument('--memory-limit', type=float, default=8.0,
                       help='Memory limit in GB (default: 8.0)')
    parser.add_argument('--n-cores', type=int, default=-1,
                       help='Number of processor cores to use (default: -1)')
    parser.add_argument('--verbose', action='store_true', default=False,
                       help='Enable verbose output')
    
    # **NEW**: Multi-class handling arguments
    parser.add_argument('--class-handling', type=str, default='keep_all',
                       choices=['keep_all', 'remove_unknown', 'binary_unknown_as_malware', 
                               'binary_unknown_as_benign', 'relabel_sequential'],
                       help='Strategy for handling multi-class data (default: keep_all)')
    parser.add_argument('--unknown-class-value', type=int, default=-1,
                       help='Value representing unknown class (default: -1)')
    
    args = parser.parse_args()
    
    # Set random seed
    np.random.seed(args.random_seed)
    
    try:
        print("🚀 Starting EMBER2018 Data Preprocessing...")
        start_time = time.time()
        
        # Initialize DataLoader
        print("📂 Initializing DataLoader...")
        data_loader = DataLoader(
            data_dir=args.data_dir,
            n_cores=args.n_cores
        )
        
        # Create configuration
        config = create_config_from_args(args)
        
        # Initialize DataPreprocessor
        print("🔧 Initializing DataPreprocessor...")
        preprocessor = DataPreprocessor(data_loader, config)
        
        # Run preprocessing pipeline
        print("⚙️ Running preprocessing pipeline...")
        saved_files = preprocessor.preprocess_and_save(args.output_dir)
        
        # Generate report
        if args.report_level != 'basic':
            print("📊 Generating preprocessing report...")
            report = preprocessor.generate_preprocessing_report()
            
            # Save report
            report_path = Path(args.output_dir) / "preprocessing_report.json"
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            saved_files['report'] = str(report_path)
        
        total_time = time.time() - start_time
        
        print("\n" + "="*60)
        print("✅ PREPROCESSING COMPLETED SUCCESSFULLY")
        print("="*60)
        print(f"⏱️  Total time: {total_time:.2f}s")
        print(f"📁 Output directory: {args.output_dir}")
        print(f"💾 String data saved: {'Yes' if config.get('save_string_data', True) else 'No'}")
        print("\n📄 Generated files:")
        for file_type, file_path in saved_files.items():
            print(f"  {file_type}: {file_path}")
        
        print("\n🎯 Ready for training! Use trainer.py with processed data.")
        
    except Exception as e:
        print(f"\n❌ PREPROCESSING FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
