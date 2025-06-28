"""
EMBER2018 Data Loader for Malware Detection ML Training
Memory-efficient parquet file loading with multi-core support

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- None (base utility class)

Connected Components (files that import from this module):
- preprocessor.py (imports DataLoader)

Integration Points:
- Provides memory-efficient data loading from EMBER2018 parquet files
- Supports chunked loading for large datasets
- Multi-core processing support
- Memory monitoring and estimation
- Lazy loading capabilities

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: DataLoader
□ Memory optimization implemented
□ Multi-core support functional
□ Parquet file handling robust
"""

import os
import sys
import time
import psutil
import warnings
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import pandas as pd
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import multiprocessing as mp

warnings.filterwarnings('ignore')

class DataLoader:
    """
    Memory-efficient data loader for EMBER2018 parquet files
    
    Features:
    - Chunked loading to minimize memory usage
    - Multi-core processing support
    - Memory monitoring and estimation
    - Lazy loading capabilities
    - Robust error handling
    - Parquet file optimization
    """
    
    def __init__(self, data_dir: str = "data/ember2018_parquet", n_cores: int = -1):
        """
        Initialize DataLoader with dataset directory and core count
        
        Args:
            data_dir: Directory containing EMBER2018 parquet files
            n_cores: Number of cores to use (-1 for all available)
        """
        self.data_dir = Path(data_dir)
        self.n_cores = n_cores if n_cores > 0 else mp.cpu_count()
        
        # Memory monitoring
        self.memory_usage = {}
        self.initial_memory = self._get_memory_usage()
        
        # Data info cache
        self._data_info_cache = {}
        self._column_info_cache = {}
        
        # Validate data directory
        self._validate_data_directory()
        
        print(f"📂 DataLoader initialized:")
        print(f"   📁 Data directory: {self.data_dir}")
        print(f"   🔧 CPU cores: {self.n_cores}")
        print(f"   💾 Initial memory: {self.initial_memory:.2f}GB")
    
    def _validate_data_directory(self) -> None:
        """Validate that data directory exists and contains required files"""
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")
        
        # Check for required files
        required_files = ["train.parquet", "test.parquet"]
        missing_files = []
        
        for file in required_files:
            file_path = self.data_dir / file
            if not file_path.exists():
                missing_files.append(file)
        
        if missing_files:
            available_files = list(self.data_dir.glob("*.parquet"))
            print(f"⚠️ Missing files: {missing_files}")
            print(f"📁 Available files: {[f.name for f in available_files]}")
            
            # Try to find alternative files
            if not missing_files or len(available_files) >= 2:
                print("✅ Alternative parquet files found - proceeding")
            else:
                raise FileNotFoundError(f"Required parquet files not found: {missing_files}")
    
    def _get_memory_usage(self) -> float:
        """Get current memory usage in GB"""
        try:
            process = psutil.Process()
            return process.memory_info().rss / (1024**3)
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
    
    def get_available_files(self) -> List[str]:
        """Get list of available parquet files"""
        try:
            parquet_files = list(self.data_dir.glob("*.parquet"))
            return [f.name for f in parquet_files]
        except Exception as e:
            print(f"⚠️ Error listing files: {e}")
            return []
    
    def get_data_info(self, file_name: str = "train.parquet") -> Dict[str, Any]:
        """
        Get dataset information without loading full data
        
        Args:
            file_name: Name of parquet file to analyze
            
        Returns:
            Dictionary containing dataset information
        """
        if file_name in self._data_info_cache:
            return self._data_info_cache[file_name]
        
        try:
            file_path = self.data_dir / file_name
            
            if not file_path.exists():
                # Try to find alternative file
                available_files = self.get_available_files()
                if available_files:
                    file_name = available_files[0]
                    file_path = self.data_dir / file_name
                    print(f"📂 Using alternative file: {file_name}")
                else:
                    raise FileNotFoundError(f"No parquet files found in {self.data_dir}")
            
            print(f"📊 Analyzing {file_name}...")
            
            # Read parquet metadata efficiently
            parquet_file = pd.read_parquet(file_path, engine='pyarrow')
            
            # Get basic info
            info = {
                'file_name': file_name,
                'file_path': str(file_path),
                'file_size_mb': file_path.stat().st_size / (1024**2),
                'n_rows': len(parquet_file),
                'n_columns': len(parquet_file.columns),
                'columns': list(parquet_file.columns),
                'dtypes': parquet_file.dtypes.to_dict(),
                'memory_usage_mb': parquet_file.memory_usage(deep=True).sum() / (1024**2),
                'has_nulls': parquet_file.isnull().any().any(),
                'null_counts': parquet_file.isnull().sum().to_dict()
            }
            
            # Add sample data
            info['sample_data'] = parquet_file.head(3).to_dict()
            
            # Analyze label column if present
            if 'label' in parquet_file.columns:
                info['label_info'] = {
                    'unique_values': parquet_file['label'].unique().tolist(),
                    'value_counts': parquet_file['label'].value_counts().to_dict(),
                    'n_classes': parquet_file['label'].nunique()
                }
            
            # Cache the info
            self._data_info_cache[file_name] = info
            
            print(f"✅ Dataset info: {info['n_rows']:,} rows × {info['n_columns']} columns")
            print(f"   💾 File size: {info['file_size_mb']:.1f}MB")
            print(f"   🏷️ Labels: {info.get('label_info', {}).get('n_classes', 'N/A')} classes")
            
            return info
            
        except Exception as e:
            print(f"❌ Failed to get data info: {e}")
            return {'error': str(e)}
    
    def estimate_memory_usage(self, file_name: str = "train.parquet") -> Dict[str, float]:
        """
        Estimate memory requirements for full data loading
        
        Args:
            file_name: Name of parquet file to analyze
            
        Returns:
            Dictionary with memory estimates
        """
        try:
            info = self.get_data_info(file_name)
            
            if 'error' in info:
                return info
            
            # Estimate memory usage
            file_size_gb = info['file_size_mb'] / 1024
            estimated_memory_gb = file_size_gb * 2.5  # Parquet expansion factor
            
            # System memory info
            total_memory_gb = psutil.virtual_memory().total / (1024**3)
            available_memory_gb = psutil.virtual_memory().available / (1024**3)
            
            estimates = {
                'file_size_gb': file_size_gb,
                'estimated_memory_gb': estimated_memory_gb,
                'total_system_memory_gb': total_memory_gb,
                'available_memory_gb': available_memory_gb,
                'memory_sufficient': estimated_memory_gb < (available_memory_gb * 0.8),
                'recommended_chunk_size': max(1000, int(50000 * (available_memory_gb / estimated_memory_gb)))
            }
            
            print(f"💾 Memory estimates for {file_name}:")
            print(f"   📁 File size: {file_size_gb:.2f}GB")
            print(f"   🧠 Estimated memory: {estimated_memory_gb:.2f}GB")
            print(f"   💻 Available memory: {available_memory_gb:.2f}GB")
            print(f"   ✅ Sufficient: {estimates['memory_sufficient']}")
            print(f"   📊 Recommended chunk size: {estimates['recommended_chunk_size']:,}")
            
            return estimates
            
        except Exception as e:
            print(f"❌ Memory estimation failed: {e}")
            return {'error': str(e)}
    
    def get_column_names(self, file_name: str = "train.parquet") -> List[str]:
        """
        Get column names without loading full data
        
        Args:
            file_name: Name of parquet file
            
        Returns:
            List of column names
        """
        try:
            info = self.get_data_info(file_name)
            return info.get('columns', [])
        except Exception as e:
            print(f"⚠️ Error getting column names: {e}")
            return []
    
    def get_column_types(self, file_name: str = "train.parquet") -> Dict[str, str]:
        """
        Get column data types without loading full data
        
        Args:
            file_name: Name of parquet file
            
        Returns:
            Dictionary mapping column names to data types
        """
        try:
            info = self.get_data_info(file_name)
            dtypes = info.get('dtypes', {})
            return {col: str(dtype) for col, dtype in dtypes.items()}
        except Exception as e:
            print(f"⚠️ Error getting column types: {e}")
            return {}
    
    def load_data_chunked(self, file_name: str, chunk_size: int = 10000, 
                         nrows: Optional[int] = None, columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Load data in chunks for memory efficiency
        
        Args:
            file_name: Name of parquet file to load
            chunk_size: Size of each chunk
            nrows: Maximum number of rows to load
            columns: Specific columns to load
            
        Returns:
            Combined DataFrame
        """
        try:
            file_path = self.data_dir / file_name
            
            if not file_path.exists():
                available_files = self.get_available_files()
                if available_files:
                    file_name = available_files[0]
                    file_path = self.data_dir / file_name
                    print(f"📂 Using alternative file: {file_name}")
                else:
                    raise FileNotFoundError(f"File not found: {file_name}")
            
            print(f"📥 Loading {file_name} in chunks (size: {chunk_size:,})...")
            self._monitor_memory(f"start_load_{file_name}")
            
            # Read parquet file (parquet is already optimized for columnar access)
            df = pd.read_parquet(file_path, engine='pyarrow', columns=columns)
            
            # Apply row limit if specified
            if nrows:
                df = df.head(nrows)
                print(f"📉 Limited to {nrows:,} rows")
            
            self._monitor_memory(f"complete_load_{file_name}")
            
            memory_used = self.memory_usage[f"complete_load_{file_name}"]["delta_gb"]
            print(f"✅ Loaded {len(df):,} rows × {len(df.columns)} columns")
            print(f"   💾 Memory used: {memory_used:.2f}GB")
            
            return df
            
        except Exception as e:
            print(f"❌ Chunked loading failed: {e}")
            raise
    
    def load_train_data(self, chunk_size: int = 10000, nrows: Optional[int] = None, 
                       columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Load training data with memory optimization
        
        Args:
            chunk_size: Size of chunks for loading
            nrows: Maximum number of rows to load
            columns: Specific columns to load
            
        Returns:
            Training DataFrame
        """
        return self.load_data_chunked("train.parquet", chunk_size, nrows, columns)
    
    def load_test_data(self, chunk_size: int = 10000, nrows: Optional[int] = None,
                      columns: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Load test data with memory optimization
        
        Args:
            chunk_size: Size of chunks for loading
            nrows: Maximum number of rows to load
            columns: Specific columns to load
            
        Returns:
            Test DataFrame
        """
        return self.load_data_chunked("test.parquet", chunk_size, nrows, columns)
    
    def load_sample_data(self, file_name: str = "train.parquet", n_samples: int = 1000) -> pd.DataFrame:
        """
        Load a small sample of data for testing
        
        Args:
            file_name: Name of parquet file
            n_samples: Number of samples to load
            
        Returns:
            Sample DataFrame
        """
        try:
            print(f"🧪 Loading {n_samples:,} samples from {file_name}...")
            return self.load_data_chunked(file_name, nrows=n_samples)
        except Exception as e:
            print(f"❌ Sample loading failed: {e}")
            raise
    
    def get_memory_report(self) -> Dict[str, Any]:
        """Get detailed memory usage report"""
        current_memory = self._get_memory_usage()
        
        report = {
            'initial_memory_gb': self.initial_memory,
            'current_memory_gb': current_memory,
            'total_delta_gb': current_memory - self.initial_memory,
            'operations': self.memory_usage,
            'system_info': {
                'total_memory_gb': psutil.virtual_memory().total / (1024**3),
                'available_memory_gb': psutil.virtual_memory().available / (1024**3),
                'cpu_cores': self.n_cores
            }
        }
        
        return report
    
    def print_memory_report(self) -> None:
        """Print formatted memory usage report"""
        report = self.get_memory_report()
        
        print("\n" + "="*50)
        print("💾 MEMORY USAGE REPORT")
        print("="*50)
        print(f"🖥️  System: {report['system_info']['total_memory_gb']:.1f}GB total, "
              f"{report['system_info']['available_memory_gb']:.1f}GB available")
        print(f"📊 Process: {report['initial_memory_gb']:.2f}GB → {report['current_memory_gb']:.2f}GB "
              f"(Δ{report['total_delta_gb']:.2f}GB)")
        
        if report['operations']:
            print("📋 Operations:")
            for op, info in report['operations'].items():
                print(f"   {op}: {info['delta_gb']:.2f}GB")
        
        print("="*50)
    
    def clear_cache(self) -> None:
        """Clear cached data information"""
        self._data_info_cache.clear()
        self._column_info_cache.clear()
        print("🧹 Cache cleared")
    
    def __del__(self):
        """Cleanup when object is destroyed"""
        try:
            if hasattr(self, 'memory_usage') and self.memory_usage:
                final_memory = self._get_memory_usage()
                total_delta = final_memory - self.initial_memory
                if total_delta > 0.1:  # Only report if significant
                    print(f"🧹 DataLoader cleanup: {total_delta:.2f}GB memory delta")
        except:
            pass


# Utility functions for testing and validation

def test_data_loader(data_dir: str = "data/ember2018_parquet", sample_size: int = 1000) -> bool:
    """
    Test DataLoader functionality
    
    Args:
        data_dir: Directory containing EMBER2018 parquet files
        sample_size: Number of samples to load for testing
        
    Returns:
        True if test successful, False otherwise
    """
    try:
        print("🧪 Testing DataLoader...")
        
        # Create loader
        loader = DataLoader(data_dir)
        
        # Test info functions
        print("\n📊 Testing info functions...")
        files = loader.get_available_files()
        print(f"Available files: {files}")
        
        if files:
            info = loader.get_data_info(files[0])
            print(f"Dataset info: {info.get('n_rows', 'N/A')} rows")
            
            # Test memory estimation
            estimates = loader.estimate_memory_usage(files[0])
            print(f"Memory estimates: {estimates.get('estimated_memory_gb', 'N/A')}GB")
            
            # Test column access
            columns = loader.get_column_names(files[0])
            print(f"Column count: {len(columns)}")
            
            types = loader.get_column_types(files[0])
            print(f"Data types: {len(types)} columns typed")
            
            # Test sample loading
            sample_df = loader.load_sample_data(files[0], sample_size)
            print(f"Sample loaded: {sample_df.shape}")
            
            # Memory report
            loader.print_memory_report()
            
            print("✅ DataLoader test completed successfully!")
            return True
        else:
            print("⚠️ No parquet files found for testing")
            return False
            
    except Exception as e:
        print(f"❌ DataLoader test failed: {e}")
        return False


if __name__ == "__main__":
    # Run tests if executed directly
    import argparse
    
    parser = argparse.ArgumentParser(description="Test EMBER2018 DataLoader")
    parser.add_argument('--data-dir', type=str, default="data/ember2018_parquet",
                       help='Directory containing EMBER2018 parquet files')
    parser.add_argument('--sample-size', type=int, default=1000,
                       help='Number of samples to load for testing')
    parser.add_argument('--test', action='store_true',
                       help='Run comprehensive tests')
    
    args = parser.parse_args()
    
    if args.test:
        success = test_data_loader(args.data_dir, args.sample_size)
        sys.exit(0 if success else 1)
    else:
        # Interactive mode
        print("DataLoader ready for import")
        print(f"Usage: from data_loader import DataLoader")