"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Helper Functions - Common Utility Functions

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- ALL files (common utilities)
- src.core.scanner_engine (ScannerEngine)
- src.ui.main_window (MainWindow)
- src.detection.classification_engine (ClassificationEngine)
- src.notification.notification_manager (NotificationManager)
- src.intelligence.threat_intel (ThreatIntelligence)

Integration Points:
- Common utility functions used across the application
- String manipulation and formatting
- Time and date utilities
- File size formatting
- Version comparison
- Configuration validation
- Error message formatting
- Performance measurement
- Data structure manipulation

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: HelperFunctions
□ Dependencies properly imported with EXACT class names
□ All connected files can access HelperFunctions functionality
□ Common utilities implemented
□ String and formatting functions
□ Time and measurement utilities
□ Comprehensive error handling
"""

import os
import sys
import logging
import time
import re
import json
import platform
import psutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Callable
from datetime import datetime, timedelta
from functools import wraps
import traceback

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler


class HelperFunctions:
    """
    Collection of common utility functions used throughout the antivirus application.
    
    Provides helper functions for:
    - String manipulation and formatting
    - Time and date operations
    - File size and unit conversion
    - System information gathering
    - Performance measurement
    - Configuration validation
    - Error handling and logging
    - Data structure operations
    """
    
    def __init__(self):
        """Initialize helper functions with encoding support."""
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("HelperFunctions")
        
        # Performance tracking
        self.function_calls = {}
        self.total_execution_time = {}
        
        self.logger.info("HelperFunctions initialized")
    
    def format_file_size(self, size_bytes: Union[int, float], decimal_places: int = 2) -> str:
        """
        Format file size in human-readable format.
        
        Args:
            size_bytes: Size in bytes
            decimal_places: Number of decimal places to show
            
        Returns:
            Formatted size string (e.g., "1.23 MB")
        """
        try:
            if size_bytes == 0:
                return "0 B"
            
            # Handle negative sizes
            if size_bytes < 0:
                return f"-{self.format_file_size(-size_bytes, decimal_places)}"
            
            size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
            size_bytes = float(size_bytes)
            i = 0
            
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1
            
            if i == 0:  # Bytes - no decimal places
                return f"{int(size_bytes)} {size_names[i]}"
            else:
                return f"{size_bytes:.{decimal_places}f} {size_names[i]}"
                
        except Exception as e:
            self.logger.error(f"Error formatting file size: {e}")
            return f"{size_bytes} B"
    
    def format_duration(self, seconds: Union[int, float], precision: str = 'auto') -> str:
        """
        Format duration in human-readable format.
        
        Args:
            seconds: Duration in seconds
            precision: Precision level ('auto', 'seconds', 'milliseconds', 'microseconds')
            
        Returns:
            Formatted duration string
        """
        try:
            if seconds < 0:
                return f"-{self.format_duration(-seconds, precision)}"
            
            if precision == 'auto':
                if seconds < 0.001:  # Less than 1ms
                    precision = 'microseconds'
                elif seconds < 1:  # Less than 1s
                    precision = 'milliseconds'
                else:
                    precision = 'seconds'
            
            if precision == 'microseconds':
                microseconds = seconds * 1_000_000
                return f"{microseconds:.1f} μs"
            elif precision == 'milliseconds':
                milliseconds = seconds * 1000
                return f"{milliseconds:.1f} ms"
            else:  # seconds
                if seconds < 60:
                    return f"{seconds:.2f} s"
                elif seconds < 3600:  # Less than 1 hour
                    minutes = int(seconds // 60)
                    remaining_seconds = seconds % 60
                    return f"{minutes}m {remaining_seconds:.1f}s"
                else:  # 1 hour or more
                    hours = int(seconds // 3600)
                    remaining_minutes = int((seconds % 3600) // 60)
                    remaining_seconds = seconds % 60
                    return f"{hours}h {remaining_minutes}m {remaining_seconds:.0f}s"
                    
        except Exception as e:
            self.logger.error(f"Error formatting duration: {e}")
            return f"{seconds} s"
    
    def format_timestamp(self, timestamp: Union[datetime, float, int], 
                        format_type: str = 'standard') -> str:
        """
        Format timestamp in various formats.
        
        Args:
            timestamp: Timestamp to format
            format_type: Format type ('standard', 'iso', 'compact', 'relative')
            
        Returns:
            Formatted timestamp string
        """
        try:
            # Convert to datetime if necessary
            if isinstance(timestamp, (int, float)):
                dt = datetime.fromtimestamp(timestamp)
            elif isinstance(timestamp, datetime):
                dt = timestamp
            else:
                return str(timestamp)
            
            if format_type == 'iso':
                return dt.isoformat()
            elif format_type == 'compact':
                return dt.strftime('%Y%m%d_%H%M%S')
            elif format_type == 'relative':
                return self._format_relative_time(dt)
            else:  # standard
                return dt.strftime('%Y-%m-%d %H:%M:%S')
                
        except Exception as e:
            self.logger.error(f"Error formatting timestamp: {e}")
            return str(timestamp)
    
    def _format_relative_time(self, dt: datetime) -> str:
        """Format datetime as relative time (e.g., '2 hours ago')."""
        try:
            now = datetime.now()
            diff = now - dt
            
            if diff.total_seconds() < 0:
                # Future time
                diff = dt - now
                suffix = "from now"
            else:
                suffix = "ago"
            
            seconds = abs(diff.total_seconds())
            
            if seconds < 60:
                return f"{int(seconds)} seconds {suffix}"
            elif seconds < 3600:
                minutes = int(seconds // 60)
                return f"{minutes} minute{'s' if minutes != 1 else ''} {suffix}"
            elif seconds < 86400:
                hours = int(seconds // 3600)
                return f"{hours} hour{'s' if hours != 1 else ''} {suffix}"
            else:
                days = int(seconds // 86400)
                return f"{days} day{'s' if days != 1 else ''} {suffix}"
                
        except Exception:
            return "unknown time"
    
    def sanitize_string(self, text: str, max_length: int = None, 
                       remove_newlines: bool = True, 
                       remove_control_chars: bool = True) -> str:
        """
        Sanitize string for safe display and logging.
        
        Args:
            text: Text to sanitize
            max_length: Maximum length (truncate if exceeded)
            remove_newlines: Whether to remove newline characters
            remove_control_chars: Whether to remove control characters
            
        Returns:
            Sanitized string
        """
        try:
            if not isinstance(text, str):
                text = str(text)
            
            # Remove control characters
            if remove_control_chars:
                text = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')
            
            # Remove newlines
            if remove_newlines:
                text = text.replace('\n', ' ').replace('\r', ' ')
            
            # Normalize whitespace
            text = ' '.join(text.split())
            
            # Truncate if necessary
            if max_length and len(text) > max_length:
                text = text[:max_length-3] + "..."
            
            return text
            
        except Exception as e:
            self.logger.error(f"Error sanitizing string: {e}")
            return str(text)[:100] if text else ""
    
    def validate_file_path(self, path: Union[str, Path], 
                          must_exist: bool = True, 
                          must_be_file: bool = True) -> bool:
        """
        Validate file path.
        
        Args:
            path: Path to validate
            must_exist: Whether path must exist
            must_be_file: Whether path must be a file (not directory)
            
        Returns:
            True if path is valid
        """
        try:
            path = Path(path)
            
            if must_exist and not path.exists():
                return False
            
            if must_be_file and path.exists() and not path.is_file():
                return False
            
            # Check if path is reasonable (not too long, no invalid characters)
            path_str = str(path)
            if len(path_str) > 260:  # Windows path length limit
                return False
            
            # Check for invalid characters (basic check)
            invalid_chars = '<>:"|?*' if os.name == 'nt' else '\0'
            if any(char in path_str for char in invalid_chars):
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error validating path {path}: {e}")
            return False
    
    def parse_version_string(self, version: str) -> Tuple[int, ...]:
        """
        Parse version string into tuple of integers.
        
        Args:
            version: Version string (e.g., "1.2.3")
            
        Returns:
            Tuple of version numbers
        """
        try:
            # Remove any non-numeric characters except dots
            clean_version = re.sub(r'[^\d.]', '', version)
            
            # Split by dots and convert to integers
            parts = clean_version.split('.')
            return tuple(int(part) for part in parts if part.isdigit())
            
        except Exception as e:
            self.logger.error(f"Error parsing version string '{version}': {e}")
            return (0,)
    
    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            version1: First version string
            version2: Second version string
            
        Returns:
            -1 if version1 < version2, 0 if equal, 1 if version1 > version2
        """
        try:
            v1_parts = self.parse_version_string(version1)
            v2_parts = self.parse_version_string(version2)
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts += (0,) * (max_len - len(v1_parts))
            v2_parts += (0,) * (max_len - len(v2_parts))
            
            if v1_parts < v2_parts:
                return -1
            elif v1_parts > v2_parts:
                return 1
            else:
                return 0
                
        except Exception as e:
            self.logger.error(f"Error comparing versions: {e}")
            return 0
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get comprehensive system information.
        
        Returns:
            Dictionary with system information
        """
        try:
            system_info = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.architecture(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'hostname': platform.node()
            }
            
            # Add memory information if psutil is available
            try:
                memory = psutil.virtual_memory()
                system_info.update({
                    'total_memory': memory.total,
                    'available_memory': memory.available,
                    'memory_percent': memory.percent,
                    'total_memory_str': self.format_file_size(memory.total),
                    'available_memory_str': self.format_file_size(memory.available)
                })
                
                # CPU information
                system_info.update({
                    'cpu_count': psutil.cpu_count(),
                    'cpu_count_logical': psutil.cpu_count(logical=True),
                    'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None
                })
                
                # Disk information
                disk_usage = psutil.disk_usage('/')
                system_info.update({
                    'disk_total': disk_usage.total,
                    'disk_used': disk_usage.used,
                    'disk_free': disk_usage.free,
                    'disk_total_str': self.format_file_size(disk_usage.total),
                    'disk_used_str': self.format_file_size(disk_usage.used),
                    'disk_free_str': self.format_file_size(disk_usage.free)
                })
                
            except Exception as psutil_error:
                self.logger.debug(f"Error getting psutil info: {psutil_error}")
            
            return system_info
            
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {'error': str(e)}
    
    def chunks(self, lst: List[Any], chunk_size: int) -> List[List[Any]]:
        """
        Split list into chunks of specified size.
        
        Args:
            lst: List to split
            chunk_size: Size of each chunk
            
        Returns:
            List of chunks
        """
        try:
            if chunk_size <= 0:
                return [lst]
            
            return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]
            
        except Exception as e:
            self.logger.error(f"Error splitting list into chunks: {e}")
            return [lst]
    
    def flatten_dict(self, d: Dict[str, Any], parent_key: str = '', 
                    separator: str = '.') -> Dict[str, Any]:
        """
        Flatten nested dictionary.
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for recursion
            separator: Separator for nested keys
            
        Returns:
            Flattened dictionary
        """
        try:
            items = []
            for k, v in d.items():
                new_key = f"{parent_key}{separator}{k}" if parent_key else k
                if isinstance(v, dict):
                    items.extend(self.flatten_dict(v, new_key, separator).items())
                else:
                    items.append((new_key, v))
            
            return dict(items)
            
        except Exception as e:
            self.logger.error(f"Error flattening dictionary: {e}")
            return d
    
    def safe_json_loads(self, json_str: str, default: Any = None) -> Any:
        """
        Safely parse JSON string.
        
        Args:
            json_str: JSON string to parse
            default: Default value if parsing fails
            
        Returns:
            Parsed JSON or default value
        """
        try:
            return json.loads(json_str)
        except Exception as e:
            self.logger.debug(f"Error parsing JSON: {e}")
            return default
    
    def safe_json_dumps(self, obj: Any, default: str = "{}") -> str:
        """
        Safely serialize object to JSON string.
        
        Args:
            obj: Object to serialize
            default: Default value if serialization fails
            
        Returns:
            JSON string or default value
        """
        try:
            return json.dumps(obj, default=str, ensure_ascii=False)
        except Exception as e:
            self.logger.debug(f"Error serializing to JSON: {e}")
            return default
    
    def timing_decorator(self, func_name: str = None):
        """
        Decorator to measure function execution time.
        
        Args:
            func_name: Name to use for tracking (uses function name if None)
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                name = func_name or func.__name__
                start_time = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    execution_time = time.time() - start_time
                    
                    # Track performance
                    if name not in self.function_calls:
                        self.function_calls[name] = 0
                        self.total_execution_time[name] = 0.0
                    
                    self.function_calls[name] += 1
                    self.total_execution_time[name] += execution_time
                    
                    return result
                    
                except Exception as e:
                    execution_time = time.time() - start_time
                    self.logger.error(f"Error in {name} after {execution_time:.3f}s: {e}")
                    raise
                    
            return wrapper
        return decorator
    
    def retry_on_exception(self, max_retries: int = 3, delay: float = 1.0, 
                          backoff_factor: float = 2.0):
        """
        Decorator to retry function on exception.
        
        Args:
            max_retries: Maximum number of retries
            delay: Initial delay between retries
            backoff_factor: Factor to increase delay by
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                current_delay = delay
                
                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        if attempt == max_retries:
                            self.logger.error(f"Function {func.__name__} failed after {max_retries} retries: {e}")
                            raise
                        
                        self.logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {e}")
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                        
            return wrapper
        return decorator
    
    def format_error_message(self, error: Exception, include_traceback: bool = False) -> str:
        """
        Format error message for logging or display.
        
        Args:
            error: Exception to format
            include_traceback: Whether to include full traceback
            
        Returns:
            Formatted error message
        """
        try:
            error_type = type(error).__name__
            error_message = str(error)
            
            if include_traceback:
                tb = traceback.format_exc()
                return f"{error_type}: {error_message}\n{tb}"
            else:
                return f"{error_type}: {error_message}"
                
        except Exception:
            return f"Unknown error: {error}"
    
    def get_performance_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Get performance statistics for tracked functions.
        
        Returns:
            Dictionary with performance statistics
        """
        try:
            stats = {}
            
            for func_name in self.function_calls:
                calls = self.function_calls[func_name]
                total_time = self.total_execution_time[func_name]
                avg_time = total_time / calls if calls > 0 else 0.0
                
                stats[func_name] = {
                    'calls': calls,
                    'total_time': total_time,
                    'average_time': avg_time,
                    'total_time_str': self.format_duration(total_time),
                    'average_time_str': self.format_duration(avg_time)
                }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting performance stats: {e}")
            return {}
    
    def reset_performance_stats(self) -> None:
        """Reset performance statistics."""
        self.function_calls.clear()
        self.total_execution_time.clear()
        self.logger.info("Performance statistics reset")


# Global helper instance for application-wide use
_global_helpers = None


def get_helpers() -> HelperFunctions:
    """
    Get the global helper functions instance.
    
    Returns:
        Global HelperFunctions instance
    """
    global _global_helpers
    if _global_helpers is None:
        _global_helpers = HelperFunctions()
    return _global_helpers


# Convenience functions for common operations
def format_file_size(size_bytes: Union[int, float], decimal_places: int = 2) -> str:
    """Convenience function for formatting file size."""
    helpers = get_helpers()
    return helpers.format_file_size(size_bytes, decimal_places)


def format_duration(seconds: Union[int, float], precision: str = 'auto') -> str:
    """Convenience function for formatting duration."""
    helpers = get_helpers()
    return helpers.format_duration(seconds, precision)


def sanitize_string(text: str, max_length: int = None) -> str:
    """Convenience function for sanitizing strings."""
    helpers = get_helpers()
    return helpers.sanitize_string(text, max_length)


def compare_versions(version1: str, version2: str) -> int:
    """Convenience function for comparing versions."""
    helpers = get_helpers()
    return helpers.compare_versions(version1, version2)


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    print("Testing HelperFunctions...")
    
    helpers = HelperFunctions()
    
    # Test file size formatting
    print(f"✅ File Size: {helpers.format_file_size(1024*1024*1.5)}")
    print(f"✅ File Size: {helpers.format_file_size(1024*1024*1024*2.7)}")
    
    # Test duration formatting
    print(f"✅ Duration: {helpers.format_duration(0.001234)}")
    print(f"✅ Duration: {helpers.format_duration(123.45)}")
    print(f"✅ Duration: {helpers.format_duration(3661)}")
    
    # Test timestamp formatting
    now = datetime.now()
    print(f"✅ Timestamp: {helpers.format_timestamp(now, 'standard')}")
    print(f"✅ Timestamp: {helpers.format_timestamp(now, 'iso')}")
    print(f"✅ Timestamp: {helpers.format_timestamp(now, 'compact')}")
    
    # Test string sanitization
    dirty_string = "Hello\nWorld\x00\x01Test"
    clean_string = helpers.sanitize_string(dirty_string)
    print(f"✅ Sanitized: '{clean_string}'")
    
    # Test version comparison
    print(f"✅ Version Compare 1.2.3 vs 1.2.4: {helpers.compare_versions('1.2.3', '1.2.4')}")
    print(f"✅ Version Compare 2.0.0 vs 1.9.9: {helpers.compare_versions('2.0.0', '1.9.9')}")
    
    # Test system info
    system_info = helpers.get_system_info()
    print(f"✅ System: {system_info.get('platform')} {system_info.get('platform_release')}")
    if 'total_memory_str' in system_info:
        print(f"✅ Memory: {system_info['available_memory_str']} / {system_info['total_memory_str']}")
    
    # Test list chunking
    test_list = list(range(10))
    chunks = helpers.chunks(test_list, 3)
    print(f"✅ Chunks: {chunks}")
    
    # Test performance tracking
    @helpers.timing_decorator()
    def test_function():
        time.sleep(0.01)
        return "test"
    
    # Call function a few times
    for _ in range(3):
        test_function()
    
    stats = helpers.get_performance_stats()
    print(f"✅ Performance Stats: {stats}")
    
    print("✅ HelperFunctions test completed successfully")