"""
Advanced Multi-Algorithm Antivirus Software
==========================================
File Utilities - Comprehensive File Operations Engine

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.detection.feature_extractor (FeatureExtractor)
- src.core.file_manager (FileManager)
- src.core.scanner_engine (ScannerEngine)
- src.detection.signature_detector (SignatureDetector)
- src.detection.yara_detector (YaraDetector)
- src.intelligence.threat_intel (ThreatIntelligence)

Integration Points:
- Safe file operations with encoding handling
- File type detection and validation
- Secure file reading/writing operations
- File hashing and integrity checking
- Path manipulation and validation
- File metadata extraction
- Temporary file management
- File system monitoring utilities
- Memory-efficient file processing

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: FileUtils
□ Dependencies properly imported with EXACT class names
□ All connected files can access FileUtils functionality
□ Safe file operations implemented
□ Encoding-safe file handling
□ Comprehensive error handling
□ Memory optimization implemented
"""

import os
import sys
import logging
import hashlib
import shutil
import tempfile
import mimetypes
import stat
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, Iterator, BinaryIO
import time
from datetime import datetime
import threading
from contextlib import contextmanager

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler


class FileUtils:
    """
    Comprehensive file operations utility class for antivirus software.
    
    Provides secure, encoding-safe file operations with:
    - Safe file reading/writing with memory management
    - File type detection and validation
    - Hash computation for integrity checking
    - Path manipulation and validation
    - Temporary file management
    - File metadata extraction
    - Error handling and logging
    """
    
    def __init__(self):
        """Initialize FileUtils with encoding handler and configuration."""
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("FileUtils")
        
        # File operation configuration
        self.max_file_size = 500 * 1024 * 1024  # 500MB limit for safety
        self.chunk_size = 64 * 1024  # 64KB chunks for memory efficiency
        self.temp_dir = None  # Will be set dynamically
        
        # File type mappings
        self.executable_extensions = {
            '.exe', '.dll', '.sys', '.ocx', '.cpl', '.drv', '.scr',
            '.com', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.js'
        }
        
        self.archive_extensions = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',
            '.cab', '.iso', '.dmg', '.pkg'
        }
        
        self.document_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.rtf', '.odt', '.ods', '.odp'
        }
        
        # Threading lock for thread-safe operations
        self._lock = threading.Lock()
        
        self.logger.info("FileUtils initialized successfully")
    
    def read_file_bytes(self, file_path: Union[str, Path], max_size: Optional[int] = None) -> Optional[bytes]:
        """
        Safely read file as bytes with memory management.
        
        Args:
            file_path: Path to the file to read
            max_size: Maximum file size to read (uses default if None)
            
        Returns:
            File content as bytes or None if error
        """
        try:
            file_path = Path(file_path)
            
            # Validate file existence and readability
            if not self.validate_file_path(file_path):
                return None
            
            # Check file size
            file_size = file_path.stat().st_size
            max_allowed = max_size or self.max_file_size
            
            if file_size > max_allowed:
                self.logger.warning(f"File too large ({file_size} bytes), limiting to {max_allowed}: {file_path}")
                
            # Read file with memory management
            with open(file_path, 'rb') as f:
                if file_size <= max_allowed:
                    content = f.read()
                else:
                    content = f.read(max_allowed)
            
            self.logger.debug(f"Successfully read {len(content)} bytes from: {file_path.name}")
            return content
            
        except PermissionError:
            self.logger.error(f"Permission denied reading file: {file_path}")
            return None
        except MemoryError:
            self.logger.error(f"Not enough memory to read file: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def read_file_text(self, file_path: Union[str, Path], encoding: Optional[str] = None) -> Optional[str]:
        """
        Safely read file as text with encoding detection.
        
        Args:
            file_path: Path to the file to read
            encoding: Specific encoding to use (auto-detect if None)
            
        Returns:
            File content as string or None if error
        """
        try:
            file_path = Path(file_path)
            
            # Read as bytes first
            content_bytes = self.read_file_bytes(file_path)
            if content_bytes is None:
                return None
            
            # Use encoding handler for safe text conversion
            if encoding:
                return self.encoding_handler.decode_text(content_bytes, encoding)
            else:
                return self.encoding_handler.safe_decode(content_bytes)
                
        except Exception as e:
            self.logger.error(f"Error reading text file {file_path}: {e}")
            return None
    
    def write_file_bytes(self, file_path: Union[str, Path], content: bytes) -> bool:
        """
        Safely write bytes to file with atomic operation.
        
        Args:
            file_path: Path to write the file
            content: Bytes content to write
            
        Returns:
            True if successful, False otherwise
        """
        try:
            file_path = Path(file_path)
            
            # Create directory if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temporary file for atomic write
            temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
            
            try:
                # Write to temporary file
                with open(temp_path, 'wb') as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
                
                # Atomic rename
                temp_path.replace(file_path)
                
                self.logger.debug(f"Successfully wrote {len(content)} bytes to: {file_path}")
                return True
                
            except Exception as write_error:
                # Clean up temporary file on error
                if temp_path.exists():
                    temp_path.unlink()
                raise write_error
                
        except Exception as e:
            self.logger.error(f"Error writing file {file_path}: {e}")
            return False
    
    def write_file_text(self, file_path: Union[str, Path], content: str, encoding: str = 'utf-8') -> bool:
        """
        Safely write text to file with encoding.
        
        Args:
            file_path: Path to write the file
            content: Text content to write
            encoding: Text encoding to use
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert text to bytes using encoding handler
            content_bytes = self.encoding_handler.encode_text(content, encoding)
            if content_bytes is None:
                return False
            
            return self.write_file_bytes(file_path, content_bytes)
            
        except Exception as e:
            self.logger.error(f"Error writing text file {file_path}: {e}")
            return False
    
    def copy_file(self, source: Union[str, Path], destination: Union[str, Path]) -> bool:
        """
        Safely copy file with metadata preservation.
        
        Args:
            source: Source file path
            destination: Destination file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            source_path = Path(source)
            dest_path = Path(destination)
            
            # Validate source file
            if not self.validate_file_path(source_path):
                return False
            
            # Create destination directory
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy with metadata
            shutil.copy2(source_path, dest_path)
            
            self.logger.debug(f"Successfully copied: {source_path} -> {dest_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error copying file {source} to {destination}: {e}")
            return False
    
    def move_file(self, source: Union[str, Path], destination: Union[str, Path]) -> bool:
        """
        Safely move file with atomic operation.
        
        Args:
            source: Source file path
            destination: Destination file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            source_path = Path(source)
            dest_path = Path(destination)
            
            # Validate source file
            if not self.validate_file_path(source_path):
                return False
            
            # Create destination directory
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Move file
            shutil.move(str(source_path), str(dest_path))
            
            self.logger.debug(f"Successfully moved: {source_path} -> {dest_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error moving file {source} to {destination}: {e}")
            return False
    
    def delete_file(self, file_path: Union[str, Path]) -> bool:
        """
        Safely delete file with error handling.
        
        Args:
            file_path: Path to the file to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                self.logger.debug(f"File does not exist for deletion: {file_path}")
                return True
            
            # Remove read-only attribute if present
            if file_path.stat().st_mode & stat.S_IWRITE == 0:
                file_path.chmod(stat.S_IWRITE)
            
            file_path.unlink()
            
            self.logger.debug(f"Successfully deleted: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting file {file_path}: {e}")
            return False
    
    def validate_file_path(self, file_path: Union[str, Path]) -> bool:
        """
        Validate file path for existence and readability.
        
        Args:
            file_path: Path to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            file_path = Path(file_path)
            
            # Check existence
            if not file_path.exists():
                self.logger.debug(f"File does not exist: {file_path}")
                return False
            
            # Check if it's a file (not directory)
            if not file_path.is_file():
                self.logger.debug(f"Path is not a file: {file_path}")
                return False
            
            # Check readability
            if not os.access(file_path, os.R_OK):
                self.logger.debug(f"File is not readable: {file_path}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Error validating file path {file_path}: {e}")
            return False
    
    def get_file_hash(self, file_path: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate file hash using specified algorithm.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256', 'sha512')
            
        Returns:
            Hex string of file hash or None if error
        """
        try:
            file_path = Path(file_path)
            
            if not self.validate_file_path(file_path):
                return None
            
            # Get hash function
            if algorithm.lower() == 'md5':
                hash_func = hashlib.md5()
            elif algorithm.lower() == 'sha1':
                hash_func = hashlib.sha1()
            elif algorithm.lower() == 'sha256':
                hash_func = hashlib.sha256()
            elif algorithm.lower() == 'sha512':
                hash_func = hashlib.sha512()
            else:
                self.logger.error(f"Unsupported hash algorithm: {algorithm}")
                return None
            
            # Calculate hash in chunks for memory efficiency
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    hash_func.update(chunk)
            
            file_hash = hash_func.hexdigest()
            self.logger.debug(f"Calculated {algorithm} hash for {file_path.name}: {file_hash[:16]}...")
            return file_hash
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def get_file_info(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive file information.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information or None if error
        """
        try:
            file_path = Path(file_path)
            
            if not self.validate_file_path(file_path):
                return None
            
            stat_info = file_path.stat()
            
            file_info = {
                'path': str(file_path),
                'name': file_path.name,
                'size': stat_info.st_size,
                'created': datetime.fromtimestamp(stat_info.st_ctime),
                'modified': datetime.fromtimestamp(stat_info.st_mtime),
                'accessed': datetime.fromtimestamp(stat_info.st_atime),
                'extension': file_path.suffix.lower(),
                'is_executable': self.is_executable_file(file_path),
                'is_archive': self.is_archive_file(file_path),
                'is_document': self.is_document_file(file_path),
                'mime_type': self.get_mime_type(file_path),
                'permissions': oct(stat_info.st_mode)[-3:],
                'size_human': self.format_file_size(stat_info.st_size)
            }
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            return None
    
    def is_executable_file(self, file_path: Union[str, Path]) -> bool:
        """Check if file is an executable type."""
        try:
            file_path = Path(file_path)
            return file_path.suffix.lower() in self.executable_extensions
        except Exception:
            return False
    
    def is_archive_file(self, file_path: Union[str, Path]) -> bool:
        """Check if file is an archive type."""
        try:
            file_path = Path(file_path)
            return file_path.suffix.lower() in self.archive_extensions
        except Exception:
            return False
    
    def is_document_file(self, file_path: Union[str, Path]) -> bool:
        """Check if file is a document type."""
        try:
            file_path = Path(file_path)
            return file_path.suffix.lower() in self.document_extensions
        except Exception:
            return False
    
    def get_mime_type(self, file_path: Union[str, Path]) -> Optional[str]:
        """Get MIME type of file."""
        try:
            mime_type, _ = mimetypes.guess_type(str(file_path))
            return mime_type
        except Exception:
            return None
    
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        try:
            if size_bytes == 0:
                return "0 B"
            
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1
            
            return f"{size_bytes:.1f} {size_names[i]}"
            
        except Exception:
            return f"{size_bytes} B"
    
    @contextmanager
    def temporary_file(self, suffix: str = '', prefix: str = 'temp_', delete: bool = True):
        """
        Context manager for temporary file operations.
        
        Args:
            suffix: File suffix/extension
            prefix: File prefix
            delete: Whether to delete file on exit
            
        Yields:
            Path to temporary file
        """
        temp_file = None
        try:
            # Create temporary file
            temp_fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=self.temp_dir)
            os.close(temp_fd)  # Close file descriptor
            
            temp_file = Path(temp_path)
            self.logger.debug(f"Created temporary file: {temp_file}")
            
            yield temp_file
            
        except Exception as e:
            self.logger.error(f"Error with temporary file: {e}")
            raise
        finally:
            # Clean up
            if temp_file and temp_file.exists() and delete:
                try:
                    temp_file.unlink()
                    self.logger.debug(f"Deleted temporary file: {temp_file}")
                except Exception as cleanup_error:
                    self.logger.warning(f"Error deleting temporary file: {cleanup_error}")
    
    def read_file_chunks(self, file_path: Union[str, Path], chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """
        Read file in chunks for memory-efficient processing.
        
        Args:
            file_path: Path to the file
            chunk_size: Size of each chunk (uses default if None)
            
        Yields:
            Bytes chunks from the file
        """
        try:
            file_path = Path(file_path)
            
            if not self.validate_file_path(file_path):
                return
            
            chunk_size = chunk_size or self.chunk_size
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    yield chunk
                    
        except Exception as e:
            self.logger.error(f"Error reading file chunks from {file_path}: {e}")
    
    def find_files(self, directory: Union[str, Path], pattern: str = '*', recursive: bool = True) -> List[Path]:
        """
        Find files matching pattern in directory.
        
        Args:
            directory: Directory to search
            pattern: File pattern to match
            recursive: Whether to search recursively
            
        Returns:
            List of matching file paths
        """
        try:
            directory = Path(directory)
            
            if not directory.exists() or not directory.is_dir():
                self.logger.error(f"Invalid directory: {directory}")
                return []
            
            if recursive:
                files = list(directory.rglob(pattern))
            else:
                files = list(directory.glob(pattern))
            
            # Filter to only files (not directories)
            file_paths = [f for f in files if f.is_file()]
            
            self.logger.debug(f"Found {len(file_paths)} files matching '{pattern}' in {directory}")
            return file_paths
            
        except Exception as e:
            self.logger.error(f"Error finding files in {directory}: {e}")
            return []
    
    def ensure_directory(self, directory: Union[str, Path]) -> bool:
        """
        Ensure directory exists, creating if necessary.
        
        Args:
            directory: Directory path to ensure
            
        Returns:
            True if directory exists/created, False otherwise
        """
        try:
            directory = Path(directory)
            directory.mkdir(parents=True, exist_ok=True)
            
            self.logger.debug(f"Ensured directory exists: {directory}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error ensuring directory {directory}: {e}")
            return False
    
    def get_available_space(self, path: Union[str, Path]) -> Optional[int]:
        """
        Get available disk space for given path.
        
        Args:
            path: Path to check space for
            
        Returns:
            Available space in bytes or None if error
        """
        try:
            path = Path(path)
            
            if os.name == 'nt':  # Windows
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(str(path)),
                    ctypes.pointer(free_bytes),
                    None,
                    None
                )
                return free_bytes.value
            else:  # Unix/Linux
                statvfs = os.statvfs(path)
                return statvfs.f_frsize * statvfs.f_bavail
                
        except Exception as e:
            self.logger.error(f"Error getting available space for {path}: {e}")
            return None
    
    def is_file_locked(self, file_path: Union[str, Path]) -> bool:
        """
        Check if file is locked by another process.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if file is locked, False otherwise
        """
        try:
            file_path = Path(file_path)
            
            if not file_path.exists():
                return False
            
            # Try to open file in exclusive mode
            try:
                with open(file_path, 'r+b') as f:
                    pass
                return False
            except (IOError, OSError):
                return True
                
        except Exception as e:
            self.logger.debug(f"Error checking file lock for {file_path}: {e}")
            return True  # Assume locked if can't determine
    
    def set_temp_directory(self, temp_dir: Union[str, Path]) -> bool:
        """
        Set custom temporary directory.
        
        Args:
            temp_dir: Path to temporary directory
            
        Returns:
            True if successful, False otherwise
        """
        try:
            temp_dir = Path(temp_dir)
            
            if self.ensure_directory(temp_dir):
                self.temp_dir = str(temp_dir)
                self.logger.info(f"Set temporary directory to: {temp_dir}")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting temporary directory: {e}")
            return False
    
    def cleanup_temp_files(self, max_age_hours: int = 24) -> int:
        """
        Clean up old temporary files.
        
        Args:
            max_age_hours: Maximum age of files to keep (in hours)
            
        Returns:
            Number of files cleaned up
        """
        try:
            if not self.temp_dir:
                return 0
            
            temp_path = Path(self.temp_dir)
            if not temp_path.exists():
                return 0
            
            current_time = time.time()
            max_age_seconds = max_age_hours * 3600
            cleaned_count = 0
            
            for file_path in temp_path.iterdir():
                if file_path.is_file():
                    try:
                        file_age = current_time - file_path.stat().st_mtime
                        if file_age > max_age_seconds:
                            file_path.unlink()
                            cleaned_count += 1
                    except Exception as cleanup_error:
                        self.logger.debug(f"Error cleaning up {file_path}: {cleanup_error}")
            
            self.logger.info(f"Cleaned up {cleaned_count} temporary files")
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Error during temp file cleanup: {e}")
            return 0


# Utility functions for convenience
def read_file_safely(file_path: Union[str, Path]) -> Optional[bytes]:
    """Convenience function to safely read file bytes."""
    try:
        file_utils = FileUtils()
        return file_utils.read_file_bytes(file_path)
    except Exception as e:
        logging.getLogger("FileUtils").error(f"Error in convenience function: {e}")
        return None


def get_file_hash_quick(file_path: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
    """Convenience function to quickly get file hash."""
    try:
        file_utils = FileUtils()
        return file_utils.get_file_hash(file_path, algorithm)
    except Exception as e:
        logging.getLogger("FileUtils").error(f"Error in convenience function: {e}")
        return None


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import sys
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        print(f"Testing FileUtils on: {test_file}")
        
        file_utils = FileUtils()
        
        # Test file info
        file_info = file_utils.get_file_info(test_file)
        if file_info:
            print(f"✅ File Info:")
            print(f"   Name: {file_info['name']}")
            print(f"   Size: {file_info['size_human']}")
            print(f"   Type: {file_info['mime_type']}")
            print(f"   Executable: {file_info['is_executable']}")
            print(f"   Archive: {file_info['is_archive']}")
            print(f"   Modified: {file_info['modified']}")
        
        # Test hash calculation
        file_hash = file_utils.get_file_hash(test_file)
        if file_hash:
            print(f"✅ SHA256 Hash: {file_hash[:32]}...")
        
        # Test file reading
        content = file_utils.read_file_bytes(test_file, max_size=1024)
        if content:
            print(f"✅ Read {len(content)} bytes successfully")
        
    else:
        print("Usage: python file_utils.py <file_path>")