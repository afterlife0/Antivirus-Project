"""
Advanced Multi-Algorithm Antivirus Software
==========================================
File Manager - Secure File Operations and Quarantine Management

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)
- src.utils.file_utils (FileUtils)
- src.utils.crypto_utils (CryptoUtils)
- src.core.app_config (AppConfig)

Connected Components (files that import from this module):
- src.core.scanner_engine (ScannerEngine)
- src.ui.quarantine_window (QuarantineWindow)
- src.core.threat_database (ThreatDatabase)

Integration Points:
- Secure file system operations and management
- Quarantine file handling with encryption and metadata
- File restoration and recovery capabilities
- Secure file deletion and cleanup operations
- Integration with scanning engine for file processing
- Threat database integration for file tracking
- File permission and access control management
- Backup and recovery operations for quarantined files
- File integrity verification and validation
- Comprehensive file operation logging and audit trail

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: FileManager
□ Dependencies properly imported with EXACT class names
□ All connected files can access FileManager functionality
□ File operations implemented
□ Quarantine management functional
□ Security features working
□ Integration points established
□ Error handling comprehensive
"""

import os
import sys
import logging
import shutil
import time
import json
import hashlib
import sqlite3
import threading
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import stat
import tempfile

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler
from src.utils.file_utils import FileUtils
from src.utils.crypto_utils import CryptoUtils
from src.core.app_config import AppConfig


class FileOperation(Enum):
    """File operation types."""
    QUARANTINE = "quarantine"
    RESTORE = "restore"
    DELETE = "delete"
    COPY = "copy"
    MOVE = "move"
    BACKUP = "backup"
    SCAN = "scan"
    ANALYZE = "analyze"


class FileStatus(Enum):
    """File status in quarantine."""
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    DELETED = "deleted"
    CORRUPTED = "corrupted"
    PENDING = "pending"
    PROCESSING = "processing"


class QuarantineReason(Enum):
    """Reasons for file quarantine."""
    MALWARE_DETECTED = "malware_detected"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    POLICY_VIOLATION = "policy_violation"
    USER_REQUEST = "user_request"
    AUTOMATIC_SCAN = "automatic_scan"
    MANUAL_SCAN = "manual_scan"
    REAL_TIME_PROTECTION = "real_time_protection"


@dataclass
class FileMetadata:
    """Container for file metadata."""
    file_path: str
    file_name: str
    file_size: int
    file_hash_md5: str
    file_hash_sha256: str
    file_type: str
    file_extension: str
    creation_time: str
    modification_time: str
    access_time: str
    permissions: str
    owner: str
    attributes: Dict[str, Any]
    is_executable: bool
    is_system_file: bool
    is_hidden: bool


@dataclass
class QuarantineEntry:
    """Container for quarantine entry information."""
    entry_id: str
    original_path: str
    quarantine_path: str
    file_metadata: FileMetadata
    quarantine_reason: QuarantineReason
    threat_classification: str
    confidence_score: float
    risk_score: float
    quarantine_timestamp: str
    status: FileStatus
    detection_method: str
    threat_details: Dict[str, Any]
    restore_info: Optional[Dict[str, Any]] = None
    notes: str = ""
    encrypted: bool = True


@dataclass
class FileOperationResult:
    """Result of file operation."""
    operation: FileOperation
    success: bool
    source_path: str
    destination_path: Optional[str]
    error_message: Optional[str]
    processing_time: float
    file_size: int
    operation_timestamp: str
    additional_info: Dict[str, Any] = field(default_factory=dict)


class FileManager:
    """
    Secure File Operations and Quarantine Management System.
    
    Provides comprehensive file management capabilities with security features,
    quarantine management, and integration with threat detection systems.
    
    Features:
    - Secure file operations with encryption
    - Quarantine management with metadata tracking
    - File restoration and recovery capabilities
    - Secure file deletion and cleanup
    - File integrity verification
    - Comprehensive operation logging
    - Permission and access control management
    - Backup and recovery operations
    - Integration with scanning and detection systems
    - SQLite-based quarantine database
    """
    
    def __init__(self, config: Optional[AppConfig] = None):
        """
        Initialize File Manager.
        
        Args:
            config: Application configuration instance
        """
        self.encoding_handler = EncodingHandler()
        self.file_utils = FileUtils()
        self.crypto_utils = CryptoUtils()
        self.config = config or AppConfig()
        self.logger = logging.getLogger("FileManager")
        
        # File manager configuration
        self.quarantine_dir = self._get_quarantine_directory()
        self.backup_dir = self._get_backup_directory()
        self.temp_dir = self._get_temp_directory()
        
        # Database configuration
        self.quarantine_db_path = self.quarantine_dir / "quarantine.db"
        self.db_connection = None
        
        # Security settings
        self.encryption_enabled = True
        self.secure_deletion = True
        self.max_file_size = 500 * 1024 * 1024  # 500MB max for quarantine
        self.max_quarantine_age_days = 30  # Auto-cleanup after 30 days
        
        # Performance settings
        self.chunk_size = 64 * 1024  # 64KB chunks for large files
        self.max_concurrent_operations = 3
        self.operation_timeout = 300  # 5 minutes timeout
        
        # Operation tracking
        self.active_operations = {}
        self.operation_history = []
        self.operation_statistics = {
            'total_operations': 0,
            'successful_operations': 0,
            'failed_operations': 0,
            'quarantine_count': 0,
            'restore_count': 0,
            'delete_count': 0
        }
        
        # Thread safety
        self._db_lock = threading.Lock()
        self._operations_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        
        # Initialize file manager
        self._initialize_directories()
        self._initialize_database()
        
        self.logger.info("FileManager initialized")
    
    def _get_quarantine_directory(self) -> Path:
        """Get quarantine directory path."""
        try:
            quarantine_path = self.config.get_quarantine_directory()
            if quarantine_path:
                return Path(quarantine_path)
            
            # Fallback to default location
            project_root = Path(__file__).parent.parent.parent.parent
            return project_root / "quarantine"
            
        except Exception as e:
            self.logger.error(f"Error getting quarantine directory: {e}")
            return Path("quarantine")
    
    def _get_backup_directory(self) -> Path:
        """Get backup directory path."""
        try:
            return self.quarantine_dir / "backups"
        except Exception as e:
            self.logger.error(f"Error getting backup directory: {e}")
            return Path("backups")
    
    def _get_temp_directory(self) -> Path:
        """Get temporary directory path."""
        try:
            return self.quarantine_dir / "temp"
        except Exception as e:
            self.logger.error(f"Error getting temp directory: {e}")
            return Path("temp")
    
    def _initialize_directories(self) -> None:
        """Initialize required directories."""
        try:
            # Create directories if they don't exist
            directories = [
                self.quarantine_dir,
                self.backup_dir,
                self.temp_dir
            ]
            
            for directory in directories:
                directory.mkdir(parents=True, exist_ok=True)
                
                # Set restrictive permissions on Windows
                if os.name == 'nt':
                    try:
                        os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                    except OSError:
                        pass  # Permissions may not be fully supported
            
            self.logger.info("File manager directories initialized")
            
        except Exception as e:
            self.logger.error(f"Error initializing directories: {e}")
    
    def _initialize_database(self) -> bool:
        """Initialize quarantine database."""
        try:
            with self._db_lock:
                self.db_connection = sqlite3.connect(
                    str(self.quarantine_db_path),
                    check_same_thread=False,
                    timeout=30.0
                )
                self.db_connection.row_factory = sqlite3.Row
                
                cursor = self.db_connection.cursor()
                
                # Create quarantine entries table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS quarantine_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT NOT NULL UNIQUE,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        file_hash_md5 TEXT NOT NULL,
                        file_hash_sha256 TEXT NOT NULL,
                        file_type TEXT,
                        file_extension TEXT,
                        creation_time TEXT,
                        modification_time TEXT,
                        quarantine_reason TEXT NOT NULL,
                        threat_classification TEXT,
                        confidence_score REAL,
                        risk_score REAL,
                        quarantine_timestamp TEXT NOT NULL,
                        status TEXT NOT NULL,
                        detection_method TEXT,
                        threat_details TEXT,
                        restore_info TEXT,
                        notes TEXT,
                        encrypted BOOLEAN DEFAULT 1
                    )
                """)
                
                # Create file operations log table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS file_operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation_type TEXT NOT NULL,
                        source_path TEXT NOT NULL,
                        destination_path TEXT,
                        success BOOLEAN NOT NULL,
                        error_message TEXT,
                        processing_time REAL,
                        file_size INTEGER,
                        operation_timestamp TEXT NOT NULL,
                        additional_info TEXT
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_entry_id ON quarantine_entries(entry_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_original_path ON quarantine_entries(original_path)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp ON quarantine_entries(quarantine_timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON quarantine_entries(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_operation_timestamp ON file_operations(operation_timestamp)")
                
                self.db_connection.commit()
                
                self.logger.info("Quarantine database initialized successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            return False
    
    def quarantine_file(self, file_path: Union[str, Path], 
                       reason: QuarantineReason,
                       threat_classification: str = "unknown",
                       confidence_score: float = 0.0,
                       risk_score: float = 0.0,
                       detection_method: str = "manual",
                       threat_details: Optional[Dict[str, Any]] = None,
                       notes: str = "") -> Optional[QuarantineEntry]:
        """
        Quarantine a file with metadata and encryption.
        
        Args:
            file_path: Path to the file to quarantine
            reason: Reason for quarantine
            threat_classification: Type of threat detected
            confidence_score: Detection confidence (0.0-1.0)
            risk_score: Risk assessment (0.0-1.0)
            detection_method: Method used for detection
            threat_details: Additional threat information
            notes: Additional notes
            
        Returns:
            QuarantineEntry if successful, None otherwise
        """
        try:
            start_time = time.time()
            file_path = Path(file_path)
            
            if not file_path.exists() or not file_path.is_file():
                self.logger.error(f"File not found or not a file: {file_path}")
                return None
            
            self.logger.info(f"Quarantining file: {file_path.name}")
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > self.max_file_size:
                self.logger.error(f"File too large for quarantine: {file_size} bytes")
                return None
            
            # Generate unique entry ID
            entry_id = self._generate_entry_id(file_path)
            
            # Extract file metadata
            metadata = self._extract_file_metadata(file_path)
            if not metadata:
                self.logger.error("Failed to extract file metadata")
                return None
            
            # Create quarantine path
            quarantine_path = self._create_quarantine_path(entry_id, file_path.suffix)
            
            # Copy file to quarantine with optional encryption
            success = self._secure_copy_file(file_path, quarantine_path, encrypt=self.encryption_enabled)
            if not success:
                self.logger.error("Failed to copy file to quarantine")
                return None
            
            # Create quarantine entry
            quarantine_entry = QuarantineEntry(
                entry_id=entry_id,
                original_path=str(file_path),
                quarantine_path=str(quarantine_path),
                file_metadata=metadata,
                quarantine_reason=reason,
                threat_classification=threat_classification,
                confidence_score=confidence_score,
                risk_score=risk_score,
                quarantine_timestamp=datetime.now().isoformat(),
                status=FileStatus.QUARANTINED,
                detection_method=detection_method,
                threat_details=threat_details or {},
                notes=notes,
                encrypted=self.encryption_enabled
            )
            
            # Store in database
            if not self._store_quarantine_entry(quarantine_entry):
                # Cleanup quarantine file if database storage fails
                try:
                    quarantine_path.unlink()
                except:
                    pass
                return None
            
            # Log operation
            processing_time = time.time() - start_time
            self._log_file_operation(
                FileOperation.QUARANTINE,
                str(file_path),
                str(quarantine_path),
                True,
                None,
                processing_time,
                file_size
            )
            
            # Update statistics
            self._update_statistics(FileOperation.QUARANTINE, True)
            
            self.logger.info(f"File quarantined successfully: {entry_id} ({processing_time:.3f}s)")
            return quarantine_entry
            
        except Exception as e:
            self.logger.error(f"Error quarantining file: {e}")
            self._update_statistics(FileOperation.QUARANTINE, False)
            return None
    
    def restore_file(self, entry_id: str, 
                    restore_path: Optional[Union[str, Path]] = None,
                    overwrite: bool = False) -> Optional[FileOperationResult]:
        """
        Restore a quarantined file to its original location or specified path.
        
        Args:
            entry_id: Quarantine entry ID
            restore_path: Optional custom restore path
            overwrite: Whether to overwrite existing files
            
        Returns:
            FileOperationResult if successful, None otherwise
        """
        try:
            start_time = time.time()
            
            # Get quarantine entry
            quarantine_entry = self._get_quarantine_entry(entry_id)
            if not quarantine_entry:
                self.logger.error(f"Quarantine entry not found: {entry_id}")
                return None
            
            if quarantine_entry.status != FileStatus.QUARANTINED:
                self.logger.error(f"File is not in quarantined status: {quarantine_entry.status}")
                return None
            
            # Determine restore path
            target_path = Path(restore_path) if restore_path else Path(quarantine_entry.original_path)
            
            # Check if target exists and handle overwrite
            if target_path.exists() and not overwrite:
                error_msg = f"Target file exists and overwrite is False: {target_path}"
                self.logger.error(error_msg)
                return FileOperationResult(
                    operation=FileOperation.RESTORE,
                    success=False,
                    source_path=quarantine_entry.quarantine_path,
                    destination_path=str(target_path),
                    error_message=error_msg,
                    processing_time=time.time() - start_time,
                    file_size=quarantine_entry.file_metadata.file_size,
                    operation_timestamp=datetime.now().isoformat()
                )
            
            # Create parent directories if needed
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy file from quarantine with decryption if needed
            quarantine_path = Path(quarantine_entry.quarantine_path)
            success = self._secure_copy_file(
                quarantine_path, 
                target_path, 
                decrypt=quarantine_entry.encrypted
            )
            
            if not success:
                error_msg = "Failed to copy file from quarantine"
                self.logger.error(error_msg)
                return FileOperationResult(
                    operation=FileOperation.RESTORE,
                    success=False,
                    source_path=quarantine_entry.quarantine_path,
                    destination_path=str(target_path),
                    error_message=error_msg,
                    processing_time=time.time() - start_time,
                    file_size=quarantine_entry.file_metadata.file_size,
                    operation_timestamp=datetime.now().isoformat()
                )
            
            # Update quarantine entry status
            quarantine_entry.status = FileStatus.RESTORED
            quarantine_entry.restore_info = {
                'restore_path': str(target_path),
                'restore_timestamp': datetime.now().isoformat(),
                'original_restore': restore_path is None
            }
            
            self._update_quarantine_entry(quarantine_entry)
            
            # Log operation
            processing_time = time.time() - start_time
            self._log_file_operation(
                FileOperation.RESTORE,
                quarantine_entry.quarantine_path,
                str(target_path),
                True,
                None,
                processing_time,
                quarantine_entry.file_metadata.file_size
            )
            
            # Update statistics
            self._update_statistics(FileOperation.RESTORE, True)
            
            result = FileOperationResult(
                operation=FileOperation.RESTORE,
                success=True,
                source_path=quarantine_entry.quarantine_path,
                destination_path=str(target_path),
                error_message=None,
                processing_time=processing_time,
                file_size=quarantine_entry.file_metadata.file_size,
                operation_timestamp=datetime.now().isoformat(),
                additional_info={'entry_id': entry_id}
            )
            
            self.logger.info(f"File restored successfully: {entry_id} -> {target_path.name} ({processing_time:.3f}s)")
            return result
            
        except Exception as e:
            self.logger.error(f"Error restoring file: {e}")
            self._update_statistics(FileOperation.RESTORE, False)
            return None
    
    def delete_quarantined_file(self, entry_id: str, 
                               secure_delete: bool = True) -> Optional[FileOperationResult]:
        """
        Permanently delete a quarantined file.
        
        Args:
            entry_id: Quarantine entry ID
            secure_delete: Whether to use secure deletion
            
        Returns:
            FileOperationResult if successful, None otherwise
        """
        try:
            start_time = time.time()
            
            # Get quarantine entry
            quarantine_entry = self._get_quarantine_entry(entry_id)
            if not quarantine_entry:
                self.logger.error(f"Quarantine entry not found: {entry_id}")
                return None
            
            quarantine_path = Path(quarantine_entry.quarantine_path)
            
            # Perform secure deletion
            if secure_delete:
                success = self._secure_delete_file(quarantine_path)
            else:
                try:
                    quarantine_path.unlink()
                    success = True
                except Exception as e:
                    self.logger.error(f"Error deleting file: {e}")
                    success = False
            
            if not success:
                error_msg = "Failed to delete quarantined file"
                self.logger.error(error_msg)
                return FileOperationResult(
                    operation=FileOperation.DELETE,
                    success=False,
                    source_path=str(quarantine_path),
                    destination_path=None,
                    error_message=error_msg,
                    processing_time=time.time() - start_time,
                    file_size=quarantine_entry.file_metadata.file_size,
                    operation_timestamp=datetime.now().isoformat()
                )
            
            # Update quarantine entry status
            quarantine_entry.status = FileStatus.DELETED
            self._update_quarantine_entry(quarantine_entry)
            
            # Log operation
            processing_time = time.time() - start_time
            self._log_file_operation(
                FileOperation.DELETE,
                str(quarantine_path),
                None,
                True,
                None,
                processing_time,
                quarantine_entry.file_metadata.file_size
            )
            
            # Update statistics
            self._update_statistics(FileOperation.DELETE, True)
            
            result = FileOperationResult(
                operation=FileOperation.DELETE,
                success=True,
                source_path=str(quarantine_path),
                destination_path=None,
                error_message=None,
                processing_time=processing_time,
                file_size=quarantine_entry.file_metadata.file_size,
                operation_timestamp=datetime.now().isoformat(),
                additional_info={'entry_id': entry_id, 'secure_delete': secure_delete}
            )
            
            self.logger.info(f"Quarantined file deleted: {entry_id} ({processing_time:.3f}s)")
            return result
            
        except Exception as e:
            self.logger.error(f"Error deleting quarantined file: {e}")
            self._update_statistics(FileOperation.DELETE, False)
            return None
    
    def _generate_entry_id(self, file_path: Path) -> str:
        """Generate unique entry ID for quarantine."""
        try:
            timestamp = str(int(time.time() * 1000))
            file_hash = hashlib.md5(str(file_path).encode()).hexdigest()[:8]
            return f"quar_{timestamp}_{file_hash}"
        except Exception as e:
            self.logger.error(f"Error generating entry ID: {e}")
            return f"quar_{int(time.time() * 1000)}"
    
    def _extract_file_metadata(self, file_path: Path) -> Optional[FileMetadata]:
        """Extract comprehensive file metadata."""
        try:
            file_stat = file_path.stat()
            
            # Calculate file hashes
            md5_hash = self.crypto_utils.calculate_file_hash(file_path, 'md5')
            sha256_hash = self.crypto_utils.calculate_file_hash(file_path, 'sha256')
            
            # Extract file attributes
            is_executable = file_path.suffix.lower() in {'.exe', '.com', '.scr', '.bat', '.cmd'}
            is_system_file = self._is_system_file(file_path)
            is_hidden = self._is_hidden_file(file_path)
            
            # Get file owner (best effort)
            try:
                import pwd
                owner = pwd.getpwuid(file_stat.st_uid).pw_name
            except (ImportError, KeyError, OSError):
                owner = "unknown"
            
            metadata = FileMetadata(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=file_stat.st_size,
                file_hash_md5=md5_hash,
                file_hash_sha256=sha256_hash,
                file_type=self._get_file_type(file_path),
                file_extension=file_path.suffix.lower(),
                creation_time=datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                modification_time=datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                access_time=datetime.fromtimestamp(file_stat.st_atime).isoformat(),
                permissions=oct(file_stat.st_mode)[-3:],
                owner=owner,
                attributes={
                    'st_mode': file_stat.st_mode,
                    'st_ino': file_stat.st_ino,
                    'st_dev': file_stat.st_dev,
                    'st_nlink': file_stat.st_nlink,
                    'st_uid': file_stat.st_uid,
                    'st_gid': file_stat.st_gid
                },
                is_executable=is_executable,
                is_system_file=is_system_file,
                is_hidden=is_hidden
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting file metadata: {e}")
            return None
    
    def _get_file_type(self, file_path: Path) -> str:
        """Determine file type based on extension and content."""
        try:
            extension = file_path.suffix.lower()
            
            # Common file type mappings
            type_mappings = {
                '.exe': 'executable',
                '.dll': 'library',
                '.sys': 'system',
                '.com': 'executable',
                '.scr': 'screensaver',
                '.bat': 'batch',
                '.cmd': 'command',
                '.ps1': 'powershell',
                '.vbs': 'vbscript',
                '.js': 'javascript',
                '.jar': 'java_archive',
                '.pdf': 'document',
                '.doc': 'document',
                '.docx': 'document',
                '.txt': 'text',
                '.zip': 'archive',
                '.rar': 'archive',
                '.7z': 'archive'
            }
            
            return type_mappings.get(extension, 'unknown')
            
        except Exception as e:
            self.logger.error(f"Error determining file type: {e}")
            return 'unknown'
    
    def _is_system_file(self, file_path: Path) -> bool:
        """Check if file is a system file."""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                return attrs != -1 and (attrs & 0x4) != 0  # FILE_ATTRIBUTE_SYSTEM
            else:  # Unix-like
                return str(file_path).startswith('/sys') or str(file_path).startswith('/proc')
        except Exception:
            return False
    
    def _is_hidden_file(self, file_path: Path) -> bool:
        """Check if file is hidden."""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                return attrs != -1 and (attrs & 0x2) != 0  # FILE_ATTRIBUTE_HIDDEN
            else:  # Unix-like
                return file_path.name.startswith('.')
        except Exception:
            return False
    
    def _create_quarantine_path(self, entry_id: str, extension: str) -> Path:
        """Create quarantine file path."""
        try:
            # Create subdirectory based on date for organization
            date_dir = datetime.now().strftime("%Y-%m-%d")
            quarantine_subdir = self.quarantine_dir / date_dir
            quarantine_subdir.mkdir(exist_ok=True)
            
            # Create unique filename
            if self.encryption_enabled:
                filename = f"{entry_id}.quar"
            else:
                filename = f"{entry_id}{extension}"
            
            return quarantine_subdir / filename
            
        except Exception as e:
            self.logger.error(f"Error creating quarantine path: {e}")
            return self.quarantine_dir / f"{entry_id}.quar"
    
    def _secure_copy_file(self, source: Path, destination: Path, 
                         encrypt: bool = False, decrypt: bool = False) -> bool:
        """Securely copy file with optional encryption/decryption."""
        try:
            # Create destination directory if needed
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            if encrypt:
                # Encrypt while copying
                return self._encrypt_file_copy(source, destination)
            elif decrypt:
                # Decrypt while copying
                return self._decrypt_file_copy(source, destination)
            else:
                # Simple copy
                shutil.copy2(source, destination)
                return True
                
        except Exception as e:
            self.logger.error(f"Error in secure copy: {e}")
            return False
    
    def _encrypt_file_copy(self, source: Path, destination: Path) -> bool:
        """Copy file with encryption."""
        try:
            # Read source file
            with open(source, 'rb') as src_file:
                file_data = src_file.read()
            
            # Encrypt data
            encrypted_data = self.crypto_utils.encrypt_data(file_data)
            if not encrypted_data:
                return False
            
            # Write encrypted data
            with open(destination, 'wb') as dest_file:
                dest_file.write(encrypted_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error encrypting file: {e}")
            return False
    
    def _decrypt_file_copy(self, source: Path, destination: Path) -> bool:
        """Copy file with decryption."""
        try:
            # Read encrypted file
            with open(source, 'rb') as src_file:
                encrypted_data = src_file.read()
            
            # Decrypt data
            decrypted_data = self.crypto_utils.decrypt_data(encrypted_data)
            if not decrypted_data:
                return False
            
            # Write decrypted data
            with open(destination, 'wb') as dest_file:
                dest_file.write(decrypted_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error decrypting file: {e}")
            return False
    
    def _secure_delete_file(self, file_path: Path) -> bool:
        """Securely delete file by overwriting with random data."""
        try:
            if not file_path.exists():
                return True
            
            file_size = file_path.stat().st_size
            
            # Overwrite with random data multiple times
            with open(file_path, 'r+b') as file:
                for _ in range(3):  # 3 passes
                    file.seek(0)
                    file.write(os.urandom(file_size))
                    file.flush()
                    os.fsync(file.fileno())
            
            # Finally delete the file
            file_path.unlink()
            return True
            
        except Exception as e:
            self.logger.error(f"Error in secure delete: {e}")
            return False
    
    def _store_quarantine_entry(self, entry: QuarantineEntry) -> bool:
        """Store quarantine entry in database."""
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                cursor.execute("""
                    INSERT INTO quarantine_entries
                    (entry_id, original_path, quarantine_path, file_name, file_size,
                     file_hash_md5, file_hash_sha256, file_type, file_extension,
                     creation_time, modification_time, quarantine_reason,
                     threat_classification, confidence_score, risk_score,
                     quarantine_timestamp, status, detection_method, threat_details,
                     restore_info, notes, encrypted)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.entry_id, entry.original_path, entry.quarantine_path,
                    entry.file_metadata.file_name, entry.file_metadata.file_size,
                    entry.file_metadata.file_hash_md5, entry.file_metadata.file_hash_sha256,
                    entry.file_metadata.file_type, entry.file_metadata.file_extension,
                    entry.file_metadata.creation_time, entry.file_metadata.modification_time,
                    entry.quarantine_reason.value, entry.threat_classification,
                    entry.confidence_score, entry.risk_score, entry.quarantine_timestamp,
                    entry.status.value, entry.detection_method,
                    json.dumps(entry.threat_details),
                    json.dumps(entry.restore_info) if entry.restore_info else None,
                    entry.notes, entry.encrypted
                ))
                
                self.db_connection.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing quarantine entry: {e}")
            return False
    
    def _get_quarantine_entry(self, entry_id: str) -> Optional[QuarantineEntry]:
        """Get quarantine entry from database."""
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT * FROM quarantine_entries WHERE entry_id = ?
                """, (entry_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Reconstruct file metadata
                metadata = FileMetadata(
                    file_path=row['original_path'],
                    file_name=row['file_name'],
                    file_size=row['file_size'],
                    file_hash_md5=row['file_hash_md5'],
                    file_hash_sha256=row['file_hash_sha256'],
                    file_type=row['file_type'],
                    file_extension=row['file_extension'],
                    creation_time=row['creation_time'],
                    modification_time=row['modification_time'],
                    access_time="",  # Not stored in DB
                    permissions="",  # Not stored in DB
                    owner="",  # Not stored in DB
                    attributes={},  # Not stored in DB
                    is_executable=row['file_extension'] in {'.exe', '.com', '.scr'},
                    is_system_file=False,  # Not stored in DB
                    is_hidden=False  # Not stored in DB
                )
                
                # Create quarantine entry
                entry = QuarantineEntry(
                    entry_id=row['entry_id'],
                    original_path=row['original_path'],
                    quarantine_path=row['quarantine_path'],
                    file_metadata=metadata,
                    quarantine_reason=QuarantineReason(row['quarantine_reason']),
                    threat_classification=row['threat_classification'],
                    confidence_score=row['confidence_score'],
                    risk_score=row['risk_score'],
                    quarantine_timestamp=row['quarantine_timestamp'],
                    status=FileStatus(row['status']),
                    detection_method=row['detection_method'],
                    threat_details=json.loads(row['threat_details']) if row['threat_details'] else {},
                    restore_info=json.loads(row['restore_info']) if row['restore_info'] else None,
                    notes=row['notes'] or "",
                    encrypted=bool(row['encrypted'])
                )
                
                return entry
                
        except Exception as e:
            self.logger.error(f"Error getting quarantine entry: {e}")
            return None
    
    def _update_quarantine_entry(self, entry: QuarantineEntry) -> bool:
        """Update quarantine entry in database."""
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                cursor.execute("""
                    UPDATE quarantine_entries 
                    SET status = ?, restore_info = ?, notes = ?
                    WHERE entry_id = ?
                """, (
                    entry.status.value,
                    json.dumps(entry.restore_info) if entry.restore_info else None,
                    entry.notes,
                    entry.entry_id
                ))
                
                self.db_connection.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Error updating quarantine entry: {e}")
            return False
    
    def _log_file_operation(self, operation: FileOperation, source: str, 
                           destination: Optional[str], success: bool,
                           error_message: Optional[str], processing_time: float,
                           file_size: int) -> None:
        """Log file operation to database."""
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                cursor.execute("""
                    INSERT INTO file_operations
                    (operation_type, source_path, destination_path, success,
                     error_message, processing_time, file_size, operation_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    operation.value, source, destination, success,
                    error_message, processing_time, file_size,
                    datetime.now().isoformat()
                ))
                
                self.db_connection.commit()
                
        except Exception as e:
            self.logger.error(f"Error logging file operation: {e}")
    
    def _update_statistics(self, operation: FileOperation, success: bool) -> None:
        """Update operation statistics."""
        try:
            with self._stats_lock:
                self.operation_statistics['total_operations'] += 1
                
                if success:
                    self.operation_statistics['successful_operations'] += 1
                else:
                    self.operation_statistics['failed_operations'] += 1
                
                # Update operation-specific counters
                if operation == FileOperation.QUARANTINE:
                    self.operation_statistics['quarantine_count'] += 1
                elif operation == FileOperation.RESTORE:
                    self.operation_statistics['restore_count'] += 1
                elif operation == FileOperation.DELETE:
                    self.operation_statistics['delete_count'] += 1
                    
        except Exception as e:
            self.logger.error(f"Error updating statistics: {e}")
    
    def get_quarantine_entries(self, status: Optional[FileStatus] = None,
                              limit: int = 100) -> List[QuarantineEntry]:
        """Get quarantine entries with optional filtering."""
        try:
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                if status:
                    cursor.execute("""
                        SELECT * FROM quarantine_entries 
                        WHERE status = ? 
                        ORDER BY quarantine_timestamp DESC 
                        LIMIT ?
                    """, (status.value, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM quarantine_entries 
                        ORDER BY quarantine_timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                entries = []
                for row in cursor.fetchall():
                    entry = self._row_to_quarantine_entry(row)
                    if entry:
                        entries.append(entry)
                
                return entries
                
        except Exception as e:
            self.logger.error(f"Error getting quarantine entries: {e}")
            return []
    
    def _row_to_quarantine_entry(self, row: sqlite3.Row) -> Optional[QuarantineEntry]:
        """Convert database row to QuarantineEntry."""
        try:
            # Reconstruct file metadata
            metadata = FileMetadata(
                file_path=row['original_path'],
                file_name=row['file_name'],
                file_size=row['file_size'],
                file_hash_md5=row['file_hash_md5'],
                file_hash_sha256=row['file_hash_sha256'],
                file_type=row['file_type'],
                file_extension=row['file_extension'],
                creation_time=row['creation_time'],
                modification_time=row['modification_time'],
                access_time="",
                permissions="",
                owner="",
                attributes={},
                is_executable=row['file_extension'] in {'.exe', '.com', '.scr'},
                is_system_file=False,
                is_hidden=False
            )
            
            # Create quarantine entry
            entry = QuarantineEntry(
                entry_id=row['entry_id'],
                original_path=row['original_path'],
                quarantine_path=row['quarantine_path'],
                file_metadata=metadata,
                quarantine_reason=QuarantineReason(row['quarantine_reason']),
                threat_classification=row['threat_classification'],
                confidence_score=row['confidence_score'],
                risk_score=row['risk_score'],
                quarantine_timestamp=row['quarantine_timestamp'],
                status=FileStatus(row['status']),
                detection_method=row['detection_method'],
                threat_details=json.loads(row['threat_details']) if row['threat_details'] else {},
                restore_info=json.loads(row['restore_info']) if row['restore_info'] else None,
                notes=row['notes'] or "",
                encrypted=bool(row['encrypted'])
            )
            
            return entry
            
        except Exception as e:
            self.logger.error(f"Error converting row to quarantine entry: {e}")
            return None
    
    def get_file_manager_statistics(self) -> Dict[str, Any]:
        """Get comprehensive file manager statistics."""
        try:
            with self._stats_lock:
                stats = self.operation_statistics.copy()
            
            # Add database statistics
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                # Quarantine counts by status
                cursor.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM quarantine_entries 
                    GROUP BY status
                """)
                status_counts = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Recent operations
                cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM file_operations 
                    WHERE operation_timestamp >= date('now', '-7 days')
                """)
                recent_operations = cursor.fetchone()['count']
                
                # Quarantine disk usage
                total_size = 0
                cursor.execute("SELECT file_size FROM quarantine_entries WHERE status = 'quarantined'")
                for row in cursor.fetchall():
                    total_size += row['file_size']
                
                stats.update({
                    'status_counts': status_counts,
                    'recent_operations_7days': recent_operations,
                    'quarantine_disk_usage_bytes': total_size,
                    'quarantine_disk_usage_mb': total_size / (1024 * 1024),
                    'quarantine_directory': str(self.quarantine_dir),
                    'encryption_enabled': self.encryption_enabled,
                    'secure_deletion_enabled': self.secure_deletion,
                    'max_file_size_mb': self.max_file_size / (1024 * 1024),
                    'last_updated': datetime.now().isoformat()
                })
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting file manager statistics: {e}")
            return {}
    
    def cleanup_old_entries(self, max_age_days: int = None) -> int:
        """Clean up old quarantine entries."""
        try:
            max_age_days = max_age_days or self.max_quarantine_age_days
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            removed_count = 0
            
            with self._db_lock:
                cursor = self.db_connection.cursor()
                
                # Get old entries
                cursor.execute("""
                    SELECT entry_id, quarantine_path, status 
                    FROM quarantine_entries 
                    WHERE quarantine_timestamp < ?
                """, (cutoff_date.isoformat(),))
                
                old_entries = cursor.fetchall()
                
                for entry in old_entries:
                    try:
                        # Delete physical file if it exists
                        quarantine_path = Path(entry['quarantine_path'])
                        if quarantine_path.exists():
                            if self.secure_deletion:
                                self._secure_delete_file(quarantine_path)
                            else:
                                quarantine_path.unlink()
                        
                        # Remove from database
                        cursor.execute("DELETE FROM quarantine_entries WHERE entry_id = ?", 
                                     (entry['entry_id'],))
                        removed_count += 1
                        
                    except Exception as e:
                        self.logger.error(f"Error cleaning up entry {entry['entry_id']}: {e}")
                
                self.db_connection.commit()
            
            self.logger.info(f"Cleaned up {removed_count} old quarantine entries")
            return removed_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old entries: {e}")
            return 0
    
    def is_file_manager_healthy(self) -> bool:
        """Check if file manager is healthy."""
        try:
            # Check database connection
            if not self.db_connection:
                return False
            
            # Check directories exist
            if not self.quarantine_dir.exists():
                return False
            
            # Check disk space (basic check)
            try:
                total, used, free = shutil.disk_usage(self.quarantine_dir)
                if free < 100 * 1024 * 1024:  # Less than 100MB free
                    self.logger.warning("Low disk space for quarantine directory")
                    return False
            except Exception:
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking file manager health: {e}")
            return False
    
    def shutdown(self) -> None:
        """Shutdown file manager."""
        try:
            self.logger.info("Shutting down FileManager...")
            
            # Close database connection
            if self.db_connection:
                self.db_connection.close()
                self.db_connection = None
            
            self.logger.info("FileManager shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Utility function for easy file manager creation
def create_file_manager(config: Optional[AppConfig] = None) -> FileManager:
    """
    Convenience function to create a file manager.
    
    Args:
        config: Application configuration instance
        
    Returns:
        Initialized FileManager instance
    """
    try:
        return FileManager(config)
    except Exception as e:
        logging.getLogger("FileManager").error(f"Error creating file manager: {e}")
        raise


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import tempfile
    
    print("Testing FileManager...")
    
    # Create temporary test file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exe', delete=False) as temp_file:
        temp_file.write("This is a test executable file")
        temp_file_path = temp_file.name
    
    try:
        # Create file manager
        file_manager = FileManager()
        print(f"✅ FileManager created successfully")
        
        # Test health check
        is_healthy = file_manager.is_file_manager_healthy()
        print(f"✅ Health Check: {'Healthy' if is_healthy else 'Unhealthy'}")
        
        # Test file quarantine
        quarantine_entry = file_manager.quarantine_file(
            temp_file_path,
            QuarantineReason.MANUAL_SCAN,
            threat_classification="test_malware",
            confidence_score=0.8,
            risk_score=0.7,
            detection_method="test",
            notes="Test quarantine"
        )
        
        if quarantine_entry:
            print(f"✅ File quarantined successfully: {quarantine_entry.entry_id}")
            print(f"   Original: {quarantine_entry.original_path}")
            print(f"   Quarantine: {quarantine_entry.quarantine_path}")
            print(f"   Encrypted: {quarantine_entry.encrypted}")
            
            # Test getting quarantine entries
            entries = file_manager.get_quarantine_entries(limit=10)
            print(f"✅ Retrieved {len(entries)} quarantine entries")
            
            # Test file restoration
            restore_result = file_manager.restore_file(
                quarantine_entry.entry_id,
                restore_path=temp_file_path + ".restored"
            )
            
            if restore_result and restore_result.success:
                print(f"✅ File restored successfully: {restore_result.destination_path}")
                
                # Cleanup restored file
                try:
                    os.unlink(restore_result.destination_path)
                except:
                    pass
            
            # Test file deletion
            delete_result = file_manager.delete_quarantined_file(
                quarantine_entry.entry_id,
                secure_delete=True
            )
            
            if delete_result and delete_result.success:
                print(f"✅ File deleted successfully")
        
        # Test statistics
        stats = file_manager.get_file_manager_statistics()
        print(f"✅ Statistics retrieved: {len(stats)} categories")
        print(f"   Total operations: {stats.get('total_operations', 0)}")
        print(f"   Quarantine count: {stats.get('quarantine_count', 0)}")
        print(f"   Disk usage: {stats.get('quarantine_disk_usage_mb', 0):.2f} MB")
        
        print("✅ FileManager test completed successfully")
        
    except Exception as e:
        print(f"❌ FileManager test failed: {e}")
    
    finally:
        # Cleanup
        try:
            file_manager.shutdown()
            os.unlink(temp_file_path)
        except:
            pass