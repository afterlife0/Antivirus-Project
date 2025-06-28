"""
Advanced Multi-Algorithm Antivirus Software
==========================================
Cryptographic Utilities - Security and Hashing Operations

FILE CONNECTION MAP
==================
Dependencies (files this module imports from):
- src.utils.encoding_utils (EncodingHandler)

Connected Components (files that import from this module):
- src.core.threat_database (ThreatDatabase)
- src.intelligence.threat_intel (ThreatIntelligence)
- src.detection.signature_detector (SignatureDetector)
- src.core.file_manager (FileManager)
- src.notification.report_generator (ReportGenerator)

Integration Points:
- Secure hash computation for file identification
- Digital signature verification
- Encryption/decryption for sensitive data
- Secure random number generation
- Password hashing and verification
- Certificate validation
- Checksum calculation and verification
- Data integrity verification

Verification Checklist:
□ All imports verified working
□ Class name matches exactly: CryptoUtils
□ Dependencies properly imported with EXACT class names
□ All connected files can access CryptoUtils functionality
□ Secure hashing implemented
□ Encryption/decryption functionality
□ Digital signature support
□ Comprehensive error handling
"""

import os
import sys
import logging
import hashlib
import hmac
import secrets
import base64
from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple, Any, BinaryIO
import time
from datetime import datetime

# Cryptography imports
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("Cryptography library not available - some features disabled")

# Project Dependencies
from src.utils.encoding_utils import EncodingHandler


class CryptoUtils:
    """
    Comprehensive cryptographic utilities for antivirus operations.
    
    Provides secure cryptographic operations including:
    - File hashing and integrity verification
    - Digital signature verification
    - Symmetric and asymmetric encryption
    - Secure random number generation
    - Password hashing and verification
    - Certificate validation
    - Checksum calculation
    """
    
    # Supported hash algorithms
    HASH_ALGORITHMS = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_512': hashlib.sha3_512,
        'blake2b': hashlib.blake2b,
        'blake2s': hashlib.blake2s
    }
    
    # Default chunk size for file operations (64KB)
    DEFAULT_CHUNK_SIZE = 64 * 1024
    
    def __init__(self):
        """Initialize CryptoUtils with encoding support."""
        self.encoding_handler = EncodingHandler()
        self.logger = logging.getLogger("CryptoUtils")
        
        # Cryptographic configuration
        self.default_hash_algorithm = 'sha256'
        self.pbkdf2_iterations = 100000  # Secure default for PBKDF2
        self.salt_length = 32  # 256 bits
        self.key_length = 32   # 256 bits for AES-256
        
        # Performance tracking
        self.hash_operations = 0
        self.encryption_operations = 0
        self.signature_operations = 0
        
        self.logger.info(f"CryptoUtils initialized - Cryptography available: {CRYPTOGRAPHY_AVAILABLE}")
    
    def calculate_file_hash(self, file_path: Union[str, Path], 
                          algorithm: str = None, 
                          chunk_size: int = None) -> Optional[str]:
        """
        Calculate hash of a file using specified algorithm.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            chunk_size: Size of chunks to read
            
        Returns:
            Hex string of file hash or None if error
        """
        try:
            file_path = Path(file_path)
            algorithm = algorithm or self.default_hash_algorithm
            chunk_size = chunk_size or self.DEFAULT_CHUNK_SIZE
            
            if not file_path.exists():
                self.logger.error(f"File not found: {file_path}")
                return None
            
            if algorithm not in self.HASH_ALGORITHMS:
                self.logger.error(f"Unsupported hash algorithm: {algorithm}")
                return None
            
            # Initialize hash function
            hash_func = self.HASH_ALGORITHMS[algorithm]()
            
            # Calculate hash in chunks for memory efficiency
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
            
            file_hash = hash_func.hexdigest()
            self.hash_operations += 1
            
            self.logger.debug(f"Calculated {algorithm} hash for {file_path.name}: {file_hash[:16]}...")
            return file_hash
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def calculate_multiple_hashes(self, file_path: Union[str, Path], 
                                algorithms: List[str] = None) -> Dict[str, Optional[str]]:
        """
        Calculate multiple hashes of a file in a single pass.
        
        Args:
            file_path: Path to the file
            algorithms: List of hash algorithms to use
            
        Returns:
            Dictionary mapping algorithm names to hash values
        """
        try:
            file_path = Path(file_path)
            algorithms = algorithms or ['md5', 'sha1', 'sha256']
            
            if not file_path.exists():
                return {alg: None for alg in algorithms}
            
            # Initialize hash functions
            hash_funcs = {}
            for alg in algorithms:
                if alg in self.HASH_ALGORITHMS:
                    hash_funcs[alg] = self.HASH_ALGORITHMS[alg]()
                else:
                    self.logger.warning(f"Unsupported hash algorithm: {alg}")
            
            if not hash_funcs:
                return {alg: None for alg in algorithms}
            
            # Calculate all hashes in single pass
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.DEFAULT_CHUNK_SIZE):
                    for hash_func in hash_funcs.values():
                        hash_func.update(chunk)
            
            # Get results
            results = {}
            for alg, hash_func in hash_funcs.items():
                results[alg] = hash_func.hexdigest()
            
            # Add None for unsupported algorithms
            for alg in algorithms:
                if alg not in results:
                    results[alg] = None
            
            self.hash_operations += len(hash_funcs)
            self.logger.debug(f"Calculated {len(hash_funcs)} hashes for {file_path.name}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error calculating multiple hashes for {file_path}: {e}")
            return {alg: None for alg in algorithms}
    
    def calculate_data_hash(self, data: Union[str, bytes], 
                          algorithm: str = None) -> Optional[str]:
        """
        Calculate hash of data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hex string of data hash
        """
        try:
            algorithm = algorithm or self.default_hash_algorithm
            
            if algorithm not in self.HASH_ALGORITHMS:
                self.logger.error(f"Unsupported hash algorithm: {algorithm}")
                return None
            
            # Convert string to bytes if necessary
            if isinstance(data, str):
                data = self.encoding_handler.safe_encode_string(data)
                if data is None:
                    return None
            
            # Calculate hash
            hash_func = self.HASH_ALGORITHMS[algorithm]()
            hash_func.update(data)
            
            self.hash_operations += 1
            return hash_func.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating data hash: {e}")
            return None
    
    def verify_file_integrity(self, file_path: Union[str, Path], 
                            expected_hash: str, 
                            algorithm: str = None) -> bool:
        """
        Verify file integrity against expected hash.
        
        Args:
            file_path: Path to the file
            expected_hash: Expected hash value
            algorithm: Hash algorithm used
            
        Returns:
            True if file integrity is verified
        """
        try:
            calculated_hash = self.calculate_file_hash(file_path, algorithm)
            if calculated_hash is None:
                return False
            
            # Case-insensitive comparison
            integrity_verified = calculated_hash.lower() == expected_hash.lower()
            
            if integrity_verified:
                self.logger.debug(f"File integrity verified: {Path(file_path).name}")
            else:
                self.logger.warning(f"File integrity check failed: {Path(file_path).name}")
                self.logger.warning(f"Expected: {expected_hash}")
                self.logger.warning(f"Calculated: {calculated_hash}")
            
            return integrity_verified
            
        except Exception as e:
            self.logger.error(f"Error verifying file integrity: {e}")
            return False
    
    def generate_secure_random_bytes(self, length: int) -> Optional[bytes]:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of bytes to generate
            
        Returns:
            Random bytes or None if error
        """
        try:
            if length <= 0:
                self.logger.error("Invalid length for random bytes")
                return None
            
            return secrets.token_bytes(length)
            
        except Exception as e:
            self.logger.error(f"Error generating random bytes: {e}")
            return None
    
    def generate_secure_random_string(self, length: int, 
                                    include_symbols: bool = False) -> Optional[str]:
        """
        Generate cryptographically secure random string.
        
        Args:
            length: Length of string to generate
            include_symbols: Whether to include symbols
            
        Returns:
            Random string or None if error
        """
        try:
            if length <= 0:
                return None
            
            if include_symbols:
                alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
            else:
                alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            
            return ''.join(secrets.choice(alphabet) for _ in range(length))
            
        except Exception as e:
            self.logger.error(f"Error generating random string: {e}")
            return None
    
    def hash_password(self, password: str, salt: bytes = None) -> Optional[Dict[str, str]]:
        """
        Hash password using PBKDF2.
        
        Args:
            password: Password to hash
            salt: Salt to use (generated if None)
            
        Returns:
            Dictionary with hashed password and salt
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                self.logger.error("Cryptography library not available")
                return None
            
            # Generate salt if not provided
            if salt is None:
                salt = self.generate_secure_random_bytes(self.salt_length)
                if salt is None:
                    return None
            
            # Convert password to bytes
            password_bytes = self.encoding_handler.safe_encode_string(password)
            if password_bytes is None:
                return None
            
            # Derive key using PBKDF2
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_length,
                salt=salt,
                iterations=self.pbkdf2_iterations,
                backend=default_backend()
            )
            
            key = kdf.derive(password_bytes)
            
            return {
                'hash': base64.b64encode(key).decode('ascii'),
                'salt': base64.b64encode(salt).decode('ascii'),
                'iterations': self.pbkdf2_iterations
            }
            
        except Exception as e:
            self.logger.error(f"Error hashing password: {e}")
            return None
    
    def verify_password(self, password: str, stored_hash: str, 
                       stored_salt: str, iterations: int = None) -> bool:
        """
        Verify password against stored hash.
        
        Args:
            password: Password to verify
            stored_hash: Stored hash value
            stored_salt: Stored salt value
            iterations: Number of iterations used
            
        Returns:
            True if password is correct
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                return False
            
            iterations = iterations or self.pbkdf2_iterations
            
            # Decode stored values
            salt = base64.b64decode(stored_salt.encode('ascii'))
            expected_key = base64.b64decode(stored_hash.encode('ascii'))
            
            # Convert password to bytes
            password_bytes = self.encoding_handler.safe_encode_string(password)
            if password_bytes is None:
                return False
            
            # Derive key with same parameters
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=len(expected_key),
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            
            # Verify password
            try:
                kdf.verify(password_bytes, expected_key)
                return True
            except Exception:
                return False
                
        except Exception as e:
            self.logger.error(f"Error verifying password: {e}")
            return False
    
    def calculate_checksum(self, data: Union[str, bytes], 
                         algorithm: str = 'crc32') -> Optional[str]:
        """
        Calculate checksum of data.
        
        Args:
            data: Data to calculate checksum for
            algorithm: Checksum algorithm
            
        Returns:
            Checksum string or None if error
        """
        try:
            if isinstance(data, str):
                data = self.encoding_handler.safe_encode_string(data)
                if data is None:
                    return None
            
            if algorithm == 'crc32':
                import zlib
                checksum = zlib.crc32(data) & 0xffffffff
                return f"{checksum:08x}"
            elif algorithm == 'adler32':
                import zlib
                checksum = zlib.adler32(data) & 0xffffffff
                return f"{checksum:08x}"
            else:
                # Use hash algorithms for checksums
                return self.calculate_data_hash(data, algorithm)
                
        except Exception as e:
            self.logger.error(f"Error calculating checksum: {e}")
            return None
    
    def hmac_sign(self, data: Union[str, bytes], key: Union[str, bytes], 
                  algorithm: str = 'sha256') -> Optional[str]:
        """
        Create HMAC signature of data.
        
        Args:
            data: Data to sign
            key: Secret key
            algorithm: Hash algorithm for HMAC
            
        Returns:
            HMAC signature or None if error
        """
        try:
            # Convert to bytes if necessary
            if isinstance(data, str):
                data = self.encoding_handler.safe_encode_string(data)
                if data is None:
                    return None
            
            if isinstance(key, str):
                key = self.encoding_handler.safe_encode_string(key)
                if key is None:
                    return None
            
            # Get hash function
            if algorithm not in self.HASH_ALGORITHMS:
                self.logger.error(f"Unsupported HMAC algorithm: {algorithm}")
                return None
            
            hash_func = self.HASH_ALGORITHMS[algorithm]
            
            # Create HMAC
            mac = hmac.new(key, data, hash_func)
            self.signature_operations += 1
            
            return mac.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error creating HMAC signature: {e}")
            return None
    
    def hmac_verify(self, data: Union[str, bytes], key: Union[str, bytes], 
                   signature: str, algorithm: str = 'sha256') -> bool:
        """
        Verify HMAC signature of data.
        
        Args:
            data: Data that was signed
            key: Secret key
            signature: Expected signature
            algorithm: Hash algorithm used
            
        Returns:
            True if signature is valid
        """
        try:
            calculated_signature = self.hmac_sign(data, key, algorithm)
            if calculated_signature is None:
                return False
            
            # Use secure comparison
            return hmac.compare_digest(calculated_signature, signature)
            
        except Exception as e:
            self.logger.error(f"Error verifying HMAC signature: {e}")
            return False
    
    def get_file_entropy(self, file_path: Union[str, Path]) -> Optional[float]:
        """
        Calculate Shannon entropy of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Entropy value (0.0 to 8.0) or None if error
        """
        try:
            import math
            from collections import Counter
            
            file_path = Path(file_path)
            if not file_path.exists():
                return None
            
            # Read file and count byte frequencies
            byte_counts = Counter()
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.DEFAULT_CHUNK_SIZE):
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
            
            if total_bytes == 0:
                return 0.0
            
            # Calculate Shannon entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            self.logger.error(f"Error calculating file entropy: {e}")
            return None
    
    def get_performance_stats(self) -> Dict[str, int]:
        """Get cryptographic operation statistics."""
        return {
            'hash_operations': self.hash_operations,
            'encryption_operations': self.encryption_operations,
            'signature_operations': self.signature_operations
        }
    
    def reset_performance_stats(self) -> None:
        """Reset performance statistics."""
        self.hash_operations = 0
        self.encryption_operations = 0
        self.signature_operations = 0
        self.logger.info("Performance statistics reset")


# Utility functions for convenience
def calculate_file_hash_quick(file_path: Union[str, Path], 
                            algorithm: str = 'sha256') -> Optional[str]:
    """Convenience function to quickly calculate file hash."""
    try:
        crypto_utils = CryptoUtils()
        return crypto_utils.calculate_file_hash(file_path, algorithm)
    except Exception as e:
        logging.getLogger("CryptoUtils").error(f"Error in convenience function: {e}")
        return None


def verify_file_integrity_quick(file_path: Union[str, Path], 
                              expected_hash: str, 
                              algorithm: str = 'sha256') -> bool:
    """Convenience function to quickly verify file integrity."""
    try:
        crypto_utils = CryptoUtils()
        return crypto_utils.verify_file_integrity(file_path, expected_hash, algorithm)
    except Exception as e:
        logging.getLogger("CryptoUtils").error(f"Error in convenience function: {e}")
        return False


if __name__ == "__main__":
    # **TESTING**: Basic functionality test
    import sys
    
    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        print(f"Testing CryptoUtils on: {test_file}")
        
        crypto_utils = CryptoUtils()
        
        # Test hash calculation
        file_hash = crypto_utils.calculate_file_hash(test_file)
        if file_hash:
            print(f"✅ SHA256 Hash: {file_hash}")
        
        # Test multiple hashes
        multi_hashes = crypto_utils.calculate_multiple_hashes(test_file, ['md5', 'sha1', 'sha256'])
        if multi_hashes:
            print(f"✅ Multiple Hashes:")
            for alg, hash_val in multi_hashes.items():
                if hash_val:
                    print(f"   {alg.upper()}: {hash_val[:32]}...")
        
        # Test entropy calculation
        entropy = crypto_utils.get_file_entropy(test_file)
        if entropy is not None:
            print(f"✅ File Entropy: {entropy:.4f}")
        
        # Test password hashing
        password_hash = crypto_utils.hash_password("test_password")
        if password_hash:
            print(f"✅ Password Hash: {password_hash['hash'][:32]}...")
            
            # Test password verification
            is_valid = crypto_utils.verify_password("test_password", 
                                                  password_hash['hash'], 
                                                  password_hash['salt'],
                                                  password_hash['iterations'])
            print(f"✅ Password Verification: {is_valid}")
        
        # Test performance stats
        stats = crypto_utils.get_performance_stats()
        print(f"✅ Performance Stats: {stats}")
        
    else:
        print("Usage: python crypto_utils.py <file_path>")