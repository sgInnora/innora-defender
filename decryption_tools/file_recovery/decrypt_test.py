#!/usr/bin/env python3
"""
Ransomware Decryption Tester
Tests extracted encryption keys on encrypted files to attempt recovery.
Handles various encryption schemes including AES, RSA and their combinations.
"""

import os
import re
import json
import base64
import struct
import logging
import binascii
import argparse
import hashlib
import datetime
import tempfile
from typing import Dict, List, Any, Optional, Set, Tuple, BinaryIO, Union
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, padding as sym_padding
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('decrypt_test')

class DecryptionTester:
    """
    Tests decryption of encrypted files using various algorithms and keys
    """
    
    def __init__(self, config_file=None):
        """
        Initialize the decryption tester
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config = self._load_config(config_file)
        self.results_cache = {}
        self.known_extensions = self._load_known_extensions()
        self.initialized_ciphers = {}
    
    def _load_config(self, config_file=None) -> Dict:
        """
        Load configuration from file or use defaults
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        default_config = {
            "chunk_size": 1024 * 1024,  # 1MB chunks for decryption
            "max_threads": 8,  # Maximum number of parallel decryption threads
            "decryption_timeout": 120,  # Seconds before giving up on a decryption
            "header_search_size": 16384,  # Search first 16KB for file headers
            "max_sample_files": 10,  # Maximum files to test per extension
            "max_file_size": 50 * 1024 * 1024,  # Maximum file size to test (50MB)
            "min_original_file_size": 4096,  # Minimum size of original file to consider (4KB)
            "min_entropy_difference": 0.5,  # Minimum entropy difference to consider successful
            "max_decryption_attempts": 100,  # Maximum number of decryption attempts
            "algorithms": ["aes-cbc", "aes-ecb", "aes-ctr", "aes-gcm", "rc4", "chacha20"],
            "key_sizes": {
                "aes": [16, 24, 32],  # AES-128, AES-192, AES-256
                "rc4": [16, 24, 32],
                "chacha20": [32]
            },
            "known_patterns": {
                "locky": {
                    "extension": ".locky",
                    "header": b"\x00LOCKY",
                    "header_offset": 0,
                    "encryption": "aes-cbc",
                    "rsa_encrypted_key": True,
                    "key_marker": b"LOCKY"
                },
                "gandcrab": {
                    "extension": ".CRAB",
                    "header": b"GANDCRAB",
                    "header_offset": 0,
                    "encryption": "salsa20",
                    "rsa_encrypted_key": True,
                    "key_marker": None
                },
                "wannacry": {
                    "extension": ".WNCRY",
                    "header": b"WANACRY!",
                    "header_offset": 0,
                    "encryption": "aes-cbc",
                    "rsa_encrypted_key": True,
                    "key_marker": None
                }
            }
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults to ensure all keys exist
                merged_config = default_config.copy()
                for section, settings in config.items():
                    if section in merged_config and isinstance(merged_config[section], dict):
                        merged_config[section].update(settings)
                    else:
                        merged_config[section] = settings
                
                return merged_config
            except Exception as e:
                logger.error(f"Error loading configuration: {e}")
                return default_config
        else:
            return default_config
    
    def _load_known_extensions(self) -> Dict:
        """
        Load known file extensions and their signatures
        
        Returns:
            Dictionary of file extensions and their signatures
        """
        # Common file signatures for validating decrypted content
        return {
            # Image formats
            ".jpg": {
                "signature": b"\xFF\xD8\xFF",
                "offset": 0,
                "name": "JPEG image"
            },
            ".png": {
                "signature": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
                "offset": 0,
                "name": "PNG image"
            },
            ".gif": {
                "signature": b"GIF8",
                "offset": 0,
                "name": "GIF image"
            },
            ".bmp": {
                "signature": b"BM",
                "offset": 0,
                "name": "BMP image"
            },
            
            # Document formats
            ".pdf": {
                "signature": b"%PDF",
                "offset": 0,
                "name": "PDF document"
            },
            ".docx": {
                "signature": b"PK\x03\x04",
                "offset": 0,
                "name": "DOCX document"
            },
            ".xlsx": {
                "signature": b"PK\x03\x04",
                "offset": 0,
                "name": "XLSX spreadsheet"
            },
            ".pptx": {
                "signature": b"PK\x03\x04",
                "offset": 0,
                "name": "PPTX presentation"
            },
            ".doc": {
                "signature": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                "offset": 0,
                "name": "DOC document"
            },
            ".xls": {
                "signature": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                "offset": 0,
                "name": "XLS spreadsheet"
            },
            ".ppt": {
                "signature": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
                "offset": 0,
                "name": "PPT presentation"
            },
            
            # Archive formats
            ".zip": {
                "signature": b"PK\x03\x04",
                "offset": 0,
                "name": "ZIP archive"
            },
            ".rar": {
                "signature": b"Rar!\x1A\x07",
                "offset": 0,
                "name": "RAR archive"
            },
            ".7z": {
                "signature": b"7z\xBC\xAF\x27\x1C",
                "offset": 0,
                "name": "7-Zip archive"
            },
            
            # Audio/Video formats
            ".mp3": {
                "signature": b"ID3",
                "offset": 0,
                "name": "MP3 audio"
            },
            ".mp4": {
                "signature": b"ftyp",
                "offset": 4,
                "name": "MP4 video"
            },
            ".avi": {
                "signature": b"RIFF",
                "offset": 0,
                "name": "AVI video"
            },
            
            # Other common formats
            ".exe": {
                "signature": b"MZ",
                "offset": 0,
                "name": "Executable"
            },
            ".dll": {
                "signature": b"MZ",
                "offset": 0,
                "name": "DLL library"
            },
            ".txt": {
                "signatures": [b"\xEF\xBB\xBF", b"\xFE\xFF", b"\xFF\xFE", None],  # BOM or none
                "offsets": [0, 0, 0, 0],
                "name": "Text file",
                "text_check": True
            }
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to calculate entropy for
            
        Returns:
            Entropy value (0-8)
        """
        if not data:
            return 0.0
            
        entropy = 0.0
        byte_counts = {}
        data_len = len(data)
        
        # Count byte frequencies
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        # Calculate entropy
        for count in byte_counts.values():
            probability = count / data_len
            entropy -= probability * (probability).bit_length()
        
        return entropy
    
    def _check_file_header(self, data: bytes, extension: str) -> bool:
        """
        Check if file header matches the expected signature for the extension
        
        Args:
            data: First chunk of file data
            extension: File extension
            
        Returns:
            True if header matches, False otherwise
        """
        if extension not in self.known_extensions:
            return False
        
        ext_info = self.known_extensions[extension]
        
        # Check if extension has multiple possible signatures
        if "signatures" in ext_info:
            for i, signature in enumerate(ext_info["signatures"]):
                if signature is None:  # None signature means any data might be valid
                    return True
                
                offset = ext_info["offsets"][i]
                if len(data) > offset + len(signature) and data[offset:offset+len(signature)] == signature:
                    return True
            
            # Special handling for text files
            if "text_check" in ext_info and ext_info["text_check"]:
                # Check if the data is likely text (ASCII or UTF-8)
                try:
                    decoded = data.decode('utf-8', errors='strict')
                    # If we can decode at least 90% of the data as UTF-8, it's probably text
                    if len(decoded) >= len(data) * 0.9:
                        return True
                except:
                    pass
                
                # Check for ASCII text
                ascii_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))  # tab, LF, CR
                if ascii_count >= len(data) * 0.9:
                    return True
                
            return False
        else:
            # Single signature check
            signature = ext_info["signature"]
            offset = ext_info["offset"]
            
            if len(data) > offset + len(signature):
                return data[offset:offset+len(signature)] == signature
            
            return False
    
    def _identify_file_type(self, data: bytes) -> Optional[str]:
        """
        Identify file type based on header
        
        Args:
            data: First chunk of file data
            
        Returns:
            Identified file extension or None
        """
        for ext, ext_info in self.known_extensions.items():
            if "signatures" in ext_info:
                for i, signature in enumerate(ext_info["signatures"]):
                    if signature is None:
                        continue
                    
                    offset = ext_info["offsets"][i]
                    if len(data) > offset + len(signature) and data[offset:offset+len(signature)] == signature:
                        return ext
            else:
                signature = ext_info["signature"]
                offset = ext_info["offset"]
                
                if len(data) > offset + len(signature) and data[offset:offset+len(signature)] == signature:
                    return ext
        
        return None
    
    def _is_valid_decryption(self, data: bytes, original_extension: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if decrypted data seems valid
        
        Args:
            data: Decrypted data
            original_extension: Original file extension (optional)
            
        Returns:
            Tuple of (is_valid, identified_extension)
        """
        # Check if we have enough data
        if len(data) < 8:
            return False, None
        
        # If we know the original extension, check its header
        if original_extension and original_extension in self.known_extensions:
            if self._check_file_header(data, original_extension):
                return True, original_extension
        
        # Otherwise try to identify the file type
        identified_ext = self._identify_file_type(data)
        if identified_ext:
            return True, identified_ext
        
        # If we couldn't identify the file type, check entropy
        encrypted_entropy = self._calculate_entropy(data)
        if encrypted_entropy < 6.5:  # Lower entropy suggests possibly decrypted data
            # Check for text
            ascii_count = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
            if ascii_count >= len(data) * 0.9:
                return True, ".txt"
        
        return False, None
    
    def _get_aes_cipher(self, key: bytes, mode_name: str, iv: bytes = None) -> Cipher:
        """
        Get an AES cipher object
        
        Args:
            key: Encryption key
            mode_name: Cipher mode (cbc, ecb, ctr, gcm)
            iv: Initialization vector (optional)
            
        Returns:
            Cipher object
        """
        if len(key) not in (16, 24, 32):  # Must be valid AES key length
            raise ValueError(f"Invalid AES key length: {len(key)}")
        
        if mode_name == "cbc":
            if iv is None:
                iv = b"\x00" * 16  # Try zero IV if none provided
            mode = modes.CBC(iv)
        elif mode_name == "ecb":
            mode = modes.ECB()
        elif mode_name == "ctr":
            if iv is None:
                iv = b"\x00" * 16
            mode = modes.CTR(iv)
        elif mode_name == "gcm":
            if iv is None:
                iv = b"\x00" * 12  # GCM typically uses 12-byte nonce
            mode = modes.GCM(iv)
        else:
            raise ValueError(f"Unsupported AES mode: {mode_name}")
        
        return Cipher(algorithms.AES(key), mode, backend=default_backend())
    
    def _decrypt_aes(self, data: bytes, key: bytes, mode_name: str, 
                   iv: bytes = None, reversed_key: bool = False) -> Optional[bytes]:
        """
        Decrypt data with AES
        
        Args:
            data: Encrypted data
            key: Encryption key
            mode_name: Cipher mode (cbc, ecb, ctr, gcm)
            iv: Initialization vector (optional)
            reversed_key: Whether to try the key in reverse
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            # Try with provided key
            cipher = self._get_aes_cipher(key, mode_name, iv)
            decryptor = cipher.decryptor()
            result = decryptor.update(data) + decryptor.finalize()
            
            # Check if decryption seems valid
            valid, _ = self._is_valid_decryption(result)
            if valid:
                return result
                
            # If reversed key option is enabled and first attempt failed
            if reversed_key:
                reversed_cipher = self._get_aes_cipher(key[::-1], mode_name, iv)
                reversed_decryptor = reversed_cipher.decryptor()
                reversed_result = reversed_decryptor.update(data) + reversed_decryptor.finalize()
                
                valid, _ = self._is_valid_decryption(reversed_result)
                if valid:
                    return reversed_result
            
            # If both attempts failed, return the original result (might still be useful)
            return result
            
        except Exception as e:
            logger.debug(f"AES decryption error: {e}")
            return None
    
    def _decrypt_rc4(self, data: bytes, key: bytes, 
                   reversed_key: bool = False) -> Optional[bytes]:
        """
        Decrypt data with RC4
        
        Args:
            data: Encrypted data
            key: Encryption key
            reversed_key: Whether to try the key in reverse
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            # RC4 is implemented as a stream cipher
            cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            result = decryptor.update(data) + decryptor.finalize()
            
            # Check if decryption seems valid
            valid, _ = self._is_valid_decryption(result)
            if valid:
                return result
                
            # If reversed key option is enabled and first attempt failed
            if reversed_key:
                reversed_cipher = Cipher(algorithms.ARC4(key[::-1]), mode=None, backend=default_backend())
                reversed_decryptor = reversed_cipher.decryptor()
                reversed_result = reversed_decryptor.update(data) + reversed_decryptor.finalize()
                
                valid, _ = self._is_valid_decryption(reversed_result)
                if valid:
                    return reversed_result
            
            # If both attempts failed, return the original result (might still be useful)
            return result
            
        except Exception as e:
            logger.debug(f"RC4 decryption error: {e}")
            return None
    
    def _decrypt_chacha20(self, data: bytes, key: bytes, nonce: bytes = None, 
                        reversed_key: bool = False) -> Optional[bytes]:
        """
        Decrypt data with ChaCha20
        
        Args:
            data: Encrypted data
            key: Encryption key (32 bytes)
            nonce: Nonce (12 bytes, optional)
            reversed_key: Whether to try the key in reverse
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            if len(key) != 32:
                # ChaCha20 requires a 32-byte key
                logger.debug(f"Invalid ChaCha20 key length: {len(key)}")
                return None
                
            if nonce is None:
                nonce = b"\x00" * 16  # Use zeros if no nonce provided
            
            # ChaCha20 is implemented as a stream cipher
            algorithm = algorithms.ChaCha20(key, nonce)
            cipher = Cipher(algorithm, mode=None, backend=default_backend())
            decryptor = cipher.decryptor()
            result = decryptor.update(data) + decryptor.finalize()
            
            # Check if decryption seems valid
            valid, _ = self._is_valid_decryption(result)
            if valid:
                return result
                
            # If reversed key option is enabled and first attempt failed
            if reversed_key:
                reversed_algorithm = algorithms.ChaCha20(key[::-1], nonce)
                reversed_cipher = Cipher(reversed_algorithm, mode=None, backend=default_backend())
                reversed_decryptor = reversed_cipher.decryptor()
                reversed_result = reversed_decryptor.update(data) + reversed_decryptor.finalize()
                
                valid, _ = self._is_valid_decryption(reversed_result)
                if valid:
                    return reversed_result
            
            # If both attempts failed, return the original result (might still be useful)
            return result
            
        except Exception as e:
            logger.debug(f"ChaCha20 decryption error: {e}")
            return None
    
    def _decrypt_rsa(self, data: bytes, private_key_data: bytes) -> Optional[bytes]:
        """
        Decrypt data with RSA
        
        Args:
            data: Encrypted data
            private_key_data: RSA private key data
            
        Returns:
            Decrypted data or None if decryption fails
        """
        try:
            # Try to load the private key
            try:
                private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=None,
                    backend=default_backend()
                )
            except:
                # Try to load from DER format if PEM fails
                try:
                    private_key = serialization.load_der_private_key(
                        private_key_data,
                        password=None,
                        backend=default_backend()
                    )
                except:
                    logger.error("Failed to load RSA private key")
                    return None
            
            # Decrypt the data
            decrypted = private_key.decrypt(
                data,
                padding.PKCS1v15()
            )
            
            return decrypted
            
        except Exception as e:
            logger.debug(f"RSA decryption error: {e}")
            return None
    
    def test_keys_on_data(self, encrypted_data: bytes, keys: List[Dict], 
                        original_extension: str = None) -> Dict:
        """
        Test multiple keys on encrypted data
        
        Args:
            encrypted_data: Encrypted data to test
            keys: List of key dictionaries
            original_extension: Original file extension (optional)
            
        Returns:
            Dictionary with test results
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "data_size": len(encrypted_data),
            "original_extension": original_extension,
            "successful_decryptions": [],
            "all_attempts": []
        }
        
        # Calculate entropy of encrypted data for comparison
        encrypted_entropy = self._calculate_entropy(encrypted_data[:4096])
        results["encrypted_entropy"] = encrypted_entropy
        
        # Check for known ransomware headers
        for family, pattern in self.config["known_patterns"].items():
            header_offset = pattern.get("header_offset", 0)
            header = pattern.get("header")
            if header and len(encrypted_data) > header_offset + len(header):
                if encrypted_data[header_offset:header_offset+len(header)] == header:
                    results["detected_ransomware"] = {
                        "family": family,
                        "header": header.hex(),
                        "encryption": pattern.get("encryption"),
                        "extension": pattern.get("extension")
                    }
                    break
        
        # Try all keys with different algorithms
        attempt_count = 0
        for key_info in keys:
            if attempt_count >= self.config["max_decryption_attempts"]:
                logger.info(f"Reached maximum decryption attempts ({self.config['max_decryption_attempts']})")
                break
                
            key_type = key_info.get("type", "unknown").lower()
            key_data = key_info.get("data", key_info.get("bytes", key_info.get("key", b"")))
            
            # If key is a hex string, convert to bytes
            if isinstance(key_data, str):
                try:
                    key_data = bytes.fromhex(key_data.replace(':', ''))
                except:
                    try:
                        key_data = base64.b64decode(key_data)
                    except:
                        logger.warning(f"Invalid key format: {key_data[:20]}...")
                        continue
            
            # Try with different algorithms based on key type
            if key_type == "aes":
                # Try with different AES modes
                for mode in ["cbc", "ecb", "ctr", "gcm"]:
                    if attempt_count >= self.config["max_decryption_attempts"]:
                        break
                        
                    # Try zero IV
                    iv = b"\x00" * 16
                    attempt_count += 1
                    attempt = {
                        "algorithm": f"aes-{mode}",
                        "key_length": len(key_data),
                        "iv": iv.hex() if iv else None,
                        "success": False
                    }
                    
                    decrypted_data = self._decrypt_aes(
                        encrypted_data[:4096],  # Test with first block
                        key_data,
                        mode,
                        iv
                    )
                    
                    if decrypted_data:
                        decrypted_entropy = self._calculate_entropy(decrypted_data[:4096])
                        entropy_diff = encrypted_entropy - decrypted_entropy
                        
                        valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                        
                        if valid or entropy_diff > self.config["min_entropy_difference"]:
                            attempt["success"] = True
                            attempt["decrypted_entropy"] = decrypted_entropy
                            attempt["entropy_difference"] = entropy_diff
                            attempt["identified_extension"] = identified_ext
                            
                            results["successful_decryptions"].append({
                                "algorithm": f"aes-{mode}",
                                "key": key_data.hex(),
                                "key_length": len(key_data),
                                "iv": iv.hex() if iv else None,
                                "decrypted_entropy": decrypted_entropy,
                                "entropy_difference": entropy_diff,
                                "identified_extension": identified_ext
                            })
                    
                    results["all_attempts"].append(attempt)
                    
                    # Try with IV from the first 16 bytes of the file
                    if mode != "ecb" and len(encrypted_data) >= 16:
                        iv = encrypted_data[:16]
                        attempt_count += 1
                        attempt = {
                            "algorithm": f"aes-{mode}",
                            "key_length": len(key_data),
                            "iv": "from_file_header",
                            "success": False
                        }
                        
                        decrypted_data = self._decrypt_aes(
                            encrypted_data[16:4096+16],  # Skip IV
                            key_data,
                            mode,
                            iv
                        )
                        
                        if decrypted_data:
                            decrypted_entropy = self._calculate_entropy(decrypted_data[:4096])
                            entropy_diff = encrypted_entropy - decrypted_entropy
                            
                            valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                            
                            if valid or entropy_diff > self.config["min_entropy_difference"]:
                                attempt["success"] = True
                                attempt["decrypted_entropy"] = decrypted_entropy
                                attempt["entropy_difference"] = entropy_diff
                                attempt["identified_extension"] = identified_ext
                                
                                results["successful_decryptions"].append({
                                    "algorithm": f"aes-{mode}",
                                    "key": key_data.hex(),
                                    "key_length": len(key_data),
                                    "iv": iv.hex(),
                                    "iv_source": "file_header",
                                    "decrypted_entropy": decrypted_entropy,
                                    "entropy_difference": entropy_diff,
                                    "identified_extension": identified_ext
                                })
                        
                        results["all_attempts"].append(attempt)
            
            elif key_type == "rc4":
                attempt_count += 1
                attempt = {
                    "algorithm": "rc4",
                    "key_length": len(key_data),
                    "success": False
                }
                
                decrypted_data = self._decrypt_rc4(
                    encrypted_data[:4096],  # Test with first block
                    key_data
                )
                
                if decrypted_data:
                    decrypted_entropy = self._calculate_entropy(decrypted_data[:4096])
                    entropy_diff = encrypted_entropy - decrypted_entropy
                    
                    valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                    
                    if valid or entropy_diff > self.config["min_entropy_difference"]:
                        attempt["success"] = True
                        attempt["decrypted_entropy"] = decrypted_entropy
                        attempt["entropy_difference"] = entropy_diff
                        attempt["identified_extension"] = identified_ext
                        
                        results["successful_decryptions"].append({
                            "algorithm": "rc4",
                            "key": key_data.hex(),
                            "key_length": len(key_data),
                            "decrypted_entropy": decrypted_entropy,
                            "entropy_difference": entropy_diff,
                            "identified_extension": identified_ext
                        })
                
                results["all_attempts"].append(attempt)
            
            elif key_type == "chacha20":
                attempt_count += 1
                attempt = {
                    "algorithm": "chacha20",
                    "key_length": len(key_data),
                    "success": False
                }
                
                # Try with zero nonce
                nonce = b"\x00" * 16
                
                decrypted_data = self._decrypt_chacha20(
                    encrypted_data[:4096],  # Test with first block
                    key_data,
                    nonce
                )
                
                if decrypted_data:
                    decrypted_entropy = self._calculate_entropy(decrypted_data[:4096])
                    entropy_diff = encrypted_entropy - decrypted_entropy
                    
                    valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                    
                    if valid or entropy_diff > self.config["min_entropy_difference"]:
                        attempt["success"] = True
                        attempt["decrypted_entropy"] = decrypted_entropy
                        attempt["entropy_difference"] = entropy_diff
                        attempt["identified_extension"] = identified_ext
                        
                        results["successful_decryptions"].append({
                            "algorithm": "chacha20",
                            "key": key_data.hex(),
                            "key_length": len(key_data),
                            "nonce": nonce.hex(),
                            "decrypted_entropy": decrypted_entropy,
                            "entropy_difference": entropy_diff,
                            "identified_extension": identified_ext
                        })
                
                results["all_attempts"].append(attempt)
                
                # Try with nonce from the first 16 bytes of the file
                if len(encrypted_data) >= 16:
                    attempt_count += 1
                    attempt = {
                        "algorithm": "chacha20",
                        "key_length": len(key_data),
                        "nonce": "from_file_header",
                        "success": False
                    }
                    
                    nonce = encrypted_data[:16]
                    
                    decrypted_data = self._decrypt_chacha20(
                        encrypted_data[16:4096+16],  # Skip nonce
                        key_data,
                        nonce
                    )
                    
                    if decrypted_data:
                        decrypted_entropy = self._calculate_entropy(decrypted_data[:4096])
                        entropy_diff = encrypted_entropy - decrypted_entropy
                        
                        valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                        
                        if valid or entropy_diff > self.config["min_entropy_difference"]:
                            attempt["success"] = True
                            attempt["decrypted_entropy"] = decrypted_entropy
                            attempt["entropy_difference"] = entropy_diff
                            attempt["identified_extension"] = identified_ext
                            
                            results["successful_decryptions"].append({
                                "algorithm": "chacha20",
                                "key": key_data.hex(),
                                "key_length": len(key_data),
                                "nonce": nonce.hex(),
                                "nonce_source": "file_header",
                                "decrypted_entropy": decrypted_entropy,
                                "entropy_difference": entropy_diff,
                                "identified_extension": identified_ext
                            })
                    
                    results["all_attempts"].append(attempt)
            
            elif key_type == "rsa":
                # RSA is typically used to encrypt symmetric keys, not file content
                # But we'll try direct decryption in case this is a small file
                if len(encrypted_data) <= 512:  # RSA typically can't encrypt more than the key size
                    attempt_count += 1
                    attempt = {
                        "algorithm": "rsa",
                        "key_type": "private_key",
                        "success": False
                    }
                    
                    decrypted_data = self._decrypt_rsa(
                        encrypted_data,
                        key_data
                    )
                    
                    if decrypted_data:
                        decrypted_entropy = self._calculate_entropy(decrypted_data)
                        entropy_diff = encrypted_entropy - decrypted_entropy
                        
                        valid, identified_ext = self._is_valid_decryption(decrypted_data, original_extension)
                        
                        if valid or entropy_diff > self.config["min_entropy_difference"]:
                            attempt["success"] = True
                            attempt["decrypted_entropy"] = decrypted_entropy
                            attempt["entropy_difference"] = entropy_diff
                            attempt["identified_extension"] = identified_ext
                            
                            results["successful_decryptions"].append({
                                "algorithm": "rsa",
                                "key_type": "private_key",
                                "decrypted_entropy": decrypted_entropy,
                                "entropy_difference": entropy_diff,
                                "identified_extension": identified_ext
                            })
                    
                    results["all_attempts"].append(attempt)
        
        # Sort successful decryptions by entropy difference (descending)
        results["successful_decryptions"].sort(
            key=lambda x: x.get("entropy_difference", 0),
            reverse=True
        )
        
        return results
    
    def decrypt_file(self, encrypted_file: str, output_file: str, 
                   algorithm: str, key: bytes, iv: bytes = None) -> bool:
        """
        Decrypt a file with the specified algorithm and key
        
        Args:
            encrypted_file: Path to encrypted file
            output_file: Path to output decrypted file
            algorithm: Encryption algorithm (aes-cbc, aes-ecb, rc4, etc.)
            key: Encryption key
            iv: Initialization vector (optional)
            
        Returns:
            True if decryption succeeded, False otherwise
        """
        try:
            # Convert key and IV to bytes if they are hex strings
            if isinstance(key, str):
                key = bytes.fromhex(key.replace(':', ''))
                
            if iv and isinstance(iv, str):
                iv = bytes.fromhex(iv.replace(':', ''))
            
            # Create decryptor based on algorithm
            if algorithm.startswith("aes-"):
                mode = algorithm.split("-")[1]
                cipher = self._get_aes_cipher(key, mode, iv)
                decryptor = cipher.decryptor()
            elif algorithm == "rc4":
                cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
            elif algorithm == "chacha20":
                if not iv:
                    iv = b"\x00" * 16
                algorithm_obj = algorithms.ChaCha20(key, iv)
                cipher = Cipher(algorithm_obj, mode=None, backend=default_backend())
                decryptor = cipher.decryptor()
            else:
                logger.error(f"Unsupported algorithm: {algorithm}")
                return False
            
            # Process file in chunks
            chunk_size = self.config["chunk_size"]
            
            with open(encrypted_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
                # Special handling for CBC mode with IV
                if algorithm == "aes-cbc" and iv and iv == "from_file_header":
                    # Read the first 16 bytes as IV
                    iv = in_file.read(16)
                    cipher = self._get_aes_cipher(key, "cbc", iv)
                    decryptor = cipher.decryptor()
                elif algorithm == "chacha20" and iv and iv == "from_file_header":
                    # Read the first 16 bytes as nonce
                    iv = in_file.read(16)
                    algorithm_obj = algorithms.ChaCha20(key, iv)
                    cipher = Cipher(algorithm_obj, mode=None, backend=default_backend())
                    decryptor = cipher.decryptor()
                
                # Decrypt in chunks
                while True:
                    chunk = in_file.read(chunk_size)
                    if not chunk:
                        break
                        
                    decrypted_chunk = decryptor.update(chunk)
                    out_file.write(decrypted_chunk)
                
                # Finalize
                final_chunk = decryptor.finalize()
                if final_chunk:
                    out_file.write(final_chunk)
            
            return True
            
        except Exception as e:
            logger.error(f"Error decrypting file: {e}")
            return False
    
    def batch_test_files(self, file_paths: List[str], keys: List[Dict], 
                       output_dir: str = None) -> Dict:
        """
        Test keys on multiple files in parallel
        
        Args:
            file_paths: List of paths to encrypted files
            keys: List of key dictionaries
            output_dir: Directory to save decrypted files (optional)
            
        Returns:
            Dictionary with test results
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "files_tested": len(file_paths),
            "keys_tested": len(keys),
            "successful_decryptions": {},
            "summary": {
                "total_success": 0,
                "total_files": len(file_paths),
                "success_rate": 0.0
            }
        }
        
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Process files in parallel
        with ThreadPoolExecutor(max_workers=self.config["max_threads"]) as executor:
            future_to_file = {}
            
            for file_path in file_paths:
                if not os.path.exists(file_path):
                    logger.warning(f"File not found: {file_path}")
                    continue
                    
                # Skip files that are too large
                if os.path.getsize(file_path) > self.config["max_file_size"]:
                    logger.warning(f"Skipping large file: {file_path} ({os.path.getsize(file_path)} bytes)")
                    continue
                    
                # Get original extension (before encryption)
                file_name = os.path.basename(file_path)
                original_extension = None
                
                # Try to extract original extension from ransomware extension
                for pattern in self.config["known_patterns"].values():
                    encrypted_ext = pattern.get("extension")
                    if encrypted_ext and file_name.endswith(encrypted_ext):
                        # Remove ransomware extension to get original filename
                        original_name = file_name[:-len(encrypted_ext)]
                        # Extract extension
                        original_extension = os.path.splitext(original_name)[1].lower()
                        break
                
                # If no original extension found from patterns, try common approach
                if not original_extension:
                    # Many ransomware adds its extension after the original
                    # e.g. document.docx.encrypted
                    parts = file_name.split('.')
                    if len(parts) >= 3:
                        # Assume second-to-last part is the original extension
                        original_extension = f".{parts[-2]}"
                
                # Read file data (first part)
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read(4096)  # Read first 4KB for testing
                        
                    # Submit task
                    future = executor.submit(
                        self.test_keys_on_data,
                        file_data,
                        keys,
                        original_extension
                    )
                    future_to_file[future] = file_path
                    
                except Exception as e:
                    logger.error(f"Error reading file {file_path}: {e}")
            
            # Collect results
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_result = future.result()
                    if file_result["successful_decryptions"]:
                        results["successful_decryptions"][file_path] = file_result["successful_decryptions"]
                        results["summary"]["total_success"] += 1
                        
                        # If output directory is provided, decrypt the file
                        if output_dir:
                            best_decryption = file_result["successful_decryptions"][0]
                            
                            # Prepare decryption parameters
                            algorithm = best_decryption["algorithm"]
                            key = bytes.fromhex(best_decryption["key"])
                            iv = None
                            if "iv" in best_decryption:
                                if best_decryption.get("iv_source") == "file_header":
                                    iv = "from_file_header"
                                else:
                                    iv = bytes.fromhex(best_decryption["iv"])
                            
                            # Determine output file path
                            file_name = os.path.basename(file_path)
                            
                            # Try to remove ransomware extension
                            for pattern in self.config["known_patterns"].values():
                                encrypted_ext = pattern.get("extension")
                                if encrypted_ext and file_name.endswith(encrypted_ext):
                                    file_name = file_name[:-len(encrypted_ext)]
                                    break
                            
                            # Add decrypted extension if identified
                            if best_decryption.get("identified_extension"):
                                # Check if file already has the original extension
                                if not file_name.endswith(best_decryption["identified_extension"]):
                                    file_name += best_decryption["identified_extension"]
                            else:
                                file_name += ".decrypted"
                                
                            output_path = os.path.join(output_dir, file_name)
                            
                            # Decrypt the file
                            success = self.decrypt_file(
                                file_path,
                                output_path,
                                algorithm,
                                key,
                                iv
                            )
                            
                            if success:
                                logger.info(f"Successfully decrypted {file_path} to {output_path}")
                                results["successful_decryptions"][file_path][0]["decrypted_file"] = output_path
                                
                except Exception as e:
                    logger.error(f"Error processing results for {file_path}: {e}")
        
        # Calculate success rate
        if results["summary"]["total_files"] > 0:
            results["summary"]["success_rate"] = results["summary"]["total_success"] / results["summary"]["total_files"]
        
        return results
    
    def recover_files(self, encrypted_dir: str, keys: List[Dict], 
                    output_dir: str, sample_count: int = None) -> Dict:
        """
        Attempt to recover files in a directory
        
        Args:
            encrypted_dir: Directory containing encrypted files
            keys: List of key dictionaries
            output_dir: Directory to save decrypted files
            sample_count: Number of files to sample per extension (optional)
            
        Returns:
            Dictionary with recovery results
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "encrypted_dir": encrypted_dir,
            "output_dir": output_dir,
            "extensions_found": {},
            "files_processed": 0,
            "successful_decryptions": 0,
            "detailed_results": {}
        }
        
        if not os.path.isdir(encrypted_dir):
            logger.error(f"Invalid encrypted directory: {encrypted_dir}")
            results["error"] = "Invalid encrypted directory"
            return results
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Find all files recursively
        all_files = []
        for root, _, files in os.walk(encrypted_dir):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
        
        logger.info(f"Found {len(all_files)} files in {encrypted_dir}")
        
        # Group files by extension
        extension_files = {}
        for file_path in all_files:
            file_ext = os.path.splitext(file_path)[1].lower()
            if not file_ext:
                file_ext = ".noext"  # For files without extension
                
            if file_ext not in extension_files:
                extension_files[file_ext] = []
                
            extension_files[file_ext].append(file_path)
        
        # Update results with extension counts
        for ext, files in extension_files.items():
            results["extensions_found"][ext] = len(files)
        
        # Sample files from each extension
        test_files = []
        sample_count = sample_count or self.config["max_sample_files"]
        
        for ext, files in extension_files.items():
            # Sort by file size (smallest first) for quicker testing
            sorted_files = sorted(files, key=os.path.getsize)
            
            # Skip very small files (likely empty or headers-only)
            valid_files = [f for f in sorted_files if os.path.getsize(f) >= self.config["min_original_file_size"]]
            
            # Take sample
            ext_samples = valid_files[:sample_count]
            test_files.extend(ext_samples)
        
        logger.info(f"Selected {len(test_files)} files for testing")
        
        # Test keys on files
        batch_results = self.batch_test_files(test_files, keys, output_dir)
        
        # Update results
        results["files_processed"] = batch_results["summary"]["total_files"]
        results["successful_decryptions"] = batch_results["summary"]["total_success"]
        results["detailed_results"] = batch_results["successful_decryptions"]
        
        # Add success rate
        results["success_rate"] = batch_results["summary"]["success_rate"]
        
        # If successful decryptions found, decrypt all files with the same params
        if batch_results["successful_decryptions"]:
            # Find the most successful decryption parameters
            best_params = None
            best_count = 0
            
            # Count occurrences of each decryption parameter set
            param_counts = {}
            for file_path, decryptions in batch_results["successful_decryptions"].items():
                if not decryptions:
                    continue
                    
                decryption = decryptions[0]  # Take the best result
                param_key = f"{decryption['algorithm']}:{decryption['key']}"
                
                if "iv" in decryption:
                    param_key += f":{decryption['iv']}"
                
                if param_key not in param_counts:
                    param_counts[param_key] = {
                        "count": 0,
                        "params": decryption
                    }
                
                param_counts[param_key]["count"] += 1
            
            # Find the most common params
            for param_key, data in param_counts.items():
                if data["count"] > best_count:
                    best_count = data["count"]
                    best_params = data["params"]
            
            if best_params:
                # Ask if user wants to decrypt all files with these params
                logger.info(f"Found successful decryption parameters: {best_params['algorithm']} with key {best_params['key'][:10]}...")
                logger.info(f"Used successfully on {best_count} out of {len(test_files)} tested files")
                
                results["best_decryption_params"] = best_params
        
        return results


def load_keys_from_file(key_file: str) -> List[Dict]:
    """
    Load encryption keys from a file
    
    Args:
        key_file: Path to key file (JSON, text, or binary)
        
    Returns:
        List of key dictionaries
    """
    keys = []
    
    if not os.path.exists(key_file):
        logger.error(f"Key file not found: {key_file}")
        return keys
    
    # Try to load as JSON
    try:
        with open(key_file, 'r') as f:
            data = json.load(f)
        
        # If data is a dictionary with a 'keys' or 'promising_keys' field
        if isinstance(data, dict):
            # Check for memory analysis format
            if "promising_keys" in data:
                for key_info in data["promising_keys"]:
                    if "hex" in key_info:
                        keys.append({
                            "type": key_info.get("type", "unknown"),
                            "data": bytes.fromhex(key_info["hex"])
                        })
            # Check for extracted_keys format
            elif "key_data" in data:
                keys.append({
                    "type": data.get("key_type", "unknown"),
                    "data": bytes.fromhex(data["key_data"]["hex"])
                })
            # Check for keys array
            elif "keys" in data and isinstance(data["keys"], list):
                for key_info in data["keys"]:
                    if "data" in key_info or "hex" in key_info:
                        keys.append({
                            "type": key_info.get("type", "unknown"),
                            "data": bytes.fromhex(key_info.get("data", key_info.get("hex", "")))
                        })
        
        # If data is a list
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if "key_data" in item:
                        keys.append({
                            "type": item.get("key_type", "unknown"),
                            "data": bytes.fromhex(item["key_data"]["hex"])
                        })
                    elif "data" in item or "hex" in item or "key" in item:
                        key_data = item.get("data", item.get("hex", item.get("key", "")))
                        if isinstance(key_data, str):
                            key_data = bytes.fromhex(key_data)
                        keys.append({
                            "type": item.get("type", "unknown"),
                            "data": key_data
                        })
        
        return keys
        
    except json.JSONDecodeError:
        # Not a valid JSON file, try as text or binary
        pass
    
    # Try to read as text file with hex keys
    try:
        with open(key_file, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Try to extract key info
            key_type = "unknown"
            key_data = line
            
            # Check for format like "aes: 0123456789abcdef"
            if ":" in line:
                parts = line.split(":", 1)
                key_type = parts[0].strip().lower()
                key_data = parts[1].strip()
            
            # Convert hex string to bytes
            try:
                key_bytes = bytes.fromhex(key_data.replace(":", "").replace(" ", ""))
                keys.append({
                    "type": key_type,
                    "data": key_bytes
                })
            except:
                # Not a valid hex string, skip
                continue
        
        return keys
        
    except:
        # Not a valid text file, try as binary
        pass
    
    # Try to read as binary file
    try:
        with open(key_file, 'rb') as f:
            data = f.read()
        
        # Try to guess key type from size
        key_type = "unknown"
        if len(data) in (16, 24, 32):
            key_type = "aes"
        elif len(data) > 128:
            key_type = "rsa"
        
        keys.append({
            "type": key_type,
            "data": data
        })
        
        return keys
        
    except:
        logger.error(f"Failed to read key file: {key_file}")
        return keys


def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="Ransomware Decryption Tester")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', help='Path to encrypted file')
    input_group.add_argument('--directory', '-d', help='Path to directory with encrypted files')
    
    # Key options
    parser.add_argument('--key-file', '-k', required=True, help='Path to file containing encryption keys')
    parser.add_argument('--config', '-c', help='Path to configuration file')
    
    # Output options
    parser.add_argument('--output', '-o', required=True, help='Output directory for decrypted files')
    parser.add_argument('--report', '-r', help='Output file for report (JSON)')
    
    args = parser.parse_args()
    
    # Load keys
    keys = load_keys_from_file(args.key_file)
    if not keys:
        logger.error("No valid keys found in key file")
        return 1
    
    logger.info(f"Loaded {len(keys)} keys from {args.key_file}")
    
    # Create decryption tester
    tester = DecryptionTester(args.config)
    
    # Process based on input options
    results = None
    if args.file:
        logger.info(f"Testing keys on file: {args.file}")
        
        # Read file data
        try:
            with open(args.file, 'rb') as f:
                file_data = f.read(4096)  # Read first 4KB for testing
        except Exception as e:
            logger.error(f"Error reading file: {e}")
            return 1
        
        # Test keys
        original_extension = os.path.splitext(os.path.basename(args.file))[1].lower()
        results = tester.test_keys_on_data(file_data, keys, original_extension)
        
        # Check if any decryption was successful
        if results["successful_decryptions"]:
            logger.info(f"Found {len(results['successful_decryptions'])} successful decryption methods")
            
            # Decrypt the file with the best method
            best_decryption = results["successful_decryptions"][0]
            
            algorithm = best_decryption["algorithm"]
            key = bytes.fromhex(best_decryption["key"])
            iv = None
            if "iv" in best_decryption:
                if best_decryption.get("iv_source") == "file_header":
                    iv = "from_file_header"
                else:
                    iv = bytes.fromhex(best_decryption["iv"])
            
            # Determine output file path
            file_name = os.path.basename(args.file)
            
            # Try to remove ransomware extension
            for pattern in tester.config["known_patterns"].values():
                encrypted_ext = pattern.get("extension")
                if encrypted_ext and file_name.endswith(encrypted_ext):
                    file_name = file_name[:-len(encrypted_ext)]
                    break
            
            # Add decrypted extension if identified
            if best_decryption.get("identified_extension"):
                # Check if file already has the original extension
                if not file_name.endswith(best_decryption["identified_extension"]):
                    file_name += best_decryption["identified_extension"]
            else:
                file_name += ".decrypted"
                
            os.makedirs(args.output, exist_ok=True)
            output_path = os.path.join(args.output, file_name)
            
            # Decrypt the file
            success = tester.decrypt_file(
                args.file,
                output_path,
                algorithm,
                key,
                iv
            )
            
            if success:
                logger.info(f"Successfully decrypted to {output_path}")
                results["decrypted_file"] = output_path
            else:
                logger.error("Failed to decrypt file")
                results["error"] = "Failed to decrypt file"
        else:
            logger.info("No successful decryption method found")
    
    elif args.directory:
        logger.info(f"Recovering files from directory: {args.directory}")
        
        # Recover files
        results = tester.recover_files(args.directory, keys, args.output)
        
        if results["successful_decryptions"] > 0:
            logger.info(f"Successfully decrypted {results['successful_decryptions']} out of {results['files_processed']} files")
            logger.info(f"Decrypted files saved to {args.output}")
            
            if "best_decryption_params" in results:
                best_params = results["best_decryption_params"]
                logger.info(f"Best decryption method: {best_params['algorithm']} with key {best_params['key'][:10]}...")
        else:
            logger.info("No files were successfully decrypted")
    
    # Save report if requested
    if args.report and results:
        try:
            with open(args.report, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Report saved to {args.report}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")
    
    return 0


if __name__ == "__main__":
    main()