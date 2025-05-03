#!/usr/bin/env python3
"""
Encryption Key Validator
Tests and validates encryption keys extracted from memory or ransom notes.
"""

import os
import re
import json
import base64
import struct
import logging
import hashlib
import datetime
import tempfile
from typing import Dict, List, Any, Optional, Set, Tuple, BinaryIO, Union

# Cryptography imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('key_validator')

class KeyValidator:
    """
    Validates and tests encryption keys for various algorithms
    """
    
    def __init__(self):
        """Initialize the key validator"""
        self.results_cache = {}
        self.test_string = b"This is a test string for encryption validation!!! 12345"
    
    def validate_aes_key(self, key: bytes) -> Dict:
        """
        Validate an AES key
        
        Args:
            key: Potential AES key
            
        Returns:
            Validation results dictionary
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "key_type": "aes",
            "key_length": len(key),
            "key_hex": key.hex(),
            "valid": False,
            "issues": []
        }
        
        # Check key length
        if len(key) not in (16, 24, 32):
            results["issues"].append(f"Invalid AES key length: {len(key)} bytes (must be 16, 24, or 32)")
            return results
        
        # Check entropy
        entropy = self._calculate_entropy(key)
        results["entropy"] = entropy
        
        if entropy < 3.5:
            results["issues"].append(f"Low entropy ({entropy:.2f}) suggests this may not be a random key")
        
        # Consistency check - encrypt and decrypt test string
        for mode_name in ("cbc", "ecb"):
            try:
                # Initialize cipher for encryption
                if mode_name == "cbc":
                    iv = os.urandom(16)
                    mode = modes.CBC(iv)
                    results[f"{mode_name}_iv"] = iv.hex()
                else:
                    iv = None
                    mode = modes.ECB()
                
                encryptor = Cipher(
                    algorithms.AES(key),
                    mode,
                    backend=default_backend()
                ).encryptor()
                
                # Encrypt test string
                ciphertext = encryptor.update(self.test_string) + encryptor.finalize()
                
                # Initialize cipher for decryption
                decryptor = Cipher(
                    algorithms.AES(key),
                    mode,
                    backend=default_backend()
                ).decryptor()
                
                # Decrypt test string
                plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Check if decryption worked
                if plaintext == self.test_string:
                    results[f"{mode_name}_functional"] = True
                else:
                    results[f"{mode_name}_functional"] = False
                    results["issues"].append(f"AES-{mode_name.upper()} encryption/decryption test failed")
            except Exception as e:
                results[f"{mode_name}_functional"] = False
                results["issues"].append(f"AES-{mode_name.upper()} encryption/decryption error: {str(e)}")
        
        # Key is valid if at least one mode works and entropy is sufficient
        if (results.get("cbc_functional", False) or results.get("ecb_functional", False)) and entropy >= 3.0:
            results["valid"] = True
        
        return results
    
    def validate_rsa_key(self, key_data: bytes) -> Dict:
        """
        Validate an RSA key
        
        Args:
            key_data: Potential RSA key data
            
        Returns:
            Validation results dictionary
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "key_type": "rsa",
            "key_length": len(key_data),
            "key_hex": key_data.hex()[:100] + "..." if len(key_data) > 50 else key_data.hex(),
            "valid": False,
            "issues": []
        }
        
        # Try to load as PEM private key
        try:
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Check key size
            key_size = private_key.key_size
            results["key_size"] = key_size
            
            if key_size < 1024:
                results["issues"].append(f"RSA key size too small: {key_size} bits")
            
            # Functional test
            try:
                # Encrypt test string
                ciphertext = private_key.public_key().encrypt(
                    self.test_string[:100],  # RSA can only encrypt small amounts of data
                    padding.PKCS1v15()
                )
                
                # Decrypt test string
                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.PKCS1v15()
                )
                
                # Check if decryption worked
                if plaintext == self.test_string[:100]:
                    results["functional"] = True
                    results["key_format"] = "PEM"
                    results["valid"] = True
                else:
                    results["functional"] = False
                    results["issues"].append("RSA encryption/decryption test failed")
            except Exception as e:
                results["functional"] = False
                results["issues"].append(f"RSA encryption/decryption error: {str(e)}")
                
            return results
            
        except Exception as e:
            # Not a PEM private key, try DER
            pass
        
        # Try to load as DER private key
        try:
            private_key = serialization.load_der_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            
            # Check key size
            key_size = private_key.key_size
            results["key_size"] = key_size
            
            if key_size < 1024:
                results["issues"].append(f"RSA key size too small: {key_size} bits")
            
            # Functional test
            try:
                # Encrypt test string
                ciphertext = private_key.public_key().encrypt(
                    self.test_string[:100],  # RSA can only encrypt small amounts of data
                    padding.PKCS1v15()
                )
                
                # Decrypt test string
                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.PKCS1v15()
                )
                
                # Check if decryption worked
                if plaintext == self.test_string[:100]:
                    results["functional"] = True
                    results["key_format"] = "DER"
                    results["valid"] = True
                else:
                    results["functional"] = False
                    results["issues"].append("RSA encryption/decryption test failed")
            except Exception as e:
                results["functional"] = False
                results["issues"].append(f"RSA encryption/decryption error: {str(e)}")
                
            return results
            
        except Exception as e:
            # Not a DER private key, try other formats or return invalid
            results["issues"].append(f"Failed to load RSA key: {str(e)}")
            
        # If we couldn't load the key in any format, it's not a valid RSA key
        return results
    
    def validate_key(self, key_data: bytes, key_type: str = None) -> Dict:
        """
        Validate an encryption key
        
        Args:
            key_data: Key data to validate
            key_type: Type of key (aes, rsa, etc.) or None to auto-detect
            
        Returns:
            Validation results dictionary
        """
        if key_type is None:
            # Try to auto-detect key type
            # Use length as a heuristic
            if len(key_data) in (16, 24, 32):
                key_type = "aes"
            elif len(key_data) > 100 and (b"-----BEGIN" in key_data or b"\x30\x82" in key_data):
                key_type = "rsa"
            else:
                # Default to AES for unknown types
                key_type = "aes"
        
        # Validate based on key type
        key_type = key_type.lower()
        if key_type == "aes":
            return self.validate_aes_key(key_data)
        elif key_type == "rsa":
            return self.validate_rsa_key(key_data)
        else:
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "key_type": key_type,
                "key_length": len(key_data),
                "key_hex": key_data.hex(),
                "valid": False,
                "issues": [f"Unsupported key type: {key_type}"]
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
            if probability > 0:
                entropy -= probability * (probability).bit_length()
        
        return entropy
    
    def extract_key_from_file(self, file_path: str, key_type: str = None, 
                           offset: int = None, length: int = None) -> Dict:
        """
        Extract and validate a key from a file
        
        Args:
            file_path: Path to file containing the key
            key_type: Type of key (aes, rsa, etc.) or None to auto-detect
            offset: Offset in the file (optional)
            length: Length of the key (optional)
            
        Returns:
            Validation results dictionary
        """
        try:
            with open(file_path, 'rb') as f:
                if offset is not None:
                    f.seek(offset)
                
                if length is not None:
                    key_data = f.read(length)
                else:
                    key_data = f.read()
                
                return self.validate_key(key_data, key_type)
                
        except Exception as e:
            return {
                "timestamp": datetime.datetime.now().isoformat(),
                "error": f"Failed to extract key from file: {str(e)}",
                "valid": False
            }
    
    def extract_key_from_memory_dump(self, dump_file: str, pattern: bytes, 
                                  key_type: str = None, length: int = None) -> List[Dict]:
        """
        Extract and validate keys from a memory dump
        
        Args:
            dump_file: Path to memory dump file
            pattern: Bytes pattern to search for
            key_type: Type of key (aes, rsa, etc.) or None to auto-detect
            length: Length of the key after the pattern (optional)
            
        Returns:
            List of validation results dictionaries
        """
        results = []
        
        try:
            with open(dump_file, 'rb') as f:
                dump_data = f.read()
                
            pattern_len = len(pattern)
            offset = 0
            
            while True:
                # Find the pattern
                pos = dump_data.find(pattern, offset)
                if pos == -1:
                    break
                    
                # Extract the key after the pattern
                if length is not None:
                    key_data = dump_data[pos + pattern_len:pos + pattern_len + length]
                else:
                    # Try to auto-detect key length
                    if key_type == "aes":
                        # Try lengths of 16, 24, and 32 bytes
                        for key_len in (32, 24, 16):
                            key_data = dump_data[pos + pattern_len:pos + pattern_len + key_len]
                            validation = self.validate_key(key_data, key_type)
                            if validation["valid"]:
                                validation["offset"] = pos + pattern_len
                                results.append(validation)
                        
                        # Move to next occurrence
                        offset = pos + pattern_len
                        continue
                    else:
                        # Default to reading 128 bytes
                        key_data = dump_data[pos + pattern_len:pos + pattern_len + 128]
                
                # Validate the key
                validation = self.validate_key(key_data, key_type)
                validation["offset"] = pos + pattern_len
                results.append(validation)
                
                # Move to next occurrence
                offset = pos + pattern_len
                
        except Exception as e:
            logger.error(f"Failed to extract keys from memory dump: {str(e)}")
            
        return results
    
    def analyze_keys(self, keys: List[Dict]) -> Dict:
        """
        Analyze multiple keys to find the best candidates
        
        Args:
            keys: List of key dictionaries
            
        Returns:
            Analysis results dictionary
        """
        results = {
            "timestamp": datetime.datetime.now().isoformat(),
            "total_keys": len(keys),
            "valid_keys": 0,
            "aes_keys": [],
            "rsa_keys": [],
            "other_keys": []
        }
        
        for key_info in keys:
            key_type = key_info.get("key_type", "unknown").lower()
            key_data = key_info.get("data", key_info.get("key_data", key_info.get("bytes", key_info.get("key", b""))))
            
            # Skip if no key data
            if not key_data:
                continue
                
            # Convert to bytes if it's a string
            if isinstance(key_data, str):
                try:
                    if key_data.startswith("-----BEGIN"):
                        # Probably a PEM key
                        key_data = key_data.encode()
                    else:
                        # Try hex
                        key_data = bytes.fromhex(key_data.replace(":", ""))
                except:
                    try:
                        # Try base64
                        key_data = base64.b64decode(key_data)
                    except:
                        continue
            
            # Validate the key
            validation = self.validate_key(key_data, key_type)
            
            # Store the result
            if validation["valid"]:
                results["valid_keys"] += 1
                
                if validation["key_type"] == "aes":
                    results["aes_keys"].append(validation)
                elif validation["key_type"] == "rsa":
                    results["rsa_keys"].append(validation)
                else:
                    results["other_keys"].append(validation)
        
        # Sort keys by entropy (higher is better)
        results["aes_keys"].sort(key=lambda x: x.get("entropy", 0), reverse=True)
        
        return results


def main():
    """Main function for command-line usage"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description="Encryption Key Validator")
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--key', '-k', help='Hexadecimal key to validate')
    input_group.add_argument('--key-file', '-f', help='Path to file containing key')
    input_group.add_argument('--memory-dump', '-m', help='Path to memory dump file')
    
    # Key options
    parser.add_argument('--type', '-t', choices=['aes', 'rsa'], help='Key type')
    parser.add_argument('--offset', type=int, help='Offset in file')
    parser.add_argument('--length', type=int, help='Length of key')
    parser.add_argument('--pattern', '-p', help='Hex pattern to search for in memory dump')
    
    # Output options
    parser.add_argument('--output', '-o', help='Output file for validation results (JSON)')
    
    args = parser.parse_args()
    
    # Create validator
    validator = KeyValidator()
    
    # Process based on input options
    results = None
    if args.key:
        # Validate key directly
        try:
            key_data = bytes.fromhex(args.key.replace(":", ""))
            results = validator.validate_key(key_data, args.type)
        except Exception as e:
            logger.error(f"Error parsing key: {e}")
            return 1
    
    elif args.key_file:
        # Extract key from file
        results = validator.extract_key_from_file(
            args.key_file,
            args.type,
            args.offset,
            args.length
        )
    
    elif args.memory_dump:
        # Extract keys from memory dump
        if not args.pattern:
            logger.error("Memory dump mode requires a pattern (--pattern)")
            return 1
            
        try:
            pattern = bytes.fromhex(args.pattern.replace(":", ""))
            results = validator.extract_key_from_memory_dump(
                args.memory_dump,
                pattern,
                args.type,
                args.length
            )
        except Exception as e:
            logger.error(f"Error parsing pattern: {e}")
            return 1
    
    # Display results
    if results:
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                logger.info(f"Results saved to {args.output}")
            except Exception as e:
                logger.error(f"Error saving results: {e}")
        else:
            print(json.dumps(results, indent=2))
    
    return 0


if __name__ == "__main__":
    main()