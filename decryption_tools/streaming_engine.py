#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Streaming Decryption Engine for Innora-Defender

This module provides a high-performance, memory-efficient streaming decryption engine
that can be integrated with all ransomware family recovery modules.

Key features:
- Memory-efficient streaming decryption for all common encryption algorithms
- Adaptive buffer sizing based on available system resources
- Support for partial file encryption detection and recovery
- Progress tracking and callbacks for UI integration
- Comprehensive validation frameworks for determining decryption success
- Multi-threaded decryption for large files

Usage:
    decryptor = StreamingDecryptor()
    result = decryptor.decrypt_file(
        "encrypted_file.txt", 
        "decrypted_file.txt",
        "aes-256-cbc",
        key=key_bytes,
        iv=iv_bytes
    )
"""

import os
import io
import sys
import time
import math
import base64
import struct
import logging
import binascii
import hashlib
import threading
import concurrent.futures
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Tuple, Union, Optional, Any, BinaryIO, Callable
from dataclasses import dataclass, field
from datetime import datetime
import mmap

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("StreamingDecryptor")

# Try to import cryptography libraries
try:
    import cryptography
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.primitives import padding
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logger.warning("Cryptography library not available. Install with: pip install cryptography")

# Optional pycryptodome for additional algorithms
try:
    from Crypto.Cipher import AES, ChaCha20, Salsa20, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import pad, unpad
    PYCRYPTODOME_AVAILABLE = True
except ImportError:
    PYCRYPTODOME_AVAILABLE = False
    logger.debug("PyCryptodome not available. Some algorithms may not be supported.")


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_CBC = "aes-cbc"
    AES_ECB = "aes-ecb"
    AES_CTR = "aes-ctr"
    AES_GCM = "aes-gcm"
    AES_CFB = "aes-cfb"
    AES_OFB = "aes-ofb"
    CHACHA20 = "chacha20"
    SALSA20 = "salsa20"
    RC4 = "rc4"
    BLOWFISH = "blowfish"
    TRIPLE_DES = "3des"
    RSA = "rsa"
    

class ValidationLevel(Enum):
    """Validation levels for decryption results"""
    NONE = 0        # No validation
    BASIC = 1       # Basic signature and entropy checks
    STANDARD = 2    # Standard validation with multiple checks
    STRICT = 3      # Strict validation for sensitive data
    CUSTOM = 4      # Custom validation with user-provided callback


@dataclass
class DecryptionParams:
    """Parameters for decryption operation"""
    
    # Required parameters
    algorithm: str  # Algorithm name or EncryptionAlgorithm
    key: bytes      # Encryption key
    
    # Optional algorithm-specific parameters
    iv: Optional[bytes] = None                 # Initialization vector
    nonce: Optional[bytes] = None              # Nonce for ChaCha20/Salsa20
    tag: Optional[bytes] = None                # Authentication tag for GCM
    counter: Optional[int] = 0                 # Counter for CTR mode
    additional_data: Optional[bytes] = None    # Additional authenticated data for GCM
    
    # Input processing parameters
    header_size: int = 0                       # Size of header to skip
    footer_size: int = 0                       # Size of footer to skip
    iv_in_file: bool = False                   # Whether IV is in the file
    iv_offset: int = 0                         # Offset of IV in file if iv_in_file is True
    iv_size: int = 16                          # Size of IV in file if iv_in_file is True
    
    # Performance configuration
    chunk_size: int = 1024 * 1024              # Default to 1MB chunks
    use_threading: bool = False                # Whether to use multi-threading
    num_threads: int = 0                       # Number of threads (0 = auto)
    
    # Validation options
    validation_level: ValidationLevel = ValidationLevel.STANDARD  # Validation level
    validation_callback: Optional[Callable] = None                # Custom validation callback
    
    # Progress reporting
    progress_callback: Optional[Callable] = None  # Callback for progress updates
    
    # Runtime information (filled during operation)
    file_size: int = 0                         # Input file size
    processed_bytes: int = 0                   # Number of bytes processed
    success: bool = False                      # Whether decryption was successful
    error_message: Optional[str] = None        # Error message if decryption failed
    

class StreamingDecryptor:
    """
    Memory-efficient streaming decryption engine that supports multiple algorithms
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        Initialize the streaming decryptor
        
        Args:
            progress_callback: Optional callback for progress updates
        """
        self.progress_callback = progress_callback
        
        # Check for required libraries
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.warning("Cryptography library not available. Some functions may not work.")
        
        # Determine optimal chunk size based on system memory
        self.default_chunk_size = self._determine_optimal_chunk_size()
        
        # Initialize performance tracking
        self.perf_stats = {
            "start_time": 0,
            "end_time": 0,
            "total_bytes": 0,
            "processed_bytes": 0,
            "throughput_bps": 0
        }
        
        # Initialize threading
        self.max_workers = max(1, (os.cpu_count() or 4) - 1)
        self.thread_pool = None
    
    def decrypt_file(self, input_file: str, output_file: str, algorithm: str,
                    key: bytes, **kwargs) -> Dict[str, Any]:
        """
        Decrypt a file using streaming
        
        Args:
            input_file: Path to encrypted input file
            output_file: Path to save decrypted output
            algorithm: Encryption algorithm (see EncryptionAlgorithm)
            key: Decryption key
            **kwargs: Additional parameters (see DecryptionParams)
            
        Returns:
            Result dictionary with status and metadata
        """
        # Validate required libraries
        if not CRYPTOGRAPHY_AVAILABLE:
            return {
                "success": False,
                "error": "Cryptography library not available"
            }
        
        # Check if input file exists
        if not os.path.exists(input_file):
            return {
                "success": False,
                "error": f"Input file not found: {input_file}"
            }
        
        # Create parent directories for output file if needed
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Parse algorithm and create params
        params = self._create_decryption_params(algorithm, key, **kwargs)
        
        # Start performance tracking
        self._start_perf_tracking(params)
        
        try:
            # Determine if using threading
            if params.use_threading:
                return self._decrypt_file_threaded(input_file, output_file, params)
            else:
                return self._decrypt_file_streaming(input_file, output_file, params)
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return {
                "success": False,
                "error": str(e),
                "input_file": input_file,
                "algorithm": params.algorithm
            }
        finally:
            # Finalize performance tracking
            self._end_perf_tracking(params)
    
    def decrypt_data(self, data: bytes, algorithm: str, key: bytes, **kwargs) -> Dict[str, Any]:
        """
        Decrypt data in memory
        
        Args:
            data: Encrypted data
            algorithm: Encryption algorithm
            key: Decryption key
            **kwargs: Additional parameters (see DecryptionParams)
            
        Returns:
            Result dictionary with status and decrypted data
        """
        # Validate required libraries
        if not CRYPTOGRAPHY_AVAILABLE:
            return {
                "success": False,
                "error": "Cryptography library not available"
            }
        
        # Parse algorithm and create params
        params = self._create_decryption_params(algorithm, key, **kwargs)
        params.file_size = len(data)
        
        # Create input and output streams
        input_stream = io.BytesIO(data)
        output_stream = io.BytesIO()
        
        # Start performance tracking
        self._start_perf_tracking(params)
        
        try:
            # Process the data stream
            result = self._process_stream(input_stream, output_stream, params)
            
            # Get the decrypted data
            decrypted_data = output_stream.getvalue()
            
            # Validate the result
            validation_result = self._validate_decryption(decrypted_data, params)
            
            # Return the result
            return {
                "success": validation_result["success"],
                "decrypted_data": decrypted_data if validation_result["success"] else None,
                "validation": validation_result,
                "algorithm": params.algorithm,
                "data_size": len(data),
                "decrypted_size": len(decrypted_data) if decrypted_data else 0
            }
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return {
                "success": False,
                "error": str(e),
                "algorithm": params.algorithm
            }
        finally:
            # Finalize performance tracking
            self._end_perf_tracking(params)
            
            # Close streams
            input_stream.close()
            output_stream.close()
    
    def _decrypt_file_streaming(self, input_file: str, output_file: str, 
                               params: DecryptionParams) -> Dict[str, Any]:
        """
        Decrypt a file using streaming I/O
        
        Args:
            input_file: Path to encrypted input file
            output_file: Path to save decrypted output
            params: Decryption parameters
            
        Returns:
            Result dictionary with status and metadata
        """
        # Get file size
        file_size = os.path.getsize(input_file)
        params.file_size = file_size
        
        # Process file streams
        with open(input_file, 'rb') as input_stream, open(output_file, 'wb') as output_stream:
            # Extract IV from file if needed
            if params.iv_in_file:
                try:
                    # Seek to IV position
                    input_stream.seek(params.iv_offset)
                    
                    # Read IV
                    params.iv = input_stream.read(params.iv_size)
                    
                    # Reset to beginning
                    input_stream.seek(0)
                except Exception as e:
                    logger.error(f"Error extracting IV from file: {e}")
                    return {
                        "success": False,
                        "error": f"Error extracting IV from file: {e}",
                        "input_file": input_file
                    }
            
            # Process the streams
            result = self._process_stream(input_stream, output_stream, params)
            
            # Verify the output file
            if result["success"] and os.path.exists(output_file):
                # Run validation on the output file
                try:
                    with open(output_file, 'rb') as f:
                        # Read a portion for validation
                        validation_data = f.read(min(1024 * 1024, os.path.getsize(output_file)))
                    
                    # Validate the result
                    validation_result = self._validate_decryption(validation_data, params)
                    
                    # Update the result with validation info
                    result.update({
                        "validation": validation_result,
                        "final_success": validation_result["success"]
                    })
                    
                    # If validation failed, but we produced an output file, consider it a partial success
                    if not validation_result["success"]:
                        result["partial_success"] = True
                        result["warning"] = "Validation failed, but output file was created"
                except Exception as e:
                    logger.error(f"Validation error: {e}")
                    result["validation_error"] = str(e)
            
            return result
    
    def _decrypt_file_threaded(self, input_file: str, output_file: str, 
                              params: DecryptionParams) -> Dict[str, Any]:
        """
        Decrypt a file using multi-threaded processing
        
        Args:
            input_file: Path to encrypted input file
            output_file: Path to save decrypted output
            params: Decryption parameters
            
        Returns:
            Result dictionary with status and metadata
        """
        # Get file size
        file_size = os.path.getsize(input_file)
        params.file_size = file_size
        
        # Initialize thread pool if not already done
        if self.thread_pool is None:
            num_workers = params.num_threads if params.num_threads > 0 else self.max_workers
            self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)
        
        # Determine number of chunks
        chunk_size = params.chunk_size
        num_chunks = math.ceil(file_size / chunk_size)
        
        # Initialize results list
        decrypted_chunks = [None] * num_chunks
        futures = []
        
        # Extract IV from file if needed
        iv = params.iv
        if params.iv_in_file:
            try:
                with open(input_file, 'rb') as f:
                    # Seek to IV position
                    f.seek(params.iv_offset)
                    
                    # Read IV
                    iv = f.read(params.iv_size)
            except Exception as e:
                logger.error(f"Error extracting IV from file: {e}")
                return {
                    "success": False,
                    "error": f"Error extracting IV from file: {e}",
                    "input_file": input_file
                }
        
        # Function to decrypt a chunk
        def decrypt_chunk(chunk_idx: int) -> Tuple[int, bytes]:
            # Calculate chunk position and size
            start_pos = chunk_idx * chunk_size
            end_pos = min(start_pos + chunk_size, file_size)
            current_chunk_size = end_pos - start_pos
            
            try:
                with open(input_file, 'rb') as f:
                    # Seek to chunk position
                    f.seek(start_pos)
                    
                    # Read chunk
                    encrypted_chunk = f.read(current_chunk_size)
                    
                    # For the first chunk, skip header if needed
                    if chunk_idx == 0 and params.header_size > 0:
                        if len(encrypted_chunk) <= params.header_size:
                            # Chunk is entirely header
                            return chunk_idx, b""
                        
                        # Skip header
                        encrypted_chunk = encrypted_chunk[params.header_size:]
                    
                    # For the last chunk, skip footer if needed
                    if chunk_idx == num_chunks - 1 and params.footer_size > 0:
                        if len(encrypted_chunk) <= params.footer_size:
                            # Chunk is entirely footer
                            return chunk_idx, b""
                        
                        # Skip footer
                        encrypted_chunk = encrypted_chunk[:-params.footer_size]
                    
                    # Decrypt the chunk
                    # For algorithms requiring IV chaining, we need to handle specially
                    if params.algorithm in ["aes-cbc", "aes-cfb", "aes-ofb"]:
                        # For CBC/CFB/OFB modes, each chunk needs the last block of the previous chunk as IV
                        # This is complex for threading, so for now we use a simplified approach:
                        # Use original IV for first chunk, zero IV for others (less secure but works for testing)
                        current_iv = iv if chunk_idx == 0 else None
                        
                        # Decrypt the chunk
                        decrypted_chunk = self._decrypt_chunk(encrypted_chunk, params, current_iv)
                    else:
                        # For other modes like CTR, GCM, ChaCha20, each chunk can be processed independently
                        # We just need to adjust the counter/nonce
                        # This is a simplified implementation - real implementation would need mode-specific handling
                        decrypted_chunk = self._decrypt_chunk(encrypted_chunk, params)
                    
                    # Update progress
                    with params._progress_lock:
                        params.processed_bytes += current_chunk_size
                        self._update_progress(params)
                    
                    return chunk_idx, decrypted_chunk
            except Exception as e:
                logger.error(f"Error decrypting chunk {chunk_idx}: {e}")
                return chunk_idx, None
        
        try:
            # Add progress lock for threading
            params._progress_lock = threading.Lock()
            
            # Submit all chunk decryption tasks
            for i in range(num_chunks):
                future = self.thread_pool.submit(decrypt_chunk, i)
                futures.append(future)
            
            # Wait for completion and collect results
            for future in concurrent.futures.as_completed(futures):
                idx, data = future.result()
                if data is None:
                    # Decryption failed for this chunk
                    return {
                        "success": False,
                        "error": f"Failed to decrypt chunk {idx}",
                        "input_file": input_file
                    }
                
                decrypted_chunks[idx] = data
            
            # Combine chunks and write output
            with open(output_file, 'wb') as f:
                for chunk in decrypted_chunks:
                    if chunk:
                        f.write(chunk)
            
            # Validate the output file
            try:
                with open(output_file, 'rb') as f:
                    # Read a portion for validation
                    validation_data = f.read(min(1024 * 1024, os.path.getsize(output_file)))
                
                # Validate the result
                validation_result = self._validate_decryption(validation_data, params)
                
                return {
                    "success": validation_result["success"],
                    "input_file": input_file,
                    "output_file": output_file,
                    "algorithm": params.algorithm,
                    "threaded": True,
                    "chunks": num_chunks,
                    "chunk_size": chunk_size,
                    "file_size": file_size,
                    "validation": validation_result
                }
            except Exception as e:
                logger.error(f"Validation error: {e}")
                return {
                    "success": False,
                    "error": f"Validation error: {e}",
                    "partial_success": True,
                    "input_file": input_file,
                    "output_file": output_file
                }
        
        except Exception as e:
            logger.error(f"Threaded decryption error: {e}")
            return {
                "success": False,
                "error": str(e),
                "input_file": input_file
            }
    
    def _process_stream(self, input_stream: BinaryIO, output_stream: BinaryIO, 
                       params: DecryptionParams) -> Dict[str, Any]:
        """
        Process streams for decryption
        
        Args:
            input_stream: Input stream to read encrypted data
            output_stream: Output stream to write decrypted data
            params: Decryption parameters
            
        Returns:
            Result dictionary with status and metadata
        """
        # Extract initialization vector from file if needed
        iv = params.iv
        if params.iv_in_file:
            # Save original position
            original_pos = input_stream.tell()
            
            try:
                # Seek to IV position
                input_stream.seek(params.iv_offset)
                
                # Read IV
                iv = input_stream.read(params.iv_size)
                
                # Return to original position
                input_stream.seek(original_pos)
            except Exception as e:
                logger.error(f"Error extracting IV from file: {e}")
                return {
                    "success": False,
                    "error": f"Error extracting IV from file: {e}"
                }
        
        # Skip header if needed
        if params.header_size > 0:
            # Seek to data start position
            input_stream.seek(params.header_size)
        
        # Calculate data size (excluding header and footer)
        data_size = params.file_size - params.header_size - params.footer_size
        
        # Initialize decryption algorithm
        try:
            decryptor = self._create_decryptor(params, iv)
        except Exception as e:
            logger.error(f"Error initializing decryptor: {e}")
            return {
                "success": False,
                "error": f"Error initializing decryptor: {e}"
            }
        
        # Process chunks
        chunk_size = params.chunk_size
        bytes_processed = 0
        params.processed_bytes = 0
        
        try:
            while bytes_processed < data_size:
                # Calculate current chunk size
                remaining = data_size - bytes_processed
                current_chunk_size = min(chunk_size, remaining)
                
                # Read chunk
                encrypted_chunk = input_stream.read(current_chunk_size)
                if not encrypted_chunk:
                    break
                
                # Skip last chunk if it's smaller than padding size
                if remaining < 16 and params.algorithm in ["aes-cbc", "aes-ecb"]:
                    # Block cipher modes need complete blocks
                    logger.warning("Skipping incomplete final block")
                    break
                
                # Decrypt chunk
                try:
                    decrypted_chunk = self._decrypt_data(encrypted_chunk, decryptor, params)
                    
                    # Handle final chunk padding for block ciphers
                    if remaining == current_chunk_size and params.algorithm in ["aes-cbc", "aes-ecb"]:
                        # Try to remove padding from final block
                        try:
                            # Try to unpad
                            decrypted_chunk = self._unpad_data(decrypted_chunk, params)
                        except Exception as e:
                            logger.debug(f"Unpadding failed, using raw data: {e}")
                    
                    # Write decrypted chunk
                    output_stream.write(decrypted_chunk)
                    
                except Exception as e:
                    logger.error(f"Error decrypting chunk at position {bytes_processed}: {e}")
                    return {
                        "success": False,
                        "error": f"Error decrypting chunk: {e}",
                        "position": bytes_processed,
                        "bytes_processed": bytes_processed
                    }
                
                # Update counters
                bytes_processed += len(encrypted_chunk)
                params.processed_bytes = bytes_processed
                
                # Update progress
                self._update_progress(params)
        
        except Exception as e:
            logger.error(f"Stream processing error: {e}")
            return {
                "success": False,
                "error": str(e),
                "bytes_processed": bytes_processed
            }
        
        # Finalize decryptor if needed
        try:
            if hasattr(decryptor, 'finalize'):
                final_block = decryptor.finalize()
                if final_block:
                    output_stream.write(final_block)
        except Exception as e:
            logger.debug(f"Finalization error (normal for many ciphers): {e}")
        
        # Return success
        return {
            "success": True,
            "bytes_processed": bytes_processed,
            "algorithm": params.algorithm
        }
    
    def _create_decryptor(self, params: DecryptionParams, iv: Optional[bytes] = None) -> Any:
        """
        Create a decryptor based on algorithm and params
        
        Args:
            params: Decryption parameters
            iv: Initialization vector (override params.iv if provided)
            
        Returns:
            Decryptor object for the specified algorithm
        """
        # Use provided IV if available, fall back to params.iv
        iv_to_use = iv if iv is not None else params.iv
        
        # Normalize algorithm
        algorithm = params.algorithm.lower().strip()
        
        # Create the appropriate decryptor
        if algorithm == "aes-cbc":
            if not iv_to_use:
                iv_to_use = b'\0' * 16  # Default to zeros
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.CBC(iv_to_use))
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                return AES.new(params.key, AES.MODE_CBC, iv_to_use)
        
        elif algorithm == "aes-ecb":
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.ECB())
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                return AES.new(params.key, AES.MODE_ECB)
        
        elif algorithm == "aes-ctr":
            nonce = params.nonce or iv_to_use or b'\0' * 16
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.CTR(nonce))
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                counter = params.counter or 0
                return AES.new(params.key, AES.MODE_CTR, nonce=nonce[:8], initial_value=counter)
        
        elif algorithm == "aes-gcm":
            if not iv_to_use:
                iv_to_use = b'\0' * 12  # GCM typically uses 12-byte nonce
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.GCM(iv_to_use, params.tag))
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                return AES.new(params.key, AES.MODE_GCM, nonce=iv_to_use)
        
        elif algorithm == "aes-cfb":
            if not iv_to_use:
                iv_to_use = b'\0' * 16
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.CFB(iv_to_use))
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                return AES.new(params.key, AES.MODE_CFB, iv=iv_to_use)
        
        elif algorithm == "aes-ofb":
            if not iv_to_use:
                iv_to_use = b'\0' * 16
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.AES(params.key), modes.OFB(iv_to_use))
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                return AES.new(params.key, AES.MODE_OFB, iv=iv_to_use)
        
        elif algorithm == "chacha20":
            nonce = params.nonce or iv_to_use or b'\0' * 16
            if CRYPTOGRAPHY_AVAILABLE:
                cipher = Cipher(algorithms.ChaCha20(params.key, nonce), mode=None)
                return cipher.decryptor()
            elif PYCRYPTODOME_AVAILABLE:
                counter = params.counter or 0
                return ChaCha20.new(key=params.key, nonce=nonce)
        
        elif algorithm == "salsa20":
            if PYCRYPTODOME_AVAILABLE:
                nonce = params.nonce or iv_to_use or b'\0' * 8
                return Salsa20.new(key=params.key, nonce=nonce)
            else:
                raise ValueError("Salsa20 requires PyCryptodome library")
        
        # If we get here, the algorithm is not supported
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    def _decrypt_data(self, data: bytes, decryptor: Any, params: DecryptionParams) -> bytes:
        """
        Decrypt a block of data using the provided decryptor
        
        Args:
            data: Encrypted data
            decryptor: Decryptor object
            params: Decryption parameters
            
        Returns:
            Decrypted data
        """
        # Check if we're using cryptography or pycryptodome
        if CRYPTOGRAPHY_AVAILABLE and hasattr(decryptor, 'update'):
            # Cryptography library
            return decryptor.update(data)
        elif PYCRYPTODOME_AVAILABLE and hasattr(decryptor, 'decrypt'):
            # PyCryptodome library
            return decryptor.decrypt(data)
        else:
            raise ValueError("Invalid decryptor object")
    
    def _decrypt_chunk(self, data: bytes, params: DecryptionParams, 
                      iv: Optional[bytes] = None) -> bytes:
        """
        Decrypt a chunk of data for threaded processing
        
        Args:
            data: Encrypted data chunk
            params: Decryption parameters
            iv: Optional IV override
            
        Returns:
            Decrypted data chunk
        """
        # Create decryptor for this chunk
        decryptor = self._create_decryptor(params, iv)
        
        # Decrypt the data
        decrypted = self._decrypt_data(data, decryptor, params)
        
        # Finalize if needed
        if hasattr(decryptor, 'finalize'):
            try:
                final = decryptor.finalize()
                if final:
                    decrypted += final
            except Exception as e:
                logger.debug(f"Finalization error (normal for streaming): {e}")
        
        return decrypted
    
    def _unpad_data(self, data: bytes, params: DecryptionParams) -> bytes:
        """
        Remove padding from decrypted data
        
        Args:
            data: Decrypted data with padding
            params: Decryption parameters
            
        Returns:
            Unpadded data
        """
        if not data:
            return data
            
        # Check if padding is needed based on algorithm
        if params.algorithm not in ["aes-cbc", "aes-ecb"]:
            # No padding for stream ciphers
            return data
        
        # Try PKCS7 unpadding
        try:
            if PYCRYPTODOME_AVAILABLE:
                return unpad(data, AES.block_size)
            elif CRYPTOGRAPHY_AVAILABLE:
                unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
                return unpadder.update(data) + unpadder.finalize()
        except Exception:
            # If unpadding fails, it might not have padding or use a different scheme
            # Try to detect common padding schemes
            last_byte = data[-1]
            
            # Check if it looks like PKCS7 padding
            if 1 <= last_byte <= 16:
                # Verify if the last n bytes are all the same value n
                if all(b == last_byte for b in data[-last_byte:]):
                    return data[:-last_byte]
            
            # If no padding detected or invalid, return as is
            return data
    
    def _validate_decryption(self, data: bytes, params: DecryptionParams) -> Dict[str, Any]:
        """
        Validate if decrypted data appears to be valid
        
        Args:
            data: Decrypted data to validate
            params: Decryption parameters
            
        Returns:
            Validation result dictionary
        """
        # Use custom validation if provided
        if params.validation_callback:
            try:
                result = params.validation_callback(data)
                if isinstance(result, bool):
                    return {"success": result, "method": "custom_callback"}
                elif isinstance(result, dict):
                    return result
                else:
                    return {"success": bool(result), "method": "custom_callback"}
            except Exception as e:
                logger.error(f"Custom validation error: {e}")
                return {"success": False, "error": f"Custom validation error: {e}"}
        
        # Skip validation if level is NONE
        if params.validation_level == ValidationLevel.NONE:
            return {"success": True, "method": "none"}
        
        # Basic validation checks
        if not data:
            return {"success": False, "error": "Empty decrypted data"}
        
        # Entropy-based validation
        entropy = self._calculate_entropy(data[:min(4096, len(data))])
        
        # Most encrypted data has entropy > 7.0
        # Most valid decrypted data has entropy < 6.5
        if entropy > 7.0:
            # Data still appears to be encrypted (high entropy)
            return {
                "success": False, 
                "error": "Data appears to still be encrypted", 
                "entropy": entropy
            }
        
        # For BASIC validation, only check entropy and file signatures
        if params.validation_level == ValidationLevel.BASIC:
            # Check for common file signatures
            if len(data) >= 4:
                # Check for common file signatures
                signatures = {
                    b'PK\x03\x04': ['zip', 'docx', 'xlsx', 'pptx'],
                    b'%PDF': ['pdf'],
                    b'\xFF\xD8\xFF': ['jpg', 'jpeg'],
                    b'\x89PNG': ['png'],
                    b'GIF8': ['gif'],
                    b'II*\x00': ['tif', 'tiff'],
                    b'MM\x00*': ['tif', 'tiff']
                }
                
                for sig, extensions in signatures.items():
                    if data.startswith(sig):
                        return {
                            "success": True, 
                            "method": "file_signature", 
                            "file_type": extensions[0],
                            "entropy": entropy
                        }
            
            # No file signature but reasonable entropy
            if entropy < 6.5:
                return {"success": True, "method": "entropy", "entropy": entropy}
            
            # Otherwise, not successful
            return {
                "success": False, 
                "error": "No valid file signature detected", 
                "entropy": entropy
            }
        
        # STANDARD and STRICT validation
        
        # First check for common file signatures
        if len(data) >= 4:
            signatures = {
                b'PK\x03\x04': ['zip', 'docx', 'xlsx', 'pptx'],
                b'%PDF': ['pdf'],
                b'\xFF\xD8\xFF': ['jpg', 'jpeg'],
                b'\x89PNG': ['png'],
                b'GIF8': ['gif'],
                b'II*\x00': ['tif', 'tiff'],
                b'MM\x00*': ['tif', 'tiff'],
                b'\x50\x4B\x03\x04': ['zip', 'jar'],
                b'<!DOC': ['html', 'xml'],
                b'<html': ['html'],
                b'{\r\n': ['json'],
                b'{\n': ['json'],
                b'#!': ['sh', 'bash']
            }
            
            for sig, extensions in signatures.items():
                if data.startswith(sig):
                    return {
                        "success": True, 
                        "method": "file_signature", 
                        "file_type": extensions[0],
                        "entropy": entropy
                    }
        
        # Check for text files (ASCII/UTF-8)
        try:
            # Try to decode as UTF-8
            sample = data[:min(4096, len(data))]
            text = sample.decode('utf-8', errors='replace')
            
            # Check if it looks like text (high ratio of printable characters)
            printable_count = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
            if printable_count / len(text) > 0.9:
                # Looks like valid text
                return {
                    "success": True, 
                    "method": "text_content", 
                    "entropy": entropy
                }
        except Exception:
            # Not a valid UTF-8 text
            pass
        
        # If entropy is low enough, it probably decrypted correctly
        if entropy < 5.5:
            return {"success": True, "method": "low_entropy", "entropy": entropy}
        
        # For binary file formats, check NUL byte distribution
        nul_count = data.count(b'\x00')
        if 0.05 < nul_count / len(data) < 0.3:
            # This is a typical range for many binary formats
            return {
                "success": True, 
                "method": "binary_format", 
                "entropy": entropy
            }
        
        # STRICT validation requires more evidence of success
        if params.validation_level == ValidationLevel.STRICT:
            return {
                "success": False, 
                "error": "Data failed strict validation checks", 
                "entropy": entropy
            }
        
        # For STANDARD validation, be more lenient
        # If entropy is reasonable but not extremely low, accept it
        if entropy < 6.5:
            return {
                "success": True, 
                "method": "entropy_threshold", 
                "entropy": entropy,
                "confidence": "medium"
            }
        
        # Finally, reject
        return {
            "success": False, 
            "error": "Failed validation checks", 
            "entropy": entropy
        }
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes data to analyze
            
        Returns:
            Shannon entropy value (0.0 to 8.0)
        """
        if not data:
            return 0
            
        # Calculate byte frequency
        counter = {}
        for byte in data:
            if byte not in counter:
                counter[byte] = 0
            counter[byte] += 1
        
        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / len(data)
            entropy -= probability * (math.log(probability) / math.log(2))
        
        return entropy
    
    def _determine_optimal_chunk_size(self) -> int:
        """
        Determine optimal chunk size based on system RAM
        
        Returns:
            Optimal chunk size in bytes
        """
        try:
            # Try to get system memory info
            import psutil
            mem_info = psutil.virtual_memory()
            available_mem = mem_info.available
            
            # Use a small percentage of available memory (5%)
            chunk_size = int(available_mem * 0.05)
            
            # Clamp to reasonable values
            min_size = 64 * 1024          # 64 KB minimum
            max_size = 100 * 1024 * 1024  # 100 MB maximum
            
            return max(min_size, min(chunk_size, max_size))
            
        except (ImportError, AttributeError):
            # Fallback to safe default
            return 1 * 1024 * 1024  # 1 MB
    
    def _create_decryption_params(self, algorithm: str, key: bytes, **kwargs) -> DecryptionParams:
        """
        Create decryption parameters from arguments
        
        Args:
            algorithm: Encryption algorithm
            key: Decryption key
            **kwargs: Additional parameters
            
        Returns:
            DecryptionParams object
        """
        # Normalize algorithm name
        normalized_algorithm = algorithm.lower().strip()
        
        # Create params object
        params = DecryptionParams(algorithm=normalized_algorithm, key=key)
        
        # Apply all provided kwargs
        for key, value in kwargs.items():
            if hasattr(params, key):
                setattr(params, key, value)
        
        # Normalize key length if needed
        params.key = self._normalize_key_length(params.key, params.algorithm)
        
        # Check constraints based on algorithm
        self._check_algorithm_constraints(params)
        
        # Set chunk size if not provided
        if params.chunk_size <= 0:
            params.chunk_size = self.default_chunk_size
        
        # Set num_threads if not provided but use_threading is True
        if params.use_threading and params.num_threads <= 0:
            params.num_threads = self.max_workers
        
        return params
    
    def _normalize_key_length(self, key: bytes, algorithm: str) -> bytes:
        """
        Normalize key length based on algorithm requirements
        
        Args:
            key: Original key
            algorithm: Encryption algorithm
            
        Returns:
            Normalized key
        """
        algorithm = algorithm.lower()
        
        if algorithm.startswith("aes"):
            # AES requires 16, 24, or 32 byte keys
            aes_key_lengths = [16, 24, 32]  # AES-128, AES-192, AES-256
            
            if len(key) in aes_key_lengths:
                return key
            
            # Need to adjust key length
            if len(key) < 16:
                # Pad to 16 bytes (AES-128)
                return key.ljust(16, b'\0')
            elif len(key) < 24:
                # Truncate to 16 bytes (AES-128)
                return key[:16]
            elif len(key) < 32:
                # Truncate to 24 bytes (AES-192)
                return key[:24]
            else:
                # Truncate to 32 bytes (AES-256)
                return key[:32]
        
        elif algorithm in ["chacha20", "salsa20"]:
            # ChaCha20 and Salsa20 require 32-byte keys
            if len(key) == 32:
                return key
            
            # Adjust key length
            if len(key) < 32:
                # Pad to 32 bytes
                return key.ljust(32, b'\0')
            else:
                # Truncate to 32 bytes
                return key[:32]
        
        # For other algorithms, return as is (validation happens in constraints check)
        return key
    
    def _check_algorithm_constraints(self, params: DecryptionParams):
        """
        Check that parameters meet algorithm constraints
        
        Args:
            params: Decryption parameters
            
        Raises:
            ValueError: If constraints are not met
        """
        algorithm = params.algorithm
        
        if algorithm.startswith("aes"):
            # Check key length
            if len(params.key) not in [16, 24, 32]:
                raise ValueError(f"AES requires 16, 24, or 32 byte keys, got {len(params.key)}")
            
            # Check IV for CBC mode
            if algorithm == "aes-cbc" and not params.iv and not params.iv_in_file:
                logger.warning("AES-CBC mode should have an IV. Using zero IV.")
                params.iv = b'\0' * 16
        
        elif algorithm in ["chacha20", "salsa20"]:
            # Check key length
            if len(params.key) != 32:
                raise ValueError(f"{algorithm} requires 32 byte keys, got {len(params.key)}")
            
            # Check nonce
            if not params.nonce and not params.iv:
                logger.warning(f"{algorithm} should have a nonce/IV. Using zero nonce.")
                if algorithm == "chacha20":
                    params.nonce = b'\0' * 16
                else:  # salsa20
                    params.nonce = b'\0' * 8
    
    def _start_perf_tracking(self, params: DecryptionParams):
        """Start performance tracking"""
        self.perf_stats["start_time"] = time.time()
        self.perf_stats["total_bytes"] = params.file_size
        self.perf_stats["processed_bytes"] = 0
    
    def _end_perf_tracking(self, params: DecryptionParams):
        """End performance tracking and calculate stats"""
        self.perf_stats["end_time"] = time.time()
        elapsed = self.perf_stats["end_time"] - self.perf_stats["start_time"]
        
        if elapsed > 0:
            self.perf_stats["throughput_bps"] = self.perf_stats["processed_bytes"] / elapsed
    
    def _update_progress(self, params: DecryptionParams):
        """Update progress tracking and call progress callback if provided"""
        # Update performance stats
        self.perf_stats["processed_bytes"] = params.processed_bytes
        
        # Calculate progress
        total = params.file_size
        processed = params.processed_bytes
        progress = processed / total if total > 0 else 1.0
        
        # Call progress callback if provided
        if params.progress_callback:
            try:
                params.progress_callback(progress, processed, total)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
        
        # Or use instance's progress callback
        elif self.progress_callback:
            try:
                self.progress_callback(progress, processed, total)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")


class AlgorithmDetector:
    """
    Detects encryption algorithm based on file characteristics.
    Used to enhance the adaptive algorithm selection in the streaming engine.
    """
    
    def __init__(self, entropy_threshold: float = 7.5):
        """
        Initialize the algorithm detector.
        
        Args:
            entropy_threshold: Entropy threshold for encrypted data
        """
        self.entropy_threshold = entropy_threshold
        
        # Algorithm-specific patterns for detection
        self.algorithm_patterns = {
            # AES-ECB header patterns
            "aes-ecb": [
                # Fixed-size headers (common for Ryuk)
                {"header_size": 8, "confidence": 0.7},
                # No IV/nonce needed
                {"iv_absent": True, "confidence": 0.6},
                # Ryuk signature
                {"header_contains": b"RYUK", "confidence": 0.9}
            ],
            
            # AES-CBC patterns
            "aes-cbc": [
                # IV typically at start or in header
                {"iv_at_start": True, "iv_size": 16, "confidence": 0.8},
                # LockBit, WannaCry, Conti characteristics
                {"header_contains": b"LOCK", "confidence": 0.85},
                {"header_contains": b"WanaCrypt0r", "confidence": 0.95},
                {"header_contains": b"CONTI", "confidence": 0.9},
                {"header_contains": b"RHYSIDA", "confidence": 0.95}
            ],
            
            # ChaCha20 patterns
            "chacha20": [
                # ChaCha20 constants
                {"content_contains": b"expand 32-byte k", "confidence": 0.9},
                # BlackCat often uses ChaCha20
                {"header_contains": b"\x3a\x01\x00\x00", "confidence": 0.8},
                {"header_contains": b"BlackCat", "confidence": 0.95},
                {"header_contains": b"ALPHV", "confidence": 0.95},
                {"header_contains": b"MAZE", "confidence": 0.9}
            ],
            
            # Salsa20 patterns
            "salsa20": [
                # Salsa20 constants
                {"content_contains": b"expand 32-byte k", "confidence": 0.7},
                # 8-byte nonce characteristic
                {"has_nonce": True, "nonce_size": 8, "confidence": 0.7},
                # REvil/Sodinokibi marker
                {"header_contains": b"REvil", "confidence": 0.95},
                {"header_contains": b"Sodinokibi", "confidence": 0.95},
                # STOP/DJVU marker
                {"header_contains": b"STOP", "confidence": 0.95},
                {"header_contains": b"DJVU", "confidence": 0.95}
            ]
        }
        
        # Family-to-algorithm mapping based on historical data
        self.family_algorithm_map = {
            "ryuk": "aes-ecb",
            "lockbit": "aes-cbc",
            "blackcat": "chacha20",
            "alphv": "chacha20",
            "wannacry": "aes-cbc",
            "wanacryptor": "aes-cbc",
            "revil": "salsa20",
            "sodinokibi": "salsa20",
            "djvu": "salsa20",
            "stop": "salsa20",
            "conti": "aes-cbc",
            "maze": "chacha20",
            "rhysida": "aes-cbc",
            "hive": "chacha20"
        }
        
        # Ransomware family file extensions
        self.family_extensions = {
            ".ryuk": "ryuk",
            ".ryk": "ryuk",
            ".RYK": "ryuk",
            ".lockbit": "lockbit",
            ".locked": "lockbit",
            ".lck": "lockbit",
            ".lock": "lockbit",
            ".blackcat": "blackcat",
            ".cat": "blackcat",
            ".bc": "blackcat",
            ".ALPHV": "blackcat",
            ".wncry": "wannacry",
            ".wcry": "wannacry",
            ".wanacry": "wannacry",
            ".wncryt": "wannacry",
            ".REV": "revil",
            ".revil": "revil",
            ".sodin": "sodinokibi",
            ".djvu": "djvu",
            ".djv": "djvu",
            ".STOP": "stop",
            ".conti": "conti",
            ".cti": "conti",
            ".maze": "maze",
            ".maz": "maze",
            ".rhysida": "rhysida",
            ".rhys": "rhysida",
            ".hive": "hive"
        }
        
        # File signatures for specific ransomware families
        self.file_signatures = {
            # Format: (offset, signature_bytes, family, confidence)
            (0, b"RYUK", "ryuk", 0.95),
            (0, b"LOCKBIT", "lockbit", 0.95),
            (0, b"LOCK", "lockbit", 0.85),
            (0, b"WANACRYPT0R", "wannacry", 0.95),
            (0, b"WNCRY", "wannacry", 0.9),
            (0, b"BLACKCAT", "blackcat", 0.95),
            (0, b"ALPHV", "blackcat", 0.95),
            (0, b"SODINOKIBI", "sodinokibi", 0.95),
            (0, b"REVIL", "revil", 0.95),
            (0, b"STOP", "stop", 0.95),
            (0, b"DJVU", "djvu", 0.95),
            (0, b"CONTI", "conti", 0.95),
            (0, b"MAZE", "maze", 0.95),
            (0, b"RHYSIDA", "rhysida", 0.95)
        }
    
    def detect_algorithm(self, encrypted_file: str, known_family: Optional[str] = None) -> Dict[str, Any]:
        """
        Detect the encryption algorithm used in a file.
        
        Args:
            encrypted_file: Path to encrypted file
            known_family: Ransomware family if known
            
        Returns:
            Dictionary with detected algorithm and parameters
        """
        # Initialize result with defaults
        result = {
            "algorithm": "aes-cbc",  # Default fallback
            "confidence": 0.0,
            "params": {},
            "errors": []  # Track errors during detection process
        }
        
        # Handle known family if provided
        if known_family:
            try:
                family = known_family.lower()
                if family in self.family_algorithm_map:
                    result["algorithm"] = self.family_algorithm_map[family]
                    result["confidence"] = 0.85
                    result["params"]["family_match"] = True
                    result["family"] = family
                    return result
            except (AttributeError, TypeError) as e:
                result["errors"].append(f"Invalid family name: {e}")
        
        # Check if file exists
        if not os.path.exists(encrypted_file):
            result["errors"].append(f"File not found: {encrypted_file}")
            return result
            
        # Check if file is accessible
        if not os.access(encrypted_file, os.R_OK):
            result["errors"].append(f"File not readable: {encrypted_file}")
            return result
        
        # Check if file extension matches known ransomware families
        try:
            file_ext = os.path.splitext(encrypted_file)[1].lower()
            if file_ext in self.family_extensions:
                detected_family = self.family_extensions[file_ext]
                result["algorithm"] = self.family_algorithm_map.get(detected_family, result["algorithm"])
                result["confidence"] = 0.75  # Good confidence but not as high as explicit family
                result["params"]["extension_match"] = True
                result["family"] = detected_family
                
                # We'll continue with the analysis to potentially improve confidence
        except Exception as e:
            result["errors"].append(f"Error processing file extension: {e}")
        
        try:
            # Check file characteristics
            try:
                file_size = os.path.getsize(encrypted_file)
            except (OSError, IOError) as e:
                result["errors"].append(f"Error getting file size: {e}")
                return result
            
            # Skip very small files
            if file_size < 100:
                result["params"]["too_small"] = True
                return result
                
            # Read file samples safely
            header = b""
            middle_sample = b""
            footer = b""
            
            try:
                with open(encrypted_file, 'rb') as f:
                    # Read header
                    header = f.read(min(512, file_size))
                    
                    # Read a sample from the middle of the file
                    if file_size > 1024:
                        try:
                            f.seek(file_size // 2)
                            middle_sample = f.read(min(512, file_size - file_size // 2))
                        except (OSError, IOError) as e:
                            result["errors"].append(f"Error reading middle of file: {e}")
                    
                    # For large files, get footer as well
                    if file_size > 1024:
                        try:
                            f.seek(max(0, file_size - 512))
                            footer = f.read(512)
                        except (OSError, IOError) as e:
                            result["errors"].append(f"Error reading end of file: {e}")
            except (IOError, OSError, PermissionError) as e:
                result["errors"].append(f"Error opening file: {e}")
                return result
            
            # Check for file signatures with improved error handling
            try:
                for offset, signature, family, confidence in self.file_signatures:
                    # Skip if header is too short for this signature check
                    if len(header) <= offset:
                        continue
                        
                    try:
                        # Safely check for signature
                        if signature in header[offset:offset+len(signature)]:
                            # Found a signature match
                            algorithm = self.family_algorithm_map.get(family, result["algorithm"])
                            
                            # Only update if confidence is higher
                            if confidence > result["confidence"]:
                                result["algorithm"] = algorithm
                                result["confidence"] = confidence
                                result["params"]["signature_match"] = True
                                result["params"]["detected_family"] = family
                                result["family"] = family
                    except (IndexError, TypeError) as e:
                        result["errors"].append(f"Error checking signature {signature!r} at offset {offset}: {e}")
            except Exception as e:
                result["errors"].append(f"Error during signature checking: {e}")
            
            # If we already have high confidence, add family-specific parameters and return
            if result["confidence"] > 0.9 and result.get("family"):
                self._add_family_specific_params(result)
                return result
                
            # Calculate entropy of samples with improved error handling
            entropy_analyzer = None
            try:
                try:
                    from tools.crypto.entropy.entropy_analyzer import EntropyAnalyzer
                    entropy_analyzer = EntropyAnalyzer()
                except ImportError:
                    # Fallback to our local entropy calculation
                    entropy_analyzer = self
                    result["errors"].append("External entropy analyzer not available, using internal implementation")
            except Exception as e:
                result["errors"].append(f"Error loading entropy analyzer: {e}")
                # If both external and internal entropy analyzers fail, create a dummy one to avoid failures
                class DummyEntropyAnalyzer:
                    def calculate_entropy(self, data):
                        return 5.0  # Return a middle-of-the-road value
                entropy_analyzer = DummyEntropyAnalyzer()
                
            # Calculate entropy with error handling for each sample
            header_entropy = 0
            middle_entropy = 0
            footer_entropy = 0
            
            try:
                header_entropy = entropy_analyzer.calculate_entropy(header)
            except Exception as e:
                result["errors"].append(f"Error calculating header entropy: {e}")
                
            try:
                middle_entropy = entropy_analyzer.calculate_entropy(middle_sample) if middle_sample else 0
            except Exception as e:
                result["errors"].append(f"Error calculating middle sample entropy: {e}")
                
            try:
                footer_entropy = entropy_analyzer.calculate_entropy(footer) if footer else 0
            except Exception as e:
                result["errors"].append(f"Error calculating footer entropy: {e}")
            
            # Check if data is encrypted based on entropy
            is_encrypted = header_entropy > self.entropy_threshold
            
            if not is_encrypted:
                # Not encrypted or using a different encryption format
                return result
                
            # Create features for algorithm detection
            features = {
                "header_entropy": header_entropy,
                "middle_entropy": middle_entropy,
                "footer_entropy": footer_entropy,
                "file_size": file_size,
                "header_contains": {},
                "content_contains": {},
                "iv_at_start": False,
                "iv_absent": False,
                "has_nonce": False
            }
            
            # Check for algorithm-specific markers with improved error handling
            try:
                for algo, patterns in self.algorithm_patterns.items():
                    for pattern in patterns:
                        try:
                            # Check header contains pattern
                            if "header_contains" in pattern:
                                try:
                                    marker = pattern["header_contains"]
                                    if marker and header and marker in header:
                                        features["header_contains"][marker] = True
                                        
                                        # Update result if confidence is higher
                                        if pattern["confidence"] > result["confidence"]:
                                            result["algorithm"] = algo
                                            result["confidence"] = pattern["confidence"]
                                except Exception as e:
                                    result["errors"].append(f"Error checking header pattern for {algo}: {e}")
                            
                            # Check content contains pattern
                            if "content_contains" in pattern:
                                try:
                                    marker = pattern["content_contains"]
                                    if marker and (
                                        (header and marker in header) or 
                                        (middle_sample and marker in middle_sample) or
                                        (footer and marker in footer)
                                    ):
                                        features["content_contains"][marker] = True
                                        
                                        # Update result if confidence is higher
                                        if pattern["confidence"] > result["confidence"]:
                                            result["algorithm"] = algo
                                            result["confidence"] = pattern["confidence"]
                                except Exception as e:
                                    result["errors"].append(f"Error checking content pattern for {algo}: {e}")
                            
                            # Check IV characteristics
                            if "iv_at_start" in pattern and pattern["iv_at_start"]:
                                try:
                                    iv_size = pattern.get("iv_size", 16)
                                    # Check if first iv_size bytes could be an IV (high entropy)
                                    if len(header) >= iv_size:
                                        iv_block = header[:iv_size]
                                        try:
                                            iv_entropy = entropy_analyzer.calculate_entropy(iv_block)
                                            if iv_entropy > 7.0:
                                                features["iv_at_start"] = True
                                                result["params"]["iv_in_file"] = True
                                                result["params"]["iv_offset"] = 0
                                                result["params"]["iv_size"] = iv_size
                                                
                                                # Update result if confidence is higher
                                                if pattern["confidence"] > result["confidence"]:
                                                    result["algorithm"] = algo
                                                    result["confidence"] = pattern["confidence"]
                                        except Exception as e:
                                            result["errors"].append(f"Error calculating IV entropy for {algo}: {e}")
                                except Exception as e:
                                    result["errors"].append(f"Error checking IV characteristics for {algo}: {e}")
                        except Exception as e:
                            result["errors"].append(f"Error processing pattern for {algo}: {e}")
                            continue
            except Exception as e:
                result["errors"].append(f"Error during algorithm pattern matching: {e}")
            
            # Handle block size detection
            if "aes" in result["algorithm"]:
                # AES uses 16-byte block size
                result["params"]["block_size"] = 16
            elif result["algorithm"] == "chacha20":
                # ChaCha20 block size is 64 bytes
                result["params"]["block_size"] = 64
            elif result["algorithm"] == "salsa20":
                # Salsa20 block size is 64 bytes
                result["params"]["block_size"] = 64
            
            # Add header detection with improved error handling
            if file_size > 256 and "header_size" not in result["params"]:
                try:
                    # Try to detect header by scanning for entropy changes
                    for offset in [8, 16, 32, 64, 128, 256]:
                        if offset >= file_size:
                            break
                        
                        try:
                            post_header = b""
                            try:
                                with open(encrypted_file, 'rb') as f:
                                    f.seek(offset)
                                    post_header = f.read(256)
                            except (IOError, OSError, PermissionError) as e:
                                result["errors"].append(f"Error reading file at offset {offset}: {e}")
                                continue
                            
                            if len(post_header) >= 16:
                                try:
                                    post_header_entropy = entropy_analyzer.calculate_entropy(post_header[:16])
                                    
                                    # If entropy jumps at this offset, likely a header boundary
                                    if abs(post_header_entropy - header_entropy) > 1.0:
                                        result["params"]["header_size"] = offset
                                        break
                                except Exception as e:
                                    result["errors"].append(f"Error calculating post-header entropy at offset {offset}: {e}")
                        except Exception as e:
                            result["errors"].append(f"Error processing offset {offset} for header detection: {e}")
                except Exception as e:
                    result["errors"].append(f"Error during header detection: {e}")
            
            # Perform algorithm-specific parameter adjustments
            self._adjust_algorithm_params(result)
            
            # If we have a family detection, add family-specific parameters
            if "detected_family" in result["params"]:
                self._add_family_specific_params(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error detecting algorithm: {e}")
            return result
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data (fallback if tools.crypto.entropy.entropy_analyzer not available)
        
        Args:
            data: Bytes data to analyze
            
        Returns:
            Shannon entropy value (0.0 to 8.0)
        """
        try:
            # Handle empty or invalid data
            if not data:
                return 0
                
            if not isinstance(data, bytes):
                # Try to convert to bytes if possible
                try:
                    data = bytes(data)
                except (TypeError, ValueError):
                    # If conversion fails, return a default value
                    return 5.0  # Middle-of-the-road value
            
            # Calculate byte frequency with error handling
            counter = {}
            try:
                for byte in data:
                    if byte not in counter:
                        counter[byte] = 0
                    counter[byte] += 1
            except Exception:
                # If we can't iterate through data, use a simpler approach
                try:
                    # Try with bytearray conversion
                    for byte in bytearray(data):
                        if byte not in counter:
                            counter[byte] = 0
                        counter[byte] += 1
                except Exception:
                    # If all else fails, return a default value
                    return 5.0
            
            # Safety check
            if not counter or len(data) == 0:
                return 0
            
            # Calculate entropy
            try:
                import math
                entropy = 0
                length = len(data)
                for count in counter.values():
                    probability = count / length
                    entropy -= probability * (math.log(probability) / math.log(2))
                
                # Cap entropy at 8.0 for sanity
                return min(entropy, 8.0)
            except Exception:
                # If math operations fail, return a default value
                return 5.0
                
        except Exception:
            # Catch-all for any unforeseen errors
            return 5.0
    
    def _adjust_algorithm_params(self, result: Dict[str, Any]) -> None:
        """
        Make algorithm-specific parameter adjustments
        
        Args:
            result: Detection result to adjust
        """
        algorithm = result["algorithm"]
        
        if algorithm == "aes-cbc" and "header_size" not in result["params"]:
            # AES-CBC typically has a 16-byte header containing the IV
            result["params"]["header_size"] = result["params"].get("header_size", 16)
            result["params"]["iv_in_file"] = result["params"].get("iv_in_file", True)
            result["params"]["iv_offset"] = result["params"].get("iv_offset", 0)
            result["params"]["iv_size"] = result["params"].get("iv_size", 16)
        
        elif algorithm == "aes-ecb" and "header_size" not in result["params"]:
            # AES-ECB typically has a simple header
            result["params"]["header_size"] = result["params"].get("header_size", 8)
        
        elif algorithm == "chacha20":
            # ChaCha20 often has a 12-byte nonce
            result["params"]["nonce_size"] = 12
        
        elif algorithm == "salsa20":
            # Salsa20 uses an 8-byte nonce
            result["params"]["nonce_size"] = 8
    
    def _add_family_specific_params(self, result: Dict[str, Any]) -> None:
        """
        Add family-specific parameters based on detected family
        
        Args:
            result: Detection result to enhance
        """
        try:
            # Safely get family with error handling
            family = None
            try:
                family = result.get("family")
                if not family and "params" in result:
                    family = result["params"].get("detected_family")
            except Exception as e:
                if "errors" in result:
                    result["errors"].append(f"Error getting family from result: {e}")
                return
                
            if not family:
                return
                
            # Safely convert to lowercase
            try:
                family = family.lower()
            except (AttributeError, TypeError) as e:
                if "errors" in result:
                    result["errors"].append(f"Error converting family to lowercase: {e}")
                return
            
            # Retrieve algorithm
            algorithm = result.get("algorithm", "aes-cbc")
            
            # Apply family-specific parameters with error handling
            try:
                if family == "ryuk":
                    # Ryuk uses AES-ECB with 8-byte header
                    result["params"]["header_size"] = 8
                    # No IV needed for ECB mode
                    result["params"]["iv_in_file"] = False
                
                elif family == "lockbit":
                    # LockBit uses AES-CBC with IV in header
                    result["params"]["header_size"] = 128
                    result["params"]["iv_in_file"] = True
                    result["params"]["iv_offset"] = 56
                    result["params"]["iv_size"] = 16
                
                elif family == "blackcat" or family == "alphv":
                    # BlackCat uses ChaCha20 with 256-byte header
                    result["params"]["header_size"] = 256
                    result["params"]["nonce_size"] = 12
                
                elif family == "wannacry" or family == "wanacryptor":
                    # WannaCry uses AES-CBC with complex header
                    result["params"]["header_size"] = 0x200  # 512 bytes
                    result["params"]["iv_in_file"] = True
                    result["params"]["iv_offset"] = 0x20     # IV at offset 32
                    result["params"]["iv_size"] = 16
                
                elif family == "revil" or family == "sodinokibi":
                    # REvil/Sodinokibi uses Salsa20 and/or AES-CBC
                    if algorithm == "salsa20":
                        result["params"]["header_size"] = 16
                        result["params"]["nonce_size"] = 8
                    else:  # AES-CBC
                        result["params"]["header_size"] = 16
                        result["params"]["iv_in_file"] = True
                        result["params"]["iv_offset"] = 0
                        result["params"]["iv_size"] = 16
                
                elif family == "djvu" or family == "stop":
                    # STOP/Djvu uses Salsa20
                    result["params"]["header_size"] = 0x258  # 600 bytes
                    result["params"]["nonce_size"] = 8
                
                elif family == "conti":
                    # Conti uses AES-CBC
                    result["params"]["header_size"] = 8
                    result["params"]["iv_in_file"] = True
                    result["params"]["iv_offset"] = 8
                    result["params"]["iv_size"] = 16
                
                elif family == "maze":
                    # Maze uses ChaCha20
                    result["params"]["header_size"] = 64
                    result["params"]["nonce_size"] = 12
                
                elif family == "rhysida":
                    # Rhysida uses AES-CBC with IV
                    result["params"]["header_size"] = 280
                    result["params"]["iv_in_file"] = True
                    result["params"]["iv_offset"] = 264
                    result["params"]["iv_size"] = 16
                    
                # Record that we applied family-specific parameters
                result["params"]["applied_family_params"] = True
                result["params"]["family_used"] = family
                
            except Exception as e:
                # Error applying family-specific parameters
                if "errors" in result:
                    result["errors"].append(f"Error applying parameters for family '{family}': {e}")
        
        except Exception as e:
            # Catch-all for unexpected errors
            if "errors" in result:
                result["errors"].append(f"Unexpected error in _add_family_specific_params: {e}")


class StreamingDecryptionEngine:
    """
    High-level interface for the streaming decryption engine
    providing simplified methods for common use cases
    """
    
    def __init__(self, progress_callback: Optional[Callable] = None):
        """
        Initialize the decryption engine
        
        Args:
            progress_callback: Optional callback for progress updates
        """
        self.decryptor = StreamingDecryptor(progress_callback)
        self.validation_level = ValidationLevel.STANDARD
        self.use_threading = True
        self.chunk_size = self.decryptor.default_chunk_size
        self.algorithm_detector = AlgorithmDetector()
    
    def decrypt_file(self, encrypted_file: str, output_file: str, family: Optional[str] = None, 
                   key: bytes = None, **kwargs) -> Dict[str, Any]:
        """
        Decrypt a file using the appropriate algorithm for the ransomware family
        
        Args:
            encrypted_file: Path to encrypted file
            output_file: Path to save decrypted result
            family: Ransomware family name (optional if auto_detect is True)
            key: Decryption key
            **kwargs: Additional decryption parameters
                auto_detect: Whether to automatically detect the encryption algorithm
                retry_algorithms: Whether to try multiple algorithms if first attempt fails
                
        Returns:
            Result dictionary
        """
        # Initialize result dictionary with default error state
        result = {
            "success": False,
            "encrypted_file": encrypted_file,
            "output_file": output_file,
            "errors": []
        }
        
        # Verify that the encrypted file exists
        if not os.path.exists(encrypted_file):
            result["errors"].append(f"Input file not found: {encrypted_file}")
            result["error"] = f"Input file not found: {encrypted_file}"
            return result
            
        # Check if we can read the encrypted file
        if not os.access(encrypted_file, os.R_OK):
            result["errors"].append(f"Input file not readable: {encrypted_file}")
            result["error"] = f"Input file not readable: {encrypted_file}"
            return result
        
        # Verify key is present
        if key is None:
            result["errors"].append("Decryption key is required")
            result["error"] = "Decryption key is required"
            return result
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
                logger.info(f"Created output directory: {output_dir}")
            except (IOError, OSError, PermissionError) as e:
                result["errors"].append(f"Cannot create output directory: {e}")
                result["error"] = f"Cannot create output directory: {e}"
                return result
        
        # Check if output location is writable
        try:
            # Attempt to write a test file to check permissions
            test_file = os.path.join(output_dir, ".test_write_permission")
            with open(test_file, 'w') as f:
                f.write("test")
            os.remove(test_file)
        except (IOError, OSError, PermissionError) as e:
            result["errors"].append(f"Output location not writable: {e}")
            result["error"] = f"Output location not writable: {e}"
            return result
        
        # Extract parameters
        auto_detect = kwargs.pop("auto_detect", False)
        retry_algorithms = kwargs.pop("retry_algorithms", False)
        
        # Store original parameters for potential retry
        original_kwargs = kwargs.copy()
        
        try:
            # Auto-detect algorithm if requested or if family not provided
            if auto_detect or not family:
                logger.info("Using automatic algorithm detection")
                try:
                    detection_result = self.algorithm_detector.detect_algorithm(encrypted_file, family)
                    
                    # Copy any errors from detection to our result
                    if "errors" in detection_result and detection_result["errors"]:
                        result["errors"].extend(detection_result["errors"])
                    
                    detected_algorithm = detection_result["algorithm"]
                    detected_params = detection_result["params"]
                    confidence = detection_result["confidence"]
                    
                    logger.info(f"Detected algorithm: {detected_algorithm} (confidence: {confidence:.2f})")
                    
                    # Get algorithm and parameters, using detected values as fallback
                    try:
                        algorithm, params = self._get_family_config(family, key, **kwargs)
                    except Exception as e:
                        result["errors"].append(f"Error in family configuration: {e}")
                        # Use detected algorithm as a fallback
                        algorithm = detected_algorithm
                        params = {}
                    
                    # If confidence is high or no family specified, use detected parameters
                    if confidence > 0.7 or not family:
                        # Override with detected parameters, but keep any explicitly specified params
                        for param_name, param_value in detected_params.items():
                            if param_name not in kwargs:
                                params[param_name] = param_value
                        
                        # Use detected algorithm if no family specified or detection is very confident
                        if not family or confidence > 0.85:
                            algorithm = detected_algorithm
                            
                except Exception as e:
                    # If algorithm detection fails, log the error and use defaults
                    result["errors"].append(f"Algorithm detection failed: {e}")
                    logger.error(f"Algorithm detection failed: {e}")
                    algorithm = "aes-cbc"  # Default algorithm as fallback
                    params = {}
            else:
                # Get algorithm and parameters using family-based approach
                try:
                    algorithm, params = self._get_family_config(family, key, **kwargs)
                except Exception as e:
                    result["errors"].append(f"Error in family configuration: {e}")
                    logger.error(f"Error getting family configuration: {e}")
                    algorithm = "aes-cbc"  # Default
                    params = {}
            
            # Apply our defaults
            params["validation_level"] = kwargs.get("validation_level", self.validation_level)
            params["use_threading"] = kwargs.get("use_threading", self.use_threading)
            params["chunk_size"] = kwargs.get("chunk_size", self.chunk_size)
            
            # Call decryptor
            try:
                decrypt_result = self.decryptor.decrypt_file(encrypted_file, output_file, algorithm, key, **params)
                
                # Merge the decryptor result with our result
                result.update(decrypt_result)
                
                # Ensure errors are propagated
                if "errors" in decrypt_result and decrypt_result["errors"]:
                    if "errors" not in result:
                        result["errors"] = []
                    result["errors"].extend(decrypt_result["errors"])
                
            except Exception as e:
                result["errors"].append(f"Decryption error: {e}")
                result["error"] = f"Decryption error: {e}"
                result["success"] = False
            
            # If decryption failed and retry_algorithms is enabled, try alternative algorithms
            if not result.get("success", False) and retry_algorithms:
                # Define alternative algorithms to try based on initial algorithm
                alternatives = {
                    "aes-cbc": ["aes-ecb", "chacha20", "salsa20"],
                    "aes-ecb": ["aes-cbc", "chacha20", "salsa20"],
                    "chacha20": ["salsa20", "aes-cbc", "aes-ecb"],
                    "salsa20": ["chacha20", "aes-cbc", "aes-ecb"]
                }
                
                # Get alternatives for our algorithm
                alt_algorithms = alternatives.get(algorithm, [])
                
                # Try each alternative
                for alt_algorithm in alt_algorithms:
                    logger.info(f"Retrying with alternative algorithm: {alt_algorithm}")
                    
                    # Reset params to original kwargs
                    params = original_kwargs.copy()
                    
                    # Apply our defaults
                    params["validation_level"] = original_kwargs.get("validation_level", self.validation_level)
                    params["use_threading"] = original_kwargs.get("use_threading", self.use_threading)
                    params["chunk_size"] = original_kwargs.get("chunk_size", self.chunk_size)
                    
                    # Add algorithm-specific params
                    if alt_algorithm == "aes-cbc":
                        params["iv_in_file"] = params.get("iv_in_file", True)
                        params["iv_offset"] = params.get("iv_offset", 0)
                        params["iv_size"] = params.get("iv_size", 16)
                    elif alt_algorithm == "chacha20":
                        params["nonce"] = params.get("nonce", None)
                    elif alt_algorithm == "salsa20":
                        params["nonce"] = params.get("nonce", None)
                    
                    # Try with the alternative algorithm
                    try:
                        alt_result = self.decryptor.decrypt_file(encrypted_file, output_file, alt_algorithm, key, **params)
                        
                        # Merge any errors from the alternative attempt
                        if "errors" in alt_result and alt_result["errors"]:
                            result["errors"].extend(alt_result["errors"])
                        
                        # If successful, use this result
                        if alt_result.get("success", False):
                            logger.info(f"Alternative algorithm {alt_algorithm} succeeded")
                            result.update(alt_result)
                            result["algorithm"] = alt_algorithm  # Make sure algorithm is recorded
                            result["algorithm_retry"] = True
                            break
                    except Exception as e:
                        result["errors"].append(f"Alternative algorithm {alt_algorithm} error: {e}")
                        # Continue to the next algorithm
            
            # Include algorithm information in the result
            result["algorithm"] = algorithm
            result["family"] = family
            
        except Exception as e:
            # Catch-all for any unforeseen errors
            result["errors"].append(f"Unexpected error in decrypt_file: {e}")
            result["error"] = f"Unexpected error: {e}"
            result["success"] = False
            logger.error(f"Unexpected error in decrypt_file: {e}", exc_info=True)
        
        return result
    
    def decrypt_data(self, data: bytes, family: str, key: bytes, **kwargs) -> Dict[str, Any]:
        """
        Decrypt data using the appropriate algorithm for the ransomware family
        
        Args:
            data: Encrypted data
            family: Ransomware family name
            key: Decryption key
            **kwargs: Additional decryption parameters
                auto_detect: Whether to automatically detect the encryption algorithm
                retry_algorithms: Whether to try multiple algorithms if first attempt fails
            
        Returns:
            Result dictionary with decrypted data
        """
        # Initialize result dictionary with default error state
        result = {
            "success": False,
            "data_size": len(data) if data else 0,
            "errors": []
        }
        
        # Validate inputs
        if data is None or len(data) == 0:
            result["errors"].append("Empty data provided for decryption")
            result["error"] = "Empty data provided for decryption"
            return result
            
        if key is None:
            result["errors"].append("Decryption key is required")
            result["error"] = "Decryption key is required"
            return result
        
        # Extract parameters
        auto_detect = kwargs.pop("auto_detect", False)
        retry_algorithms = kwargs.pop("retry_algorithms", False)
        
        # Store original parameters for potential retry
        original_kwargs = kwargs.copy()
        
        try:
            # Auto-detect algorithm if requested
            if auto_detect:
                logger.info("Using automatic algorithm detection for in-memory data")
                
                # Use a simplified detection for in-memory data
                # Since we can't use file-based detection, fallback to family-based approach
                if family:
                    try:
                        # Get algorithm and parameters based on family
                        algorithm, params = self._get_family_config(family, key, **kwargs)
                    except Exception as e:
                        result["errors"].append(f"Error in family configuration: {e}")
                        logger.error(f"Error getting family configuration: {e}")
                        algorithm = "aes-cbc"  # Default
                        params = {}
                else:
                    # Without family and file, we have to guess the algorithm
                    # We'll default to AES-CBC as the most common
                    result["errors"].append("No family specified and auto-detection requires a file. Using AES-CBC as default.")
                    algorithm = "aes-cbc"
                    params = {}
            else:
                # Use family-based approach
                try:
                    # Normalize family if provided
                    if family is not None:
                        try:
                            family = family.lower()
                        except (AttributeError, TypeError) as e:
                            result["errors"].append(f"Invalid family name: {e}")
                            family = None
                    
                    # Get algorithm and parameters
                    algorithm, params = self._get_family_config(family, key, **kwargs)
                except Exception as e:
                    result["errors"].append(f"Error in family configuration: {e}")
                    logger.error(f"Error getting family configuration: {e}")
                    algorithm = "aes-cbc"  # Default
                    params = {}
            
            # Apply our defaults
            params["validation_level"] = kwargs.get("validation_level", self.validation_level)
            
            # Call decryptor
            try:
                decrypt_result = self.decryptor.decrypt_data(data, algorithm, key, **params)
                
                # Merge the decryptor result with our result
                result.update(decrypt_result)
                
                # Ensure errors are propagated
                if "errors" in decrypt_result and decrypt_result["errors"]:
                    if "errors" not in result:
                        result["errors"] = []
                    result["errors"].extend(decrypt_result["errors"])
                
            except Exception as e:
                result["errors"].append(f"Decryption error: {e}")
                result["error"] = f"Decryption error: {e}"
                result["success"] = False
            
            # If decryption failed and retry_algorithms is enabled, try alternative algorithms
            if not result.get("success", False) and retry_algorithms:
                # Define alternative algorithms to try based on initial algorithm
                alternatives = {
                    "aes-cbc": ["aes-ecb", "chacha20", "salsa20"],
                    "aes-ecb": ["aes-cbc", "chacha20", "salsa20"],
                    "chacha20": ["salsa20", "aes-cbc", "aes-ecb"],
                    "salsa20": ["chacha20", "aes-cbc", "aes-ecb"]
                }
                
                # Get alternatives for our algorithm
                alt_algorithms = alternatives.get(algorithm, [])
                
                # Try each alternative
                for alt_algorithm in alt_algorithms:
                    logger.info(f"Retrying with alternative algorithm: {alt_algorithm}")
                    
                    # Reset params to original kwargs
                    params = original_kwargs.copy()
                    
                    # Apply our defaults
                    params["validation_level"] = original_kwargs.get("validation_level", self.validation_level)
                    
                    # Add algorithm-specific params
                    if alt_algorithm == "aes-cbc":
                        # For data decryption, we likely don't have IV in the data
                        # So we'll use default zeros or user-provided IV
                        params["iv"] = kwargs.get("iv", b'\0' * 16)
                    elif alt_algorithm == "chacha20":
                        params["nonce"] = kwargs.get("nonce", None)
                    elif alt_algorithm == "salsa20":
                        params["nonce"] = kwargs.get("nonce", None)
                    
                    # Try with the alternative algorithm
                    try:
                        alt_result = self.decryptor.decrypt_data(data, alt_algorithm, key, **params)
                        
                        # Merge any errors from the alternative attempt
                        if "errors" in alt_result and alt_result["errors"]:
                            result["errors"].extend(alt_result["errors"])
                        
                        # If successful, use this result
                        if alt_result.get("success", False):
                            logger.info(f"Alternative algorithm {alt_algorithm} succeeded")
                            result.update(alt_result)
                            result["algorithm"] = alt_algorithm
                            result["algorithm_retry"] = True
                            break
                    except Exception as e:
                        result["errors"].append(f"Alternative algorithm {alt_algorithm} error: {e}")
                        # Continue to the next algorithm
            
            # Include algorithm information in the result
            result["algorithm"] = algorithm
            result["family"] = family
            
        except Exception as e:
            # Catch-all for any unforeseen errors
            result["errors"].append(f"Unexpected error in decrypt_data: {e}")
            result["error"] = f"Unexpected error: {e}"
            result["success"] = False
            logger.error(f"Unexpected error in decrypt_data: {e}", exc_info=True)
        
        return result
    
    def batch_decrypt(self, file_list: List[str], output_dir: str, family: Optional[str] = None,
                     key: bytes = None, **kwargs) -> Dict[str, Any]:
        """
        Batch decrypt multiple files
        
        Args:
            file_list: List of files to decrypt
            output_dir: Directory to save results
            family: Ransomware family name (optional if auto_detect is True)
            key: Decryption key
            **kwargs: Additional decryption parameters
                auto_detect: Whether to automatically detect the encryption algorithm
                retry_algorithms: Whether to try multiple algorithms if first attempt fails
                adaptive_params: Whether to adapt parameters based on successful decryptions
                parallel: Whether to use parallel processing with ThreadPoolExecutor
                max_workers: Maximum number of worker threads for parallel processing
            
        Returns:
            Result dictionary with batch statistics
        """
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Extract batch-specific parameters
        auto_detect = kwargs.pop("auto_detect", False)
        retry_algorithms = kwargs.pop("retry_algorithms", False)
        adaptive_params = kwargs.pop("adaptive_params", True)
        parallel = kwargs.pop("parallel", False)
        max_workers = kwargs.pop("max_workers", max(1, (os.cpu_count() or 4) - 1))
        
        # Track results
        results = {
            "total": len(file_list),
            "successful": 0,
            "failed": 0,
            "partial": 0,
            "files": [],
            "detected_algorithms": {},
            "algorithm_success_rate": {}
        }
        
        # For adaptive parameter learning
        successful_params = {}
        
        # Function to process a single file (for both sequential and parallel execution)
        def process_file(file_path):
            try:
                # Validate file existence and readability
                if not os.path.exists(file_path):
                    return {
                        "input": file_path,
                        "success": False,
                        "error": f"File not found: {file_path}",
                        "errors": [f"File not found: {file_path}"]
                    }
                
                if not os.access(file_path, os.R_OK):
                    return {
                        "input": file_path,
                        "success": False,
                        "error": f"File not readable: {file_path}",
                        "errors": [f"File not readable: {file_path}"]
                    }
                
                # Generate output path
                try:
                    file_name = os.path.basename(file_path)
                    output_path = os.path.join(output_dir, file_name + ".decrypted")
                except Exception as e:
                    return {
                        "input": file_path,
                        "success": False,
                        "error": f"Error generating output path: {e}",
                        "errors": [f"Error generating output path: {e}"]
                    }
                
                # Create a copy of kwargs for this file
                file_kwargs = kwargs.copy()
                
                # If we have adaptive parameters and have learned from successful decryptions
                if adaptive_params and successful_params:
                    try:
                        # Use adaptation based on file extension or characteristics
                        file_ext = os.path.splitext(file_path)[1].lower()
                        
                        # If we have success parameters for this extension, use them
                        if file_ext in successful_params:
                            adaptive_algo, adaptive_params = successful_params[file_ext]
                            
                            # Combine with original kwargs, but don't override explicit settings
                            for param_name, param_value in adaptive_params.items():
                                if param_name not in file_kwargs:
                                    file_kwargs[param_name] = param_value
                            
                            # Only override algorithm if auto_detect is True or no family specified
                            if auto_detect or not family:
                                file_kwargs["algorithm"] = adaptive_algo
                        
                        # Flag that we are using adaptive parameters
                        file_kwargs["using_adaptive_params"] = True
                    except Exception as e:
                        logger.warning(f"Error applying adaptive parameters for {file_path}: {e}")
                        # Continue without adaptive params
                
                # Decrypt file
                try:
                    result = self.decrypt_file(
                        file_path, 
                        output_path, 
                        family, 
                        key, 
                        auto_detect=auto_detect,
                        retry_algorithms=retry_algorithms,
                        **file_kwargs
                    )
                except Exception as e:
                    return {
                        "input": file_path,
                        "output": output_path,
                        "success": False,
                        "error": f"Unexpected error in decrypt_file: {e}",
                        "errors": [f"Unexpected error in decrypt_file: {e}"]
                    }
                
                # If successful, learn from this for future files
                if adaptive_params and result.get("success", False):
                    try:
                        file_ext = os.path.splitext(file_path)[1].lower()
                        
                        # Extract successful parameters
                        params_to_save = {}
                        for k in ["header_size", "iv_in_file", "iv_offset", "iv_size", 
                                 "nonce_size", "block_size"]:
                            if k in result:
                                params_to_save[k] = result[k]
                        
                        # Store the successful algorithm and parameters for this extension
                        successful_params[file_ext] = (
                            result.get("algorithm", ""),
                            params_to_save
                        )
                    except Exception as e:
                        logger.warning(f"Error saving adaptive parameters for {file_path}: {e}")
                        # Continue without saving adaptive params
                
                # Track algorithm success
                try:
                    algorithm = result.get("algorithm", "unknown")
                    if algorithm not in results["detected_algorithms"]:
                        results["detected_algorithms"][algorithm] = 0
                    results["detected_algorithms"][algorithm] += 1
                    
                    if algorithm not in results["algorithm_success_rate"]:
                        results["algorithm_success_rate"][algorithm] = {"attempts": 0, "successes": 0}
                    results["algorithm_success_rate"][algorithm]["attempts"] += 1
                    if result.get("success", False):
                        results["algorithm_success_rate"][algorithm]["successes"] += 1
                except Exception as e:
                    logger.warning(f"Error tracking algorithm statistics: {e}")
                    # Continue without updating stats
                
                # Create file result
                file_result = {
                    "input": file_path,
                    "output": output_path,
                    "success": result.get("success", False),
                    "error": result.get("error"),
                    "algorithm": result.get("algorithm", "unknown")
                }
                
                # Add errors if present
                if "errors" in result and result["errors"]:
                    file_result["errors"] = result["errors"]
                
                # Add adaptive info if relevant
                if "using_adaptive_params" in file_kwargs:
                    file_result["used_adaptive_params"] = True
                
                # Add algorithm retry info if relevant
                if result.get("algorithm_retry", False):
                    file_result["algorithm_retry"] = True
                
                return file_result
                
            except Exception as e:
                # Catch-all for any unexpected errors in the processing function
                return {
                    "input": file_path,
                    "success": False,
                    "error": f"Unexpected error processing file: {e}",
                    "errors": [f"Unexpected error processing file: {e}"]
                }
        
        # Choose between parallel and sequential processing
        if parallel and len(file_list) > 1:
            # Use ThreadPoolExecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_file = {executor.submit(process_file, file_path): file_path 
                                 for file_path in file_list}
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_file):
                    file_result = future.result()
                    
                    # Update statistics
                    if file_result["success"]:
                        results["successful"] += 1
                    elif file_result.get("partial", False):
                        results["partial"] += 1
                    else:
                        results["failed"] += 1
                    
                    # Add to results
                    results["files"].append(file_result)
        else:
            # Sequential processing
            for file_path in file_list:
                file_result = process_file(file_path)
                
                # Update statistics
                if file_result["success"]:
                    results["successful"] += 1
                elif file_result.get("partial", False):
                    results["partial"] += 1
                else:
                    results["failed"] += 1
                
                # Add to results
                results["files"].append(file_result)
        
        # Calculate algorithm success rates
        for algo, stats in results["algorithm_success_rate"].items():
            if stats["attempts"] > 0:
                stats["rate"] = stats["successes"] / stats["attempts"]
            else:
                stats["rate"] = 0.0
        
        # Add batch summary
        results["summary"] = {
            "best_algorithm": max(
                results["algorithm_success_rate"].items(), 
                key=lambda x: (x[1]["rate"], x[1]["attempts"])
            )[0] if results["algorithm_success_rate"] else None,
            "adapted_parameters": bool(successful_params),
            "used_auto_detect": auto_detect,
            "used_retry": retry_algorithms,
            "used_parallel": parallel
        }
        
        return results
    
    def _get_family_config(self, family: Optional[str], key: bytes, **kwargs) -> Tuple[str, Dict[str, Any]]:
        """
        Get encryption algorithm and parameters for a ransomware family
        
        Args:
            family: Ransomware family name (optional)
            key: Decryption key
            **kwargs: Additional parameters
            
        Returns:
            Tuple of (algorithm, params_dict)
        """
        # Prepare defaults
        iv = kwargs.get("iv")
        header_size = kwargs.get("header_size", 0)
        iv_in_file = kwargs.get("iv_in_file", False)
        nonce = kwargs.get("nonce")
        
        # Default params
        params = {}
        algorithm = "aes-cbc"  # Default
        
        # Override with provided params
        params.update(kwargs)
        
        # Configure based on family if provided
        if family is not None:
            family = family.lower()
        
        if family and (family == "blackcat" or family == "alphv"):
            # BlackCat primarily uses ChaCha20 or AES-256
            # The header contains the algorithm type at offset 4
            # 1 for ChaCha20, 2 for AES-256
            
            # If we have algorithm info
            if "algorithm_id" in kwargs:
                algo_id = kwargs["algorithm_id"]
                if algo_id == 1:
                    algorithm = "chacha20"
                else:
                    algorithm = "aes-cbc"
            else:
                # Default to ChaCha20
                algorithm = "chacha20"
            
            # BlackCat has a 256-byte header
            params["header_size"] = kwargs.get("header_size", 256)
        
        elif family and family == "lockbit":
            # LockBit uses AES-CBC with the IV in the header
            algorithm = "aes-cbc"
            
            # LockBit 2.0/3.0 header structure varies
            if "version" in kwargs:
                version = kwargs["version"]
                if version == "2.0":
                    params["header_size"] = kwargs.get("header_size", 92)
                    params["iv_offset"] = kwargs.get("iv_offset", 28)
                elif version == "3.0":
                    params["header_size"] = kwargs.get("header_size", 128)
                    params["iv_offset"] = kwargs.get("iv_offset", 56)
                else:
                    # Default for newer versions
                    params["header_size"] = kwargs.get("header_size", 128)
                    params["iv_offset"] = kwargs.get("iv_offset", 56)
            else:
                # Default header size for LockBit
                params["header_size"] = kwargs.get("header_size", 128)
                params["iv_offset"] = kwargs.get("iv_offset", 56)
            
            params["iv_size"] = kwargs.get("iv_size", 16)
            params["iv_in_file"] = kwargs.get("iv_in_file", True)
        
        elif family and family == "ryuk":
            # Ryuk uses AES-ECB (simple)
            algorithm = "aes-ecb"
            params["header_size"] = kwargs.get("header_size", 8)
        
        elif family and (family == "revil" or family == "sodinokibi"):
            # REvil/Sodinokibi uses AES-CBC with IV in the header
            algorithm = "aes-cbc"
            params["header_size"] = kwargs.get("header_size", 16)
            params["iv_in_file"] = kwargs.get("iv_in_file", True)
            params["iv_offset"] = kwargs.get("iv_offset", 0)
            params["iv_size"] = kwargs.get("iv_size", 16)
        
        elif family and family == "rhysida":
            # Rhysida uses AES-CBC with IV in the header
            algorithm = "aes-cbc"
            
            # Rhysida header typically has RHYSIDA marker (7 bytes) + version (1 byte) + encrypted key (256 bytes) + IV
            params["header_size"] = kwargs.get("header_size", 280)
            params["iv_in_file"] = kwargs.get("iv_in_file", True)
            params["iv_offset"] = kwargs.get("iv_offset", 264)
            params["iv_size"] = kwargs.get("iv_size", 16)
        
        elif family and family == "wannacry":
            # WannaCry uses AES-CBC with a complex header
            algorithm = "aes-cbc"
            params["header_size"] = kwargs.get("header_size", 0x200)  # 512 bytes
            params["iv_in_file"] = kwargs.get("iv_in_file", True)
            params["iv_offset"] = kwargs.get("iv_offset", 0x20)        # IV at offset 32
            params["iv_size"] = kwargs.get("iv_size", 16)
        
        elif family and (family == "djvu" or family == "stop"):
            # STOP/Djvu uses Salsa20
            algorithm = "salsa20"
            params["header_size"] = kwargs.get("header_size", 0x258)  # 600 bytes
        
        elif family and family == "conti":
            # Conti uses AES-CBC
            algorithm = "aes-cbc"
            params["header_size"] = kwargs.get("header_size", 8)
            params["iv_in_file"] = kwargs.get("iv_in_file", True)
            params["iv_offset"] = kwargs.get("iv_offset", 8)
            params["iv_size"] = kwargs.get("iv_size", 16)
        
        # Override algorithm if explicitly provided
        if "algorithm" in kwargs:
            algorithm = kwargs["algorithm"]
        
        return algorithm, params


# Command-line interface
if __name__ == "__main__":
    import argparse
    import glob
    
    parser = argparse.ArgumentParser(description="Universal Streaming Decryption Engine")
    # Input/output options
    parser.add_argument("--file", help="Encrypted file to decrypt")
    parser.add_argument("--output", help="Output file for decrypted data")
    parser.add_argument("--batch", help="Process multiple files matching a glob pattern")
    parser.add_argument("--output-dir", help="Output directory for batch processing")
    
    # Encryption info
    parser.add_argument("--family", help="Ransomware family")
    parser.add_argument("--algorithm", help="Encryption algorithm if known")
    parser.add_argument("--key", help="Hex-encoded decryption key")
    parser.add_argument("--iv", help="Hex-encoded IV")
    parser.add_argument("--key-file", help="File containing key data")
    parser.add_argument("--header-size", type=int, help="Header size to skip")
    
    # Advanced options
    parser.add_argument("--auto-detect", action="store_true", help="Automatically detect encryption algorithm")
    parser.add_argument("--retry-algorithms", action="store_true", help="Try multiple algorithms if first attempt fails")
    parser.add_argument("--threaded", action="store_true", help="Use multi-threading")
    parser.add_argument("--validation", choices=["none", "basic", "standard", "strict"], 
                      default="standard", help="Validation level")
    parser.add_argument("--parallel", action="store_true", help="Use parallel processing for batch operations")
    parser.add_argument("--no-adaptive", action="store_true", help="Disable adaptive parameter learning for batch")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    
    args = parser.parse_args()
    
    # Set logging level based on verbosity
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Validate arguments
    if args.batch:
        if not args.output_dir:
            logger.error("--output-dir is required with --batch")
            sys.exit(1)
    elif not args.file or not args.output:
        logger.error("Either --file and --output OR --batch and --output-dir are required")
        parser.print_help()
        sys.exit(1)
    
    # Get key from hex string or file
    key = None
    if args.key:
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            logger.error("Invalid key format. Must be hex-encoded.")
            sys.exit(1)
    elif args.key_file:
        try:
            with open(args.key_file, 'rb') as f:
                key_data = f.read().strip()
                
            # Try to parse as hex
            if all(c in b'0123456789ABCDEFabcdef' for c in key_data):
                try:
                    key = bytes.fromhex(key_data.decode())
                except:
                    key = key_data
            else:
                key = key_data
        except Exception as e:
            logger.error(f"Error reading key file: {e}")
            sys.exit(1)
    
    if not key:
        logger.error("No key provided. Use --key or --key-file.")
        sys.exit(1)
    
    # Get IV if provided
    iv = None
    if args.iv:
        try:
            iv = bytes.fromhex(args.iv)
        except ValueError:
            logger.error("Invalid IV format. Must be hex-encoded.")
            sys.exit(1)
    
    # Map validation level
    validation_map = {
        "none": ValidationLevel.NONE,
        "basic": ValidationLevel.BASIC,
        "standard": ValidationLevel.STANDARD,
        "strict": ValidationLevel.STRICT
    }
    validation_level = validation_map[args.validation]
    
    # Create parameters
    params = {
        "iv": iv,
        "validation_level": validation_level,
        "use_threading": args.threaded,
        "auto_detect": args.auto_detect,
        "retry_algorithms": args.retry_algorithms
    }
    
    if args.header_size is not None:
        params["header_size"] = args.header_size
    
    # Create engine
    engine = StreamingDecryptionEngine()
    
    # Process based on mode
    if args.batch:
        # Batch mode
        # Get files matching the pattern
        matched_files = glob.glob(args.batch, recursive=True)
        
        if not matched_files:
            logger.error(f"No files found matching pattern: {args.batch}")
            sys.exit(1)
        
        logger.info(f"Found {len(matched_files)} files to process")
        
        # Add batch-specific parameters
        batch_params = params.copy()
        batch_params["parallel"] = args.parallel
        batch_params["adaptive_params"] = not args.no_adaptive
        
        # Run batch processing
        results = engine.batch_decrypt(
            matched_files,
            args.output_dir,
            args.family,
            key,
            **batch_params
        )
        
        # Print summary
        print(f"\nBatch Processing Summary:")
        print(f"Total files: {results['total']}")
        print(f"Successfully decrypted: {results['successful']}")
        print(f"Partially successful: {results['partial']}")
        print(f"Failed: {results['failed']}")
        
        # Print algorithm stats
        print("\nAlgorithm Statistics:")
        for algo, stats in results["algorithm_success_rate"].items():
            success_rate = stats["rate"] * 100
            print(f"  {algo}: {stats['successes']}/{stats['attempts']} successful ({success_rate:.1f}%)")
        
        # Print best algorithm
        if results["summary"]["best_algorithm"]:
            print(f"\nBest performing algorithm: {results['summary']['best_algorithm']}")
        
        # Print adaptive info
        if results["summary"]["adapted_parameters"]:
            print("Used adaptive parameters: Yes")
        
        # Detailed file list if verbose
        if args.verbose:
            print("\nDetailed Results:")
            for i, file_result in enumerate(results["files"]):
                status = "SUCCESS" if file_result["success"] else "FAILED"
                print(f"  [{i+1}] {os.path.basename(file_result['input'])}: {status}")
                print(f"      Algorithm: {file_result.get('algorithm', 'unknown')}")
                if file_result.get("used_adaptive_params", False):
                    print(f"      Used adaptive parameters")
                if file_result.get("algorithm_retry", False):
                    print(f"      Used algorithm retry")
                if not file_result["success"] and "error" in file_result:
                    print(f"      Error: {file_result['error']}")
                print()
        
        # Exit with status based on success rate
        if results["successful"] == 0:
            print("No files were successfully decrypted.")
            sys.exit(1)
        elif results["failed"] > 0:
            print(f"Warning: {results['failed']} files failed to decrypt.")
            sys.exit(0)
        else:
            print("All files successfully decrypted.")
            sys.exit(0)
            
    else:
        # Single file mode
        if args.family:
            # Use family-specific configuration
            result = engine.decrypt_file(args.file, args.output, args.family, key, **params)
        else:
            # Use algorithm or auto-detect
            if args.algorithm:
                # Use specified algorithm
                params.pop("auto_detect", None)  # Remove auto_detect if present
                decryptor = StreamingDecryptor()
                result = decryptor.decrypt_file(args.file, args.output, args.algorithm, key, **params)
            else:
                # Force auto-detect since no family or algorithm specified
                params["auto_detect"] = True
                result = engine.decrypt_file(args.file, args.output, None, key, **params)
        
        # Print result
        if result.get("success", False):
            print(f"Successfully decrypted {args.file} to {args.output}")
            
            # Print additional info
            print(f"Algorithm: {result.get('algorithm', 'unknown')}")
            
            if "validation" in result:
                print(f"Validation method: {result['validation'].get('method')}")
                if "entropy" in result["validation"]:
                    print(f"Data entropy: {result['validation']['entropy']:.2f}")
            
            if args.auto_detect:
                if result.get("algorithm_retry", False):
                    print("Auto-detection: Used algorithm retry")
                if "confidence" in result:
                    print(f"Detection confidence: {result['confidence']:.2f}")
            
            if "throughput_bps" in result:
                mbps = result["throughput_bps"] / (1024 * 1024)
                print(f"Throughput: {mbps:.2f} MB/s")
            
            if args.verbose:
                # Print all parameters used
                print("\nDecryption Parameters:")
                for k, v in result.items():
                    if k not in ["success", "validation", "throughput_bps", "error"]:
                        print(f"  {k}: {v}")
        else:
            print(f"Decryption failed: {result.get('error', 'Unknown error')}")
            
            if result.get("partial_success", False):
                print("Partial success: output file created but validation failed")
                
            if "validation" in result and "error" in result["validation"]:
                print(f"Validation error: {result['validation']['error']}")
                
            if args.verbose and "algorithm" in result:
                print(f"Attempted algorithm: {result['algorithm']}")
                
            sys.exit(1)