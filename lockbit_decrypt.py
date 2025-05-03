#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LockBit Decryption Tool

A streamlined interface for optimized LockBit ransomware decryption.
This tool combines memory analysis, network key extraction, and advanced
decryption techniques to recover files encrypted by LockBit ransomware.

Usage:
  python lockbit_decrypt.py --file [encrypted_file] --output [output_file]
  python lockbit_decrypt.py --dir [directory] --output-dir [output_directory]
"""

import os
import sys
import time
import logging
import argparse
from typing import List, Dict, Optional, Any, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("lockbit_decrypt.log")
    ]
)
logger = logging.getLogger("LockBitDecrypt")


def setup_environment():
    """Set up the environment and check dependencies"""
    try:
        # Add project root to path
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        
        # Import required modules
        from decryption_tools.network_forensics.lockbit_optimized_recovery import (
            OptimizedLockBitRecovery, CRYPTOGRAPHY_AVAILABLE, NETWORK_RECOVERY_AVAILABLE
        )
        from tools.memory.key_extractors.ransomware_key_extractor import (
            LockBitKeyExtractor
        )
        
        if not CRYPTOGRAPHY_AVAILABLE:
            logger.error("Cryptography library not available. Please install: pip install cryptography")
            return False
        
        if not NETWORK_RECOVERY_AVAILABLE:
            logger.error("NetworkBasedRecovery module not available")
            return False
        
        return True
    
    except ImportError as e:
        logger.error(f"Error importing required modules: {e}")
        return False


def extract_keys_from_memory_dump(memory_dump_path: str) -> List[bytes]:
    """
    Extract potential LockBit keys from memory dump
    
    Args:
        memory_dump_path: Path to memory dump file
        
    Returns:
        List of potential decryption keys
    """
    try:
        from tools.memory.key_extractors.ransomware_key_extractor import LockBitKeyExtractor
        
        logger.info(f"Analyzing memory dump: {memory_dump_path}")
        extractor = LockBitKeyExtractor()
        results = extractor.analyze_memory_for_lockbit(memory_dump_path)
        
        # Extract raw key data
        keys = []
        for result in results:
            if result.key_data not in keys:
                keys.append(result.key_data)
        
        logger.info(f"Extracted {len(keys)} potential keys from memory dump")
        return keys
    
    except Exception as e:
        logger.error(f"Error extracting keys from memory: {e}")
        return []


def extract_keys_from_sample(sample_path: str) -> List[bytes]:
    """
    Extract potential LockBit keys from ransomware sample
    
    Args:
        sample_path: Path to ransomware sample
        
    Returns:
        List of potential decryption keys
    """
    try:
        from decryption_tools.network_forensics.lockbit_optimized_recovery import OptimizedLockBitRecovery
        
        logger.info(f"Analyzing ransomware sample: {sample_path}")
        recovery = OptimizedLockBitRecovery()
        extracted_keys = recovery.analyze_sample(sample_path)
        
        # Extract raw key data
        keys = []
        for key in extracted_keys:
            if key.key_data not in keys:
                keys.append(key.key_data)
        
        logger.info(f"Extracted {len(keys)} potential keys from sample")
        return keys
    
    except Exception as e:
        logger.error(f"Error extracting keys from sample: {e}")
        return []


def decrypt_file(file_path: str, output_path: Optional[str] = None, 
                keys: Optional[List[bytes]] = None) -> bool:
    """
    Decrypt a LockBit encrypted file
    
    Args:
        file_path: Path to encrypted file
        output_path: Optional path for decrypted output
        keys: Optional list of keys to try
        
    Returns:
        True if decryption was successful, False otherwise
    """
    try:
        from decryption_tools.network_forensics.lockbit_optimized_recovery import OptimizedLockBitRecovery
        
        logger.info(f"Attempting to decrypt: {file_path}")
        
        # Initialize recovery module
        recovery = OptimizedLockBitRecovery()
        
        # Set default output path if not provided
        if not output_path:
            base_dir = os.path.dirname(file_path)
            file_name = os.path.basename(file_path)
            
            # Clean up LockBit extensions
            if '.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in file_name:
                file_name = file_name.split('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}')[0]
            elif file_name.endswith('.restorebackup'):
                file_name = file_name[:-14]
            
            output_path = os.path.join(base_dir, f"decrypted_{file_name}")
        
        # Attempt decryption
        start_time = time.time()
        success = recovery.decrypt_file(file_path, output_path, extra_keys=keys)
        elapsed_time = time.time() - start_time
        
        if success:
            logger.info(f"Successfully decrypted to: {output_path} in {elapsed_time:.2f} seconds")
            return True
        else:
            logger.info(f"Decryption failed after {elapsed_time:.2f} seconds")
            return False
    
    except Exception as e:
        logger.error(f"Error during decryption: {e}")
        return False


def batch_decrypt(directory_path: str, output_dir: Optional[str] = None,
                 keys: Optional[List[bytes]] = None) -> Dict[str, bool]:
    """
    Batch decrypt all LockBit encrypted files in a directory
    
    Args:
        directory_path: Path to directory with encrypted files
        output_dir: Optional output directory
        keys: Optional list of keys to try
        
    Returns:
        Dictionary mapping file paths to decryption success
    """
    try:
        from decryption_tools.network_forensics.lockbit_optimized_recovery import OptimizedLockBitRecovery
        
        logger.info(f"Batch processing directory: {directory_path}")
        
        # Initialize recovery module
        recovery = OptimizedLockBitRecovery()
        
        # Add extra keys if provided
        if keys:
            for key in keys:
                # Create mock ExtractedKey objects
                from decryption_tools.network_forensics.network_based_recovery import ExtractedKey
                import datetime
                
                extracted_key = ExtractedKey(
                    key_data=key,
                    key_type="aes-256" if len(key) == 32 else "aes-128",
                    source_ip="local",
                    destination_ip="local",
                    timestamp=datetime.datetime.now(),
                    confidence=0.8,
                    context={"source": "user_provided"}
                )
                recovery.add_keys([extracted_key])
        
        # Find all potential LockBit encrypted files
        encrypted_files = []
        for root, _, files in os.walk(directory_path):
            for filename in files:
                if ('.{1765FE8E-2103-66E3-7DCB-72284ABD03AA}' in filename or
                    filename.endswith('.restorebackup') or
                    '.locked' in filename.lower()):
                    file_path = os.path.join(root, filename)
                    encrypted_files.append(file_path)
        
        if not encrypted_files:
            logger.warning("No LockBit encrypted files found")
            return {}
        
        logger.info(f"Found {len(encrypted_files)} encrypted files")
        
        # Process files in batches for better performance
        batch_size = 10
        results = {}
        
        for i in range(0, len(encrypted_files), batch_size):
            batch = encrypted_files[i:i+batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(encrypted_files) + batch_size - 1)//batch_size}")
            
            batch_results = recovery.batch_decrypt(batch, output_dir)
            results.update(batch_results)
            
            # Status update
            success_count = sum(1 for success in results.values() if success)
            logger.info(f"Progress: {len(results)}/{len(encrypted_files)} files processed, "
                        f"{success_count} successfully decrypted")
        
        # Export successful keys
        recovery.export_successful_keys()
        
        return results
    
    except Exception as e:
        logger.error(f"Error during batch decryption: {e}")
        return {}


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="LockBit Ransomware Decryption Tool")
    
    # File/directory input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", help="Path to encrypted file")
    input_group.add_argument("--dir", help="Directory with encrypted files")
    
    # Output options
    parser.add_argument("--output", help="Output file for decrypted data")
    parser.add_argument("--output-dir", help="Output directory for batch decryption")
    
    # Key sources
    parser.add_argument("--memory-dump", help="Path to memory dump for key extraction")
    parser.add_argument("--sample", help="Path to ransomware sample for key extraction")
    parser.add_argument("--key", help="Hex-encoded decryption key to try", action='append')
    
    # Mode options
    parser.add_argument("--export-keys", help="Export successful keys to file", action='store_true')
    parser.add_argument("--verbose", help="Enable verbose logging", action='store_true')
    
    args = parser.parse_args()
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check environment
    if not setup_environment():
        return 1
    
    # Collect keys from different sources
    keys = []
    
    # 1. From memory dump
    if args.memory_dump:
        memory_keys = extract_keys_from_memory_dump(args.memory_dump)
        keys.extend(memory_keys)
    
    # 2. From ransomware sample
    if args.sample:
        sample_keys = extract_keys_from_sample(args.sample)
        keys.extend(sample_keys)
    
    # 3. From command line arguments
    if args.key:
        for key_hex in args.key:
            try:
                key_bytes = bytes.fromhex(key_hex)
                keys.append(key_bytes)
                logger.info(f"Added user-provided key: {key_hex[:8]}...")
            except Exception as e:
                logger.error(f"Invalid key format: {key_hex} - {e}")
    
    # Deduplicate keys
    unique_keys = []
    for key in keys:
        if key not in unique_keys:
            unique_keys.append(key)
    
    if unique_keys:
        logger.info(f"Using {len(unique_keys)} unique keys for decryption attempts")
    
    # Process file or directory
    if args.file:
        success = decrypt_file(args.file, args.output, keys=unique_keys)
        return 0 if success else 1
    
    elif args.dir:
        results = batch_decrypt(args.dir, args.output_dir, keys=unique_keys)
        
        # Print summary
        if results:
            success_count = sum(1 for success in results.values() if success)
            success_rate = success_count / len(results) * 100
            
            print(f"\nDecryption Summary:")
            print(f"-------------------")
            print(f"Processed files: {len(results)}")
            print(f"Successfully decrypted: {success_count} ({success_rate:.1f}%)")
            print(f"Failed decryption: {len(results) - success_count}")
            
            if success_count > 0:
                print(f"\nSuccessfully decrypted files:")
                for file_path, success in results.items():
                    if success:
                        print(f"- {file_path}")
            
            return 0 if success_count > 0 else 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())