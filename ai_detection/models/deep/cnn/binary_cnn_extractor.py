#!/usr/bin/env python3
"""
Binary CNN Feature Extractor

This module implements a CNN-based feature extractor for binary PE files,
extracting spatial features directly from raw binary data for ransomware detection.
"""

import os
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, List, Tuple, Optional, Union, Any
import logging
from pathlib import Path
import lief  # Library for PE file parsing

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('binary_cnn_extractor')

class BinaryImageConverter:
    """Converts binary PE files to image-like representations for CNN processing"""
    
    def __init__(self, width: int = 256, height: Optional[int] = None, 
                max_size: int = 2*1024*1024, pad: bool = True):
        """
        Initialize the binary to image converter.
        
        Args:
            width: Width of the image representation
            height: Height of the image (calculated based on width if None)
            max_size: Maximum file size to process (bytes)
            pad: Whether to pad smaller files
        """
        self.width = width
        self.height = height
        self.max_size = max_size
        self.pad = pad
    
    def convert_to_image(self, file_path: str) -> np.ndarray:
        """
        Convert binary file to a 2D image-like array
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            2D numpy array representation of the file
        """
        try:
            # Read file as binary
            with open(file_path, 'rb') as f:
                binary_data = f.read(self.max_size)
            
            # Convert to numpy array of uint8
            data = np.frombuffer(binary_data, dtype=np.uint8)
            
            # Calculate dimensions
            if self.height is None:
                # Calculate height to match the file size
                file_size = len(data)
                height = file_size // self.width
                if file_size % self.width != 0:
                    height += 1
            else:
                height = self.height
            
            # Resize the data to match the dimensions
            if len(data) < self.width * height and self.pad:
                # Pad with zeros
                padded_data = np.zeros(self.width * height, dtype=np.uint8)
                padded_data[:len(data)] = data
                data = padded_data
            elif len(data) > self.width * height:
                # Truncate
                data = data[:self.width * height]
            
            # Reshape to 2D array
            image = data.reshape(height, self.width)
            
            return image
            
        except Exception as e:
            logger.error(f"Error converting file to image: {e}")
            # Return empty image in case of error
            return np.zeros((self.height or 256, self.width), dtype=np.uint8)
    
    def convert_to_multichannel(self, file_path: str, channels: int = 3) -> np.ndarray:
        """
        Convert binary file to a multi-channel image-like array
        
        Args:
            file_path: Path to the binary file
            channels: Number of channels (1, 3, or 4)
            
        Returns:
            Multi-channel numpy array representation of the file
        """
        try:
            # Get basic image
            image = self.convert_to_image(file_path)
            
            if channels == 1:
                # Single channel (grayscale)
                return image.reshape(1, *image.shape)
            
            # For PE files, create a more meaningful representation
            if file_path.lower().endswith('.exe') or file_path.lower().endswith('.dll'):
                try:
                    # Use LIEF to parse PE structure
                    pe = lief.parse(file_path)
                    
                    # Create header channel - highlight PE header
                    header_channel = np.zeros_like(image)
                    header_size = min(pe.dos_header.addressof_new_exeheader + pe.header.sizeof_headers, 
                                    self.width * (self.height or 256))
                    header_size = header_size // self.width
                    header_channel[:header_size, :] = image[:header_size, :]
                    
                    # Create code channel - highlight code sections
                    code_channel = np.zeros_like(image)
                    for section in pe.sections:
                        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_CODE):
                            start = section.offset // self.width
                            end = start + (section.size // self.width)
                            if start < image.shape[0] and end <= image.shape[0]:
                                code_channel[start:end, :] = image[start:end, :]
                    
                    # Create data channel - highlight data sections
                    data_channel = np.zeros_like(image)
                    for section in pe.sections:
                        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA):
                            start = section.offset // self.width
                            end = start + (section.size // self.width)
                            if start < image.shape[0] and end <= image.shape[0]:
                                data_channel[start:end, :] = image[start:end, :]
                    
                    if channels == 3:
                        # Three channels (header, code, data)
                        return np.stack([header_channel, code_channel, data_channel])
                    
                    elif channels == 4:
                        # Four channels (raw, header, code, data)
                        return np.stack([image, header_channel, code_channel, data_channel])
                    
                except Exception as e:
                    logger.warning(f"PE parsing failed, using generic multi-channel: {e}")
            
            # Generic approach for non-PE files or if PE parsing fails
            if channels == 3:
                # Three channels (original, bit-shifted, entropy)
                channel1 = image
                channel2 = np.roll(image, 1, axis=1)  # Shift bits
                
                # Entropy channel (using local windowed entropy)
                channel3 = np.zeros_like(image)
                window_size = 8
                for i in range(image.shape[0] - window_size + 1):
                    for j in range(image.shape[1] - window_size + 1):
                        window = image[i:i+window_size, j:j+window_size].flatten()
                        hist = np.bincount(window, minlength=256) / (window_size * window_size)
                        hist = hist[hist > 0]  # Remove zeros
                        entropy = -np.sum(hist * np.log2(hist))
                        channel3[i+window_size//2, j+window_size//2] = min(entropy * 32, 255)
                
                return np.stack([channel1, channel2, channel3])
                
            elif channels == 4:
                # Four channels
                channel1 = image
                channel2 = np.roll(image, 1, axis=1)
                channel3 = np.roll(image, 1, axis=0)
                
                # XOR channel
                channel4 = channel1 ^ channel2
                
                return np.stack([channel1, channel2, channel3, channel4])
            
            # Default fallback
            return np.stack([image] * channels)
            
        except Exception as e:
            logger.error(f"Error converting file to multi-channel image: {e}")
            # Return empty channels in case of error
            shape = (self.height or 256, self.width)
            return np.zeros((channels, *shape), dtype=np.uint8)


class BinaryCNNModel(nn.Module):
    """CNN model for binary malware classification from image-like data"""
    
    def __init__(self, input_channels: int = 3, output_dim: int = 256):
        """
        Initialize the CNN model.
        
        Args:
            input_channels: Number of input channels
            output_dim: Output embedding dimension
        """
        super(BinaryCNNModel, self).__init__()
        
        # First convolutional block
        self.conv1 = nn.Conv2d(input_channels, 32, kernel_size=3, stride=1, padding=1)
        self.bn1 = nn.BatchNorm2d(32)
        self.pool1 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        # Second convolutional block
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, stride=1, padding=1)
        self.bn2 = nn.BatchNorm2d(64)
        self.pool2 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        # Third convolutional block
        self.conv3 = nn.Conv2d(64, 128, kernel_size=3, stride=1, padding=1)
        self.bn3 = nn.BatchNorm2d(128)
        self.pool3 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        # Fourth convolutional block
        self.conv4 = nn.Conv2d(128, 256, kernel_size=3, stride=1, padding=1)
        self.bn4 = nn.BatchNorm2d(256)
        self.pool4 = nn.MaxPool2d(kernel_size=2, stride=2)
        
        # Adaptive pooling to handle variable input sizes
        self.adaptive_pool = nn.AdaptiveAvgPool2d((4, 4))
        
        # Fully connected layers
        self.fc1 = nn.Linear(256 * 4 * 4, 1024)
        self.dropout1 = nn.Dropout(0.5)
        self.fc2 = nn.Linear(1024, output_dim)
        
    def forward(self, x):
        """Forward pass"""
        # Convolutional blocks
        x = self.pool1(F.relu(self.bn1(self.conv1(x))))
        x = self.pool2(F.relu(self.bn2(self.conv2(x))))
        x = self.pool3(F.relu(self.bn3(self.conv3(x))))
        x = self.pool4(F.relu(self.bn4(self.conv4(x))))
        
        # Adaptive pooling
        x = self.adaptive_pool(x)
        
        # Flatten
        x = x.view(x.size(0), -1)
        
        # Fully connected layers
        x = F.relu(self.fc1(x))
        x = self.dropout1(x)
        x = self.fc2(x)
        
        return x


class BinaryCNNExtractor:
    """Feature extractor using CNN for binary ransomware classification"""
    
    def __init__(self, model_path: Optional[str] = None, 
                 input_channels: int = 3, output_dim: int = 256,
                 image_width: int = 256, device: Optional[str] = None):
        """
        Initialize the binary CNN feature extractor.
        
        Args:
            model_path: Path to pre-trained model weights
            input_channels: Number of input channels
            output_dim: Output embedding dimension
            image_width: Width of the image representation
            device: Device to use (cuda or cpu)
        """
        # Initialize image converter
        self.image_converter = BinaryImageConverter(width=image_width)
        
        # Set device
        if device is None:
            self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        else:
            self.device = torch.device(device)
        
        # Initialize model
        self.model = BinaryCNNModel(input_channels=input_channels, output_dim=output_dim)
        
        # Load pre-trained weights if available
        if model_path and os.path.exists(model_path):
            try:
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
                logger.info(f"Loaded pre-trained model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load pre-trained model: {e}")
        
        # Move model to device
        self.model.to(self.device)
        
        # Set model to evaluation mode
        self.model.eval()
        
        # Input channels
        self.input_channels = input_channels
        
    def extract_features(self, file_path: str) -> np.ndarray:
        """
        Extract CNN features from a binary file.
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            Feature vector (embedding) of the binary file
        """
        try:
            # Convert file to multi-channel image
            image = self.image_converter.convert_to_multichannel(file_path, channels=self.input_channels)
            
            # Normalize to [0, 1] range
            image = image.astype(np.float32) / 255.0
            
            # Convert to tensor and add batch dimension
            image_tensor = torch.tensor(image, dtype=torch.float32).unsqueeze(0).to(self.device)
            
            # Extract features
            with torch.no_grad():
                features = self.model(image_tensor)
            
            # Convert to numpy array
            features_np = features.cpu().numpy()[0]
            
            return features_np
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            # Return zero vector in case of error
            return np.zeros(self.model.fc2.out_features, dtype=np.float32)
    
    def extract_features_batch(self, file_paths: List[str]) -> np.ndarray:
        """
        Extract CNN features from multiple binary files.
        
        Args:
            file_paths: List of paths to binary files
            
        Returns:
            Batch of feature vectors
        """
        try:
            # Initialize batch of images
            batch_size = len(file_paths)
            images = []
            
            # Convert files to multi-channel images
            for file_path in file_paths:
                image = self.image_converter.convert_to_multichannel(file_path, channels=self.input_channels)
                # Normalize to [0, 1] range
                image = image.astype(np.float32) / 255.0
                images.append(image)
            
            # Stack images into a batch
            image_batch = np.stack(images)
            
            # Convert to tensor
            image_tensor = torch.tensor(image_batch, dtype=torch.float32).to(self.device)
            
            # Extract features
            with torch.no_grad():
                features = self.model(image_tensor)
            
            # Convert to numpy array
            features_np = features.cpu().numpy()
            
            return features_np
            
        except Exception as e:
            logger.error(f"Error extracting batch features: {e}")
            # Return zero vectors in case of error
            return np.zeros((len(file_paths), self.model.fc2.out_features), dtype=np.float32)
    
    def extract_pe_section_features(self, file_path: str) -> Dict[str, np.ndarray]:
        """
        Extract features from specific PE sections for more detailed analysis.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dictionary of section name to feature vector mappings
        """
        try:
            # Parse PE file
            pe = lief.parse(file_path)
            
            # Extract features for each section
            section_features = {}
            
            for section in pe.sections:
                # Skip if section is too small
                if section.size < 64:
                    continue
                
                # Read section data
                with open(file_path, 'rb') as f:
                    f.seek(section.offset)
                    section_data = f.read(min(section.size, self.image_converter.max_size))
                
                # Convert to numpy array
                data = np.frombuffer(section_data, dtype=np.uint8)
                
                # Reshape to 2D array with fixed size
                width = self.image_converter.width
                height = len(data) // width
                if height == 0:
                    height = 1
                
                # Resize to match dimensions
                if len(data) > width * height:
                    data = data[:width * height]
                elif len(data) < width * height:
                    padded_data = np.zeros(width * height, dtype=np.uint8)
                    padded_data[:len(data)] = data
                    data = padded_data
                
                # Reshape to 2D
                image = data.reshape(height, width)
                
                # Create 3-channel representation
                # Channel 1: Raw data
                channel1 = image
                # Channel 2: Bit-shifted
                channel2 = np.roll(image, 1, axis=1)
                # Channel 3: XOR
                channel3 = channel1 ^ channel2
                
                # Stack channels
                section_image = np.stack([channel1, channel2, channel3])
                
                # Normalize
                section_image = section_image.astype(np.float32) / 255.0
                
                # Convert to tensor
                image_tensor = torch.tensor(section_image, dtype=torch.float32).unsqueeze(0).to(self.device)
                
                # Extract features
                with torch.no_grad():
                    features = self.model(image_tensor)
                
                # Store features
                section_features[section.name] = features.cpu().numpy()[0]
            
            return section_features
            
        except Exception as e:
            logger.error(f"Error extracting PE section features: {e}")
            return {}
    
    def get_section_importances(self, file_path: str) -> Dict[str, float]:
        """
        Calculate the importance of each PE section for ransomware detection.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dictionary of section name to importance score mappings
        """
        try:
            # Extract section features
            section_features = self.extract_pe_section_features(file_path)
            
            # Calculate L2 norm of each section's features
            section_importances = {}
            for section_name, features in section_features.items():
                norm = np.linalg.norm(features)
                section_importances[section_name] = float(norm)
            
            # Normalize importances
            total_importance = sum(section_importances.values())
            if total_importance > 0:
                for section_name in section_importances:
                    section_importances[section_name] /= total_importance
            
            return section_importances
            
        except Exception as e:
            logger.error(f"Error calculating section importances: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    import argparse
    import json
    
    parser = argparse.ArgumentParser(description="Extract CNN features from binary files")
    parser.add_argument('--input', required=True, help='Path to binary file or directory')
    parser.add_argument('--model', help='Path to pre-trained model')
    parser.add_argument('--output', help='Output JSON file for features')
    parser.add_argument('--channels', type=int, default=3, help='Number of channels (1, 3, or 4)')
    parser.add_argument('--width', type=int, default=256, help='Width of image representation')
    parser.add_argument('--section-analysis', action='store_true', help='Perform section-level analysis for PE files')
    
    args = parser.parse_args()
    
    # Initialize extractor
    extractor = BinaryCNNExtractor(
        model_path=args.model,
        input_channels=args.channels,
        image_width=args.width
    )
    
    results = {}
    
    # Process input
    if os.path.isdir(args.input):
        # Process all files in directory
        for filename in os.listdir(args.input):
            file_path = os.path.join(args.input, filename)
            if os.path.isfile(file_path):
                try:
                    features = extractor.extract_features(file_path)
                    results[filename] = {
                        "features": features.tolist()
                    }
                    
                    # Perform section analysis if requested
                    if args.section_analysis and (filename.lower().endswith('.exe') or filename.lower().endswith('.dll')):
                        section_importances = extractor.get_section_importances(file_path)
                        results[filename]["section_importances"] = section_importances
                        
                    print(f"Processed {filename}")
                except Exception as e:
                    print(f"Error processing {filename}: {e}")
    else:
        # Process single file
        try:
            features = extractor.extract_features(args.input)
            filename = os.path.basename(args.input)
            results[filename] = {
                "features": features.tolist()
            }
            
            # Perform section analysis if requested
            if args.section_analysis and (args.input.lower().endswith('.exe') or args.input.lower().endswith('.dll')):
                section_importances = extractor.get_section_importances(args.input)
                results[filename]["section_importances"] = section_importances
                
            print(f"Processed {filename}")
        except Exception as e:
            print(f"Error processing {args.input}: {e}")
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        print(json.dumps(results, indent=2))