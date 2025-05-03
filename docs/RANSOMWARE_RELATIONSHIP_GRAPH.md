# Ransomware Family Relationship Graph

This document provides an overview of the ransomware family relationship graph visualization system, which helps analysts understand the connections between different ransomware families and their variants.

## Overview

The relationship graph visualization system provides insights into how different ransomware families and variants are related to each other. It analyzes the features and characteristics of ransomware samples to identify relationships and similarities, and presents this information in an interactive visualization.

Key features:

- **Family-Variant Relationships**: Visualize the relationships between base ransomware families and their variants
- **Cross-Family Similarities**: Identify similarities between variants of different ransomware families
- **Interactive Visualization**: Explore the relationship graph with zoom, pan, and hover capabilities
- **Feature-Based Analysis**: Analyze the distinctive features of each variant
- **Confidence Scoring**: Understand the confidence level of detected relationships
- **Customizable Visualization**: Adjust link strength, node repulsion, and other parameters
- **Export Options**: Generate HTML visualizations or JSON data for external tools

## Architecture

The relationship graph visualization system consists of several components:

1. **RelationshipGraph**: Core component that analyzes family and variant data to generate graph data
2. **D3.js Visualization**: Interactive web-based visualization using D3.js
3. **CLI**: Command-line interface for generating visualizations and analyzing relationships
4. **JSON Export**: Export graph data for use in external visualization tools

## Installation

The visualization system is integrated with the existing threat intelligence framework. No additional installation is required beyond the dependencies for the enhanced family detection and automatic variant detection systems.

## Usage

### Command-line Interface

The visualization system provides a command-line interface for generating visualizations and analyzing relationships.

```bash
# Generate a relationship graph
python -m threat_intel.visualization.graph_cli generate --format html --open-browser

# List available families and variants
python -m threat_intel.visualization.graph_cli list --show-variants

# Analyze similarities between variants
python -m threat_intel.visualization.graph_cli similarities --limit 20 --output similarities.json

# Analyze a specific variant
python -m threat_intel.visualization.graph_cli variant --variant-name lockbit_variant_20230101 --output variant_analysis.json
```

### Command Options

#### Generate Command

```bash
python -m threat_intel.visualization.graph_cli generate [options]
```

Options:
- `--families-dir DIR`: Directory containing family definitions
- `--yara-rules-dir DIR`: Directory containing YARA rules
- `--clusters-dir DIR`: Directory containing variant clusters
- `--output-dir DIR`: Directory for output files
- `--output-file FILE`: Output file path
- `--format FORMAT`: Output format (html or json, default: html)
- `--min-confidence FLOAT`: Minimum confidence threshold (default: 0.6)
- `--open-browser`: Open HTML file in browser

#### List Command

```bash
python -m threat_intel.visualization.graph_cli list [options]
```

Options:
- `--families-dir DIR`: Directory containing family definitions
- `--yara-rules-dir DIR`: Directory containing YARA rules
- `--clusters-dir DIR`: Directory containing variant clusters
- `--min-confidence FLOAT`: Minimum confidence threshold (default: 0.6)
- `--show-variants`: Show variants for each family

#### Similarities Command

```bash
python -m threat_intel.visualization.graph_cli similarities [options]
```

Options:
- `--families-dir DIR`: Directory containing family definitions
- `--yara-rules-dir DIR`: Directory containing YARA rules
- `--clusters-dir DIR`: Directory containing variant clusters
- `--min-confidence FLOAT`: Minimum confidence threshold (default: 0.6)
- `--limit INT`: Maximum number of similarities to show (default: 10)
- `--output FILE`: Output file for JSON data

#### Variant Command

```bash
python -m threat_intel.visualization.graph_cli variant [options]
```

Options:
- `--families-dir DIR`: Directory containing family definitions
- `--yara-rules-dir DIR`: Directory containing YARA rules
- `--clusters-dir DIR`: Directory containing variant clusters
- `--min-confidence FLOAT`: Minimum confidence threshold (default: 0.6)
- `--variant-id ID`: Variant cluster ID
- `--variant-name NAME`: Variant name
- `--output FILE`: Output file for JSON data

## Visualization Layout

The relationship graph visualization is an interactive HTML page that uses D3.js for rendering. It includes the following components:

- **Nodes**: Represent ransomware families (blue) and variants (red)
- **Links**: Represent relationships between nodes (variant_of, similar_to, related)
- **Tooltips**: Show detailed information about nodes on hover
- **Controls**: Adjust link strength, node repulsion, and zoom
- **Legend**: Explain the meaning of node and link colors

### Node Types

- **Family Node**: Represents a base ransomware family (blue)
- **Variant Node**: Represents a ransomware variant (red)

### Link Types

- **Variant Of**: Links a variant to its base family (green)
- **Similar To**: Links similar variants (purple)
- **Related**: Links related families (orange)

### Tooltip Information

- **Family Node**: Name, family ID
- **Variant Node**: Name, base family, confidence

### Controls

- **Link Strength**: Adjust the distance between connected nodes
- **Node Repulsion**: Adjust the repulsion force between nodes
- **Reset Zoom**: Reset the zoom level to fit the graph

## Graph Data Format

The relationship graph visualization uses the following data format:

```json
{
  "nodes": [
    {
      "id": "family_0",
      "name": "LockBit",
      "full_name": "LockBit",
      "type": "family",
      "family_id": "lockbit",
      "group": 1,
      "size": 10
    },
    {
      "id": "variant_0",
      "name": "3.0",
      "full_name": "LockBit 3.0",
      "type": "variant",
      "variant_id": "lockbit_variant_3.0",
      "base_family": "lockbit",
      "confidence": 0.85,
      "group": 2,
      "size": 9.25
    }
  ],
  "links": [
    {
      "source": "family_0",
      "target": "variant_0",
      "value": 1,
      "type": "variant_of",
      "confidence": 0.85
    },
    {
      "source": "variant_0",
      "target": "variant_1",
      "value": 0.75,
      "type": "similar_to",
      "similarity": 0.75
    }
  ]
}
```

## Similarity Analysis

The relationship graph visualization uses multiple approaches to analyze similarities between ransomware variants:

1. **Base Family Relationship**: Variants of the same family have a base similarity
2. **Feature Analysis**: Compare common features between variants
   - String patterns
   - Behavior patterns
   - File structure
   - Ransomware extensions
   - Network indicators
   - YARA rule matches
3. **Jaccard Similarity**: Calculate similarity between feature sets
4. **Relationship Score**: Compare relationship to base family

Similarity scores range from 0.0 to 1.0, with higher scores indicating more similar variants.

## Use Cases

### Identifying Evolutionary Patterns

The relationship graph helps identify how ransomware families evolve over time, including:

- **Variant Progression**: Track the development of variants within a family
- **Feature Adoption**: Identify features that spread between variants
- **Cross-Family Influences**: Detect when features from one family appear in another

### Attributing New Samples

When a new ransomware sample is detected, the relationship graph can help:

- **Family Attribution**: Identify the most likely family based on feature analysis
- **Variant Classification**: Determine if the sample is a known or new variant
- **Confidence Assessment**: Evaluate the confidence level of the attribution

### Threat Intelligence Analysis

The relationship graph provides valuable insights for threat intelligence:

- **Campaign Tracking**: Identify related campaigns based on variant similarities
- **Actor Attribution**: Link variants to potential threat actors
- **Forecasting**: Predict likely future developments based on evolutionary patterns

## Implementation Details

### Similarity Calculation

The core similarity calculation algorithm compares feature categories between variants:

```python
def _calculate_variant_similarity(self, variant1, variant2):
    # Base similarity if they share the same family
    if variant1.get('base_family') == variant2.get('base_family'):
        base_similarity = 0.5
    else:
        base_similarity = 0.0
    
    # Feature similarity calculation
    feature_similarity = 0.0
    
    # Compare common feature categories
    common_categories = set(cluster1.common_features.keys()).intersection(
        set(cluster2.common_features.keys())
    )
    
    for category in common_categories:
        category_similarity = self._compare_feature_category(
            cluster1.common_features.get(category, {}),
            cluster2.common_features.get(category, {})
        )
        feature_similarity += category_similarity
    
    # Normalize
    if common_categories:
        feature_similarity /= len(common_categories)
    
    # Combine similarities
    return (base_similarity + feature_similarity) / 2
```

### Feature Comparison

Different types of features are compared using appropriate similarity metrics:

```python
def _compare_feature_category(self, features1, features2):
    # Dictionary features
    if isinstance(features1, dict) and isinstance(features2, dict):
        # Calculate Jaccard similarity of keys
        common_keys = set(features1.keys()).intersection(set(features2.keys()))
        all_keys = set(features1.keys()).union(set(features2.keys()))
        
        return len(common_keys) / len(all_keys) if all_keys else 1.0
    
    # List features
    elif isinstance(features1, list) and isinstance(features2, list):
        # Calculate Jaccard similarity of list items
        set1 = set(features1)
        set2 = set(features2)
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    # Different types
    return 0.0
```

## Performance Considerations

- The visualization is designed to handle hundreds of nodes and links
- For very large datasets, consider using the JSON export and a specialized visualization tool
- The similarity analysis can be computationally intensive, especially with many variants
- Adjust the minimum confidence threshold to focus on the most significant relationships

## Future Enhancements

- **Timeline Visualization**: Add temporal dimension to show family evolution over time
- **Geographic Overlay**: Add geographic information to show regional targeting
- **Threat Actor Attribution**: Link variants to known threat actors
- **Attack Vector Analysis**: Include information about infection vectors
- **Victim Industry Targeting**: Visualize targeting patterns by industry
- **Machine Learning Enhancement**: Use ML to improve similarity detection
- **Interactive Filtering**: Add interactive controls to filter by various attributes
- **3D Visualization**: Explore 3D visualizations for more complex relationships

## Related Documentation

- [Enhanced Family Detection](ENHANCED_FAMILY_DETECTION.md)
- [Automatic Variant Detection](AUTO_VARIANT_DETECTION.md)
- [Real-time Ransomware Monitoring](REALTIME_RANSOMWARE_MONITORING.md)