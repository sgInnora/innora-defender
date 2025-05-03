#!/usr/bin/env python3
"""
Ransomware Family Relationship Graph Visualization

This module generates visualization of relationships between ransomware families and variants
to facilitate analysis and understanding of ransomware evolution.
"""

import os
import sys
import json
import logging
import datetime
from typing import Dict, List, Any, Optional, Set, Tuple, Union
import hashlib

# Add parent directory to path to import from threat_intel
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(script_dir)
sys.path.append(parent_dir)

from family_detection.integration_with_variant import AdvancedFamilyDetectionIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('relationship_graph')

class RelationshipGraph:
    """
    Ransomware family relationship graph generator
    
    This class analyzes ransomware families and variants to generate
    relationship graphs that visualize their connections.
    """
    
    def __init__(self, 
                detection: Optional[AdvancedFamilyDetectionIntegration] = None,
                families_dir: Optional[str] = None,
                yara_rules_dir: Optional[str] = None,
                clusters_dir: Optional[str] = None,
                output_dir: Optional[str] = None,
                min_confidence: float = 0.6):
        """
        Initialize the relationship graph generator
        
        Args:
            detection: AdvancedFamilyDetectionIntegration instance
            families_dir: Directory containing family definition files
            yara_rules_dir: Directory containing YARA rules
            clusters_dir: Directory containing variant clusters
            output_dir: Directory for output files
            min_confidence: Minimum confidence threshold for including variants
        """
        # Initialize detection integration
        self.detection = detection or AdvancedFamilyDetectionIntegration(
            families_dir=families_dir,
            yara_rules_dir=yara_rules_dir,
            clusters_dir=clusters_dir,
            auto_variant_detection=True
        )
        
        # Initialize output directory
        self.output_dir = output_dir or os.path.join(parent_dir, 'data', 'visualization')
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Initialize configuration
        self.min_confidence = min_confidence
        
        logger.info("Relationship graph generator initialized")
    
    def generate_d3_graph(self) -> Dict[str, Any]:
        """
        Generate D3.js compatible graph data
        
        Returns:
            Dictionary containing nodes and links for D3.js visualization
        """
        # Get family and variant data
        families = self.detection.get_all_family_names()
        
        # Prepare graph data
        nodes = []
        links = []
        node_ids = {}  # Maps family/variant names to node IDs
        
        # Process base families
        for i, family in enumerate(families):
            if not family.get('is_variant', False):
                family_id = family.get('id', 'unknown')
                family_name = family.get('name', family_id)
                
                # Add family node
                node_id = f"family_{i}"
                nodes.append({
                    "id": node_id,
                    "name": family_name,
                    "full_name": family_name,
                    "type": "family",
                    "family_id": family_id,
                    "group": 1,
                    "size": 10
                })
                
                # Store node ID mapping
                node_ids[family_id] = node_id
        
        # Process variants
        variant_count = 0
        for family in families:
            if family.get('is_variant', False):
                base_family = family.get('base_family', 'unknown')
                variant_name = family.get('name', 'unknown')
                variant_id = family.get('id', 'unknown')
                confidence = family.get('confidence', 0)
                
                # Skip variants with low confidence
                if confidence < self.min_confidence:
                    continue
                
                # Add variant node
                node_id = f"variant_{variant_count}"
                variant_count += 1
                
                nodes.append({
                    "id": node_id,
                    "name": self._get_short_variant_name(variant_name, base_family),
                    "full_name": variant_name,
                    "type": "variant",
                    "variant_id": variant_id,
                    "base_family": base_family,
                    "confidence": confidence,
                    "group": 2,
                    "size": 5 + min(confidence * 5, 5)  # Size based on confidence
                })
                
                # Store node ID mapping
                node_ids[variant_id] = node_id
                
                # Add link to base family
                if base_family in node_ids:
                    links.append({
                        "source": node_ids[base_family],
                        "target": node_id,
                        "value": 1,
                        "type": "variant_of",
                        "confidence": confidence
                    })
        
        # Add family relationships
        for family in families:
            if not family.get('is_variant', False):
                family_id = family.get('id', 'unknown')
                family_data = self.detection.refine_family_information(family_id)
                
                # Check for family relationships
                if family_data.get('related_families'):
                    for related in family_data.get('related_families', []):
                        related_id = related.get('family_id', 'unknown')
                        relationship = related.get('relationship', 'related')
                        strength = related.get('strength', 0.5)
                        
                        # Skip if related family is not in graph
                        if related_id not in node_ids:
                            continue
                        
                        # Add relationship link
                        links.append({
                            "source": node_ids[family_id],
                            "target": node_ids[related_id],
                            "value": strength,
                            "type": relationship,
                            "strength": strength
                        })
        
        # Add variant relationships
        if self.detection.variant_detector:
            valid_variants = self.detection.variant_detector.evaluate_clusters()
            
            for variant in valid_variants:
                # Get variant ID
                variant_id = variant.get('cluster_id', 'unknown')
                
                # Skip if variant is not in graph
                if variant_id not in node_ids:
                    continue
                
                # Check for similar variants
                similar_variants = self._find_similar_variants(variant, valid_variants)
                
                for similar_id, similarity in similar_variants:
                    # Skip if similar variant is not in graph
                    if similar_id not in node_ids:
                        continue
                    
                    # Add similarity link
                    links.append({
                        "source": node_ids[variant_id],
                        "target": node_ids[similar_id],
                        "value": similarity,
                        "type": "similar_to",
                        "similarity": similarity
                    })
        
        # Finalize graph data
        graph_data = {
            "nodes": nodes,
            "links": links
        }
        
        return graph_data
    
    def _get_short_variant_name(self, variant_name: str, base_family: str) -> str:
        """
        Get a short name for a variant
        
        Args:
            variant_name: Variant name
            base_family: Base family name
            
        Returns:
            Short variant name
        """
        # Remove base family prefix if present
        if variant_name.lower().startswith(base_family.lower()):
            short_name = variant_name[len(base_family):].strip('_-. ')
            return short_name
        
        # Otherwise return original name
        return variant_name
    
    def _find_similar_variants(self, variant: Dict[str, Any], all_variants: List[Dict[str, Any]]) -> List[Tuple[str, float]]:
        """
        Find similar variants based on feature analysis
        
        Args:
            variant: Variant information
            all_variants: List of all variants
            
        Returns:
            List of tuples (variant_id, similarity_score)
        """
        similar_variants = []
        variant_id = variant.get('cluster_id', 'unknown')
        
        for other in all_variants:
            other_id = other.get('cluster_id', 'unknown')
            
            # Skip self-comparison
            if other_id == variant_id:
                continue
            
            # Calculate similarity
            similarity = self._calculate_variant_similarity(variant, other)
            
            # Add if similarity is above threshold
            if similarity > 0.5:
                similar_variants.append((other_id, similarity))
        
        # Sort by similarity (descending)
        similar_variants.sort(key=lambda x: x[1], reverse=True)
        
        # Return top 3 similar variants
        return similar_variants[:3]
    
    def _calculate_variant_similarity(self, variant1: Dict[str, Any], variant2: Dict[str, Any]) -> float:
        """
        Calculate similarity between two variants
        
        Args:
            variant1: First variant information
            variant2: Second variant information
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Check if they share the same base family
        if variant1.get('base_family') == variant2.get('base_family'):
            base_similarity = 0.5
        else:
            base_similarity = 0.0
        
        # Check feature similarity if we have a variant detector
        if self.detection.variant_detector:
            cluster1 = self.detection.variant_detector.clusters.get(variant1.get('cluster_id'))
            cluster2 = self.detection.variant_detector.clusters.get(variant2.get('cluster_id'))
            
            if cluster1 and cluster2:
                # Compare common features
                feature_similarity = 0.0
                
                # Get common feature categories
                common_categories = set(cluster1.common_features.keys()).intersection(
                    set(cluster2.common_features.keys())
                )
                
                # Compare features in each category
                for category in common_categories:
                    cat_sim = self._compare_feature_category(
                        cluster1.common_features.get(category, {}),
                        cluster2.common_features.get(category, {})
                    )
                    feature_similarity += cat_sim
                
                # Normalize
                if common_categories:
                    feature_similarity /= len(common_categories)
                
                # Combine with base similarity
                return (base_similarity + feature_similarity) / 2
        
        # Fallback to relationship scores
        relationship_diff = abs(
            variant1.get('relationship_score', 0) - variant2.get('relationship_score', 0)
        )
        
        # Calculate total similarity
        return base_similarity * (1 - relationship_diff)
    
    def _compare_feature_category(self, features1: Union[Dict, List], features2: Union[Dict, List]) -> float:
        """
        Compare features in a category
        
        Args:
            features1: Features from first variant
            features2: Features from second variant
            
        Returns:
            Similarity score (0.0 to 1.0)
        """
        # Handle dictionary features
        if isinstance(features1, dict) and isinstance(features2, dict):
            # Get common keys
            common_keys = set(features1.keys()).intersection(set(features2.keys()))
            all_keys = set(features1.keys()).union(set(features2.keys()))
            
            # Check if dictionaries are empty
            if not all_keys:
                return 1.0
            
            # Calculate Jaccard similarity
            return len(common_keys) / len(all_keys)
        
        # Handle list features
        elif isinstance(features1, list) and isinstance(features2, list):
            # Convert to sets
            set1 = set(features1)
            set2 = set(features2)
            
            # Check if lists are empty
            if not set1 and not set2:
                return 1.0
            
            # Calculate Jaccard similarity
            intersection = len(set1.intersection(set2))
            union = len(set1.union(set2))
            
            return intersection / union if union > 0 else 0.0
        
        # Different types, no meaningful comparison
        return 0.0
    
    def generate_html_visualization(self, output_file: Optional[str] = None) -> str:
        """
        Generate an HTML file with D3.js visualization
        
        Args:
            output_file: Output file path
            
        Returns:
            Path to the generated HTML file
        """
        # Generate graph data
        graph_data = self.generate_d3_graph()
        
        # Create output file name if not provided
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            output_file = os.path.join(self.output_dir, f"ransomware_relationship_graph_{timestamp}.html")
        
        # Create HTML content
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Ransomware Family Relationship Graph</title>
    <style>
        body {{
            margin: 0;
            font-family: Arial, sans-serif;
            overflow: hidden;
        }}
        
        #graph-container {{
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
        }}
        
        .node {{
            stroke: #fff;
            stroke-width: 1.5px;
        }}
        
        .link {{
            stroke: #999;
            stroke-opacity: 0.6;
        }}
        
        .family-node {{
            fill: #3498db;
        }}
        
        .variant-node {{
            fill: #e74c3c;
        }}
        
        .tooltip {{
            position: absolute;
            background-color: rgba(0, 0, 0, 0.7);
            color: white;
            padding: 10px;
            border-radius: 5px;
            pointer-events: none;
            z-index: 10;
            display: none;
            max-width: 300px;
        }}
        
        #controls {{
            position: absolute;
            top: 10px;
            left: 10px;
            background-color: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 5px;
            z-index: 5;
        }}
        
        #legend {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background-color: rgba(255, 255, 255, 0.8);
            padding: 10px;
            border-radius: 5px;
            z-index: 5;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }}
        
        .legend-color {{
            width: 15px;
            height: 15px;
            margin-right: 5px;
            border-radius: 50%;
        }}
        
        .legend-text {{
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div id="graph-container"></div>
    <div id="tooltip" class="tooltip"></div>
    
    <div id="controls">
        <h3>Ransomware Family Relationships</h3>
        <div>
            <label for="link-strength">Link Strength: </label>
            <input type="range" id="link-strength" min="0" max="100" value="30">
        </div>
        <div>
            <label for="node-repulsion">Node Repulsion: </label>
            <input type="range" id="node-repulsion" min="0" max="100" value="50">
        </div>
        <div>
            <button id="reset-zoom">Reset Zoom</button>
        </div>
    </div>
    
    <div id="legend">
        <h4>Legend</h4>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #3498db;"></div>
            <div class="legend-text">Ransomware Family</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #e74c3c;"></div>
            <div class="legend-text">Ransomware Variant</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #999; border-radius: 0;"></div>
            <div class="legend-text">Relationship</div>
        </div>
    </div>
    
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script>
        // Graph data
        const graphData = {JSON_GRAPH_DATA};
        
        // Configuration
        const width = window.innerWidth;
        const height = window.innerHeight;
        const nodeRadius = {
            family: 12,
            variant: 8
        };
        
        // Create SVG element
        const svg = d3.select("#graph-container")
            .append("svg")
            .attr("width", width)
            .attr("height", height)
            .attr("viewBox", [0, 0, width, height])
            .call(d3.zoom().on("zoom", zoomed));
        
        const container = svg.append("g");
        
        // Create tooltip
        const tooltip = d3.select("#tooltip");
        
        // Create simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-500))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .on("tick", ticked);
        
        // Create links
        const link = container.append("g")
            .selectAll("line")
            .data(graphData.links)
            .join("line")
            .attr("class", "link")
            .style("stroke-width", d => Math.sqrt(d.value) * 2)
            .style("stroke", d => getLinkColor(d.type));
        
        // Create nodes
        const node = container.append("g")
            .selectAll("circle")
            .data(graphData.nodes)
            .join("circle")
            .attr("class", d => `node \${d.type}-node`)
            .attr("r", d => getNodeRadius(d))
            .attr("fill", d => getNodeColor(d.type))
            .call(drag(simulation))
            .on("mouseover", showTooltip)
            .on("mousemove", moveTooltip)
            .on("mouseout", hideTooltip);
        
        // Create labels
        const label = container.append("g")
            .selectAll("text")
            .data(graphData.nodes)
            .join("text")
            .attr("class", "node-label")
            .attr("font-size", 10)
            .attr("dx", 12)
            .attr("dy", ".35em")
            .text(d => d.name);
        
        // Handle controls
        d3.select("#link-strength").on("input", function() {
            const strength = +this.value / 100 * 200;
            simulation.force("link").distance(strength);
            simulation.alpha(0.3).restart();
        });
        
        d3.select("#node-repulsion").on("input", function() {
            const repulsion = -+this.value * 20;
            simulation.force("charge").strength(repulsion);
            simulation.alpha(0.3).restart();
        });
        
        d3.select("#reset-zoom").on("click", function() {
            svg.transition()
                .duration(750)
                .call(d3.zoom().transform, d3.zoomIdentity);
        });
        
        // Utility functions
        function zoomed(event) {
            container.attr("transform", event.transform);
        }
        
        function ticked() {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
            
            label
                .attr("x", d => d.x)
                .attr("y", d => d.y);
        }
        
        function drag(simulation) {
            function dragstarted(event) {
                if (!event.active) simulation.alphaTarget(0.3).restart();
                event.subject.fx = event.subject.x;
                event.subject.fy = event.subject.y;
            }
            
            function dragged(event) {
                event.subject.fx = event.x;
                event.subject.fy = event.y;
            }
            
            function dragended(event) {
                if (!event.active) simulation.alphaTarget(0);
                event.subject.fx = null;
                event.subject.fy = null;
            }
            
            return d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended);
        }
        
        function getNodeRadius(node) {
            const baseRadius = nodeRadius[node.type] || 8;
            return baseRadius * (node.size / 10);
        }
        
        function getNodeColor(type) {
            switch (type) {
                case "family":
                    return "#3498db";
                case "variant":
                    return "#e74c3c";
                default:
                    return "#95a5a6";
            }
        }
        
        function getLinkColor(type) {
            switch (type) {
                case "variant_of":
                    return "#2ecc71";
                case "similar_to":
                    return "#9b59b6";
                case "related":
                    return "#f39c12";
                default:
                    return "#999";
            }
        }
        
        function showTooltip(event, d) {
            let tooltipContent = `<strong>\${d.full_name}</strong><br>`;
            tooltipContent += `Type: \${d.type}<br>`;
            
            if (d.type === "family") {
                tooltipContent += `Family ID: \${d.family_id}<br>`;
            } else if (d.type === "variant") {
                tooltipContent += `Base Family: \${d.base_family}<br>`;
                tooltipContent += `Confidence: \${(d.confidence * 100).toFixed(1)}%<br>`;
            }
            
            tooltip
                .html(tooltipContent)
                .style("display", "block");
            
            moveTooltip(event);
        }
        
        function moveTooltip(event) {
            tooltip
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY + 10) + "px");
        }
        
        function hideTooltip() {
            tooltip.style("display", "none");
        }
    </script>
</body>
</html>
"""
        
        # Replace JSON_GRAPH_DATA placeholder with actual data
        html_content = html_content.replace("{JSON_GRAPH_DATA}", json.dumps(graph_data))
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML visualization: {output_file}")
        
        return output_file
    
    def generate_json_data(self, output_file: Optional[str] = None) -> str:
        """
        Generate JSON data file for external visualization
        
        Args:
            output_file: Output file path
            
        Returns:
            Path to the generated JSON file
        """
        # Generate graph data
        graph_data = self.generate_d3_graph()
        
        # Create output file name if not provided
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            output_file = os.path.join(self.output_dir, f"ransomware_relationship_data_{timestamp}.json")
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(graph_data, f, indent=2)
        
        logger.info(f"Generated JSON data: {output_file}")
        
        return output_file


def create_relationship_graph(families_dir: Optional[str] = None,
                            yara_rules_dir: Optional[str] = None,
                            clusters_dir: Optional[str] = None,
                            output_dir: Optional[str] = None,
                            min_confidence: float = 0.6) -> RelationshipGraph:
    """
    Create a relationship graph generator
    
    Args:
        families_dir: Directory containing family definition files
        yara_rules_dir: Directory containing YARA rules
        clusters_dir: Directory containing variant clusters
        output_dir: Directory for output files
        min_confidence: Minimum confidence threshold for including variants
        
    Returns:
        RelationshipGraph instance
    """
    return RelationshipGraph(
        families_dir=families_dir,
        yara_rules_dir=yara_rules_dir,
        clusters_dir=clusters_dir,
        output_dir=output_dir,
        min_confidence=min_confidence
    )


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Family Relationship Graph")
    parser.add_argument('--families-dir', help='Directory containing family definitions')
    parser.add_argument('--yara-rules-dir', help='Directory containing YARA rules')
    parser.add_argument('--clusters-dir', help='Directory containing variant clusters')
    parser.add_argument('--output-dir', help='Directory for output files')
    parser.add_argument('--output-file', help='Output file path')
    parser.add_argument('--min-confidence', type=float, default=0.6, help='Minimum confidence threshold')
    parser.add_argument('--format', choices=['html', 'json'], default='html', help='Output format')
    
    args = parser.parse_args()
    
    # Create relationship graph generator
    graph_generator = create_relationship_graph(
        families_dir=args.families_dir,
        yara_rules_dir=args.yara_rules_dir,
        clusters_dir=args.clusters_dir,
        output_dir=args.output_dir,
        min_confidence=args.min_confidence
    )
    
    # Generate visualization
    if args.format == 'html':
        output_file = graph_generator.generate_html_visualization(args.output_file)
    else:
        output_file = graph_generator.generate_json_data(args.output_file)
    
    print(f"Generated {args.format} file: {output_file}")