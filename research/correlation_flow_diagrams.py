#!/usr/bin/env python3
"""
correlation_flow_diagrams.py

Generates visual diagrams showing how findings in one module trigger 
analysis in subsequent modules across the three scenarios.

Requires: matplotlib, networkx
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import numpy as np

def plot_correlation_architecture():
    """
    Generate the overall Cybersleuth correlation architecture diagram
    """
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Define module boxes and positions
    modules = {
        "Packet Capture": (7, 9, "#E3F2FD"),
        "Network Anomaly\nDetection": (7, 7, "#FFECB3"),
        "Phishing Detector": (7, 5, "#F3E5F5"),
        "Web Scanner": (7, 3, "#E8F5E9"),
        "Correlation Engine": (7, 1, "#FFEBEE"),
    }
    
    # Draw module boxes
    for module_name, (x, y, color) in modules.items():
        box = FancyBboxPatch(
            (x - 1.5, y - 0.4), 3, 0.8,
            boxstyle="round,pad=0.1",
            edgecolor='black', facecolor=color, linewidth=2
        )
        ax.add_patch(box)
        ax.text(x, y, module_name, ha='center', va='center', 
               fontweight='bold', fontsize=10)
    
    # Draw decision arrows with thresholds
    decisions = [
        ((7, 8.6), (7, 7.4), "All packets", "black", 1),
        ((7, 6.6), (7, 5.4), "If anomaly\nscore > 0.5", "#FF6B00", 2),
        ((7, 4.6), (7, 3.4), "If phishing\nconfidence ≥ 75%", "#7B1FA2", 2),
        ((7, 2.6), (7, 1.4), "Combine all\nsignals", "#C62828", 2),
    ]
    
    for (x1, y1), (x2, y2), label, color, width in decisions:
        arrow = FancyArrowPatch(
            (x1, y1), (x2, y2),
            arrowstyle='->', mutation_scale=30, linewidth=width,
            color=color, alpha=0.8
        )
        ax.add_patch(arrow)
        
        # Label on arrow
        mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mid_x + 1.0, mid_y, label, fontsize=8, style='italic',
               bbox=dict(boxstyle='round', facecolor='white', alpha=0.85, edgecolor=color))
    
    # Add bypassable exit (no escalation path)
    bypass_x = 4.5
    ax.annotate('', xy=(bypass_x, 5.4), xytext=(bypass_x, 1.4),
               arrowprops=dict(arrowstyle='->', color='green', lw=1.5, linestyle='--'))
    ax.text(bypass_x - 0.7, 3.4, "No escalation\n(LOW risk)", fontsize=8, 
           color='green', fontweight='bold',
           bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.7))
    
    # Add module output descriptions
    outputs = [
        (9.8, 7, "Anomaly Score\n(0-1)"),
        (9.8, 5, "Phishing Verdict\nConfidence (%)"),
        (9.8, 3, "Vulnerabilities\nFound"),
        (9.8, 1, "Composite Risk\nScore (0-10)"),
    ]
    
    for x, y, label in outputs:
        ax.text(x, y, label, fontsize=7, ha='left',
               bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))
    
    # Add legend
    legend_y = 10
    ax.text(0.5, legend_y, "Cybersleuth Correlation Flow", fontsize=12, 
           fontweight='bold', bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
    
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 10.5)
    ax.axis('off')
    ax.set_aspect('equal')
    
    plt.title("Figure 10.1: Cybersleuth Module Correlation Architecture\n" + 
             "Cascade model with decision gates at each module boundary",
             fontsize=13, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('figure_10_1_correlation_architecture.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_10_1_correlation_architecture.png")
    plt.close()

def plot_scenario_correlation_flows():
    """
    Generate three side-by-side diagrams showing correlation flow for each scenario
    """
    fig, axes = plt.subplots(1, 3, figsize=(16, 6))
    
    scenarios = [
        {
            "name": "Scenario 1: Credential Harvesting",
            "color": "#FF6B6B",
            "flow": [
                ("Network Analysis", "Anomaly: 0.92", True),
                ("Phishing Detector", "Confidence: 94%", True),
                ("Web Scanner", "3 Vulns Found", True),
                ("Alert", "CRITICAL (8.9/10)", True),
            ]
        },
        {
            "name": "Scenario 2: Benign SaaS",
            "color": "#4CAF50",
            "flow": [
                ("Network Analysis", "Anomaly: 0.08", False),
                ("(Bypassed)", "Score too low", False),
                ("(No Scanner)", "No escalation", False),
                ("Alert", "SAFE (1.0/10)", False),
            ]
        },
        {
            "name": "Scenario 3: C2 Beacon",
            "color": "#FFA500",
            "flow": [
                ("Network Analysis", "Anomaly: 0.87", True),
                ("Phishing Detector", "Confidence: 78%", True),
                ("Web Scanner", "Signature: 82%", True),
                ("Alert", "CRITICAL (9.4/10)", True),
            ]
        }
    ]
    
    for idx, (ax, scenario) in enumerate(zip(axes, scenarios)):
        color = scenario["color"]
        
        # Title
        ax.text(0.5, 1.0, scenario["name"], ha='center', fontsize=11, fontweight='bold',
               transform=ax.transAxes, bbox=dict(boxstyle='round', facecolor=color, 
                alpha=0.3, edgecolor=color, linewidth=2))
        
        # Flow steps
        flow = scenario["flow"]
        y_positions = np.linspace(0.9, 0.1, len(flow))
        
        for step_idx, (y, (module, result, escalated)) in enumerate(zip(y_positions, flow)):
            # Box color based on escalation
            box_color = "lightgreen" if escalated else "lightgray"
            edge_color = color if escalated else "gray"
            edge_width = 2 if escalated else 1
            
            # Module box
            box = mpatches.FancyBboxPatch(
                (0.05, y - 0.04), 0.9, 0.08,
                boxstyle="round,pad=0.01", transform=ax.transAxes,
                facecolor=box_color, edgecolor=edge_color, linewidth=edge_width
            )
            ax.add_patch(box)
            
            # Module name (left)
            ax.text(0.08, y, module, fontsize=9, fontweight='bold', va='center',
                   transform=ax.transAxes)
            
            # Result (right)
            ax.text(0.92, y, result, fontsize=8, ha='right', va='center',
                   transform=ax.transAxes, style='italic')
            
            # Arrow to next step
            if step_idx < len(flow) - 1:
                arrow = FancyArrowPatch(
                    (0.5, y - 0.05), (0.5, y_positions[step_idx + 1] + 0.05),
                    arrowstyle='->', mutation_scale=20, linewidth=1.5,
                    color=edge_color, alpha=0.6, transform=ax.transAxes
                )
                ax.add_patch(arrow)
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis('off')
    
    plt.suptitle("Figure 10.2: Correlation Flow Across Scenarios\n" +
                "Green (escalated) vs Gray (bypassed) modules show decision logic",
                fontsize=13, fontweight='bold', y=0.98)
    
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig('figure_10_2_scenario_correlation_flows.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_10_2_scenario_correlation_flows.png")
    plt.close()

def plot_interdependency_heatmap():
    """
    Generate a heatmap showing module interdependencies and signal strength
    """
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Interdependency matrix
    modules = ["Network\nAnomaly", "Phishing\nDetector", "Web\nScanner", "Correlation\nEngine"]
    
    # Dependency strength: 0 = no dependency, 1 = critical dependency
    dependency_matrix = np.array([
        [0.0,   0.95,  0.0,   0.0],    # Network → Phishing (high)
        [0.3,   0.0,   0.92,  0.0],    # Phishing → Scanner (high)
        [0.1,   0.4,   0.0,   0.95],   # Scanner → Correlation (high)
        [0.9,   0.9,   0.85,  0.0],    # All → Correlation (all high)
    ])
    
    # Create heatmap
    im = ax.imshow(dependency_matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)
    
    # Labels
    ax.set_xticks(np.arange(len(modules)))
    ax.set_yticks(np.arange(len(modules)))
    ax.set_xticklabels(modules, fontsize=10, fontweight='bold')
    ax.set_yticklabels(modules, fontsize=10, fontweight='bold')
    
    # Rotate x labels
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
    
    # Add text annotations
    for i in range(len(modules)):
        for j in range(len(modules)):
            value = dependency_matrix[i, j]
            if value > 0:
                text_color = "white" if value > 0.6 else "black"
                text = ax.text(j, i, f"{value:.2f}", ha="center", va="center",
                             color=text_color, fontweight='bold', fontsize=10)
    
    # Colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label("Dependency Strength", rotation=270, labelpad=20, fontweight='bold')
    
    ax.set_title("Figure 10.3: Module Interdependency Matrix\n" +
                "How strongly each module depends on outputs from others",
                fontsize=12, fontweight='bold', pad=20)
    
    plt.tight_layout()
    plt.savefig('figure_10_3_interdependency_heatmap.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_10_3_interdependency_heatmap.png")
    plt.close()

def plot_correlation_strength_comparison():
    """
    Generate a comparison chart showing correlation strength across scenarios
    """
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    # Scenario data
    scenarios = ['Scenario 1\n(Harvest)', 'Scenario 2\n(Benign)', 'Scenario 3\n(C2)']
    
    # 1. Module Agreement Score
    ax = axes[0, 0]
    agreement_scores = [
        (0.92 + 0.94) / 2,  # Scenario 1: avg of anomaly and phishing
        (0.08 + 0.02) / 2,  # Scenario 2: avg
        (0.87 + 0.78) / 2,  # Scenario 3: avg
    ]
    colors = ['#FF6B6B', '#4CAF50', '#FFA500']
    bars = ax.bar(scenarios, agreement_scores, color=colors, edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Module Agreement Score (0-1)", fontweight='bold')
    ax.set_title("Module 1 & 2 Signal Agreement", fontweight='bold')
    ax.set_ylim(0, 1)
    for bar, score in zip(bars, agreement_scores):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
               f"{score:.2f}", ha='center', fontweight='bold', fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    
    # 2. Correlation Strength (by # of modules triggered)
    ax = axes[0, 1]
    modules_triggered = [3, 1, 3]  # Scenario 1: 3 modules, Scenario 2: 1 module, Scenario 3: 3 modules
    bars = ax.bar(scenarios, [m/3 for m in modules_triggered], color=colors, 
                  edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Modules Triggered (normalized to 3)", fontweight='bold')
    ax.set_title("Escalation Depth (# Modules Involved)", fontweight='bold')
    ax.set_ylim(0, 1.1)
    for bar, modules in zip(bars, modules_triggered):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
               f"{modules}/3 modules", ha='center', fontweight='bold', fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    
    # 3. Signal Combination Index
    ax = axes[1, 0]
    # How well signals reinforce each other
    signal_combo = [
        0.95,  # Scenario 1: very high (all agree)
        0.05,  # Scenario 2: very low (all agree it's safe, but low urgency)
        0.82,  # Scenario 3: high (network + phishing + signature match)
    ]
    bars = ax.bar(scenarios, signal_combo, color=colors, edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Signal Reinforcement Index (0-1)", fontweight='bold')
    ax.set_title("How Well Signals Reinforce Each Other", fontweight='bold')
    ax.set_ylim(0, 1)
    for bar, combo in zip(bars, signal_combo):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02, 
               f"{combo:.2f}", ha='center', fontweight='bold', fontsize=9)
    ax.axhline(y=0.5, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='Threshold')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # 4. Final Risk Score vs Correlation Strength
    ax = axes[1, 1]
    final_risks = [8.9, 1.0, 9.4]
    correlation_strengths = [0.95, 0.05, 0.82]
    
    scatter = ax.scatter(correlation_strengths, final_risks, s=500, c=colors, 
                        edgecolor='black', linewidth=2, alpha=0.8)
    
    # Add scenario labels
    for i, scenario in enumerate(scenarios):
        ax.text(correlation_strengths[i] + 0.03, final_risks[i], scenario.replace('\n', ' '), 
               fontsize=9, fontweight='bold')
    
    ax.set_xlabel("Correlation Strength (Module Agreement)", fontweight='bold')
    ax.set_ylabel("Final Risk Score (0-10)", fontweight='bold')
    ax.set_title("Correlation Strength → Final Risk Score", fontweight='bold')
    ax.set_xlim(-0.05, 1.1)
    ax.set_ylim(-0.5, 10.5)
    ax.grid(alpha=0.3)
    
    # Add trend line
    z = np.polyfit(correlation_strengths, final_risks, 1)
    p = np.poly1d(z)
    x_trend = np.linspace(0, 1, 100)
    ax.plot(x_trend, p(x_trend), "k--", alpha=0.5, linewidth=1.5, label='Trend')
    ax.legend()
    
    plt.suptitle("Figure 10.4: Correlation Strength Analysis Across Scenarios",
                fontsize=13, fontweight='bold', y=0.995)
    
    plt.tight_layout()
    plt.savefig('figure_10_4_correlation_strength_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_10_4_correlation_strength_comparison.png")
    plt.close()

def main():
    print("Generating Correlation Analysis Visualization Figures...\n")
    
    plot_correlation_architecture()
    plot_scenario_correlation_flows()
    plot_interdependency_heatmap()
    plot_correlation_strength_comparison()
    
    print("\n✓ All correlation figures generated successfully!")
    print("Generated files:")
    print("  • figure_10_1_correlation_architecture.png")
    print("  • figure_10_2_scenario_correlation_flows.png")
    print("  • figure_10_3_interdependency_heatmap.png")
    print("  • figure_10_4_correlation_strength_comparison.png")

if __name__ == "__main__":
    main()
