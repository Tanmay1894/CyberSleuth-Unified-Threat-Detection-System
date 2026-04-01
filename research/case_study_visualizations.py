#!/usr/bin/env python3
"""
case_study_visualizations.py

Generates timeline diagrams and data plots for Cybersleuth case studies.
Requires: matplotlib, numpy, pandas
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Styling
plt.rcParams['figure.figsize'] = (14, 8)
plt.rcParams['font.size'] = 9

def plot_scenario_1_timeline():
    """
    Figure 15: Scenario 1 Timeline - Credential Harvesting Attack
    """
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Timeline events
    events = [
        ("T0: Packet Capture Start", 0, "Network Analysis", "#FFE6E6"),
        ("T1: Anomaly Detection", 2.14, "Network Analysis", "#FFE6E6"),
        ("T2: Phishing Analysis", 4.46, "Phishing Detector", "#FFD9B3"),
        ("T3: Vulnerability Scan", 8.79, "Web Scanner", "#E6F3FF"),
        ("T4: Final Alert", 14.15, "Correlation Engine", "#E6FFE6"),
    ]
    
    # Y-axis positions for tracks
    tracks = {
        "Network Analysis": 5,
        "Phishing Detector": 3,
        "Web Scanner": 1,
        "Correlation Engine": -1,
    }
    
    # Draw timeline axis
    ax.axhline(y=0, color='black', linewidth=0.5, linestyle='--', alpha=0.5)
    
    # Draw events
    for event_name, time, track, color in events:
        y_pos = tracks[track]
        
        # Event box
        box = FancyBboxPatch(
            (time - 0.5, y_pos - 0.3), 1, 0.6,
            boxstyle="round,pad=0.05",
            edgecolor='black', facecolor=color, linewidth=1.5
        )
        ax.add_patch(box)
        
        # Event label (time + name)
        time_label = f"T{int(14.15 if time == 14.15 else time * 10 / 2.14)}" if time > 0 else "T0"
        ax.text(time, y_pos, f"{time_label}\n{time:.2f}s", 
                ha='center', va='center', fontweight='bold', fontsize=8)
        
        # Vertical connector to timeline
        ax.plot([time, time], [y_pos - 0.35, -0.1], 'k--', linewidth=0.5, alpha=0.3)
    
    # Add phase annotations
    phases = [
        (1.07, 6.5, "Phase 1:\nCapture & Analysis\n(2.14s)"),
        (6.63, 6.5, "Phase 2:\nPhishing + Scan\n(9.69s)"),
        (14.15, 6.5, "Phase 3:\nCorrelation\n(4.46s)"),
    ]
    
    for x, y, label in phases:
        ax.text(x, y, label, ha='center', fontsize=9, 
                bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.7))
    
    # Track labels
    for track, y in tracks.items():
        ax.text(-2, y, track, ha='right', fontweight='bold', fontsize=9)
    
    # Add key metrics on the right
    metrics_text = """
    Key Metrics:
    • Anomaly Score: 0.92 (HIGH)
    • Phishing Confidence: 94%
    • Scanner Findings: 3 vulns (HIGH)
    • Final Risk Score: 8.9/10 (CRITICAL)
    """
    ax.text(16, 3, metrics_text, fontsize=8, 
            bbox=dict(boxstyle='round', facecolor='mistyrose', alpha=0.8),
            family='monospace')
    
    ax.set_xlim(-3, 18)
    ax.set_ylim(-2, 7)
    ax.set_xlabel("Time (seconds)", fontweight='bold', fontsize=10)
    ax.set_title("Figure 15: Scenario 1 Timeline – Credential Harvesting Attack\nT0 capture → T1 anomaly → T2 phishing → T3 scan → T4 final alert (14.15s end-to-end)", 
                 fontweight='bold', fontsize=12)
    ax.set_yticks([])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig('figure_15_scenario1_timeline.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_15_scenario1_timeline.png")
    plt.close()

def plot_scenario_2_timeline():
    """
    Figure 16: Scenario 2 Timeline - Benign SaaS Traffic (No Escalation)
    """
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Timeline events
    events = [
        ("T0: Packet Capture", 0, "Network Analysis", "#E8F5E9"),
        ("T1: Anomaly Detect", 1.35, "Network Analysis", "#E8F5E9"),
        ("T2: Phishing Check", 2.68, "Phishing Detector", "#C8E6C9"),
        ("T3: No Escalation", 2.70, "Dashboard", "#A5D6A7"),
    ]
    
    tracks = {
        "Network Analysis": 3,
        "Phishing Detector": 1,
        "Dashboard": -1,
    }
    
    # Draw timeline
    ax.axhline(y=0, color='black', linewidth=0.5, linestyle='--', alpha=0.5)
    
    # Draw events
    for event_name, time, track, color in events:
        y_pos = tracks[track]
        
        # Event box
        box = FancyBboxPatch(
            (time - 0.4, y_pos - 0.3), 0.8, 0.6,
            boxstyle="round,pad=0.05",
            edgecolor='green', facecolor=color, linewidth=1.5
        )
        ax.add_patch(box)
        
        # Time label
        ax.text(time, y_pos, f"{time:.2f}s", 
                ha='center', va='center', fontweight='bold', fontsize=8, color='darkgreen')
        
        # Vertical connector
        ax.plot([time, time], [y_pos - 0.35, -0.1], 'g--', linewidth=0.5, alpha=0.3)
    
    # Phase label
    ax.text(1.35, 4.2, "BENIGN Traffic Flow\n(2.70s total detection)\nNO SCANNER ESCALATION", 
            ha='center', fontsize=10, fontweight='bold',
            bbox=dict(boxstyle='round', facecolor='lightgreen', alpha=0.8, edgecolor='green', linewidth=2))
    
    # Metrics
    metrics_text = """
    Key Metrics:
    • Anomaly Score: 0.08 (LOW)
    • Phishing Confidence: 2% malicious, 99% benign
    • GSB Verdict: SAFE
    • Auto-Scan Triggered: NO
    • Final Risk Score: 1.0/10 (SAFE)
    """
    ax.text(3, 1.5, metrics_text, fontsize=8, 
            bbox=dict(boxstyle='round', facecolor='honeydew', alpha=0.9),
            family='monospace')
    
    # Track labels
    for track, y in tracks.items():
        ax.text(-0.8, y, track, ha='right', fontweight='bold', fontsize=9, color='darkgreen')
    
    ax.set_xlim(-1.2, 4)
    ax.set_ylim(-2, 4.5)
    ax.set_xlabel("Time (seconds)", fontweight='bold', fontsize=10)
    ax.set_title("Figure 16: Scenario 2 Timeline – Benign Office 365 SaaS Traffic\nQuick, safe detection → No escalation → Low overhead", 
                 fontweight='bold', fontsize=12, color='darkgreen')
    ax.set_yticks([])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig('figure_16_scenario2_timeline.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_16_scenario2_timeline.png")
    plt.close()

def plot_scenario_3_timeline():
    """
    Figure 17: Scenario 3 Timeline - C2 Beacon with Exfiltration
    """
    fig, ax = plt.subplots(figsize=(14, 10))
    
    # Timeline events
    events = [
        ("T0: Capture", 0, "Network Analysis", "#FFE6E6"),
        ("T1: Anomaly", 6.92, "Network Analysis", "#FFE6E6"),
        ("T2: Phishing/C2", 9.76, "Phishing Detector", "#FFD9B3"),
        ("T3: Sig Match", 13.84, "Web Scanner", "#FFB84D"),
        ("T4: Final Alert", 17.10, "Correlation", "#FF6B6B"),
    ]
    
    tracks = {
        "Network Analysis": 5,
        "Phishing Detector": 3,
        "Web Scanner": 1,
        "Correlation": -1,
    }
    
    ax.axhline(y=0, color='black', linewidth=0.5, linestyle='--', alpha=0.5)
    
    for event_name, time, track, color in events:
        y_pos = tracks[track]
        
        # Event box
        box = FancyBboxPatch(
            (time - 0.7, y_pos - 0.3), 1.4, 0.6,
            boxstyle="round,pad=0.05",
            edgecolor='darkred', facecolor=color, linewidth=2
        )
        ax.add_patch(box)
        
        ax.text(time, y_pos, f"{time:.2f}s", 
                ha='center', va='center', fontweight='bold', fontsize=8, color='darkred')
        
        ax.plot([time, time], [y_pos - 0.35, -0.1], 'r--', linewidth=0.5, alpha=0.3)
    
    # Critical phase label
    ax.text(8.55, 6.5, "CRITICAL THREAT DETECTED\n(C2 Beacon / Exfiltration)", 
            ha='center', fontsize=11, fontweight='bold', color='white',
            bbox=dict(boxstyle='round', facecolor='darkred', alpha=0.95, edgecolor='red', linewidth=2))
    
    # Metrics
    metrics_text = """
    Key Metrics:
    • Anomaly Score: 0.87 (CRITICAL)
    • Phishing Confidence: 78%
    • Traffic Signature Match: 82%
    • Beacon Interval: 2.1s (Cobalt Strike)
    • Off-hours Detection: 02:15 AM (HIGH RISK)
    • Final Risk Score: 9.4/10 (CRITICAL)
    """
    ax.text(18, 2, metrics_text, fontsize=8, 
            bbox=dict(boxstyle='round', facecolor='mistyrose', alpha=0.95, edgecolor='darkred', linewidth=1.5),
            family='monospace')
    
    # Track labels
    for track, y in tracks.items():
        ax.text(-2, y, track, ha='right', fontweight='bold', fontsize=9, color='darkred')
    
    ax.set_xlim(-3, 21)
    ax.set_ylim(-2, 7)
    ax.set_xlabel("Time (seconds)", fontweight='bold', fontsize=10)
    ax.set_title("Figure 17: Scenario 3 Timeline – C2 Beacon Detection\nT0 capture → T1 anomaly (0.87) → T2 phishing (78%) → T3 signature match (82%) → T4 critical alert (17.10s)", 
                 fontweight='bold', fontsize=12, color='darkred')
    ax.set_yticks([])
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    plt.tight_layout()
    plt.savefig('figure_17_scenario3_timeline.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_17_scenario3_timeline.png")
    plt.close()

def plot_metrics_comparison():
    """
    Comparative metrics table visualization across all three scenarios
    """
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    
    scenarios = ['Scenario 1\n(Credential Harvest)', 'Scenario 2\n(Benign SaaS)', 'Scenario 3\n(C2 Beacon)']
    
    # 1. End-to-end detection time
    ax = axes[0, 0]
    times = [14.15, 2.68, 17.10]
    colors_timing = ['#FF6B6B', '#4CAF50', '#FF6B6B']
    bars = ax.bar(scenarios, times, color=colors_timing, edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Time (seconds)", fontweight='bold')
    ax.set_title("End-to-End Detection Time", fontweight='bold', fontsize=11)
    ax.set_ylim(0, 20)
    for i, (bar, time) in enumerate(zip(bars, times)):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, f"{time:.2f}s", 
                ha='center', fontweight='bold', fontsize=9)
    ax.grid(axis='y', alpha=0.3)
    
    # 2. Risk scores
    ax = axes[0, 1]
    risks = [8.9, 1.0, 9.4]
    colors_risk = ['#FF6B6B' if r > 5 else '#4CAF50' for r in risks]
    bars = ax.bar(scenarios, risks, color=colors_risk, edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Risk Score (0-10)", fontweight='bold')
    ax.set_title("Final Risk Score (Composite Verdict)", fontweight='bold', fontsize=11)
    ax.set_ylim(0, 10)
    for i, (bar, risk) in enumerate(zip(bars, risks)):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3, f"{risk:.1f}", 
                ha='center', fontweight='bold', fontsize=9)
    ax.axhline(y=5, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='Escalation threshold')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # 3. Anomaly scores
    ax = axes[1, 0]
    anomalies = [0.92, 0.08, 0.87]
    colors_anomaly = ['#FF6B6B' if a > 0.5 else '#4CAF50' for a in anomalies]
    bars = ax.bar(scenarios, anomalies, color=colors_anomaly, edgecolor='black', linewidth=1.5, alpha=0.8)
    ax.set_ylabel("Anomaly Score (0-1)", fontweight='bold')
    ax.set_title("Network Anomaly Scores from ML Model", fontweight='bold', fontsize=11)
    ax.set_ylim(0, 1.0)
    for i, (bar, anom) in enumerate(zip(bars, anomalies)):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.03, f"{anom:.2f}", 
                ha='center', fontweight='bold', fontsize=9)
    ax.axhline(y=0.5, color='orange', linestyle='--', linewidth=1, alpha=0.5, label='Warning threshold')
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    # 4. Module latencies
    ax = axes[1, 1]
    modules = ['Phishing\nEngine', 'ML\nInference', 'Scanner/\nAnysis', 'WebSocket\nPush']
    latencies_s1 = [142, 18, 6200, 133]  # ms; scanner time in ms
    latencies_s2 = [89, 12, 0, 92]
    latencies_s3 = [156, 16, 4800, 128]
    
    x = np.arange(len(modules))
    width = 0.25
    
    bars1 = ax.bar(x - width, latencies_s1, width, label='Scenario 1', color='#FF6B6B', alpha=0.8, edgecolor='black')
    bars2 = ax.bar(x, latencies_s2, width, label='Scenario 2', color='#4CAF50', alpha=0.8, edgecolor='black')
    bars3 = ax.bar(x + width, latencies_s3, width, label='Scenario 3', color='#FFA500', alpha=0.8, edgecolor='black')
    
    ax.set_ylabel("Latency (ms)", fontweight='bold')
    ax.set_title("Component Latency Breakdown", fontweight='bold', fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(modules, fontsize=9)
    ax.legend(fontsize=9)
    ax.set_yscale('log')
    ax.grid(axis='y', alpha=0.3)
    
    plt.suptitle("Case Studies: Metrics Comparison Across Scenarios", fontweight='bold', fontsize=14, y=0.995)
    plt.tight_layout()
    plt.savefig('figure_18_metrics_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: figure_18_metrics_comparison.png")
    plt.close()

def main():
    print("Generating Case Study Timeline Figures...\n")
    
    plot_scenario_1_timeline()
    plot_scenario_2_timeline()
    plot_scenario_3_timeline()
    plot_metrics_comparison()
    
    print("\n✓ All figures generated successfully!")
    print("Generated files:")
    print("  • figure_15_scenario1_timeline.png")
    print("  • figure_16_scenario2_timeline.png")
    print("  • figure_17_scenario3_timeline.png")
    print("  • figure_18_metrics_comparison.png")

if __name__ == "__main__":
    main()
