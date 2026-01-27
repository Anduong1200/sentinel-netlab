#!/usr/bin/env python3
"""
Recall Comparison Script
Compares PoC scan results with ground truth (airodump-ng) to calculate detection accuracy.

Usage:
    python compare_recall.py gt_output.csv poc.json [--output recall_report.txt]
"""

import argparse
import csv
import json
import sys
from typing import Dict, Set, List, Tuple
from datetime import datetime


def parse_airodump_csv(filepath: str) -> Set[str]:
    """
    Parse airodump-ng CSV output to extract BSSIDs.
    
    Args:
        filepath: Path to airodump-ng CSV file
        
    Returns:
        Set of BSSID strings (uppercase)
    """
    bssids = set()
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        in_ap_section = False
        
        for row in reader:
            if not row:
                continue
            
            # airodump-ng CSV has "BSSID" header for AP section
            if len(row) > 0 and 'BSSID' in row[0]:
                in_ap_section = True
                continue
            
            # Station section starts here
            if len(row) > 0 and 'Station MAC' in row[0]:
                in_ap_section = False
                continue
            
            if in_ap_section and len(row) >= 1:
                bssid = row[0].strip().upper()
                # Validate MAC format
                if len(bssid) == 17 and bssid.count(':') == 5:
                    bssids.add(bssid)
    
    return bssids


def parse_poc_json(filepath: str) -> Set[str]:
    """
    Parse PoC JSON output to extract BSSIDs.
    
    Args:
        filepath: Path to PoC JSON file
        
    Returns:
        Set of BSSID strings (uppercase)
    """
    bssids = set()
    
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Handle different JSON structures
    networks = []
    if isinstance(data, list):
        networks = data
    elif isinstance(data, dict):
        networks = data.get('networks', data.get('results', data.get('data', [])))
    
    for net in networks:
        if isinstance(net, dict):
            bssid = net.get('bssid', net.get('BSSID', '')).strip().upper()
            if bssid and len(bssid) == 17:
                bssids.add(bssid)
    
    return bssids


def calculate_metrics(ground_truth: Set[str], detected: Set[str]) -> Dict[str, float]:
    """
    Calculate precision, recall, and F1 score.
    
    Args:
        ground_truth: Set of true BSSIDs
        detected: Set of detected BSSIDs
        
    Returns:
        Dictionary with metrics
    """
    if not ground_truth:
        return {"error": "Empty ground truth"}
    
    true_positives = ground_truth & detected
    false_positives = detected - ground_truth
    false_negatives = ground_truth - detected
    
    tp = len(true_positives)
    fp = len(false_positives)
    fn = len(false_negatives)
    
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "ground_truth_count": len(ground_truth),
        "detected_count": len(detected),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "missed_bssids": list(false_negatives)[:10],  # First 10 for debugging
        "extra_bssids": list(false_positives)[:10]
    }


def generate_report(metrics: Dict, gt_file: str, poc_file: str) -> str:
    """Generate human-readable report."""
    
    # Determine grade based on recall
    recall = metrics.get("recall", 0)
    if recall >= 0.80:
        grade = "PASS (Full Points)"
        score = "6/6"
    elif recall >= 0.60:
        grade = "PASS (Partial)"
        score = "4/6"
    else:
        grade = "FAIL"
        score = "0-2/6"
    
    report = f"""
================================================================================
                    RECALL COMPARISON REPORT
================================================================================

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Files Compared:
  Ground Truth: {gt_file}
  PoC Output:   {poc_file}

--------------------------------------------------------------------------------
                         SUMMARY
--------------------------------------------------------------------------------

  Ground Truth Networks:  {metrics['ground_truth_count']}
  Detected Networks:      {metrics['detected_count']}
  
  True Positives:         {metrics['true_positives']}
  False Positives:        {metrics['false_positives']}
  False Negatives:        {metrics['false_negatives']}

--------------------------------------------------------------------------------
                         METRICS
--------------------------------------------------------------------------------

  PRECISION:  {metrics['precision']:.2%}  (of detected, how many were correct)
  RECALL:     {metrics['recall']:.2%}  (of actual, how many were detected)
  F1 SCORE:   {metrics['f1_score']:.2%}  (harmonic mean)

--------------------------------------------------------------------------------
                         EVALUATION
--------------------------------------------------------------------------------

  Recall Threshold:  >= 80% for full points
  Current Recall:    {metrics['recall']:.2%}
  
  GRADE: {grade}
  SCORE: {score}

--------------------------------------------------------------------------------
                         DETAILS
--------------------------------------------------------------------------------

  Missed Networks (False Negatives - sample):
"""
    
    for bssid in metrics.get('missed_bssids', []):
        report += f"    - {bssid}\n"
    
    if not metrics.get('missed_bssids'):
        report += "    (none)\n"
    
    report += """
  Extra Networks (False Positives - sample):
"""
    
    for bssid in metrics.get('extra_bssids', []):
        report += f"    - {bssid}\n"
    
    if not metrics.get('extra_bssids'):
        report += "    (none)\n"
    
    report += """
================================================================================
                    END OF REPORT
================================================================================
"""
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Compare PoC scan results with ground truth (airodump-ng)"
    )
    parser.add_argument("gt_file", help="Ground truth CSV (airodump-ng output)")
    parser.add_argument("poc_file", help="PoC JSON output")
    parser.add_argument("-o", "--output", help="Output report file", default="recall_report.txt")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    
    print("[1/4] Parsing ground truth...")
    try:
        gt_bssids = parse_airodump_csv(args.gt_file)
        print(f"  Found {len(gt_bssids)} networks in ground truth")
    except Exception as e:
        print(f"  ERROR: Failed to parse ground truth: {e}")
        sys.exit(1)
    
    print("[2/4] Parsing PoC output...")
    try:
        poc_bssids = parse_poc_json(args.poc_file)
        print(f"  Found {len(poc_bssids)} networks in PoC output")
    except Exception as e:
        print(f"  ERROR: Failed to parse PoC output: {e}")
        sys.exit(1)
    
    print("[3/4] Calculating metrics...")
    metrics = calculate_metrics(gt_bssids, poc_bssids)
    
    print("[4/4] Generating report...")
    
    if args.json:
        output = json.dumps(metrics, indent=2)
    else:
        output = generate_report(metrics, args.gt_file, args.poc_file)
    
    # Save report
    with open(args.output, 'w') as f:
        f.write(output)
    
    print(f"\nReport saved to: {args.output}")
    print(f"\n{'='*60}")
    print(f"  RECALL: {metrics['recall']:.2%}")
    print(f"  PRECISION: {metrics['precision']:.2%}")
    print(f"  F1 SCORE: {metrics['f1_score']:.2%}")
    print(f"{'='*60}")
    
    # Exit code based on recall threshold
    if metrics['recall'] >= 0.80:
        print("\n✅ PASS: Recall meets threshold (>= 80%)")
        sys.exit(0)
    elif metrics['recall'] >= 0.60:
        print("\n⚠️  PARTIAL: Recall below optimal but acceptable (60-80%)")
        sys.exit(0)
    else:
        print("\n❌ FAIL: Recall too low (< 60%)")
        sys.exit(1)


if __name__ == "__main__":
    main()
