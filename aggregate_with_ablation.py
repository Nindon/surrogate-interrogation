"""
aggregate_with_ablation.py — Compare baseline vs majority-vote vs interrogation.

Only compares traces that appear in ALL protocol folders, ensuring a matched
comparison on the same action set.

Usage:
    python aggregate_with_ablation.py
"""

import json
import glob
import os


def get_trace_ids(results_dir):
    """Get set of trace IDs from a results directory."""
    files = glob.glob(os.path.join(results_dir, "*.json"))
    return {os.path.basename(f).replace(".json", "") for f in files}


def compute_metrics(results_dir, trace_ids=None):
    """Aggregate TP/FP/FN/TN from result files, optionally filtered to specific trace IDs."""
    files = glob.glob(os.path.join(results_dir, "*.json"))
    tp = fn = fp = tn = 0
    count = 0

    for f in files:
        trace_id = os.path.basename(f).replace(".json", "")
        if trace_ids is not None and trace_id not in trace_ids:
            continue
        d = json.load(open(f))
        s = d["summary"]
        tp += s["tp"]
        fn += s["fn"]
        fp += s["fp"]
        tn += s["tn"]
        count += 1

    total = tp + fn + fp + tn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0

    return {
        "traces": count,
        "total_actions": total,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
    }


def print_comparison(results_base="results"):
    protocols = {
        "Baseline": os.path.join(results_base, "baseline"),
        "Majority Vote (3x)": os.path.join(results_base, "majority_vote"),
        "Interrogation": os.path.join(results_base, "interrogation"),
    }

    # Find which protocols have results
    available = {}
    for name, path in protocols.items():
        if os.path.exists(path) and glob.glob(os.path.join(path, "*.json")):
            available[name] = path
        else:
            print(f"  [skipping {name} — no results at {path}]")

    if not available:
        print("No results found!")
        return

    # Find trace IDs that appear in ALL available protocol folders
    all_ids = [get_trace_ids(path) for path in available.values()]
    matched_ids = all_ids[0]
    for ids in all_ids[1:]:
        matched_ids = matched_ids & ids

    print(f"\nMatched traces across all protocols: {len(matched_ids)}")
    for name, path in available.items():
        total = len(get_trace_ids(path))
        print(f"  {name}: {total} total, {len(matched_ids)} matched")

    # Compute metrics on matched traces only
    all_metrics = {}
    for name, path in available.items():
        all_metrics[name] = compute_metrics(path, trace_ids=matched_ids)

    # Header
    col_width = 22
    header = f"{'Metric':<20s}"
    for name in all_metrics:
        header += f"{name:>{col_width}s}"
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    # Rows
    rows = [
        ("Traces", "traces", "d"),
        ("Total Actions", "total_actions", "d"),
        ("Accuracy", "accuracy", ".1%"),
        ("Precision", "precision", ".1%"),
        ("Recall", "recall", ".1%"),
        ("TP", "tp", "d"),
        ("FN", "fn", "d"),
        ("FP", "fp", "d"),
        ("TN", "tn", "d"),
    ]

    for label, key, fmt in rows:
        row = f"{label:<20s}"
        for name in all_metrics:
            val = all_metrics[name][key]
            formatted = f"{val:{fmt}}"
            row += f"{formatted:>{col_width}s}"
        print(row)

    print("=" * len(header))

    # Interpretation helper
    if "Baseline" in all_metrics and "Majority Vote (3x)" in all_metrics and "Interrogation" in all_metrics:
        b = all_metrics["Baseline"]
        mv = all_metrics["Majority Vote (3x)"]
        it = all_metrics["Interrogation"]

        print(f"\n--- Ablation interpretation (matched traces only) ---")
        print(f"Baseline recall:        {b['recall']:.1%}")
        print(f"Majority Vote recall:   {mv['recall']:.1%}")
        print(f"Interrogation recall:   {it['recall']:.1%}")
        print()
        print(f"Baseline → Majority Vote:    {mv['recall'] - b['recall']:+.1%}")
        print(f"Baseline → Interrogation:    {it['recall'] - b['recall']:+.1%}")
        print(f"Majority Vote → Interrogation: {it['recall'] - mv['recall']:+.1%}")


if __name__ == "__main__":
    print_comparison()
