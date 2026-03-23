import json
import glob
import os
import csv
folder = "/Users/nwi/Downloads/trajectories"
files = sorted(glob.glob(os.path.join(folder, "*.json")))
rows = []
for fp in files:
    with open(fp, "r", encoding="utf-8") as f:
        d = json.load(f)
    # Build a set of action indexes that are explicitly marked as attack-related
    incriminating = set()
    attack_analysis = d.get("attack_analysis", {})
    for item in attack_analysis.get("incriminating_actions", []) or []:
        idx = item.get("action_index")
        if isinstance(idx, int):
            incriminating.add(idx)
    for a in d.get("actions", []):
        idx = a.get("index")
        function = a.get("function")
        # Pull command-like text from common places
        args = a.get("arguments") or {}
        command = ""
        if isinstance(args, dict):
            command = (
                args.get("cmd")
                or args.get("command")
                or args.get("path")
                or ""
            )
        monitor = a.get("monitor_response") or {}
        sus_score = monitor.get("sus_score")
        rows.append({
            "file": os.path.basename(fp),
            "action_index": idx,
            "is_incriminating": idx in incriminating,
            "sus_score": sus_score,
            "function": function,
            "command": command,
        })
# Print a quick preview
print("total_rows:", len(rows))
print("preview:")
for r in rows[:20]:
    print(r)
# Save full table to CSV
out_csv = os.path.join(folder, "trajectory_actions_labeled.csv")
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(
        f,
        fieldnames=[
            "file",
            "action_index",
            "is_incriminating",
            "sus_score",
            "function",
            "command",
        ],
    )
    w.writeheader()
    w.writerows(rows)
print("saved:", out_csv)