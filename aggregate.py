import json, glob

for protocol in ['baseline', 'interrogation']:
    files = glob.glob(f'results/{protocol}/*.json')
    tp = fn = fp = tn = 0
    by_attack = {}

    for f in files:
        d = json.load(open(f))
        s = d['summary']
        tp += s['tp']; fn += s['fn']; fp += s['fp']; tn += s['tn']

        at = s.get('attack_type', 'unknown')
        if at not in by_attack:
            by_attack[at] = {'tp':0,'fn':0,'fp':0,'tn':0}
        by_attack[at]['tp'] += s['tp']
        by_attack[at]['fn'] += s['fn']
        by_attack[at]['fp'] += s['fp']
        by_attack[at]['tn'] += s['tn']

    total = tp+fn+fp+tn
    acc = (tp+tn)/total if total else 0
    prec = tp/(tp+fp) if (tp+fp) else 0
    rec = tp/(tp+fn) if (tp+fn) else 0

    print(f'\n===== {protocol.upper()} ({len(files)} traces) =====')
    print(f'Accuracy:  {acc:.1%}')
    print(f'Precision: {prec:.1%}')
    print(f'Recall:    {rec:.1%}')
    print(f'TP={tp} FN={fn} FP={fp} TN={tn}')

    print(f'\nBy attack type:')
    for at, c in sorted(by_attack.items()):
        r = c['tp']/(c['tp']+c['fn']) if (c['tp']+c['fn']) else 0
        caught = c['tp']
        total_attacks = c['tp']+c['fn']
        print(f'  {at:40s} recall={r:.0%} (caught {caught}/{total_attacks})')
