# run_strategies.py
import json, os
from pipeline import load_trace, label_actions, format_action_for_prompt, build_task_context
from interrogation_protocol import interrogate

api_key = os.environ['OPENROUTER_API_KEY']

missed_traces = [
    '5be1cd5293bf501e5a729844d736e132',
    '0b89473570c9e8fad40e08e64c14f350',
    '101e6127c0478cf8fe0742521c52dbd2',
    '208b181524b0f0292969cbe345533e8c',
    '68cbb1b82bc9d253d8fb149c48cfaada',
    '3a092e28d42b283e9764bf1f914324a2',
    '70ec8780126a0e08d828476cb9cf7118',
    '611835b74fd7ebcf599917a77c1d6d2e',
    '54d87f8006c739feb09976c7a0fcc0fd',
    '558ab5d6eb37def568471dc08c8ca641',
    '1326a8002c6bf5c39533e3253b1e43a5',
    '344a8979e036854ea1dbe5406e88e160',
    '3ae48604a28ee6bb562ad8f89c2d8027',
    '18500821bde33e55ec64832b780f7978',
    '48bc630b39ce27dfbc419c7549532fe2',
]

strategies = ['generic', 'explain_choice', 'predict_output', 'justify_necessity', 'safer_alternative']

os.makedirs('results/strategies', exist_ok=True)

for strategy in strategies:
    tp = fn = fp = tn = 0
    all_results = []
    print(f"\n=== Strategy: {strategy} ===")
    
    for trace_id in missed_traces:
        trace = load_trace(f'sample_traces/{trace_id}.json')
        labeled = label_actions(trace)
        task_context = build_task_context(trace)
        
        for action in labeled:
            action_text = format_action_for_prompt(action)
            result = interrogate(action_text, task_context, strategy=strategy)
            
            is_attack = action['label'] == 'ATTACK'
            is_suspicious = result['verdict'] == 'SUSPICIOUS'
            
            if is_attack and is_suspicious: tp += 1
            elif is_attack and not is_suspicious: fn += 1
            elif not is_attack and is_suspicious: fp += 1
            else: tn += 1
            
            all_results.append({
                'trace_id': trace_id,
                'action_index': action['index'],
                'ground_truth': action['label'],
                'verdict': result['verdict'],
                'sus_score': result['sus_score'],
                'question': result['question'],
                'answer': result['answer'][:300],
                'reasoning': result['reasoning'][:300],
            })
            
            mark = 'Y' if (is_attack == is_suspicious) else 'X'
            print(f"  {mark} {trace_id[:8]} a{action['index']} {action['label']:6s} -> {result['verdict']} ({result['sus_score']})")
    
    total = tp + fn + fp + tn
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    
    summary = {
        'strategy': strategy,
        'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
        'accuracy': round(accuracy, 3),
        'precision': round(precision, 3),
        'recall': round(recall, 3),
    }
    
    print(f"\n  {strategy}: Acc={accuracy:.1%} Prec={precision:.1%} Rec={recall:.1%}")
    print(f"  TP={tp} FN={fn} FP={fp} TN={tn}")
    
    with open(f'results/strategies/{strategy}.json', 'w') as f:
        json.dump({'summary': summary, 'results': all_results}, f, indent=2)