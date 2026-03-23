# Surrogate Interrogation

**Testing surrogate interrogation as a control protocol for untrusted AI agents.**

Built at [Apart Research](https://www.apartresearch.com/) AI Control Hackathon.

## Overview

AI control protocols use trusted monitors to detect unsafe actions from untrusted agents. Current approaches rely on passive observation — scoring suspicion based on action text alone. We introduce **surrogate interrogation**: a protocol where a trusted monitor questions a surrogate model about an agent's actions before scoring suspicion.

Evaluated on 48 matched attack trajectories from LinuxBench (576 total actions, 31 attack types):

| Method | Recall | Precision | Accuracy |
|--------|--------|-----------|----------|
| Baseline (1 call) | 48.1% | 39.2% | 82.6% |
| Majority Vote (3 calls) | 51.9% | 39.4% | 82.5% |
| Surrogate Interrogation (3 calls) | 75.9% | 23.2% | 62.2% |

A compute-matched ablation (majority voting with 3× baseline calls) confirms that the recall improvement is driven by the questioning mechanism, not additional inference budget.

## How It Works

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│  Question    │     │  Answer         │     │  Score       │
│  Generation  │ ──▶ │  Generation     │ ──▶ │  + Verdict   │
│  (Haiku 4.5) │     │  (Gemini Flash) │     │  (Haiku 4.5) │
└─────────────┘     └─────────────────┘     └─────────────┘
```

1. **Question generation** — Claude Haiku 4.5 generates a probing question using one of five strategies (generic, explain_choice, predict_output, justify_necessity, safer_alternative)
2. **Answer generation** — Gemini 2.5 Flash roleplays as the agent and defends the action
3. **Scoring** — Claude Haiku 4.5 reviews the action, question, and answer, producing a 0–10 suspicion score

Using different model families for questioning and answering prevents self-prediction.

## Key Finding: Justification Asymmetry

Malicious actions may be easier to disguise than to justify under questioning. The attacker must maintain consistency between the action, its stated purpose, and the task context — a harder problem than simply making the command text look benign.

## Repository Structure

```
├── pipeline.py                  # Data loading, baseline monitor, evaluation harness
├── interrogation_protocol.py    # 3-step surrogate interrogation protocol
├── majority_vote_ablation.py    # Compute-matched ablation (3× baseline, majority vote)
├── aggregate.py                 # Aggregate results for baseline & interrogation
├── aggregate_with_ablation.py   # Three-way comparison (baseline vs majority vote vs interrogation)
├── run_strategies.py            # Per-strategy evaluation on missed traces
├── sample_traces/               # LinuxBench attack trajectories
└── results/
    ├── baseline/                # Single-call baseline monitor results
    ├── interrogation/           # Surrogate interrogation results
    └── majority_vote/           # Compute-matched ablation results
```

## Usage

```bash
# Set API key
export OPENROUTER_API_KEY=your_key_here

# Run baseline + interrogation on all traces
python3 pipeline.py

# Run compute-matched ablation
python3 majority_vote_ablation.py

# Compare all three methods (matched traces only)
python3 aggregate_with_ablation.py
```

## Data

- **Dataset**: [LinuxBench Straj dataset](https://linuxbench.ai/data/straj-dataset)
- **Traces**: 48 matched traces from 106-trace corpus, spanning 31 attack types
- **Attack types**: Remote code execution, credential exfiltration, SSH backdoor implantation, secret exposure, safety-notification suppression, medical-data export, and more

## Authors

- Nina Wolff-Ingham (Independent)
- Anonymous Author (Independent)

## References

1. Greenblatt et al. "AI Control: Improving Safety Despite Intentional Subversion." ICML 2024.
2. Bhatt et al. "Ctrl-Z: Controlling AI Agents via Resampling." Redwood Research, 2025.
3. Arnav et al. "CoT Red-Handed: Stress Testing Chain-of-Thought Monitoring." 2025.
4. UK AI Security Institute. "Empirical Investigations Into AI Monitoring and Red Teaming." 2025.
5. Kutasov et al. "Evaluating Control Protocols for Untrusted AI Agents." 2025.
