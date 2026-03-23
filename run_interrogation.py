import os
from pipeline import run_evaluation, interrogation_monitor

api_key = os.environ['OPENROUTER_API_KEY']
run_evaluation(
    os.path.expanduser('~/Downloads/trajectories/0b89473570c9e8fad40e08e64c14f350.json'),
    interrogation_monitor,
    api_key,
    'interrogation_results.json'
)