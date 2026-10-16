# Evaluation harness for custom-qwentriage.
#
# Runs every saved alert in the tp, fp and inj folders through the real
# triage() function RUNS times and appends one row per run to results.csv.
# Nothing is sent to Wazuh: triage() returns the verdict, and send_msg()
# is never called. The folder an alert sits in is its ground truth.

import csv
import json
import os
import time
import importlib.util

# Import the triage script as a module, so the eval runs exactly the code Wazuh runs
spec = importlib.util.spec_from_file_location("qt", "/home/wazuhadmin/custom-qwentriage.py")
qt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qt)

PROMPT_VERSION = "V1.3"
RUNS = 30
SETS = ["tp", "fp", "inj"]
EVAL_DIR = "/home/wazuhadmin/eval"
RESULTS_FILE = f"{EVAL_DIR}/results.csv"

if not os.path.exists(RESULTS_FILE):
    with open(RESULTS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["prompt_version", "set", "file", "rule_id", "run", "verdict", "confidence", "seconds", "reasoning", "next_step"])

for set_name in SETS:
    folder = f"{EVAL_DIR}/{set_name}"
    for file_name in sorted(os.listdir(folder)):
        path = f"{folder}/{file_name}"
        with open(path) as alert_file:
            alert = json.load(alert_file)
        for run in range(1, RUNS + 1):
            start = time.time()
            # Any error, such as an Ollama 500, is recorded as FAILED instead of stopping the run
            try:
                result = qt.triage(alert)
            except Exception:
                result = None
            seconds = round(time.time() - start, 2)
            print(set_name, file_name, run, seconds)
            if result is None:
                verdict = "FAILED"
                confidence = ""
                reasoning = ""
                next_step = ""
            else:
                q = result["qwentriage"]
                verdict = q["Verdict"]
                confidence = q["Confidence"]
                reasoning = q["Reasoning"]
                next_step = q["Next_Step"]
            with open(RESULTS_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([PROMPT_VERSION, set_name, file_name, alert["rule"]["id"], run, verdict, confidence, seconds, reasoning, next_step])
