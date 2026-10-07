import hashlib
import json
import os
import sys
import time
import warnings

import joblib
import pandas as pd
from sklearn.exceptions import InconsistentVersionWarning

DEFAULT_HASH_LOG = "/home/okore/MemoryDumps/integrity.log"


def log_hash(hash_log_path, artifact, digest):
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stage": "predict",
        "artifact": artifact,
        "sha256": digest,
    }
    try:
        with open(hash_log_path, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        print(f"[-] Could not write integrity log entry: {e}", file=sys.stderr)

# Suppress sklearn version mismatch warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Suppress XGBoost serialized model warning
warnings.filterwarnings("ignore", message=".*WARNING: ./src/gbm/../common/error_msg.h.*")

# Load model
saved_model = joblib.load("/home/okore/ccf-scripts/xgb_model.pkl")

# Load features. Hash the CSV first -- this is the same file extract_features.py
# hashed right after writing it, so a mismatch here means the artifact changed
# between stages.
features_path = sys.argv[1]
with open(features_path, "rb") as f:
    csv_hash = hashlib.sha256(f.read()).hexdigest()
log_hash(os.environ.get("HASH_LOG", DEFAULT_HASH_LOG), "features_csv_at_predict", csv_hash)

df = pd.read_csv(features_path)  # First argument = CSV path

scaler = saved_model['scaler']
model = saved_model['model']

# Scale features
df = scaler.transform(df)

# Predict
prediction = model.predict(df)
proba = model.predict_proba(df)
class_malware = "Benign"
if int(prediction[0]) == 1:
    class_malware = " Malicious"

decision = {
    "prediction": int(prediction[0]),
    "class": class_malware.strip(),
    "malicious_probability": round(float(proba[0][1]) * 100, 4),
}

# Hash the decision payload itself before it is printed, so the integrity log
# records what was decided even though the JSON is never written to disk by
# this script (response.py consumes it from stdout).
decision_hash = hashlib.sha256(
    json.dumps(decision, sort_keys=True).encode()
).hexdigest()
log_hash(os.environ.get("HASH_LOG", DEFAULT_HASH_LOG), "classification_decision", decision_hash)

# Output result as JSON (consumed by response.py). Only this line goes to
# stdout -- everything else above prints to stderr or the hash log, so the
# stdout contract response.py relies on is unchanged.
print(json.dumps(decision))

