import joblib
import pandas as pd
import sys
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Suppress sklearn version mismatch warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Suppress XGBoost serialized model warning
warnings.filterwarnings("ignore", message=".*WARNING: ./src/gbm/../common/error_msg.h.*")

# Load model
saved_model = joblib.load("/home/okore/ccf-scripts/xgb_model.pkl")

# Load features
df = pd.read_csv(sys.argv[1])  # First argument = CSV path

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

# Output result
print({
    "prediction": prediction[0],
    "class": class_malware,
    "malicious_probability": f"{float(proba[0][1]) * 100}%"
})

