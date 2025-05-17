# CCF-Project: Automated Memory Forensics Pipeline for Real-Time Malware Response

## Project Overview
This project presents an automated memory forensics pipeline that integrates Wazuh SIEM with memory acquisition tools (WinPMEM) and analysis utilities (Volatility3) to detect and respond to malware infections in real time. The system leverages machine learning (XGBoost) to classify malicious activity based on memory artifacts, enabling automated containment and alerting.

PIPELINE DIAGRAM: [PIPELINE](https://www.mermaidchart.com/app/projects/48916c73-5af4-45e8-9a88-0c6445f40dcc/diagrams/6dd79821-8c80-44bc-824d-85b9d4a0b0e4/version/v0.1/edit).

**Key Features:**
- Real-time memory dumping triggered by Wazuh alerts (e.g., suspicious PowerShell activity).
- Automated feature extraction using Volatility3 plugins (`svcscan`).
- Machine learning-based malware classification (99.8% accuracy on CIC-MalMem-2022 dataset).
- SOAR-like response: Network isolation, Slack alerts, and evidence preservation.

## Repository Structure
```
.
├── Images/                          # Screenshots/logs of pipeline execution
├── Deep_Learning_&_obfuscated_malware_memory_2022_cic.ipynb  # ML model training notebook
├── extract_features.py              # Script to extract features from memory dumps
├── Obfuscated-MalMem2022.csv        # Dataset for malware memory analysis
├── predict.py                       # ML model inference script
├── response.py                      # SOAR automation script (quarantine/alerting)
├── trigger_memdump.sh               # Memory acquisition script (WinPMEM/WinRM)
└── xgb_model.pkl                    # Trained XGBoost model (joblib format)
```

## Prerequisites
- **Wazuh SIEM** (Manager + Agent setup)
- **Ubuntu VM** (Wazuh Manager): 
  - Volatility3, NetExec, Python 3.8+
  - Libraries: `pandas`, `scikit-learn`, `joblib`, `numpy`, `xgboost`
- **Windows 10 VM** (Agent):
  - WinPMEM, PowerShell Remoting (WinRM)
  - Shared folder (`C:\MemoryDumps`) for memory dumps

## Setup Instructions
1. **Environment Configuration**:
   - Clone this repo to the Wazuh Manager (Ubuntu VM).
   - Configure WinRM on the Windows Agent:
     ```powershell
     Enable-PSRemoting -Force
     Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
     ```
   - Install WinPMEM on the Windows Agent (place `winpmem.exe` in `C:\Tools`).

2. **Wazuh Integration**:
   - Add custom rules to `local_rules.xml` [Project Report](https://certain-geology-23b.notion.site/COMPUTER-FORENSIC-AND-INCIDENT-RESPONSE-1f543dbba7f98058a6c2cc1951f30f35).
   - Configure active response in `ossec.conf` to trigger scripts:
     ```xml
     <command>
       <name>trigger_memdump</name>
       <executable>/path/to/trigger_memdump.sh</executable>
     </command>
     ```

3. **ML Model Deployment**:
   - Place `xgb_model.pkl` and `predict.py` in the Wazuh Manager's pipeline directory.
   - Ensure the shared folder (`/home/okore/MemoryDumps`) is accessible to both VMs.

## Usage
1. **Trigger Memory Dump**:
   - Execute suspicious activity (e.g., `Invoke-WebRequest` to download malware).
   - Wazuh detects the behavior and runs `trigger_memdump.sh` via WinRM.

2. **Feature Extraction**:
   - `extract_features.py` processes the memory dump with Volatility3 (`svcscan` plugin).
   - Outputs features to `features.csv` (e.g., `svcscan.nservices`, `svcscan.process_services`).

3. **Automated Response**:
   - `response.py` loads the ML model, classifies the activity, and:
     - Quarantines the host (blocks network via firewall rules).
     - Sends Slack alerts with prediction details.

## Results
- **Detection Accuracy**: 99.8% (tested on WannaCry ransomware).
- **Pipeline Latency**: <3 minutes from detection to containment depending on available compute.
- Sample logs available in `Images/`.

## Future Work
- Integrate ELK Stack dashboards for incident timeline visualization.
- Expand Volatility plugins (DLLs, mutexes).
- Test with advanced fileless malware.

## References
- [CIC-MalMem-2022 Dataset](https://www.unb.ca/cic/datasets/malmem-2022.html)
- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [Wazuh Active Response Guide](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/)

---
**Demo Video**: [Yandex Disk](https://disk.yandex.com/client/disk/CCF%20Project%20Demo)  
**Author**: Okore Joel Chidike | [GitHub](https://github.com/Joellots)
