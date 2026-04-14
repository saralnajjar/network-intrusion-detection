# Network Intrusion Detection
A Python-based network intrusion detection system (NIDS) built incrementally, starting from rule-based detection and evolving toward ML-powered classification.

## Project Structure
 
```
network-intrusion-detection/
    data/
    src/
        detector.py
        parser.py
        features.py
        model.py
        cli.py
    tests/
    notebooks/
    README.md
```
 
---
## Roadmap
### Part 1: Rule Based Detection
> Working detector using rules before moving to the ML
- Parse raw network logs (CSV/PCAP-style)
- Define traffic feature schema (src/dst IP, port, protocol, byte count, duration)
- Implement rule engine: port scanning detection, SYN flood detection, brute force login attempts
- CLI: run detection on a log file, print flagged connections
- Add thresholds config (config.json)
- Unit tests for rule engine

## Part 2:Dataset + EDA
- Load and clean the NSL-KDD dataset
- Exploratory data analysis notebook: class distribution, feature correlation
- Encode categorical features (protocol, service, flag)
- Normalise continuous features
- Train/test split + save processed data


## Getting Started
 
```bash
git clone https://github.com/saralnajjar/network-intrusion-detection
cd network-intrusion-detection
pip install -r requirements.txt
```
 
Run rule-based detection on a log file (Phase 1):
```bash
python src/cli.py --input data/sample.csv --mode rules
```
 
Run ML detection (Phase 3+):
```bash
python src/cli.py --input data/sample.csv --mode model --model models/random_forest.pkl
```
 

## Dataset
 
This project uses the **NSL-KDD** dataset, a cleaned version of the KDD Cup 1999 dataset, widely used for NIDS research.
 
- Download: https://www.unb.ca/cic/datasets/nsl.html
    - Place files in `data/raw/`
 
---

## Attack Categories (NSL-KDD)
 
| Category | Description | Examples |
|----------|-------------|---------|
| DoS | Denial of Service — overwhelm the target | SYN flood, Ping of Death |
| Probe | Surveillance / port scanning | nmap, ipsweep |
| R2L | Remote to Local — unauthorised access | FTP brute force, phf |
| U2R | User to Root — privilege escalation | buffer overflow, rootkit |
 
---