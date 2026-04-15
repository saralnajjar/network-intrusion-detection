"""
detector.py: Rule-based network intrusion detection engine.

Analyses a list of connection records and flags suspicious activity
using three rules: port scanning, SYN flood, and brute force login.

Thresholds are configurable via a dict or config.json (see load_config).

Usage:
    from src.parser import parse_log
    from src.detector import detect, load_config

    records = parse_log("data/raw/KDDTrain+.csv")
    config = load_config()
    alerts = detect(records, config)
    for alert in alerts:
        print(alert)
"""