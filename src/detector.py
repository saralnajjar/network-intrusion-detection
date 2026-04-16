"""
detector.py: Rule-based network intrusion detection engine.

NSL-KDD key fields used here:
    duration          — connection length in seconds
    protocol_type     — tcp / udp / icmp
    service           — destination network service (http, ftp, etc.)
    flag              — connection status (SF, S0, REJ, RSTO, ...)
    src_bytes         — bytes from src to dst
    dst_bytes         — bytes from dst to src
    count             — connections to same host in past 2 seconds
    srv_count         — connections to same service in past 2 seconds
    serror_rate       — % connections with SYN errors (same host)
    srv_serror_rate   — % connections with SYN errors (same service)
    num_failed_logins — failed login attempts
    logged_in         — 1 if successfully logged in, else 0
    label             — attack type or "normal"
 
Thresholds are configurable via config.json (see load_config).
 
Usage:
    from src.parser import parse_log
    from src.detector import detect, load_config
 
    records = parse_log("data/raw/KDDTrain+.csv")
    config = load_config()
    alerts = detect(records, config)
    for alert in alerts:
        print(alert)
"""
import json
from pathlib import Path
 
 
# Default thresholds — override via config.json
DEFAULT_CONFIG = {
    "port_scan": {
        "min_srv_count": 20,      # connections to many services (srv_count)
        "max_same_srv_rate": 0.1, # low same-service rate = scanning wide
    },
    "syn_flood": {
        "min_count": 100,         # high connection count to same host
        "min_serror_rate": 0.5,   # high SYN error rate
        "max_duration": 0,        # zero-duration connections
    },
    "brute_force": {
        "min_failed_logins": 1,   # any failed login attempt
        "not_logged_in": True,    # didn't successfully log in after tries
    },
}
 
 
def load_config(path: str | Path = "config.json") -> dict:
    """
    Load thresholds from config.json if it exists, else use defaults.
 
    Args:
        path: Path to config file.
 
    Returns:
        Config dict with threshold values.
    """
    p = Path(path)
    if p.exists():
        with open(p, encoding="utf-8") as f:
            user_config = json.load(f)
        config = DEFAULT_CONFIG.copy()
        for rule, values in user_config.items():
            if rule in config:
                config[rule].update(values)
        return config
    return DEFAULT_CONFIG.copy()
 
 
def _alert(rule: str, service: str, protocol: str, detail: str) -> dict:
    """Build a standard alert dict."""
    return {
        "rule": rule,
        "service": service,
        "protocol": protocol,
        "detail": detail,
    }
 
 
def _detect_port_scan(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag connections that look like port scanning behaviour.
 
    NSL-KDD's srv_count = connections to same service in last 2 seconds.
    same_srv_rate = fraction of those going to the same service.
    A scanner hits many different services → high srv_count, low same_srv_rate.
    """
    alerts = []
    min_srv_count = cfg["port_scan"]["min_srv_count"]
    max_same_srv_rate = cfg["port_scan"]["max_same_srv_rate"]
 
    for r in records:
        srv_count = r.get("srv_count") or 0
        same_srv_rate = r.get("same_srv_rate") or 1.0
        service = r.get("service", "unknown")
        protocol = r.get("protocol_type", "unknown")
 
        if srv_count >= min_srv_count and same_srv_rate <= max_same_srv_rate:
            alerts.append(_alert(
                "port_scan",
                service,
                protocol,
                f"srv_count={srv_count}, same_srv_rate={same_srv_rate:.2f}",
            ))
 
    return alerts
 
 
def _detect_syn_flood(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag connections matching SYN flood patterns.
 
    SYN floods generate many zero-duration TCP connections with high
    SYN error rates. NSL-KDD captures this via: duration=0, high count,
    high serror_rate (SYN errors to same host), flag=S0 (no response).
    """
    alerts = []
    min_count = cfg["syn_flood"]["min_count"]
    min_serror_rate = cfg["syn_flood"]["min_serror_rate"]
    max_duration = cfg["syn_flood"]["max_duration"]
 
    for r in records:
        protocol = r.get("protocol_type", "")
        duration = r.get("duration") or 0
        count = r.get("count") or 0
        serror_rate = r.get("serror_rate") or 0.0
        flag = r.get("flag", "")
        service = r.get("service", "unknown")
 
        if (
            protocol == "tcp"
            and duration <= max_duration
            and count >= min_count
            and serror_rate >= min_serror_rate
        ):
            alerts.append(_alert(
                "syn_flood",
                service,
                protocol,
                f"count={count}, serror_rate={serror_rate:.2f}, flag={flag}, duration={duration}",
            ))
 
    return alerts
 
 
def _detect_brute_force(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag connections with failed login attempts.
 
    NSL-KDD records num_failed_logins per connection and whether the
    session ended with a successful login (logged_in=1). Brute force
    attempts show failed logins without a successful login.
    """
    alerts = []
    min_failed = cfg["brute_force"]["min_failed_logins"]
    require_not_logged_in = cfg["brute_force"]["not_logged_in"]
 
    for r in records:
        failed = r.get("num_failed_logins") or 0
        logged_in = r.get("logged_in") or 0
        service = r.get("service", "unknown")
        protocol = r.get("protocol_type", "unknown")
 
        if failed >= min_failed:
            if require_not_logged_in and logged_in == 1:
                continue
            alerts.append(_alert(
                "brute_force",
                service,
                protocol,
                f"num_failed_logins={failed}, logged_in={logged_in}",
            ))
 
    return alerts
 
 
def detect(records: list[dict], config: dict | None = None) -> list[dict]:
    """
    Run all detection rules over a list of connection records.
 
    Args:
        records: Parsed connection records from parser.parse_log().
        config:  Threshold config. Uses defaults if not provided.
 
    Returns:
        List of alert dicts, each with keys: rule, service, protocol, detail.
    """
    if config is None:
        config = DEFAULT_CONFIG.copy()
 
    alerts = []
    alerts.extend(_detect_port_scan(records, config))
    alerts.extend(_detect_syn_flood(records, config))
    alerts.extend(_detect_brute_force(records, config))
    return alerts
 
 
if __name__ == "__main__":
    import sys
    from src.parser import parse_log
 
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.detector <path/to/log.csv>")
        sys.exit(1)
 
    records = parse_log(sys.argv[1])
    config = load_config()
    alerts = detect(records, config)
 
    if not alerts:
        print("No alerts.")
    else:
        print(f"{len(alerts)} alert(s) detected:\n")
        for a in alerts:
            print(f"[{a['rule'].upper()}] service={a['service']} protocol={a['protocol']} — {a['detail']}")
