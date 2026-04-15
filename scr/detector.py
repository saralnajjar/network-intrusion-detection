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

import json
from collections import defaultdict
from pathlib import Path


# Default thresholds (override via config.json)
DEFAULT_CONFIG = {
    "port_scan": {
        "min_services": 10,
    },
    "syn_flood": {
        "min_connections": 50,
        "max_duration": 2,
        "window": 100,
    },
    "brute_force": {
        "min_failed_logins": 5,
        "window": 100,
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
        # Merge (user values override defaults per rule)
        config = DEFAULT_CONFIG.copy()
        for rule, values in user_config.items():
            if rule in config:
                config[rule].update(values)
        return config
    return DEFAULT_CONFIG.copy()


def _alert(rule: str, src: str, detail: str) -> dict:
    """Build a standard alert dict."""
    return {"rule": rule, "src": src, "detail": detail}


def _detect_port_scan(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag sources that connect to many distinct services.

    Port scanners probe multiple services rapidly to map open ports.
    Uses a sliding window over sequential records.
    """
    alerts = []
    window = cfg["port_scan"]["window"]
    threshold = cfg["port_scan"]["min_services"]

    for i in range(len(records)):
        chunk = records[max(0, i - window):i + 1]
        src_services: dict[str, set] = defaultdict(set)

        for r in chunk:
            src = r.get("src_bytes")  # placeholder (real logs use src_ip)
            service = r.get("service")
            if src is not None and service:
                src_services[str(src)].add(service)

        for src, services in src_services.items():
            if len(services) >= threshold:
                alerts.append(_alert(
                    "port_scan",
                    src,
                    f"contacted {len(services)} distinct services: {sorted(services)}"
                ))

    # Deduplicate (one alert per src)
    seen = set()
    unique = []
    for a in alerts:
        if a["src"] not in seen:
            seen.add(a["src"])
            unique.append(a)
    return unique


def _detect_syn_flood(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag sources sending many short TCP connections (SYN flood pattern).

    SYN floods send rapid connection attempts with minimal data transfer,
    resulting in high connection count and near-zero average duration.
    """
    alerts = []
    window = cfg["syn_flood"]["window"]
    min_conns = cfg["syn_flood"]["min_connections"]
    max_avg_duration = cfg["syn_flood"]["max_duration"]

    chunk_sources: dict[str, list] = defaultdict(list)

    for r in records:
        protocol = r.get("protocol_type", "")
        duration = r.get("duration")
        src = r.get("src_bytes")  # placeholder

        if protocol == "tcp" and src is not None and duration is not None:
            chunk_sources[str(src)].append(duration)

    for src, durations in chunk_sources.items():
        if len(durations) >= min_conns:
            avg_duration = sum(durations) / len(durations)
            if avg_duration <= max_avg_duration:
                alerts.append(_alert(
                    "syn_flood",
                    src,
                    f"{len(durations)} TCP connections, avg duration {avg_duration:.2f}s"
                ))

    return alerts


def _detect_brute_force(records: list[dict], cfg: dict) -> list[dict]:
    """
    Flag sources with repeated failed login attempts.

    Brute force attacks try many credential combinations, generating
    a high number of failed logins from the same source.
    """
    alerts = []
    threshold = cfg["brute_force"]["min_failed_logins"]

    src_failures: dict[str, int] = defaultdict(int)

    for r in records:
        failed = r.get("num_failed_logins", 0) or 0
        src = r.get("src_bytes")  # placeholder
        if src is not None and failed > 0:
            src_failures[str(src)] += failed

    for src, total_failures in src_failures.items():
        if total_failures >= threshold:
            alerts.append(_alert(
                "brute_force",
                src,
                f"{total_failures} failed login attempts"
            ))

    return alerts


def detect(records: list[dict], config: dict | None = None) -> list[dict]:
    """
    Run all detection rules over a list of connection records.

    Args:
        records: Parsed connection records from parser.parse_log().
        config:  Threshold config. Uses defaults if not provided.

    Returns:
        List of alert dicts, each with keys: rule, src, detail.
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
        print("Usage: python detector.py <path/to/log.csv>")
        sys.exit(1)

    records = parse_log(sys.argv[1])
    config = load_config()
    alerts = detect(records, config)

    if not alerts:
        print("No alerts.")
    else:
        print(f"{len(alerts)} alert(s) detected:\n")
        for a in alerts:
            print(f"[{a['rule'].upper()}] src={a['src']} — {a['detail']}")