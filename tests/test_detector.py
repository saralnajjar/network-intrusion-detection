"""
test_detector.py — Unit tests for the rule engine in src/detector.py

Run with:
    python3 -m pytest tests/test_detector.py -v
"""
import pytest
from src.detector import (
    detect,
    _detect_port_scan,
    _detect_syn_flood,
    _detect_brute_force,
    DEFAULT_CONFIG,
)


# Helpers

def make_record(**kwargs) -> dict:
    """Base connection record with safe defaults."""
    defaults = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 100,
        "dst_bytes": 100,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "label": "normal",
    }
    defaults.update(kwargs)
    return defaults


def syn_flood_record(service="http", count=150, serror_rate=1.0) -> dict:
    """Record that matches SYN flood pattern."""
    return make_record(
        protocol_type="tcp",
        service=service,
        flag="S0",
        duration=0,
        count=count,
        serror_rate=serror_rate,
    )


def port_scan_record(service="http", srv_count=25, same_srv_rate=0.05) -> dict:
    """Record that matches port scan pattern."""
    return make_record(
        service=service,
        srv_count=srv_count,
        same_srv_rate=same_srv_rate,
    )


def brute_force_record(service="ftp", num_failed_logins=3, logged_in=0) -> dict:
    """Record that matches brute force pattern."""
    return make_record(
        service=service,
        num_failed_logins=num_failed_logins,
        logged_in=logged_in,
    )

# SYN Flood

class TestSynFlood:
    def test_detects_syn_flood(self):
        records = [syn_flood_record()]
        alerts = _detect_syn_flood(records, DEFAULT_CONFIG)
        assert len(alerts) == 1
        assert alerts[0]["rule"] == "syn_flood"

    def test_no_alert_below_count_threshold(self):
        records = [syn_flood_record(count=50)]  # threshold is 100
        alerts = _detect_syn_flood(records, DEFAULT_CONFIG)
        assert len(alerts) == 0

    def test_no_alert_below_serror_threshold(self):
        records = [syn_flood_record(serror_rate=0.1)]  # threshold is 0.5
        alerts = _detect_syn_flood(records, DEFAULT_CONFIG)
        assert len(alerts) == 0

    def test_no_alert_nonzero_duration(self):
        record = syn_flood_record()
        record["duration"] = 5
        alerts = _detect_syn_flood([record], DEFAULT_CONFIG)
        assert len(alerts) == 0

    def test_no_alert_udp_protocol(self):
        record = syn_flood_record()
        record["protocol_type"] = "udp"
        alerts = _detect_syn_flood([record], DEFAULT_CONFIG)
        assert len(alerts) == 0
    
    def test_multiple_floods_detected(self):
        records = [syn_flood_record(service=s) for s in ["http", "ftp", "ssh"]]
        alerts = _detect_syn_flood(records, DEFAULT_CONFIG)
        assert len(alerts) == 3

    def test_alert_contains_expected_keys(self):
        alerts = _detect_syn_flood([syn_flood_record()], DEFAULT_CONFIG)
        assert "rule" in alerts[0]
        assert "service" in alerts[0]
        assert "protocol" in alerts[0]
        assert "detail" in alerts[0]

    def test_custom_threshold(self):
        config = {**DEFAULT_CONFIG, "syn_flood": {**DEFAULT_CONFIG["syn_flood"], "min_count": 200}}
        records = [syn_flood_record(count=150)]  # below custom threshold
        alerts = _detect_syn_flood(records, config)
        assert len(alerts) == 0