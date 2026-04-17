"""
cli.py — Command-line interface for the network intrusion detection system.
 
Usage:
    python -m src.cli --input data/raw/KDDTrain+.csv
    python -m src.cli --input data/raw/KDDTrain+.csv --config config.json
    python -m src.cli --input data/raw/KDDTrain+.csv --rule syn_flood
    python -m src.cli --input data/raw/KDDTrain+.csv --quiet
"""
 
import argparse
import sys
from pathlib import Path
 
from src.parser import parse_log
from src.detector import detect, load_config
 
 
RULES = {"port_scan", "syn_flood", "brute_force"}
 
 
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="Rule-based network intrusion detection system.",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Path to network log CSV file.",
    )
    parser.add_argument(
        "--config", "-c",
        default="config.json",
        help="Path to thresholds config (default: config.json).",
    )
    parser.add_argument(
        "--rule", "-r",
        choices=sorted(RULES),
        default=None,
        help="Run a single rule only. Runs all rules if omitted.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only print alert count, not individual alerts.",
    )
    return parser.parse_args()
 
 
def run(args: argparse.Namespace) -> int:
    """Load records, run detection, print results. Returns exit code."""
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: file not found — {input_path}", file=sys.stderr)
        return 1
 
    print(f"Loading {input_path} ...")
    try:
        records = parse_log(input_path)
    except Exception as e:
        print(f"Error parsing log: {e}", file=sys.stderr)
        return 1
 
    print(f"Parsed {len(records)} records.")
 
    config = load_config(args.config)
    alerts = detect(records, config)
 
    # Filter to single rule if requested
    if args.rule:
        alerts = [a for a in alerts if a["rule"] == args.rule]
 
    if not alerts:
        print("No alerts detected.")
        return 0
 
    print(f"\n{len(alerts)} alert(s) detected:\n")
 
    if not args.quiet:
        for a in alerts:
            print(f"  [{a['rule'].upper()}] service={a['service']} protocol={a['protocol']} — {a['detail']}")
 
    return 0
 
 
if __name__ == "__main__":
    sys.exit(run(parse_args()))