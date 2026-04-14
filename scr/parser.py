"""
parser.py: Load and parse network log CSVs into connection records.

Each record is a dict representing one network connection.
Handles missing values, type coercion, and unknown columns gracefully.

Expected columns (NSL-KDD compatible):
    duration, protocol_type, service, flag, src_bytes, dst_bytes,
    land, wrong_fragment, urgent, label (optional)

Usage:
    records = parse_log("data/raw/KDDTrain+.csv")
"""

import csv
from pathlib import Path


# Columns that should be cast to int
INT_FIELDS = {
    "duration", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
}

# Columns that should be cast to float
FLOAT_FIELDS = {
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
}


def _coerce(field: str, value: str) -> int | float | str | None:
    """Cast value to correct type for field. Return None if blank."""
    if value == "" or value is None:
        return None
    if field in INT_FIELDS:
        try:
            return int(value)
        except ValueError:
            return value
    if field in FLOAT_FIELDS:
        try:
            return float(value)
        except ValueError:
            return value
    return value


def parse_log(filepath: str | Path) -> list[dict]:
    """
    Read a network log CSV and return list of connection records.

    Each record is a plain dict — keys are column names, values are
    type-coerced (int/float/str). Rows with no data are skipped.

    Args:
        filepath: Path to CSV file.

    Returns:
        List of dicts, one per connection.

    Raises:
        FileNotFoundError: If filepath doesn't exist.
        ValueError: If file is empty or has no header row.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    records = []

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        if reader.fieldnames is None:
            raise ValueError(f"Empty or headerless file: {path}")

        for row in reader:
            # Skip blank rows
            if not any(row.values()):
                continue

            record = {
                field: _coerce(field, value)
                for field, value in row.items()
            }
            records.append(record)

    return records


def summary(records: list[dict]) -> None:
    """Print basic stats about parsed records."""
    if not records:
        print("No records loaded.")
        return

    print(f"Records:  {len(records)}")
    print(f"Fields:   {list(records[0].keys())}")

    if "label" in records[0]:
        from collections import Counter
        counts = Counter(r["label"] for r in records)
        print("Labels:")
        for label, count in counts.most_common():
            print(f"  {label}: {count}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python parser.py <path/to/log.csv>")
        sys.exit(1)

    records = parse_log(sys.argv[1])
    summary(records)