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
 
 
# NSL-KDD has no header row — define column names manually
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]
 
# Columns cast to int
INT_FIELDS = {
    "duration", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "dst_host_count", "dst_host_srv_count", "difficulty",
}
 
# Columns cast to float
FLOAT_FIELDS = {
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
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
    Read an NSL-KDD CSV and return list of connection records.
 
    Injects NSL_KDD_COLUMNS as header since the file has none.
    Each record is a plain dict with type-coerced values.
 
    Args:
        filepath: Path to CSV file.
 
    Returns:
        List of dicts, one per connection.
 
    Raises:
        FileNotFoundError: If filepath doesn't exist.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
 
    records = []
 
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not any(row):
                continue
            # Zip with column names — truncate/pad if row length differs
            record = {
                NSL_KDD_COLUMNS[i]: _coerce(NSL_KDD_COLUMNS[i], val)
                for i, val in enumerate(row)
                if i < len(NSL_KDD_COLUMNS)
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
        print("Usage: python3 src/parser.py <path/to/log.csv>")
        sys.exit(1)
 
    records = parse_log(sys.argv[1])
    summary(records)