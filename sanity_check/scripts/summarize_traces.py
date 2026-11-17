#!/usr/bin/env python3

import csv
from collections import Counter
from pathlib import Path


def count_lines(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def load_events(path: Path):
    events = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line in handle:
            if not line or line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            events.append((parts[1], parts[2]))
    return events


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    manifest_path = root / "trace_manifest.csv"

    rows = list(csv.DictReader(manifest_path.open("r", encoding="utf-8", newline="")))
    status_counts = Counter(row["status"] for row in rows)

    print(f"manifest_rows,{len(rows)}")
    for status, count in sorted(status_counts.items()):
        print(f"status,{status},{count}")
    print(f"included_pairs,{status_counts.get('included', 0)}")

    mismatches = []
    missing_files = []
    exact_event_sequence_matches = 0
    terminal_record_only_differences = 0
    event_sequence_differences = []

    for row in rows:
        if row["status"] != "included":
            continue

        for key in ("original_trace", "variant_trace"):
            rel = row[key]
            path = root / rel
            if not path.exists():
                missing_files.append((row["sha256"], key, rel))

        original_path = root / row["original_trace"]
        variant_path = root / row["variant_trace"]
        if not original_path.exists() or not variant_path.exists():
            continue

        observed_original_lines = count_lines(original_path)
        observed_variant_lines = count_lines(variant_path)
        observed_original_bytes = original_path.stat().st_size
        observed_variant_bytes = variant_path.stat().st_size

        expected = (
            int(row["original_lines"]),
            int(row["variant_lines"]),
            int(row["original_bytes"]),
            int(row["variant_bytes"]),
        )
        observed = (
            observed_original_lines,
            observed_variant_lines,
            observed_original_bytes,
            observed_variant_bytes,
        )

        if expected != observed:
            mismatches.append((row["sha256"], expected, observed))

        original_events = load_events(original_path)
        variant_events = load_events(variant_path)

        if original_events == variant_events:
            exact_event_sequence_matches += 1
            continue

        original_terminal = original_events[-1:] if original_events and original_events[-1][0] == "E" else []
        variant_terminal = variant_events[-1:] if variant_events and variant_events[-1][0] == "E" else []
        original_core = original_events[:-1] if original_terminal else original_events
        variant_core = variant_events[:-1] if variant_terminal else variant_events

        if original_core == variant_core and original_terminal != variant_terminal:
            terminal_record_only_differences += 1
            continue

        event_sequence_differences.append((row["sha256"], len(original_events), len(variant_events)))

    print(f"missing_files,{len(missing_files)}")
    print(f"content_mismatches,{len(mismatches)}")
    print(f"exact_event_sequence_matches,{exact_event_sequence_matches}")
    print(f"terminal_record_only_differences,{terminal_record_only_differences}")
    print(f"event_sequence_differences,{len(event_sequence_differences)}")

    for sha256, key, rel in missing_files[:10]:
        print(f"missing,{sha256},{key},{rel}")

    for sha256, expected, observed in mismatches[:10]:
        print(
            "mismatch,"
            f"{sha256},"
            f"expected_lines={expected[0]}/{expected[1]},"
            f"observed_lines={observed[0]}/{observed[1]},"
            f"expected_bytes={expected[2]}/{expected[3]},"
            f"observed_bytes={observed[2]}/{observed[3]}"
        )

    for sha256, original_len, variant_len in event_sequence_differences[:10]:
        print(
            "event_sequence_difference,"
            f"{sha256},"
            f"original_events={original_len},"
            f"variant_events={variant_len}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
