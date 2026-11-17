#!/usr/bin/env python3

from pathlib import Path
import re
import sys

RECORD_RE = re.compile(rb'^(?:# event_id\ttype\tname\targs|\d+\t[TASE]\t[^\t\n]+\t.*)$')


def export_valid_tsv_records(source: Path, destination: Path) -> int:
    raw = source.read_bytes()
    valid = []
    saw_padding = False

    for line in raw.splitlines():
        if not line:
            continue
        if RECORD_RE.match(line):
            if saw_padding:
                raise ValueError('Encountered a valid record after trailing non-record padding')
            valid.append(line)
            continue
        if valid:
            saw_padding = True
        elif line.strip(b'\x00'):
            raise ValueError('Encountered unexpected non-record content before the first valid TSV record')

    if not valid:
        raise ValueError('No valid TSV records found')

    destination.write_bytes(b'\n'.join(valid) + b'\n')
    return len(valid)


def main(argv):
    if len(argv) != 3:
        print(f'usage: {argv[0]} SOURCE_TRACE DESTINATION_TRACE', file=sys.stderr)
        return 2
    source = Path(argv[1])
    destination = Path(argv[2])
    exported = export_valid_tsv_records(source, destination)
    print(f'exported_records,{exported}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
