"""Prepare an offline MA-L prefix table from the IEEE Registration Authority CSV."""

import argparse
import csv
import re
from pathlib import Path


def convert(source, output):
    with source.open(encoding="utf-8-sig", newline="") as stream:
        vendors = {}
        for row in csv.DictReader(stream):
            prefix = row["Assignment"].upper()
            name = " ".join(row["Organization Name"].split())
            if row["Registry"] == "MA-L" and re.fullmatch("[0-9A-F]{6}", prefix) and name:
                vendors[prefix] = name
    if not vendors:
        raise ValueError("no IEEE MA-L records")
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        for prefix, name in sorted(vendors.items()):
            stream.write(f"{prefix}\t{name}\n")
    return len(vendors)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("ieee_csv", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    print(convert(a.ieee_csv, a.output))
