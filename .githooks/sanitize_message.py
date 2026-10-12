#!/usr/bin/env python3
"""Remove Co-Authored-By trailers from a Git message file."""

import re
import sys
from pathlib import Path


COAUTHOR = re.compile(r"^\s*co[ -]*authored[ -]*by\s*:", re.IGNORECASE)


def sanitize(text):
    lines = text.splitlines(keepends=True)
    kept = [line for line in lines if not COAUTHOR.match(line.rstrip("\r\n"))]
    if len(kept) == len(lines):
        return text

    # Removing a final trailer should not leave extra blank lines behind.
    while kept and kept[-1].strip("\r\n") == "":
        kept.pop()
    if not kept:
        return ""

    newline = "\r\n" if "\r\n" in text else "\n"
    result = "".join(kept).rstrip("\r\n")
    return result + newline


def main(argv):
    if not argv:
        print("commit hook: expected a commit message file", file=sys.stderr)
        return 2
    path = Path(argv[0])
    try:
        original = path.read_bytes()
        text = original.decode("utf-8", errors="surrogateescape")
        cleaned = sanitize(text)
        if cleaned != text:
            path.write_bytes(cleaned.encode("utf-8", errors="surrogateescape"))
    except OSError as error:
        print(f"commit hook: cannot sanitize message file {path}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
