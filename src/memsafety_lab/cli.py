"""CLI for memsafety-lab."""
import argparse
import json
import sys
from pathlib import Path

from .scanner import checklist, scan_text


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Find unsafe memory functions in C source.")
    p.add_argument("paths", nargs="+", help="C source files to scan")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)
    results = []
    for raw in args.paths:
        path = Path(raw)
        findings = scan_text(path.read_text(encoding="utf-8", errors="ignore"))
        results.append({"file": str(path),
                        "findings": [{"func": f.func, "risk": f.risk, "severity": f.severity,
                                      "line": f.line, "replacement": f.replacement,
                                      "note": f.note} for f in findings],
                        "checklist": checklist(findings)})
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(r["file"])
            for item in r["checklist"]:
                print(f"  - {item}")
            if not r["findings"]:
                print("  no unsafe memory functions found")
    return 0

if __name__ == "__main__":
    sys.exit(main())
