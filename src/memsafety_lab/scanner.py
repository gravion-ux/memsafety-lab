"""Scan C source for unsafe memory functions."""
import re
from dataclasses import dataclass

from .rules import RULE_BY_FUNC


@dataclass
class Finding:
    func: str
    risk: str
    severity: str
    line: int
    replacement: str
    note: str

def scan_text(text: str) -> list[Finding]:
    findings = []
    lines = text.splitlines()
    for func, rule in RULE_BY_FUNC.items():
        pattern = re.compile(r"\b" + re.escape(func) + r"\s*\(")
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                if func == "scanf" and re.search(r"%\d+s", line):
                    continue  # width-limited scanf is acceptable
                findings.append(Finding(func, rule.risk, rule.severity, i,
                                        rule.replacement, rule.note))
    findings.sort(key=lambda f: (f.line, f.func))
    return findings

def checklist(findings: list[Finding]) -> list[str]:
    items = []
    for f in findings:
        items.append(f"Line {f.line}: replace {f.func}() — {f.replacement}")
    return items
