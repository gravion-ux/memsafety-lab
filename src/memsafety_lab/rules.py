"""Unsafe C function rules with safe replacements (educational)."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    func: str
    risk: str
    severity: str
    replacement: str
    note: str

RULES = [
    Rule("gets", "buffer overflow", "critical", "fgets(buf, sizeof buf, stdin)",
         "gets cannot limit input length; removed from C11."),
    Rule("strcpy", "buffer overflow", "high", "strlcpy / snprintf with sizeof",
         "Copies until NUL with no destination bound."),
    Rule("strcat", "buffer overflow", "high", "strlcat / snprintf with sizeof",
         "Appends with no destination bound."),
    Rule("sprintf", "buffer overflow", "high", "snprintf(buf, sizeof buf, ...)",
         "Unbounded formatted write."),
    Rule("vsprintf", "buffer overflow", "high", "vsnprintf",
         "Unbounded formatted write from va_list."),
    Rule("scanf", "buffer overflow", "medium", "scanf with field widths, e.g. %63s",
         "%s without a width overflows fixed buffers."),
    Rule("memcpy", "length misuse", "low", "memcpy with validated lengths",
         "Safe only when the length is provably within both buffers."),
    Rule("alloca", "stack exhaustion", "medium", "heap allocation or fixed buffers",
         "Attacker-controlled sizes can exhaust the stack."),
]
RULE_BY_FUNC = {r.func: r for r in RULES}
