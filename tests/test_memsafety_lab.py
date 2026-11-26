from memsafety_lab.scanner import checklist, scan_text

SAMPLE = """
#include <stdio.h>
#include <string.h>
void f(char *in) {
    char buf[64];
    strcpy(buf, in);
    sprintf(buf, "%s", in);
    fgets(buf, sizeof buf, stdin);
    scanf("%63s", buf);
}
"""

def test_detects_strcpy_and_sprintf():
    funcs = {f.func for f in scan_text(SAMPLE)}
    assert "strcpy" in funcs and "sprintf" in funcs

def test_safe_calls_not_flagged():
    funcs = {f.func for f in scan_text(SAMPLE)}
    assert "fgets" not in funcs
    assert "scanf" not in funcs  # width-limited

def test_gets_is_critical():
    findings = scan_text("gets(buf);")
    assert findings[0].severity == "critical"

def test_checklist_mentions_replacement():
    items = checklist(scan_text(SAMPLE))
    assert any("snprintf" in i for i in items)

def test_clean_code():
    assert scan_text("int main(void) { return 0; }") == []
