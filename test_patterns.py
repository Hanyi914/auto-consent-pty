#!/usr/bin/env python3
"""
Test script for auto_consent_pty consent detection patterns.

Usage:
    python3 test_patterns.py
"""

import re
import sys

# Detection patterns (must match auto_consent_pty.py)
QUESTION_PATTERNS = [
    re.compile(r"do you want to proceed\??", re.IGNORECASE),
    re.compile(r"would you like to proceed\??", re.IGNORECASE),
    re.compile(r"proceed\?\s*$", re.IGNORECASE),
    re.compile(r"是否继续", re.IGNORECASE),
    re.compile(r"要继续(吗|么)", re.IGNORECASE),
    re.compile(r"是否授权我(使用|创建)", re.IGNORECASE),
    re.compile(r"是否授权", re.IGNORECASE),
]

YES_PATTERNS = [
    re.compile(
        r"^[\s\xa0]*[❯> ]?[\s\xa0]*1\.?[\s\xa0]*(yes|同意)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    re.compile(
        r"^[\s\xa0]*[❯> ]?[\s\xa0]*1\.?[\s\xa0]*授权(执行|创建)?\b",
        re.IGNORECASE | re.MULTILINE,
    ),
]

CANCEL_PATTERNS = [
    re.compile(r"esc\s+to\s+cancel", re.IGNORECASE),
    re.compile(r"按\s*esc", re.IGNORECASE),
    re.compile(r"enter\s+to\s+select", re.IGNORECASE),
    re.compile(r"↑/↓\s+to\s+navigate", re.IGNORECASE),
]

EXTRA_PATTERNS = [
    re.compile(r"type here to tell .* what to do differently", re.IGNORECASE),
    re.compile(r"\(MCP\)", re.IGNORECASE),
    re.compile(r"Tool use", re.IGNORECASE),
    re.compile(r"☐"),
    re.compile(r"tab to add additional instructions", re.IGNORECASE),
    re.compile(r"Type something\.", re.IGNORECASE),
]

# Test cases: (name, expected_detection, dialog_text)
TEST_CASES = [
    (
        "Standard Claude MCP dialog",
        True,
        """Tool use
   shell-mcp - execute_command(command: "ls") (MCP)

Do you want to proceed?
❯ 1. Yes
  2. Yes, and dont ask again
  3. No

Esc to cancel""",
    ),
    (
        "Chinese authorization (使用)",
        True,
        """☐ shell-mcp授权

是否授权我使用 shell-mcp 创建项目？

❯ 1. 授权执行
  2. 查看更多细节

Enter to select · ↑/↓ to navigate · Esc to cancel""",
    ),
    (
        "Chinese authorization (创建)",
        True,
        """☐ 创建collector.py

是否授权我创建 scripts/collector.py？

❯ 1. 授权创建
  2. 查看完整代码

Enter to select · Esc to cancel""",
    ),
    (
        "Generic 是否授权",
        True,
        """是否授权执行此操作？

❯ 1. 授权
  2. 取消

Esc to cancel""",
    ),
    (
        "Tab instructions hint",
        True,
        """Do you want to proceed?
❯ 1. Yes
  2. No

Tab to add additional instructions""",
    ),
    (
        "Type something hint",
        True,
        """是否授权？
❯ 1. 授权执行
  4. Type something.

Esc to cancel""",
    ),
    (
        "Would you like to proceed",
        True,
        """Would you like to proceed?
❯ 1. Yes
  2. No

Esc to cancel""",
    ),
    (
        "是否继续 pattern",
        True,
        """是否继续执行？
❯ 1. 同意
  2. 取消

按 Esc 取消""",
    ),
    (
        "Negative: Plain text output",
        False,
        """This is just regular output.
No authorization needed here.
Just some logs...""",
    ),
    (
        "Negative: Code with 'proceed' in string",
        False,
        """def ask():
    print("Do you want to proceed?")
    return input()""",
    ),
    (
        "Negative: Missing yes option",
        False,
        """Do you want to proceed?

Esc to cancel""",
    ),
]


def match_any(patterns: list, text: str) -> bool:
    """Check if any pattern matches the text."""
    return any(p.search(text) for p in patterns)


def detect_consent(text: str) -> tuple[bool, dict]:
    """
    Detect if text contains a consent dialog.
    Returns (detected, details).
    """
    q = match_any(QUESTION_PATTERNS, text)
    y = match_any(YES_PATTERNS, text)
    c = match_any(CANCEL_PATTERNS, text)
    e = match_any(EXTRA_PATTERNS, text)

    detected = q and y and (c or e)
    details = {"question": q, "yes_first": y, "cancel_hint": c, "extra_token": e}

    return detected, details


def run_tests(verbose: bool = True) -> tuple[int, int]:
    """Run all test cases. Returns (passed, failed)."""
    passed = 0
    failed = 0

    if verbose:
        print("Auto-consent-pty Pattern Tests")
        print("=" * 60)

    for name, expected, text in TEST_CASES:
        detected, details = detect_consent(text)
        ok = detected == expected

        if ok:
            passed += 1
            status = "✓ PASS"
        else:
            failed += 1
            status = "✗ FAIL"

        if verbose:
            print(f"\n{status}: {name}")
            print(
                f"  q={details['question']} y={details['yes_first']} "
                f"c={details['cancel_hint']} e={details['extra_token']}"
            )
            print(f"  detected={detected}, expected={expected}")

    if verbose:
        print("\n" + "=" * 60)
        print(f"Results: {passed}/{passed + failed} passed")

        if failed > 0:
            print(f"\n⚠️  {failed} test(s) failed!")
        else:
            print("\n✓ All tests passed!")

    return passed, failed


def main():
    """Main entry point."""
    verbose = "--quiet" not in sys.argv and "-q" not in sys.argv

    passed, failed = run_tests(verbose=verbose)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
