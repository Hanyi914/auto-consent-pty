#!/usr/bin/env python3
"""
Auto Consent PTY

Wrap a CLI process (Claude Code CLI, Codex CLI, Gemini CLI, etc.) inside a PTY
and auto-confirms the first detected consent dialog by sending Enter on the
default option (assumed to be option 1 / Yes / 同意). Detection is based on
terminal text patterns and is scoped to the wrapped process only, so other tabs
are unaffected.

Usage examples:
    python3 auto_consent_pty.py -- claude
    python3 auto_consent_pty.py -- codex --project my_proj
    python3 auto_consent_pty.py -- gemini --flag

Flags:
    --flavor {auto,claude,codex,gemini}  Optional hint for logging/detection.
    --multi                              Allow multiple auto-confirms instead
                                         of single-shot (default: single-shot).
    --debug                              Print detection debug info to stderr.
    --cooldown SECONDS                   Cooldown between auto-confirms (default: 3.0).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import tty
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set


# Comprehensive ANSI escape sequence stripper
# Covers CSI, OSC, DCS, and other terminal control sequences
ANSI_RE = re.compile(
    r"""
    \x1b\[[0-9;?]*[A-Za-z]      |  # CSI sequences: ESC [ ... letter
    \x1b\][^\x07]*\x07          |  # OSC sequences: ESC ] ... BEL
    \x1b\][^\x1b]*\x1b\\        |  # OSC with ST terminator
    \x1b[PX^_][^\x1b]*\x1b\\    |  # DCS, SOS, PM, APC sequences
    \x1b[\(\)][AB012]           |  # Character set selection
    \x1b[=>NOo]                 |  # Keypad/charset modes
    \x1b[78]                    |  # Save/restore cursor (DECSC/DECRC)
    \x1b[DME]                   |  # Index, reverse index, next line
    \x1b\[\?2026[hl]            |  # Synchronized output mode
    \x1b\[\?1004[hl]            |  # Focus events
    \x1b\[\?2004[hl]            |  # Bracketed paste mode
    \x1b\[\?25[hl]              |  # Cursor visibility
    \x1b\[\?1049[hl]            |  # Alternate screen buffer
    \x1b\[[\d;]*[Hf]            |  # Cursor position
    \x1b\[\d*[ABCDJK]           |  # Cursor movement / erase
    \x1b\[\d*[su]               |  # Save/restore cursor position
    \x1b\[\d*G                  |  # Cursor horizontal absolute
    \x07                           # Bell character
    """,
    re.VERBOSE,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for reliable pattern matching."""
    return ANSI_RE.sub("", text)


@dataclass
class DetectionResult:
    matched: bool
    reason: str
    fingerprint: str = ""


class DebugLog:
    """Collect debug lines and dump on exit when enabled."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled
        self.lines: list[str] = []

    def log(self, msg: str) -> None:
        if not self.enabled:
            return
        timestamp = time.strftime("%H:%M:%S")
        self.lines.append(f"[{timestamp}] {msg}")

    def flush(self) -> None:
        if not self.enabled or not self.lines:
            return
        print("\n[auto-consent debug log]", file=sys.stderr)
        for line in self.lines:
            print(line, file=sys.stderr)
        print("[end debug log]\n", file=sys.stderr)


class ConsentDetector:
    """
    Heuristic detector for consent dialogs like:
        Do you want to proceed?
        ❯ 1. Yes
          2. Yes, and don't ask again ...
          3. <path>
          4. Type here ...
        Esc to cancel

    Features:
        - Fingerprint-based deduplication to prevent re-triggering same dialog
        - Cooldown mechanism to prevent rapid-fire triggers
        - Conservative pattern matching to avoid false positives
    """

    # Default cooldown between auto-confirms (seconds)
    DEFAULT_COOLDOWN = 3.0

    def __init__(
        self,
        flavor: str = "auto",
        debug: bool = False,
        logger: Optional[DebugLog] = None,
        cooldown: float = DEFAULT_COOLDOWN,
    ) -> None:
        self.buffer: str = ""
        self.flavor = flavor
        self.debug = debug
        self.logger = logger or DebugLog(enabled=debug)
        self.cooldown = cooldown

        # Deduplication: track handled dialog fingerprints
        self._handled_fingerprints: Set[str] = set()

        # Cooldown: track last consent time
        self._last_consent_time: float = 0

        # Patterns are intentionally conservative to avoid false positives.
        self._question_patterns = [
            # English standard questions
            re.compile(r"do you want to proceed\??", re.IGNORECASE),
            re.compile(r"would you like to proceed\??", re.IGNORECASE),
            re.compile(r"proceed\?\s*$", re.IGNORECASE),
            # Chinese standard questions
            re.compile(r"是否继续", re.IGNORECASE),
            re.compile(r"要继续(吗|么)", re.IGNORECASE),
            # Chinese authorization questions (MCP tools, custom dialogs)
            re.compile(r"是否授权我(使用|创建)", re.IGNORECASE),
            re.compile(r"是否授权", re.IGNORECASE),
        ]
        self._yes_patterns = [
            # English: 1. Yes / Chinese: 1. 同意
            re.compile(
                r"^[\s\xa0]*[❯> ]?[\s\xa0]*1\.?[\s\xa0]*(yes|同意)\b",
                re.IGNORECASE | re.MULTILINE,
            ),
            # Chinese authorization options: 1. 授权执行 / 1. 授权创建 / 1. 授权
            re.compile(
                r"^[\s\xa0]*[❯> ]?[\s\xa0]*1\.?[\s\xa0]*授权(执行|创建)?\b",
                re.IGNORECASE | re.MULTILINE,
            ),
        ]
        self._second_option_patterns = [
            re.compile(r"don't ask again", re.IGNORECASE),
            re.compile(r"不再(询问|提醒)", re.IGNORECASE),
        ]
        self._cancel_hint_patterns = [
            re.compile(r"esc\s+to\s+cancel", re.IGNORECASE),
            re.compile(r"按\s*esc", re.IGNORECASE),
            # Navigation hints (common in MCP tool dialogs)
            re.compile(r"enter\s+to\s+select", re.IGNORECASE),
            re.compile(r"↑/↓\s*to\s+navigate", re.IGNORECASE),
        ]
        self._extra_unique_tokens = [
            # Original Claude-style token
            re.compile(r"type here to tell .* what to do differently", re.IGNORECASE),
            # MCP tool indicators
            re.compile(r"\(MCP\)"),
            re.compile(r"Tool use", re.IGNORECASE),
            re.compile(r"☐"),  # Checkbox indicator
            re.compile(r"tab to add additional instructions", re.IGNORECASE),
            # Option description patterns
            re.compile(r"Type something\.", re.IGNORECASE),
        ]

    def _log(self, message: str) -> None:
        if self.debug:
            print(f"[detector] {message}", file=sys.stderr)
        if self.logger:
            self.logger.log(message)

    def _compute_fingerprint(self, text: str) -> str:
        """
        Compute a fingerprint for the dialog content.
        Uses hash of the question line to identify unique dialogs.
        """
        for p in self._question_patterns:
            m = p.search(text)
            if m:
                # Hash the matched question plus surrounding context
                start = max(0, m.start() - 50)
                end = min(len(text), m.end() + 200)
                context = text[start:end]
                return hashlib.md5(context.encode()).hexdigest()[:16]
        return ""

    def is_in_cooldown(self) -> bool:
        """Check if we're still in cooldown period after last consent."""
        if self._last_consent_time == 0:
            return False
        elapsed = time.time() - self._last_consent_time
        in_cooldown = elapsed < self.cooldown
        if in_cooldown:
            self._log(f"in cooldown: {elapsed:.1f}s < {self.cooldown}s")
        return in_cooldown

    def feed(self, chunk: str) -> DetectionResult:
        """
        Add new output chunk and decide whether it looks like a consent dialog.
        Returns DetectionResult with matched status, reason, and fingerprint.
        """
        self.buffer = (self.buffer + chunk)[-8000:]  # keep last 8KB
        clean = strip_ansi(self.buffer)

        # Check cooldown first
        if self.is_in_cooldown():
            return DetectionResult(matched=False, reason="cooldown")

        # Compute fingerprint for deduplication
        fingerprint = self._compute_fingerprint(clean)

        # Check if already handled
        if fingerprint and fingerprint in self._handled_fingerprints:
            self._log(f"skipping already handled dialog: {fingerprint}")
            return DetectionResult(matched=False, reason="already_handled", fingerprint=fingerprint)

        matched = self._looks_like_dialog(clean)
        return DetectionResult(
            matched=matched,
            reason="pattern_match" if matched else "",
            fingerprint=fingerprint,
        )

    def mark_handled(self, fingerprint: str) -> None:
        """
        Mark a dialog as handled after sending consent.
        This prevents re-triggering on the same dialog.
        """
        if fingerprint:
            self._handled_fingerprints.add(fingerprint)
            self._log(f"marked as handled: {fingerprint}")

        # Update cooldown timer
        self._last_consent_time = time.time()

        # Clear buffer to prevent immediate re-detection
        self.buffer = ""
        self._log("buffer cleared, cooldown started")

    def _looks_like_dialog(self, text: str) -> bool:
        if not text:
            return False

        question = any(p.search(text) for p in self._question_patterns)
        yes_first = any(p.search(text) for p in self._yes_patterns)
        menu_count = len(re.findall(r"(?m)^[\s\xa0]*[❯> ]?[\s\xa0]*\d+\.", text))

        # Require both question and first option to align with the target dialog.
        if not (question and yes_first):
            return False

        # Strengthen with additional hints to avoid accidental triggers.
        has_second = any(p.search(text) for p in self._second_option_patterns)
        has_cancel = any(p.search(text) for p in self._cancel_hint_patterns)
        has_extra = any(p.search(text) for p in self._extra_unique_tokens)

        confidence = sum([has_second, has_cancel, has_extra])
        self._log(
            f"question={question}, yes_first={yes_first}, hints={confidence} "
            f"(second={has_second}, cancel={has_cancel}, extra={has_extra}), menu_count={menu_count}"
        )

        # Require at least one additional hint AND at least two menu items to avoid false positives.
        return confidence >= 1 and menu_count >= 2


def _current_winsize() -> tuple[int, int] | None:
    """Get current terminal size using TIOCGWINSZ; fallback to os.get_terminal_size."""
    for fd in (sys.stdout, sys.stdin):
        try:
            packed = fcntl.ioctl(fd.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
            rows, cols, _, _ = struct.unpack("HHHH", packed)
            if rows and cols:
                return rows, cols
        except OSError:
            continue
    try:
        size = os.get_terminal_size()
        return size.lines, size.columns
    except OSError:
        return None


def set_pty_winsize(fd: int) -> None:
    """Propagate current terminal size to the child PTY."""
    size = _current_winsize()
    if not size:
        return
    rows, cols = size
    buf = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, buf)
    except OSError:
        pass


def _write_all(fd: int, data: bytes) -> None:
    """Write all bytes, handling EAGAIN by waiting for fd to become writable."""
    view = memoryview(data)
    total = len(view)
    sent = 0
    while sent < total:
        try:
            n = os.write(fd, view[sent:])
            if n == 0:
                raise OSError("write returned 0")
            sent += n
        except BlockingIOError:
            # Wait until fd is writable then retry.
            select.select([], [fd], [])
        except InterruptedError:
            continue


def forward_loop(
    pid: int,
    master_fd: int,
    detector: ConsentDetector,
    multi: bool,
    logger: DebugLog,
) -> None:
    """
    Main loop: forward stdin to child, child output to stdout, and inject Enter when
    a consent dialog is detected.

    Features:
        - Single-shot mode: auto-confirm only the first dialog
        - Multi mode: auto-confirm multiple dialogs with cooldown protection
        - Fingerprint deduplication prevents re-triggering same dialog
    """
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()

    old_tty = termios.tcgetattr(stdin_fd)
    tty.setcbreak(stdin_fd)

    # Make stdin non-blocking to avoid select hiccups.
    old_flags = fcntl.fcntl(stdin_fd, fcntl.F_GETFL)
    fcntl.fcntl(stdin_fd, fcntl.F_SETFL, old_flags | os.O_NONBLOCK)

    consent_sent = False
    consent_count = 0

    try:
        while True:
            rlist, _, _ = select.select([master_fd, stdin_fd], [], [])

            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    data = b""

                if not data:
                    break

                # Write to stdout immediately for smooth display
                _write_all(stdout_fd, data)

                # Check for consent dialog if applicable
                should_check = (not consent_sent) or multi
                if should_check:
                    decoded = data.decode(errors="ignore")
                    result = detector.feed(decoded)

                    if result.matched:
                        detector._log(f"matched dialog (#{consent_count + 1}), sending Enter")

                        # Small delay to allow dialog to fully render
                        time.sleep(0.05)

                        # Send "1" + Enter to choose the first option
                        _write_all(master_fd, b"1\r")

                        # Mark as handled (sets cooldown and clears buffer)
                        detector.mark_handled(result.fingerprint)

                        consent_sent = True
                        consent_count += 1
                        detector._log(f"consent #{consent_count} sent successfully")

            if stdin_fd in rlist:
                try:
                    user_data = os.read(stdin_fd, 4096)
                except OSError:
                    user_data = b""

                if user_data:
                    # Translate LF to CR to better match app expectations in wrapped PTY.
                    if b"\n" in user_data and b"\r" not in user_data:
                        user_data = user_data.replace(b"\n", b"\r")
                    _write_all(master_fd, user_data)

    finally:
        # Restore terminal settings
        fcntl.fcntl(stdin_fd, fcntl.F_SETFL, old_flags)
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tty)
        os.close(master_fd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        logger.flush()


def run_wrapped(
    cmd: List[str],
    flavor: str,
    multi: bool,
    debug: bool,
    cooldown: float,
) -> None:
    pid, master_fd = pty.fork()

    if pid == 0:
        # Child process: replace with the target command.
        try:
            os.execvp(cmd[0], cmd)
        except FileNotFoundError:
            print(f"[auto-consent] command not found: {cmd[0]}", file=sys.stderr)
            os._exit(127)

    # Parent process.
    set_pty_winsize(master_fd)
    signal.signal(signal.SIGWINCH, lambda *_: set_pty_winsize(master_fd))

    logger = DebugLog(enabled=debug)
    detector = ConsentDetector(flavor=flavor, debug=debug, logger=logger, cooldown=cooldown)

    if debug:
        mode = "multi" if multi else "single-shot"
        logger.log(f"started in {mode} mode, cooldown={cooldown}s")

    try:
        forward_loop(pid, master_fd, detector, multi=multi, logger=logger)
    except KeyboardInterrupt:
        # Ensure logger flushes even on Ctrl+C
        logger.flush()
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Auto-confirm Warp/agent consent dialogs via PTY injection.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--flavor",
        choices=["auto", "claude", "codex", "gemini"],
        default="auto",
        help="Optional hint to log which CLI is being wrapped.",
    )
    parser.add_argument(
        "--multi",
        action="store_true",
        help="Allow multiple auto-confirms instead of single-shot per process.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detection debug info to stderr.",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=ConsentDetector.DEFAULT_COOLDOWN,
        help=f"Cooldown seconds between auto-confirms (default: {ConsentDetector.DEFAULT_COOLDOWN}).",
    )
    parser.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Command to run (prefix with -- to separate), e.g. -- claude --flag",
    )
    args = parser.parse_args()
    if not args.cmd:
        parser.error("Please provide a command to wrap after --, e.g. python auto_consent_pty.py -- claude")
    if args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    return args


def main() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("[auto-consent] requires an interactive TTY", file=sys.stderr)
        sys.exit(1)

    args = parse_args()
    run_wrapped(
        cmd=args.cmd,
        flavor=args.flavor,
        multi=args.multi,
        debug=args.debug,
        cooldown=args.cooldown,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
