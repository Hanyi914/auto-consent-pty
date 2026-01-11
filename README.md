# Auto Consent PTY

Minimal PTY-level auto-consent helper for agent CLIs (Claude Code CLI, Codex CLI, Gemini CLI) inside Warp. It wraps the target CLI process, watches its TUI output, and auto-presses Enter on the first option (Yes / 同意) the first time a consent dialog appears. Scope is limited to the wrapped process/tab; no other tabs receive injected input.

## Why
- Avoid manual approval when the CLI asks “Do you want to proceed?” (or “是否继续/同意”).
- Default to option 1 (Yes / 同意) and send Enter once per process lifecycle.
- PTY injection (not UI automation) so it stays inside the target tab.

## Usage
```bash
# Claude Code CLI
python3 auto_consent_pty.py -- claude

# Codex CLI
python3 auto_consent_pty.py -- codex --project myproj

# Gemini CLI
python3 auto_consent_pty.py -- gemini --flag

# Enable debug logs
python3 auto_consent_pty.py --debug -- claude

# Allow multiple auto-confirms (default is single-shot)
python3 auto_consent_pty.py --multi -- claude
```

> Tip: add a convenient alias (per tab) if you like:
> `cld(){ python3 ~/Desktop/Programming/auto-consent-pty/auto_consent_pty.py -- claude "$@"; }`

## Detection heuristics
- Looks for a consent question (`Do you want to proceed?`, `Would you like to proceed?`, `是否继续`, `要继续吗`) **and** a first option line like `1. Yes` / `1. 同意`.
- Requires at least one extra hint (`Yes, and don't ask again`, `Esc to cancel`, or the Claude-style “Type here to tell … what to do differently”) to avoid accidental triggers.
- Strips ANSI codes before matching; keeps only the latest 8KB of text.
- Single-shot by default; `--multi` keeps scanning after the first auto-enter.

## Notes
- Requires an interactive TTY (run directly in Warp tab).
- All input stays inside the PTY of the wrapped process; other tabs are untouched.
- Exits when the wrapped CLI exits. KeyboardInterrupt (Ctrl+C) stops the wrapper.
- If the TUI looks compressed, it means the child saw a small terminal size; the script now forwards the real window size via TIOCGWINSZ/SIGWINCH, but let me know if it still appears narrow.

## Shell MCP server (optional)
- A local Shell MCP server is installed at `auto-consent-pty/shell-mcp`.
- Config: `auto-consent-pty/shell-mcp/config.json` (local executor only, blacklist enabled).
- Launch manually: `cd auto-consent-pty/shell-mcp && ./run_shell_mcp.sh`
- Sample MCP config for clients: `auto-consent-pty/shell-mcp/mcp-servers.sample.json`
  - For Claude/Codex/Gemini CLI, add the `mcpServers.shell-mcp` entry to their MCP config.
  - Uses the bundled venv `shell-mcp/.venv-shell-mcp`.
