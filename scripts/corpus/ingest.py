#!/usr/bin/env python3
"""Turns a pasted on-air log excerpt into a scaffolded golden-frame capture YAML.

Parses the two on-air log formats used by this project — the structured `io_capture` tag
(hub_internal.h) and the legacy `io_frame` tag (log_frame.h) — via protolib.parse_log(), with a
liberal fallback tier for mangled pastes. Emits a capture YAML skeleton (source metadata, raw
frames, and mechanically-derived `expect:` proposals) that a human must review and confirm
before committing — see tests/corpus/README.md :: "Expectations are human-verified". Every
capture this tool emits is `key: unknown`; re-key support (`--rekey`) arrives in a later tool
version (corpus plan Step 5).

Usage:
  python3 scripts/corpus/ingest.py analysis/issues/27.txt \\
      --id issue_27_somfy_sunea_discovery --device "Somfy Sunea IO motor" \\
      --captured-with heltec-v3 --origin github-issue \\
      --issue https://github.com/laberning/home_io_control/issues/27 --date 2026-07-06 \\
      -o tests/corpus/captures/issues/issue_27_somfy_sunea_discovery.yaml

Read from stdin instead of a file with `-` as the input path — handy for piping a trimmed
excerpt (`sed -n '10,40p' analysis/issues/27.txt | python3 scripts/corpus/ingest.py - ...`)
instead of hand-editing a scratch file.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from protolib import cmd_name, ctrl0_implied_length, is_end, is_oneway, is_start, parse_log  # noqa: E402


def read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def normalize_t_ms(frames) -> None:
    """Rebase every frame's t_ms to be relative to the earliest known timestamp in the set."""
    known = [f.t_ms for f in frames if f.t_ms is not None]
    if not known:
        return
    base = min(known)
    for frame in frames:
        if frame.t_ms is not None:
            frame.t_ms -= base


def yaml_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_frame_yaml(frame) -> str:
    lines = [f"  - dir: {frame.direction}"]
    if frame.t_ms is not None:
        lines.append(f"    t_ms: {frame.t_ms}")
    if frame.freq:
        lines.append(f"    freq: {frame.freq}")
    lines.append(f"    hex: \"{frame.hex_bytes.upper()}\"")
    lines.append(f"    crc: {'present' if frame.crc_present() else 'absent'}")

    note_bits = []
    if frame.unverified:
        note_bits.append("UNVERIFIED-EXTRACTION: could not confirm frame shape from a known log tag")
    raw = frame.raw()
    if not frame.unverified and len(raw) >= FRAME_MIN_SIZE_FOR_NOTE:
        ctrl0 = raw[0]
        if len(raw) == ctrl0_implied_length(ctrl0):
            cmd = raw[8]
            note_bits.append(f"cmd={cmd_name(cmd)}(0x{cmd:02X})")
    if note_bits:
        lines.append(f"    note: {yaml_quote('; '.join(note_bits))}")
    return "\n".join(lines)


FRAME_MIN_SIZE_FOR_NOTE = 9  # mirrors protolib.FRAME_MIN_SIZE; raw[8] (cmd byte) needs len>=9


def render_expect_frame_yaml(frame) -> "str | None":
    """Mechanically-derivable proposal from CTRL0 bits alone: cmd, start/end, 1w/2w. Never
    proposes decoded semantics (1W intent, device name, position) — those need the real decoder
    and, per the corpus's human-verification rule, must be confirmed against the issue thread's
    established facts rather than rubber-stamped from any decoder's current output.
    """
    raw = frame.raw()
    if frame.unverified or len(raw) < FRAME_MIN_SIZE_FOR_NOTE:
        return None
    ctrl0 = raw[0]
    if len(raw) != ctrl0_implied_length(ctrl0):
        return None  # length disagrees with CTRL0 — extraction is unreliable, propose nothing
    cmd = raw[8]
    protocol = "1w" if is_oneway(ctrl0) else "2w"
    return (f"    - {{cmd: 0x{cmd:02X}, start: {str(is_start(ctrl0)).lower()}, "
            f"end: {str(is_end(ctrl0)).lower()}, protocol: {protocol}}}  # PROPOSED — verify before commit")


def build_yaml(args, frames) -> str:
    unverified_count = sum(1 for f in frames if f.unverified)
    description = args.description or f"Scaffolded from {args.input} by ingest.py — TODO: describe the scenario."

    lines = [
        f"id: {args.id}",
        "description: >",
        f"  {description}",
        "source:",
        f"  device: {yaml_quote(args.device)}",
        f"  captured_with: {args.captured_with}",
        f"  firmware: {yaml_quote(args.firmware) if args.firmware else 'null'}",
        f"  date: {args.date}",
        f"  origin: {args.origin}",
        f"  issue: {yaml_quote(args.issue) if args.issue else 'null'}",
        "key: unknown",
        "frames:",
    ]
    lines.extend(render_frame_yaml(frame) for frame in frames)

    expect_lines = [line for line in (render_expect_frame_yaml(f) for f in frames) if line is not None]
    if expect_lines:
        lines.append("expect:")
        lines.append("  frames:")
        lines.extend(expect_lines)

    if unverified_count:
        print(f"ingest.py: {unverified_count} frame(s) marked UNVERIFIED-EXTRACTION — review before committing",
              file=sys.stderr)

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="log file to parse, or '-' for stdin")
    parser.add_argument("--id", required=True, help="capture id (globally unique across the corpus)")
    parser.add_argument("--device", required=True, help="free-text device description")
    parser.add_argument("--captured-with", default="other", choices=["heltec-v2", "heltec-v3", "other", "synthetic"])
    parser.add_argument("--origin", required=True, choices=["own-hardware", "github-issue", "synthetic-bootstrap"])
    parser.add_argument("--issue", default=None, help="issue URL, e.g. https://github.com/.../issues/27")
    parser.add_argument("--date", required=True, help="YYYY-MM-DD")
    parser.add_argument("--firmware", default=None)
    parser.add_argument("--description", default=None, help="free-text scenario summary")
    parser.add_argument("-o", "--output", required=True, help="output capture YAML path")
    args = parser.parse_args()

    text = read_input(args.input)
    frames = parse_log(text)
    if not frames:
        print("ingest.py: no frames extracted from input", file=sys.stderr)
        return 1
    normalize_t_ms(frames)

    rendered = build_yaml(args, frames)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    unverified_count = sum(1 for f in frames if f.unverified)
    print(f"ingest.py: wrote {output_path} ({len(frames)} frames, {unverified_count} unverified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
