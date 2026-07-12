"""Shared read-side protocol helpers for the golden-frame corpus toolchain.

Ported, read-only mirrors of small pieces of components/home_io_control/proto_frame.{h,cpp} and
proto_constants.h — just enough for validate.py and ingest.py to check/derive frame shape
without a C++ toolchain in the loop. Nothing here writes wire bytes or touches crypto (that
lands in ingest.py's --rekey path, a later tool version).
"""

import re

# --- Mirrors components/home_io_control/proto_sizes.h ---------------------------------------
FRAME_MIN_SIZE = 9  # CTRL0 + CTRL1 + DST(3) + SRC(3) + CMD(1)
FRAME_MAX_SIZE = 32  # 9 header + 23 data

# --- Mirrors components/home_io_control/proto_frame.h :: CTRL0/CTRL1 bit layout -------------
CTRL0_END = 0x80
CTRL0_START = 0x40
CTRL0_PROTOCOL_1W = 0x20
CTRL0_LENGTH_MASK = 0x1F

# --- Mirrors components/home_io_control/proto_frame.cpp :: crc_ccitt() ----------------------
CRC_POLYNOMIAL_REVERSED = 0x8408


def parse_hex(hex_str: str) -> bytes:
    """Canonical hex-string -> bytes conversion, tolerant of internal whitespace.

    The one place this logic lives; build.py and validate.py's own parse_hex (which adds
    error-message context) both delegate here instead of reimplementing it.
    """
    return bytes.fromhex("".join(hex_str.split()))


def crc_ccitt(data: bytes) -> int:
    """Port of crc_ccitt() in proto_frame.cpp: poly 0x8408 (reversed), init 0x0000."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ CRC_POLYNOMIAL_REVERSED if (crc & 0x0001) else (crc >> 1)
    return crc & 0xFFFF


def ctrl0_implied_length(ctrl0: int) -> int:
    """Total non-CRC frame length implied by CTRL0 bits [4:0] (proto_frame.cpp :: frame_length())."""
    return (ctrl0 & CTRL0_LENGTH_MASK) + 1


def is_start(ctrl0: int) -> bool:
    return bool(ctrl0 & CTRL0_START)


def is_end(ctrl0: int) -> bool:
    return bool(ctrl0 & CTRL0_END)


def is_oneway(ctrl0: int) -> bool:
    return bool(ctrl0 & CTRL0_PROTOCOL_1W)


# --- Mirrors components/home_io_control/proto_constants.h :: CMD_* (subset used for scaffold
# readability/notes only — never used to derive a committed `expect:` value, which must be
# human/issue-thread verified per tests/corpus/README.md).
CMD_NAMES = {
    0x00: "EXECUTE",
    0x01: "ACTIVATE_MODE",
    0x03: "PRIVATE",
    0x04: "PRIVATE_RESP",
    0x19: "SET_SENSOR",
    0x1A: "SET_SENSOR_ACK",
    0x20: "WRITE_PRIVATE",
    0x21: "WRITE_PRIVATE_ACK",
    0x28: "DISCOVER_REQ",
    0x29: "DISCOVER_RESP",
    0x2A: "DISCOVER_SPE_REQ",
    0x2B: "DISCOVER_SPE_RESP",
    0x2C: "DISCOVER_CONFIRM",
    0x2D: "DISCOVER_CONFIRM_ACK",
    0x2E: "DISCOVER_ALT_REQ",
    0x31: "KEY_INIT",
    0x32: "KEY_TRANSFER",
    0x33: "KEY_CONFIRM",
    0x36: "ADDRESS_REQ",
    0x37: "ADDRESS_RESP",
    0x38: "LAUNCH_KEY_TRANSFER",
    0x3C: "CHALLENGE_REQ",
    0x3D: "CHALLENGE_RESP",
    0x50: "GET_NAME",
    0x51: "GET_NAME_RESP",
    0x52: "SET_NAME",
    0x53: "SET_NAME_RESP",
    0x56: "GET_INFO2",
    0x57: "GET_INFO2_RESP",
    0x6F: "SET_CONFIG1",
    0x70: "SET_CONFIG1_RESP",
    0x71: "STATUS_UPDATE",
    0x72: "STATUS_UPDATE_RESP",
    0xFE: "ERROR_RESP",
}


def cmd_name(cmd: int) -> str:
    return CMD_NAMES.get(cmd, f"UNKNOWN_0x{cmd:02X}")


class RawFrame:
    """One frame extracted from a pasted on-air log, before it becomes a capture YAML entry."""

    def __init__(self, direction: str, hex_bytes: str, freq: int = 0, t_ms: "int | None" = None,
                chip: "str | None" = None, unverified: bool = False, source_line: str = ""):
        self.direction = direction  # "tx" | "rx"
        self.hex_bytes = hex_bytes  # space-separated hex, as captured (no CRC — see crc_present)
        self.freq = freq
        self.t_ms = t_ms
        self.chip = chip
        self.unverified = unverified  # True = fallback-tier extraction, needs human review
        self.source_line = source_line

    def raw(self) -> bytes:
        return parse_hex(self.hex_bytes)

    def crc_present(self) -> bool:
        """CRC-detection rule (verified against RX call sites, see module docstring below):
        every on-air log line in analysis/issues/*.txt — both `io_capture` (tx_frame/parse_ok)
        and legacy `io_frame` (TX/RX) — logs bytes with CTRL0-implied length exactly, i.e.
        **without** the trailing 2-byte CRC. `log_component_capture()` (hub_internal.h) is
        called with the frame's own `buf/len` (post radio_sx1262.cpp's software CRC strip for
        RX; pre-hardware-CRC-append for TX), and `log_frame()` (log_frame.h, used for the
        legacy `io_frame` tag) receives the same already-stripped bytes. So `crc_present()` is
        false whenever the raw length already matches `ctrl0_implied_length()`; it is true only
        if the raw length is exactly 2 bytes longer (a shape no known capture in this repo has
        produced, but kept for forward compatibility with a future logging change).
        """
        raw = self.raw()
        if len(raw) < 1:
            return False
        implied = ctrl0_implied_length(raw[0])
        return len(raw) == implied + 2


# --- io_capture (structured) — hub_internal.h :: log_component_capture() --------------------
# With a decoded frame (cmd/src/dst present — tx_frame always has one; parse_ok always has one):
_IO_CAPTURE_WITH_FRAME_RE = re.compile(
    r"chip=(?P<chip>\S+)\s+phase=component\s+stage=(?P<stage>\S+)\s+freq=(?P<freq>\d+)\s+ts=(?P<ts>\d+)\s+"
    r"len=(?P<len>\d+)\s+cmd=0x(?P<cmd>[0-9A-Fa-f]+)\s+src=(?P<src>[0-9A-Fa-f]{6})\s+dst=(?P<dst>[0-9A-Fa-f]{6})\s+"
    r"payload=(?P<payload>[0-9A-Fa-f ]+)"
)
# Without a decoded frame (parse_fail — frame pointer was nullptr, so no cmd/src/dst fields):
_IO_CAPTURE_NO_FRAME_RE = re.compile(
    r"chip=(?P<chip>\S+)\s+phase=component\s+stage=(?P<stage>\S+)\s+freq=(?P<freq>\d+)\s+ts=(?P<ts>\d+)\s+"
    r"len=(?P<len>\d+)\s+payload=(?P<payload>[0-9A-Fa-f ]+)"
)

# --- io_frame (legacy) — log_frame.h :: log_frame() ------------------------------------------
# The `cmd=... flags` segment is optional: older firmware builds logged this tag without it
# (observed in analysis/issues/23.txt: "TX [17 bytes] freq=868950000 preamble=1024: <hex>" with
# no `cmd=` field at all), while newer builds always include it.
_IO_FRAME_RE = re.compile(
    r"(?P<prefix>TX|RX)\s+\[(?P<len>\d+)\s+bytes\]\s+freq=(?P<freq>\d+)\s*"
    r"(?:preamble=(?P<preamble>\d+)\s*)?(?:cmd=(?P<cmd_name>\S+)\s*(?P<flags>(?:\[[A-Z]+\])*)\s*)?:\s*"
    r"(?P<hex>[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})+)"
)

# ESPHome wall-clock line prefix, e.g. "[08:56:10.754][D][io_capture:190]: ..."
_TIMESTAMP_PREFIX_RE = re.compile(r"^\[(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})\.(?P<ms>\d{3})\]")

# Fallback tier: any line with a plausible run of >= FRAME_MIN_SIZE space-separated hex byte
# pairs, for logs that don't match either known tag format (mangled pastes are common in issue
# threads). Deliberately liberal; callers must treat `unverified=True` results as needing a
# human to confirm the extraction before the capture is committed.
_HEX_RUN_RE = re.compile(r"(?:\b[0-9A-Fa-f]{2}\b(?:\s+))" r"{" + str(FRAME_MIN_SIZE - 1) + r",}\b[0-9A-Fa-f]{2}\b")


def _io_capture_metadata_agrees(match: "re.Match") -> bool:
    """Cross-checks an `_IO_CAPTURE_WITH_FRAME_RE` match's cmd=/src=/dst=/len= fields against the
    parsed `payload=` bytes (design §7 item 1): the structured tag logs both independently (the
    real parser's decoded fields, and the raw wire bytes it decoded them from), so a mangled
    paste whose payload disagrees with its own logged cmd/src/dst is a corruption signal that
    CTRL0/CRC self-consistency alone would not catch — a self-consistent but wrongly-delimited
    payload still passes those checks.
    """
    payload = bytes.fromhex("".join(match.group("payload").split()))
    if len(payload) != int(match.group("len")):
        return False
    if len(payload) <= 8:
        return False
    if payload[8] != int(match.group("cmd"), 16):
        return False
    if payload[2:5] != bytes.fromhex(match.group("dst")):
        return False
    if payload[5:8] != bytes.fromhex(match.group("src")):
        return False
    return True


def _wall_clock_ms(line: str) -> "int | None":
    m = _TIMESTAMP_PREFIX_RE.match(line)
    if not m:
        return None
    h, mnt, s, ms = (int(m.group(g)) for g in ("h", "m", "s", "ms"))
    return ((h * 60 + mnt) * 60 + s) * 1000 + ms


def parse_log_line(line: str) -> "RawFrame | None":
    """Extract at most one RawFrame from a single log line, trying tiers in order:
    io_capture (structured, preferred) -> io_frame (legacy) -> freeform hex-run fallback.
    Returns None if the line carries no recognizable frame.

    `t_ms` always comes from the ESPHome `[HH:MM:SS.mmm]` wall-clock prefix that every log line
    carries, never from io_capture's `ts=` field — that field is the device's monotonic uptime
    counter (a different, unrelated time base per boot), so mixing it with wall-clock-derived
    timestamps from `io_frame`/fallback lines would produce meaningless relative offsets.
    """
    ts_ms = _wall_clock_ms(line)

    match = _IO_CAPTURE_WITH_FRAME_RE.search(line)
    if match:
        stage = match.group("stage")
        direction = "tx" if stage == "tx_frame" else "rx"
        # The structured tag's cmd=/src=/dst=/len= fields are the real parser's decoded output;
        # cross-checking them against the payload= bytes it decoded them from catches a mangled
        # paste that CTRL0/CRC self-consistency alone would miss (F-13).
        agrees = _io_capture_metadata_agrees(match)
        return RawFrame(direction, match.group("payload").strip(), freq=int(match.group("freq")), t_ms=ts_ms,
                        chip=match.group("chip"), unverified=not agrees, source_line=line)

    match = _IO_CAPTURE_NO_FRAME_RE.search(line)
    if match:
        # stage=parse_fail (no cmd/src/dst) — a frame the real parser rejected. Extracted for
        # completeness/statistics, but flagged unverified: it will not round-trip through
        # parse()/serialize() and should not be selected into a committed capture.
        return RawFrame("rx", match.group("payload").strip(), freq=int(match.group("freq")), t_ms=ts_ms,
                        chip=match.group("chip"), unverified=True, source_line=line)

    match = _IO_FRAME_RE.search(line)
    if match:
        direction = "tx" if match.group("prefix") == "TX" else "rx"
        return RawFrame(direction, match.group("hex").strip(), freq=int(match.group("freq")), t_ms=ts_ms, chip=None,
                        unverified=False, source_line=line)

    match = _HEX_RUN_RE.search(line)
    if match:
        return RawFrame("rx", match.group(0).strip(), freq=0, t_ms=ts_ms, chip=None, unverified=True,
                        source_line=line)

    return None


def _same_physical_frame(a: RawFrame, b: RawFrame) -> bool:
    """True when two adjacently-extracted RawFrames are the *same* on-air event logged twice —
    every physical TX/RX in this codebase is logged once via `io_capture` (hub_internal.h) and
    once via the legacy `io_frame` tag (log_frame.h), back-to-back within a few ms of each other
    (see analysis/issues/27.txt). Same direction + identical bytes, adjacent in parse order, is
    the signal; genuine retransmissions (e.g. three DISCOVER_REQ retries) are NOT adjacent to
    each other in this sense because caller code always logs the io_capture/io_frame pair
    together before the next real event.
    """
    return a.direction == b.direction and "".join(a.hex_bytes.split()).upper() == "".join(b.hex_bytes.split()).upper()


def _merge_frames(a: RawFrame, b: RawFrame) -> RawFrame:
    """Merge a same-physical-frame pair, keeping the best field from either side.

    Observed firmware quirk (analysis/issues/27.txt, retried DISCOVER_REQ): the io_capture
    tx_frame log entry on a retry carries freq=0 ts=0 (no capture context available at that call
    site), while the io_frame entry for the exact same transmission carries the real freq. Take
    whichever side has a non-zero freq/t_ms; prefer `a` when both are informative.
    """
    freq = a.freq if a.freq else b.freq
    if a.t_ms not in (None, 0):
        t_ms = a.t_ms
    elif b.t_ms not in (None, 0):
        t_ms = b.t_ms
    else:
        t_ms = a.t_ms if a.t_ms is not None else b.t_ms
    chip = a.chip or b.chip
    unverified = a.unverified and b.unverified
    hex_bytes = b.hex_bytes if a.unverified and not b.unverified else a.hex_bytes
    return RawFrame(a.direction, hex_bytes, freq=freq, t_ms=t_ms, chip=chip, unverified=unverified,
                    source_line=a.source_line + " | " + b.source_line)


def parse_log(text: str) -> "list[RawFrame]":
    """Extract every recognizable frame from a multi-line pasted log, in file order, merging
    adjacent io_capture/io_frame duplicates of the same physical frame (see _same_physical_frame).
    """
    frames: "list[RawFrame]" = []
    for line in text.splitlines():
        frame = parse_log_line(line)
        if frame is None:
            continue
        if frames and _same_physical_frame(frames[-1], frame):
            frames[-1] = _merge_frames(frames[-1], frame)
            continue
        frames.append(frame)
    return frames
