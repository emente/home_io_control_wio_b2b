#!/usr/bin/env python3
"""Schema and self-consistency validation for the golden-frame corpus.

Checks every capture YAML under tests/corpus/captures/**/*.yaml:
  * required fields present, `key` and `source.origin` hold allowed values;
  * `hex` is well-formed (even count of hex digits, whitespace-tolerant);
  * frame byte count is >= FRAME_MIN_SIZE (+2 when `crc: present`);
  * CTRL0 length bits (bits [4:0] = frame_length - 1, CRC bytes not counted) agree with the
    non-CRC byte count — mirrors proto_frame.cpp parse()/frame_length();
  * CRC-CCITT (poly 0x1021 reversed = 0x8408, init 0x0000) matches the trailing 2 bytes where
    `crc: present` — ported from crc_ccitt() in proto_frame.cpp;
  * duplicate `id` across the whole corpus is a hard error;
  * `expect.*` keys are restricted to the set build.py actually consumes, and `expect.frames`
    cannot have more entries than were captured — both are otherwise silently accepted by
    build.py's dict.get()/index-bounded lookups, defeating the "expectations are
    human-verified" rule (see tests/corpus/README.md).

`key: corpus` cryptographic promises (HMAC / key-transfer payload verification against the
public corpus key) are not yet checked here — that needs a Python AES/HMAC port and arrives
in a later tool version. This script emits a labeled SKIP line for that gap instead of
silently passing it.

Run via `make corpus-validate` (part of the `lint` composite). Dependency: PyYAML.
"""

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CAPTURES_DIR = REPO_ROOT / "tests" / "corpus" / "captures"

# --- Mirrors of components/home_io_control/proto_sizes.h / proto_frame.cpp -----------------
FRAME_MIN_SIZE = 9  # CTRL0 + CTRL1 + DST(3) + SRC(3) + CMD(1)
FRAME_MAX_SIZE = 32  # 9 header + 23 data
CTRL0_LENGTH_MASK = 0x1F
CRC_POLYNOMIAL_REVERSED = 0x8408

ALLOWED_KEY_MODES = {"corpus", "unknown"}
ALLOWED_ORIGINS = {"own-hardware", "github-issue", "synthetic-bootstrap"}
ALLOWED_DIRS = {"tx", "rx"}
ALLOWED_CRC = {"present", "absent"}

# --- Mirrors the expect-schema keys scripts/corpus/build.py actually consumes -------------
# A key outside these sets is silently ignored by build.py (dict.get() just returns None), so
# a typo'd expectation (e.g. `cmdd:` instead of `cmd:`) would never be checked despite the human
# believing they wrote a verified expectation. Fail loudly here instead.
ALLOWED_EXPECT_KEYS = {"frames", "exchange", "device", "oneway"}
ALLOWED_EXPECT_FRAME_KEYS = {"cmd", "start", "end", "protocol", "classification", "hmac_valid"}
ALLOWED_EXPECT_EXCHANGE_KEYS = {"kind", "outcome"}
ALLOWED_EXPECT_DEVICE_KEYS = {"reported_position", "name"}
ALLOWED_EXPECT_ONEWAY_KEYS = {"intent", "target_type", "originator", "acei"}


class ValidationError(Exception):
    """A single capture failed validation; carries a human-readable message."""


def crc_ccitt(data: bytes) -> int:
    """Port of crc_ccitt() in proto_frame.cpp: poly 0x8408 (reversed), init 0x0000."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ CRC_POLYNOMIAL_REVERSED if (crc & 0x0001) else (crc >> 1)
    return crc & 0xFFFF


def parse_hex(hex_str: str, context: str) -> bytes:
    compact = "".join(hex_str.split())
    if len(compact) % 2 != 0:
        raise ValidationError(f"{context}: hex string has an odd number of digits: {hex_str!r}")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValidationError(f"{context}: hex string is not valid hex: {hex_str!r} ({exc})") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_frame(frame: dict, index: int, capture_id: str) -> None:
    context = f"{capture_id} frame[{index}]"
    for field in ("dir", "hex", "crc"):
        require(field in frame, f"{context}: missing required field '{field}'")

    require(frame["dir"] in ALLOWED_DIRS, f"{context}: dir must be one of {sorted(ALLOWED_DIRS)}, got {frame['dir']!r}")
    require(frame["crc"] in ALLOWED_CRC, f"{context}: crc must be one of {sorted(ALLOWED_CRC)}, got {frame['crc']!r}")

    raw = parse_hex(frame["hex"], context)
    crc_present = frame["crc"] == "present"
    non_crc_len = len(raw) - 2 if crc_present else len(raw)

    require(
        non_crc_len >= FRAME_MIN_SIZE,
        f"{context}: frame is {non_crc_len} bytes (excluding CRC), below FRAME_MIN_SIZE={FRAME_MIN_SIZE}",
    )
    require(
        non_crc_len <= FRAME_MAX_SIZE,
        f"{context}: frame is {non_crc_len} bytes (excluding CRC), above FRAME_MAX_SIZE={FRAME_MAX_SIZE}",
    )

    ctrl0 = raw[0]
    expected_total = (ctrl0 & CTRL0_LENGTH_MASK) + 1
    require(
        expected_total == non_crc_len,
        f"{context}: CTRL0 length bits imply {expected_total} bytes, but captured non-CRC length is {non_crc_len}",
    )

    if crc_present:
        payload = raw[:non_crc_len]
        computed = crc_ccitt(payload)
        captured_crc = raw[non_crc_len] | (raw[non_crc_len + 1] << 8)
        require(
            computed == captured_crc,
            f"{context}: CRC mismatch — computed 0x{computed:04X}, captured 0x{captured_crc:04X}",
        )


def require_known_keys(mapping: dict, allowed: set, context: str) -> None:
    unknown = set(mapping.keys()) - allowed
    require(not unknown, f"{context}: unknown key(s) {sorted(unknown)}; expected one of {sorted(allowed)}")


def validate_expect(expect: dict, frame_count: int, capture_id: str) -> None:
    """Fail loudly on unknown expect.* keys and on more expect.frames entries than were captured
    — both are silently accepted by build.py today, defeating the "expectations are
    human-verified" rule (the extra/misspelled expectation is simply never checked).
    """
    require(isinstance(expect, dict), f"{capture_id}: 'expect' must be a mapping")
    require_known_keys(expect, ALLOWED_EXPECT_KEYS, f"{capture_id}: expect")

    expect_frames = expect.get("frames")
    if expect_frames is not None:
        require(isinstance(expect_frames, list), f"{capture_id}: expect.frames must be a list")
        require(
            len(expect_frames) <= frame_count,
            f"{capture_id}: expect.frames has {len(expect_frames)} entries but only {frame_count} "
            "frame(s) were captured — the extra entries would be silently ignored by build.py",
        )
        for index, expect_frame in enumerate(expect_frames):
            require(isinstance(expect_frame, dict), f"{capture_id}: expect.frames[{index}] must be a mapping")
            require_known_keys(expect_frame, ALLOWED_EXPECT_FRAME_KEYS, f"{capture_id}: expect.frames[{index}]")

    exchange = expect.get("exchange")
    if exchange is not None:
        require(isinstance(exchange, dict), f"{capture_id}: expect.exchange must be a mapping")
        require_known_keys(exchange, ALLOWED_EXPECT_EXCHANGE_KEYS, f"{capture_id}: expect.exchange")

    device = expect.get("device")
    if device is not None:
        require(isinstance(device, dict), f"{capture_id}: expect.device must be a mapping")
        require_known_keys(device, ALLOWED_EXPECT_DEVICE_KEYS, f"{capture_id}: expect.device")

    oneway = expect.get("oneway")
    if oneway is not None:
        require(isinstance(oneway, dict), f"{capture_id}: expect.oneway must be a mapping")
        require_known_keys(oneway, ALLOWED_EXPECT_ONEWAY_KEYS, f"{capture_id}: expect.oneway")


def validate_capture(data: dict, path: Path) -> str:
    for field in ("id", "description", "source", "key", "frames"):
        require(field in data, f"{path}: missing required top-level field '{field}'")

    capture_id = data["id"]
    require(isinstance(capture_id, str) and capture_id, f"{path}: 'id' must be a non-empty string")

    require(data["key"] in ALLOWED_KEY_MODES, f"{capture_id}: key must be one of {sorted(ALLOWED_KEY_MODES)}")

    source = data["source"]
    require(isinstance(source, dict), f"{capture_id}: 'source' must be a mapping")
    require("origin" in source, f"{capture_id}: source.origin is required")
    require(
        source["origin"] in ALLOWED_ORIGINS,
        f"{capture_id}: source.origin must be one of {sorted(ALLOWED_ORIGINS)}, got {source['origin']!r}",
    )

    frames = data["frames"]
    require(isinstance(frames, list) and len(frames) > 0, f"{capture_id}: 'frames' must be a non-empty list")
    for index, frame in enumerate(frames):
        validate_frame(frame, index, capture_id)

    if "expect" in data:
        validate_expect(data["expect"], len(frames), capture_id)

    if data["key"] == "corpus":
        print(f"  SKIP (crypto validation arrives in a later tool version): {capture_id}")

    return capture_id


def main() -> int:
    if not CAPTURES_DIR.is_dir():
        print(f"error: captures directory not found: {CAPTURES_DIR}", file=sys.stderr)
        return 1

    paths = sorted(CAPTURES_DIR.rglob("*.yaml"))
    if not paths:
        print("validate.py: no capture YAML files found (nothing to validate)")
        return 0

    seen_ids: dict = {}
    errors: list = []
    total_frames = 0

    for path in paths:
        try:
            with path.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            capture_id = validate_capture(data, path)
        except ValidationError as exc:
            errors.append(str(exc))
            continue
        except yaml.YAMLError as exc:
            errors.append(f"{path}: YAML parse error: {exc}")
            continue

        if capture_id in seen_ids:
            errors.append(f"{path}: duplicate id '{capture_id}' (already used by {seen_ids[capture_id]})")
        else:
            seen_ids[capture_id] = path
            total_frames += len(data["frames"])

    if errors:
        print("validate.py: FAILED", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1

    print(f"validate.py: OK ({len(seen_ids)} captures, {total_frames} frames)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
