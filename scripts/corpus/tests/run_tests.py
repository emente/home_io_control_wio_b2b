#!/usr/bin/env python3
"""Self-tests for the golden-frame corpus toolchain (protolib.py / ingest.py / validate.py).

Stdlib `assert`-based, no pytest — mirrors scripts/check-tuning-sync.py's dependency-light
style. Fixtures under scripts/corpus/tests/data/ are trimmed excerpts of the real
analysis/issues/*.txt logs (plus one synthetic mangled paste exercising the fallback tier).

Run via `python3 scripts/corpus/tests/run_tests.py`; wired into `make corpus-validate`.
Exits non-zero with a description of the first failure.
"""

import copy
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts" / "corpus"
DATA_DIR = Path(__file__).resolve().parent / "data"

sys.path.insert(0, str(SCRIPTS_DIR))
import build as build_module  # noqa: E402
import ingest as ingest_module  # noqa: E402
import protolib  # noqa: E402
import validate as validate_module  # noqa: E402


def _read(name: str) -> str:
    return (DATA_DIR / name).read_text(encoding="utf-8")


def test_clean_io_capture_v3() -> None:
    frames = protolib.parse_log(_read("clean_io_capture_v3.txt"))
    assert len(frames) == 2, f"expected 2 frames, got {len(frames)}"
    assert [f.direction for f in frames] == ["rx", "rx"]
    assert not any(f.unverified for f in frames), "clean io_capture lines must not be unverified"
    expected0 = bytes.fromhex("96 00 26 94 11 E6 73 34 04 05 00 00 00 C8 00 00 19 E6 73 34 00 00 00".replace(" ", ""))
    assert frames[0].raw() == expected0, f"frame0 bytes mismatch: {frames[0].raw().hex()}"
    assert frames[0].freq == 868250000
    assert frames[0].chip == "sx1262"
    assert not frames[0].crc_present(), "23-byte payload matches CTRL0 length exactly (0x96 -> 23) — no CRC"

    expected1 = bytes.fromhex("11 B3 A1 98 44 05 00 02 00 C8 00 00 00 B3 A1 98 10 00".replace(" ", ""))
    assert frames[1].raw() == expected1, f"frame1 bytes mismatch: {frames[1].raw().hex()}"
    assert frames[1].freq == 869850000


def test_io_frame_legacy_dedup_and_no_cmd_field() -> None:
    frames = protolib.parse_log(_read("io_frame_legacy.txt"))
    # The io_capture tx_frame + io_frame TX lines describe the same physical frame and must
    # merge into one; the standalone io_frame RX line (no cmd= field, older firmware shape) is
    # a second, distinct frame.
    assert len(frames) == 2, f"expected 2 frames after dedup, got {len(frames)}"
    tx, rx = frames
    assert tx.direction == "tx"
    assert rx.direction == "rx"
    expected_tx = bytes.fromhex("50 20 7F 59 58 31 BA F7 00 01 E7 D4 00 20 32 00 00".replace(" ", ""))
    assert tx.raw() == expected_tx, f"tx bytes mismatch: {tx.raw().hex()}"
    assert tx.freq == 868950000, "merge must keep the (agreeing) freq from either side"
    assert tx.chip == "sx1276", "merge must keep chip from the io_capture side (io_frame has none)"
    assert not tx.unverified

    expected_rx = bytes.fromhex("0E 00 31 BA F7 7F 59 58 3C EE 4B 9D FE 53 07".replace(" ", ""))
    assert rx.raw() == expected_rx, f"rx bytes mismatch: {rx.raw().hex()}"
    assert not rx.unverified, "the no-cmd= io_frame shape must still be recognized (not fallback tier)"
    assert not rx.crc_present(), "15-byte payload matches CTRL0 length exactly (0x0E -> 15) — no CRC"


def test_no_crc_write_private() -> None:
    frames = protolib.parse_log(_read("no_crc_write_private.txt"))
    assert len(frames) == 1
    frame = frames[0]
    expected = bytes.fromhex(
        "F5 00 00 00 3F 2F 9A 98 20 02 03 05 02 00 0F 84 FF FC 46 0E AC 87".replace(" ", "")
    )
    assert frame.raw() == expected, f"bytes mismatch: {frame.raw().hex()}"
    assert len(frame.raw()) == protolib.ctrl0_implied_length(frame.raw()[0]) == 22
    assert not frame.crc_present(), "22-byte payload matches CTRL0 length exactly (0xF5 -> 22) — no CRC"


def test_mangled_paste_fallback_tier() -> None:
    frames = protolib.parse_log(_read("mangled_paste.txt"))
    assert len(frames) == 1, f"expected exactly 1 recovered frame, got {len(frames)}"
    frame = frames[0]
    assert frame.unverified, "fallback-tier extraction must be marked unverified"
    expected = bytes.fromhex("50 20 7F 59 58 31 BA F7 00 01 E7 D4 00 20 32 00 00".replace(" ", ""))
    assert frame.raw() == expected, f"fallback extraction bytes mismatch: {frame.raw().hex()}"


def test_merge_prefers_nonzero_freq_and_t_ms() -> None:
    # Reproduces the observed firmware quirk (analysis/issues/27.txt): a retried DISCOVER_REQ's
    # io_capture tx_frame entry logs freq=0/ts=0 (no capture context at that call site), while
    # the paired io_frame entry for the exact same transmission carries the real freq.
    a = protolib.RawFrame("tx", "C8 00 00 00 3B C0 FF EE 28", freq=0, t_ms=0, chip="sx1262", unverified=False)
    b = protolib.RawFrame("tx", "C8 00 00 00 3B C0 FF EE 28", freq=868950000, t_ms=1234, chip=None, unverified=False)
    assert protolib._same_physical_frame(a, b)
    merged = protolib._merge_frames(a, b)
    assert merged.freq == 868950000
    assert merged.t_ms == 1234
    assert merged.chip == "sx1262"


def test_crc_ccitt_matches_known_vector() -> None:
    # Cross-check against tests/corpus/captures/_bootstrap/synthetic_1w_close.yaml, whose bytes
    # were generated from the real C++ crc_ccitt() (tests/corpus_bootstrap_dump_test.cpp).
    payload = bytes.fromhex("EC 00 00 00 BF AA BB CC 00 01 41 C8 00".replace(" ", ""))
    assert protolib.crc_ccitt(payload) == 0x7E35, f"crc mismatch: 0x{protolib.crc_ccitt(payload):04X}"


def _valid_capture_dict() -> dict:
    """A minimal, self-consistent capture — the same bytes as
    tests/corpus/captures/_bootstrap/synthetic_1w_close.yaml (real crc_ccitt() output, see
    test_crc_ccitt_matches_known_vector above), as a plain dict for validate_capture()/
    render_frame(), which both take dicts directly — no temp files needed for schema tests.
    """
    return {
        "id": "self_test_valid",
        "description": "schema self-test fixture",
        "source": {
            "origin": "synthetic-bootstrap",
            "captured_with": "synthetic",
            "device": "self-test fixture",
            "date": "2026-07-06",
        },
        "key": "unknown",
        "frames": [
            {
                "dir": "rx",
                "freq": 868950000,
                "hex": "EC 00 00 00 BF AA BB CC 00 01 41 C8 00 35 7E",
                "crc": "present",
            }
        ],
        "expect": {
            "frames": [{"cmd": 0x00, "start": True, "end": True, "protocol": "1w"}],
        },
    }


def _assert_validation_fails(data: dict, needle: str) -> None:
    try:
        validate_module.validate_capture(data, Path("<self-test>"))
    except validate_module.ValidationError as exc:
        assert needle in str(exc), f"expected {needle!r} in error, got: {exc}"
        return
    raise AssertionError(f"expected ValidationError containing {needle!r}, but validation passed")


def test_validate_ctrl0_length_mismatch_is_rejected() -> None:
    data = copy.deepcopy(_valid_capture_dict())
    # 0xEC -> 0xED changes the CTRL0 length bits (0x0C -> 0x0D) without changing the byte count.
    data["frames"][0]["hex"] = "ED 00 00 00 BF AA BB CC 00 01 41 C8 00 35 7E"
    _assert_validation_fails(data, "CTRL0 length bits")


def test_validate_crc_mismatch_is_rejected() -> None:
    data = copy.deepcopy(_valid_capture_dict())
    data["frames"][0]["hex"] = "EC 00 00 00 BF AA BB CC 00 01 41 C8 00 00 00"
    _assert_validation_fails(data, "CRC mismatch")


def test_validate_unknown_expect_key_is_rejected() -> None:
    data = copy.deepcopy(_valid_capture_dict())
    data["expect"]["not_a_real_expect_key"] = True
    _assert_validation_fails(data, "unknown key(s)")


def test_validate_over_length_expect_frames_is_rejected() -> None:
    data = copy.deepcopy(_valid_capture_dict())
    data["expect"]["frames"].append({"cmd": 0x01})
    _assert_validation_fails(data, "expect.frames has")


def test_validate_bad_classification_name_is_rejected() -> None:
    data = copy.deepcopy(_valid_capture_dict())
    data["expect"]["frames"][0]["classification"] = "NOT_A_REAL_DISPOSITION"
    _assert_validation_fails(data, "classification must be one of")


def test_build_partial_flag_expectation_is_rejected() -> None:
    # build.py's own hard-error (F-01 area): start/end/protocol must be specified all together
    # or not at all — a partial set would silently assert false for the missing two.
    frame = {"dir": "rx", "hex": "EC 00 00 00 BF AA BB CC 00 01 41 C8 00", "crc": "absent"}
    try:
        build_module.render_frame("self_test", 0, frame, {"start": True})
    except SystemExit as exc:
        assert "partial flag expectation" in str(exc)
        return
    raise AssertionError("expected build.py to reject a partial start/end/protocol expectation")


def test_build_output_is_deterministic() -> None:
    # Invariant 0.5.5: build.py's output must be byte-identical across runs (no timestamps, no
    # unordered iteration) — rendering the real corpus twice must produce the same bytes.
    captures = build_module.load_captures()
    first = build_module.render(captures)
    second = build_module.render(captures)
    assert first == second, "build.py render() must be byte-identical across repeated runs"


def test_end_to_end_scaffold_validate_build_roundtrip() -> None:
    """ingest.py on a fixture log -> validate.py on its output passes -> build.py compiles it.

    Uses a throwaway temp directory (auto-cleaned) — this output is a tool self-test artifact,
    never corpus material.
    """
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        captures_dir = tmp_path / "captures"
        captures_dir.mkdir()
        output_yaml = captures_dir / "scaffold_smoke.yaml"

        argv = [
            str(DATA_DIR / "clean_io_capture_v3.txt"),
            "--id",
            "scaffold_smoke",
            "--device",
            "self-test fixture",
            "--captured-with",
            "heltec-v3",
            "--origin",
            "github-issue",
            "--issue",
            "https://github.com/laberning/home_io_control/issues/3",
            "--date",
            "2026-07-06",
            "-o",
            str(output_yaml),
        ]
        rc = _run_ingest_main(argv)
        assert rc == 0, "ingest.py should exit 0 on a well-formed fixture"
        assert output_yaml.is_file(), "ingest.py must write the requested output file"

        original_captures_dir = validate_module.CAPTURES_DIR
        try:
            validate_module.CAPTURES_DIR = captures_dir
            assert validate_module.main() == 0, "validate.py must accept the scaffolded capture"
        finally:
            validate_module.CAPTURES_DIR = original_captures_dir

        original_build_captures_dir = build_module.CAPTURES_DIR
        original_output_path = build_module.OUTPUT_PATH
        try:
            build_module.CAPTURES_DIR = captures_dir
            build_module.OUTPUT_PATH = tmp_path / "corpus_generated.h"
            assert build_module.main() == 0, "build.py must compile the scaffolded capture"
            assert build_module.OUTPUT_PATH.is_file()
            generated = build_module.OUTPUT_PATH.read_text(encoding="utf-8")
            assert "scaffold_smoke" in generated
        finally:
            build_module.CAPTURES_DIR = original_build_captures_dir
            build_module.OUTPUT_PATH = original_output_path
    # tmp (and the throwaway scaffold/generated header) is deleted on context-manager exit.


def _run_ingest_main(argv: "list[str]") -> int:
    old_argv = sys.argv
    try:
        sys.argv = ["ingest.py"] + argv
        return ingest_module.main()
    finally:
        sys.argv = old_argv


TESTS = [
    test_clean_io_capture_v3,
    test_io_frame_legacy_dedup_and_no_cmd_field,
    test_no_crc_write_private,
    test_mangled_paste_fallback_tier,
    test_merge_prefers_nonzero_freq_and_t_ms,
    test_crc_ccitt_matches_known_vector,
    test_validate_ctrl0_length_mismatch_is_rejected,
    test_validate_crc_mismatch_is_rejected,
    test_validate_unknown_expect_key_is_rejected,
    test_validate_over_length_expect_frames_is_rejected,
    test_validate_bad_classification_name_is_rejected,
    test_build_partial_flag_expectation_is_rejected,
    test_build_output_is_deterministic,
    test_end_to_end_scaffold_validate_build_roundtrip,
]


def main() -> int:
    failures = []
    for test in TESTS:
        try:
            test()
        except AssertionError as exc:
            failures.append(f"{test.__name__}: {exc}")
        except Exception as exc:  # noqa: BLE001 - surface any unexpected error as a failure
            failures.append(f"{test.__name__}: unexpected {type(exc).__name__}: {exc}")

    if failures:
        print("run_tests.py: FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1

    print(f"run_tests.py: OK ({len(TESTS)} tests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
