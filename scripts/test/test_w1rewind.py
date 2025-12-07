#!/usr/bin/env python3
"""regression test harness for w1rewind

capture baseline traces for demo programs, replay with validation enabled, and check for mismatches
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
import tempfile
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional


MAGIC = b"W1RWND\n\x00"
HEADER_STRUCT = struct.Struct("<8sIIII")
EVENT_HEADER_STRUCT = struct.Struct("<BQQQI")
REGISTER_COUNT_STRUCT = struct.Struct("<I")
REGISTER_NAME_LEN_STRUCT = struct.Struct("<H")
REGISTER_VALUE_STRUCT = struct.Struct("<Q")
MEMORY_HEADER_STRUCT = struct.Struct("<QI")
BOOL_STRUCT = struct.Struct("<B")
MEMORY_LEN_STRUCT = struct.Struct("<I")


def require_bytes(buffer: memoryview, cursor: int, size: int, message: str) -> None:
    if cursor + size > len(buffer):
        raise RuntimeError(message)


@dataclass(frozen=True)
class Scenario:
    label: str
    demo: str
    frame_interval: int
    capture_overrides: Dict[str, str] = field(default_factory=dict)
    validate_overrides: Dict[str, str] = field(default_factory=dict)
    expect_mismatch: bool = False


SCENARIOS: Dict[str, Scenario] = {
    "basic": Scenario("basic", "rewind_demo_basic", 64),
    "basic_fast": Scenario("basic_fast", "rewind_demo_basic", 32),
    "calls": Scenario("calls", "rewind_demo_calls", 64),
    "memops": Scenario("memops", "rewind_demo_memops", 48),
    "io": Scenario("io", "rewind_demo_io", 64),
    "algorithms": Scenario("algorithms", "rewind_demo_algorithms", 80),
    "memreads": Scenario(
        "memreads",
        "rewind_demo_memops",
        32,
        capture_overrides={"W1REWIND_CAPTURE_MEMORY_READS": "1"},
        validate_overrides={"W1REWIND_CAPTURE_MEMORY_READS": "1"},
    ),
    "threads": Scenario(
        "threads",
        "threadtest_demo",
        64,
        capture_overrides={
            "W1REWIND_ENABLE_THREAD_HOOKS": "1",
            "THREADTEST_SEED": "1",
        },
        validate_overrides={
            "W1REWIND_ENABLE_THREAD_HOOKS": "1",
            "THREADTEST_SEED": "1",
            "W1REWIND_STACK_WINDOW": str(0x400000),
        },
    ),
    "divergence_nomem": Scenario(
        "divergence_nomem",
        "rewind_demo_memops",
        48,
        validate_overrides={"W1REWIND_RECORD_MEMORY": "0", "W1REWIND_VALIDATION_MODE": "strict"},
        expect_mismatch=True,
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run w1rewind validation scenarios")
    parser.add_argument(
        "--build-dir",
        default="build-release",
        help="Path to the CMake build directory (default: build-release)",
    )
    parser.add_argument(
        "--scenario",
        action="append",
        choices=sorted(SCENARIOS.keys()),
        help="Limit execution to the selected scenario label(s)",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep temporary traces and logs instead of cleaning up",
    )
    parser.add_argument(
        "--w1tool",
        default=None,
        help="Explicit path to w1tool; defaults to <build-dir>/w1tool",
    )
    return parser.parse_args()


def run_command(
    command: List[str], *, env: Optional[dict] = None, cwd: Optional[Path] = None
) -> subprocess.CompletedProcess:
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    return result


def ensure_success(
    result: subprocess.CompletedProcess, label: str, log_path: Path
) -> None:
    log_path.write_text(result.stdout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}; see {log_path}"
        )


def parse_validation_summary(output: str) -> int:
    summary_line: Optional[str] = None
    for line in output.splitlines():
        if "validation summary" in line:
            summary_line = line.strip()
            break
    if summary_line is None:
        raise RuntimeError("validation summary not found in tracer output")

    for chunk in summary_line.replace(",", " ").split():
        if chunk.startswith("mismatches="):
            try:
                return int(chunk.split("=", 1)[1])
            except ValueError as exc:  # pragma: no cover - defensive
                raise RuntimeError(
                    f"failed to parse mismatches from '{summary_line}'"
                ) from exc
    raise RuntimeError(f"mismatches field missing in '{summary_line}'")


def skip_memory_records(data: memoryview, cursor: int) -> int:
    require_bytes(
        data, cursor, REGISTER_COUNT_STRUCT.size, "truncated memory access count"
    )
    count = REGISTER_COUNT_STRUCT.unpack_from(data, cursor)[0]
    cursor += REGISTER_COUNT_STRUCT.size

    for _ in range(count):
        require_bytes(
            data, cursor, MEMORY_HEADER_STRUCT.size, "truncated memory access header"
        )
        cursor += MEMORY_HEADER_STRUCT.size  # address + size
        require_bytes(data, cursor, BOOL_STRUCT.size, "truncated memory access flag")
        value_known = BOOL_STRUCT.unpack_from(data, cursor)[0]
        cursor += BOOL_STRUCT.size
        require_bytes(
            data, cursor, MEMORY_LEN_STRUCT.size, "truncated memory access length"
        )
        length = MEMORY_LEN_STRUCT.unpack_from(data, cursor)[0]
        cursor += MEMORY_LEN_STRUCT.size

        require_bytes(data, cursor, length, "truncated memory access payload")
        cursor += length
        if not value_known and length != 0:
            # even when the value is unknown we still store the raw bytes; the guard keeps future tweaks obvious
            pass
    return cursor


def summarise_trace(trace_path: Path) -> Dict[str, int]:
    data = trace_path.read_bytes()
    view = memoryview(data)
    cursor = 0

    require_bytes(view, cursor, HEADER_STRUCT.size, "truncated trace header")
    magic, version, _flags, _arch, _reserved = HEADER_STRUCT.unpack_from(view, cursor)
    cursor += HEADER_STRUCT.size
    if magic != MAGIC:
        raise RuntimeError(
            f"{trace_path} is not a w1rewind trace (bad magic {magic!r})"
        )

    events = 0
    instructions = 0
    boundaries = 0

    while cursor < len(view):
        require_bytes(view, cursor, EVENT_HEADER_STRUCT.size, "truncated event header")
        event_type, _thread_id, _seq, _addr, _size = EVENT_HEADER_STRUCT.unpack_from(
            view, cursor
        )
        cursor += EVENT_HEADER_STRUCT.size
        events += 1
        if event_type == 1:
            instructions += 1

        require_bytes(
            view, cursor, REGISTER_COUNT_STRUCT.size, "truncated register count"
        )
        reg_count = REGISTER_COUNT_STRUCT.unpack_from(view, cursor)[0]
        cursor += REGISTER_COUNT_STRUCT.size

        for _ in range(reg_count):
            require_bytes(
                view,
                cursor,
                REGISTER_NAME_LEN_STRUCT.size,
                "truncated register name length",
            )
            name_len = REGISTER_NAME_LEN_STRUCT.unpack_from(view, cursor)[0]
            cursor += REGISTER_NAME_LEN_STRUCT.size
            require_bytes(view, cursor, name_len, "truncated register name")
            cursor += name_len
            require_bytes(
                view, cursor, REGISTER_VALUE_STRUCT.size, "truncated register value"
            )
            cursor += REGISTER_VALUE_STRUCT.size

        if version >= 2:
            cursor = skip_memory_records(view, cursor)  # reads
        cursor = skip_memory_records(view, cursor)  # writes

        if version >= 3:
            require_bytes(view, cursor, BOOL_STRUCT.size, "truncated boundary flag")
            has_boundary = BOOL_STRUCT.unpack_from(view, cursor)[0] != 0
            cursor += BOOL_STRUCT.size
            if has_boundary:
                require_bytes(
                    view, cursor, REGISTER_VALUE_STRUCT.size, "truncated boundary id"
                )
                cursor += REGISTER_VALUE_STRUCT.size  # boundary id
                require_bytes(
                    view, cursor, MEMORY_LEN_STRUCT.size, "truncated boundary flags"
                )
                cursor += MEMORY_LEN_STRUCT.size  # flags
                require_bytes(
                    view,
                    cursor,
                    REGISTER_NAME_LEN_STRUCT.size,
                    "truncated boundary reason length",
                )
                reason_len = REGISTER_NAME_LEN_STRUCT.unpack_from(view, cursor)[0]
                cursor += REGISTER_NAME_LEN_STRUCT.size
                require_bytes(view, cursor, reason_len, "truncated boundary reason")
                cursor += reason_len
                boundaries += 1
        elif event_type == 2:
            boundaries += 1

    return {
        "events": events,
        "instructions": instructions,
        "boundaries": boundaries,
        "size": len(view),
    }


def format_size(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)
    unit_idx = 0
    while size >= 1024.0 and unit_idx < len(units) - 1:
        size /= 1024.0
        unit_idx += 1
    if unit_idx == 0:
        return f"{int(size)} {units[unit_idx]}"
    return f"{size:.2f} {units[unit_idx]}"


def fmt_stats(summary: Dict[str, int], extra: Optional[Dict[str, int]] = None) -> str:
    parts = [
        ("size", format_size(summary["size"])),
        ("events", summary["events"]),
        ("instr", summary["instructions"]),
        ("bounds", summary["boundaries"]),
    ]
    if extra:
        parts.extend(extra.items())
    formatted = ", ".join(f"{name}={value}" for name, value in parts)
    return formatted


def run_scenario(
    scenario: Scenario,
    *,
    root_dir: Path,
    build_dir: Path,
    w1tool: Path,
    artifact_dir: Path,
) -> None:
    demo_path = build_dir / "tests" / "programs" / scenario.demo
    if not demo_path.exists():
        raise FileNotFoundError(f"demo binary not found: {demo_path}")

    trace_path = artifact_dir / f"{scenario.label}.trace"
    validation_trace_path = artifact_dir / f"{scenario.label}.validate.trace"
    capture_log = artifact_dir / f"{scenario.label}.capture.log"
    validate_log = artifact_dir / f"{scenario.label}.validate.log"

    print(f"test [{scenario.label}]")
    print(f"  capturing baseline (frame={scenario.frame_interval})")
    capture_env = os.environ.copy()
    capture_env.update(
        {
            "W1REWIND_OUTPUT": str(trace_path),
            "W1REWIND_FRAME_INTERVAL": str(scenario.frame_interval),
        }
    )
    capture_env.update(scenario.capture_overrides)
    capture_result = run_command(
        [str(w1tool), "tracer", "--no-aslr", "-n", "w1rewind", "-s", str(demo_path)],
        env=capture_env,
        cwd=root_dir,
    )
    ensure_success(capture_result, f"capture:{scenario.label}", capture_log)

    summary = summarise_trace(trace_path)
    print(f"  baseline captured")
    print(f"    {fmt_stats(summary)}")

    print(f"  validating against baseline")
    validate_env = os.environ.copy()
    validate_env.update(
        {
            "W1REWIND_COMPARE_TRACE": str(trace_path),
            "W1REWIND_OUTPUT": str(validation_trace_path),
            "W1REWIND_FRAME_INTERVAL": str(scenario.frame_interval),
            "W1REWIND_VALIDATION_MODE": "log",
        }
    )
    validate_env.update(scenario.validate_overrides)
    validate_result = run_command(
        [str(w1tool), "tracer", "--no-aslr", "-n", "w1rewind", "-s", str(demo_path)],
        env=validate_env,
        cwd=root_dir,
    )
    if not scenario.expect_mismatch:
        ensure_success(validate_result, f"validate:{scenario.label}", validate_log)
    else:
        validate_log.write_text(validate_result.stdout)

    mismatches = parse_validation_summary(validate_result.stdout)
    if scenario.expect_mismatch:
        if mismatches == 0:
            raise RuntimeError(
                f"scenario '{scenario.label}' expected mismatches but found none; see {validate_log}"
            )
        print(f"  validation detected mismatches as expected (count={mismatches})")
    else:
        if mismatches != 0:
            raise RuntimeError(
                f"scenario '{scenario.label}' reported {mismatches} mismatches; logs kept in {validate_log.parent}"
            )

    if validation_trace_path.exists():
        validation_summary = summarise_trace(validation_trace_path)
        print("  validation complete")
        print(f"    {fmt_stats(validation_summary, {'mismatches': mismatches})}")
    else:
        print("  validation trace not written (run aborted early)")


def main() -> None:
    args = parse_args()

    script_path = Path(__file__).resolve()
    root_dir = script_path.parents[2]
    build_dir = (root_dir / args.build_dir).resolve()
    if not build_dir.exists():
        raise FileNotFoundError(f"build directory not found: {build_dir}")

    w1tool = Path(args.w1tool) if args.w1tool else (build_dir / "w1tool")
    if not w1tool.exists():
        raise FileNotFoundError(
            f"w1tool not found at {w1tool}; run cmake --build first"
        )

    selected: Iterable[Scenario]
    if args.scenario:
        selected = [SCENARIOS[name] for name in args.scenario]
    else:
        selected = SCENARIOS.values()

    artifact_dir = Path(tempfile.mkdtemp(prefix="w1rewind_tests_"))
    cleanup_needed = not args.keep_artifacts
    if args.keep_artifacts:
        print(f"artifacts will be kept in {artifact_dir}")

    success = False
    try:
        for scenario in selected:
            run_scenario(
                scenario,
                root_dir=root_dir,
                build_dir=build_dir,
                w1tool=w1tool,
                artifact_dir=artifact_dir,
            )
        success = True
    finally:
        if args.keep_artifacts or not success:
            print(f"logs and traces retained in {artifact_dir}")
        elif cleanup_needed:
            shutil.rmtree(artifact_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
