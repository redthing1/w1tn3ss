#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from typing import List, Tuple

from common import (
    ensure_binaries_exist,
    find_first_matching_index,
    make_temp_trace_path,
    parse_inspect_output,
    parse_lldb_pc_values,
    record_trace,
    resolve_executable_path,
    resolve_lldb_path,
    run_inspect,
    run_lldb,
    select_thread_id,
    start_server,
    next_available_port,
    lldb_connect_commands,
)


class Scenario:
    def __init__(
        self,
        name: str,
        configs: List[str],
        sample: str,
        inspect_inst: bool,
        server_inst: bool,
    ) -> None:
        self.name = name
        self.configs = configs
        self.sample = sample
        self.inspect_inst = inspect_inst
        self.server_inst = server_inst


def parse_reverse_pc(log_text: str) -> int:
    matches = re.findall(r"thread-pcs:([0-9a-fA-F]+)", log_text)
    if not matches:
        raise AssertionError("no thread-pcs entries in gdb-remote log")
    return int(matches[-1], 16)


def run_step_session(
    lldb_path: str,
    host: str,
    port: int,
    step_count: int,
    timeout: float,
    log_path: str,
    sample_path: str,
) -> Tuple[List[int], int]:
    commands = [
        f"target create {sample_path}",
        f"log enable -f {log_path} gdb-remote packets",
        f"process connect --plugin gdb-remote connect://{host}:{port}",
        "register read pc",
    ]
    for _ in range(step_count):
        commands.append("thread step-inst -c 1")
        commands.append("register read pc")
    commands.append("process plugin packet send bs")
    commands.append("register read pc")

    commands.append("disassemble -c 1 -s $pc")
    result = run_lldb(lldb_path, commands, timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"lldb step session failed: {result.returncode}\n{output}")
    if "disassembly unavailable" in output:
        raise AssertionError("lldb disassembly unavailable in step session")
    pcs = parse_lldb_pc_values(output)
    if len(pcs) < step_count + 2:
        raise AssertionError(f"expected {step_count + 2} pc reads, got {len(pcs)}")
    try:
        with open(log_path, "r") as handle:
            log_text = handle.read()
    except OSError as exc:
        raise RuntimeError(f"failed to read gdb-remote log: {exc}") from exc
    reverse_pc = parse_reverse_pc(log_text)
    return pcs, reverse_pc


def run_break_session(
    lldb_path: str,
    sample_path: str,
    host: str,
    port: int,
    break_addr: int,
    timeout: float,
) -> int:
    commands = lldb_connect_commands(sample_path, host, port)
    commands.extend(
        [
            f"breakpoint set -a 0x{break_addr:x}",
            "process continue",
            "register read pc",
        ]
    )
    result = run_lldb(lldb_path, commands, timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"lldb break session failed: {result.returncode}\n{output}")
    pcs = parse_lldb_pc_values(output)
    if not pcs:
        raise AssertionError("no pc read after breakpoint")
    return pcs[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description="w1replay LLDB flow end-to-end test")
    parser.add_argument("--w1tool", required=True)
    parser.add_argument("--w1replay", required=True)
    parser.add_argument("--samples-dir", required=True)
    parser.add_argument("--lldb", default=os.environ.get("LLDB_PATH", "lldb"))
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    ensure_binaries_exist([args.w1tool, args.w1replay])

    lldb_path = resolve_lldb_path(args.lldb)
    if lldb_path is None:
        print("skipping: lldb not found", file=sys.stderr)
        return 0

    scenarios = [
        Scenario(
            name="block_inst",
            configs=[
                "flow=block",
                "reg_deltas=false",
                "mem_access=none",
            ],
            sample="simple_demo",
            inspect_inst=True,
            server_inst=True,
        ),
        Scenario(
            name="instruction",
            configs=[
                "flow=instruction",
                "reg_deltas=false",
                "mem_access=none",
            ],
            sample="rewind_demo_basic",
            inspect_inst=False,
            server_inst=False,
        ),
    ]

    for scenario in scenarios:
        trace_path = make_temp_trace_path(f"flow_{scenario.name}")
        sample_path = resolve_executable_path(os.path.join(args.samples_dir, scenario.sample))
        record_trace(args.w1tool, trace_path, scenario.configs, sample_path, args.timeout)
        thread_id = select_thread_id(args.w1replay, trace_path, args.timeout)

        image_mapping = f"{os.path.basename(sample_path)}={sample_path}"
        try:
            inspect_output = run_inspect(
                args.w1replay,
                trace_path,
                thread_id,
                count=10,
                timeout=args.timeout,
                inst=scenario.inspect_inst,
                image_mappings=[image_mapping] if scenario.inspect_inst else None,
            )
        except RuntimeError as exc:
            message = str(exc)
            if scenario.inspect_inst and (
                "block decoder unavailable" in message
                or "asmr decoder unavailable" in message
                or "WITNESS_ASMR" in message
                or "WITNESS_LIEF" in message
            ):
                print(f"skipping {scenario.name}: decoder unavailable", file=sys.stderr)
                continue
            raise
        inspect_trace = parse_inspect_output(inspect_output)
        expected_pcs = inspect_trace.addresses()
        if len(expected_pcs) < 6:
            raise AssertionError(f"{scenario.name}: need at least 6 inspect steps")

        host = "127.0.0.1"
        port = next_available_port(host)
        try:
            server = start_server(
                args.w1replay,
                trace_path,
                port,
                scenario.server_inst,
                args.timeout,
                image_mappings=[image_mapping],
            )
        except RuntimeError as exc:
            message = str(exc)
            if scenario.server_inst and (
                "block decoder unavailable" in message
                or "asmr decoder unavailable" in message
                or "WITNESS_ASMR" in message
                or "WITNESS_LIEF" in message
            ):
                print(f"skipping {scenario.name}: decoder unavailable", file=sys.stderr)
                continue
            raise
        try:
            step_count = 4
            log_path = os.path.join(tempfile.gettempdir(), f"w1replay_flow_{scenario.name}_{port}.log")
            pcs, reverse_pc = run_step_session(
                lldb_path, host, port, step_count, args.timeout, log_path, sample_path
            )
        finally:
            server.terminate(timeout=1.0)

        start_pc = pcs[0]
        align = find_first_matching_index(expected_pcs, start_pc)
        if align is None:
            raise AssertionError(f"{scenario.name}: current pc not found in inspect list")
        if align + step_count >= len(expected_pcs):
            raise AssertionError(f"{scenario.name}: inspect list too short for steps")

        for i in range(1, step_count + 1):
            expected = expected_pcs[align + i]
            if pcs[i] != expected:
                raise AssertionError(
                    f"{scenario.name}: step {i} pc mismatch: got 0x{pcs[i]:x}, expected 0x{expected:x}"
                )

        reverse_expected = expected_pcs[align + step_count - 1]
        if reverse_pc != reverse_expected:
            raise AssertionError(
                f"{scenario.name}: reverse step pc mismatch: got 0x{reverse_pc:x}, expected 0x{reverse_expected:x}"
            )

        break_target = expected_pcs[align + 3]
        port = next_available_port(host)
        server = start_server(
            args.w1replay,
            trace_path,
            port,
            scenario.server_inst,
            args.timeout,
            image_mappings=[image_mapping],
        )
        try:
            hit_pc = run_break_session(
                lldb_path, sample_path, host, port, break_target, args.timeout
            )
        finally:
            server.terminate(timeout=1.0)
        if hit_pc != break_target:
            raise AssertionError(
                f"{scenario.name}: breakpoint pc mismatch: got 0x{hit_pc:x}, expected 0x{break_target:x}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
