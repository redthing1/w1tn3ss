#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, List, Optional, Tuple

from common import (
    ensure_binaries_exist,
    find_first_matching_index,
    find_stack_pointer,
    make_temp_trace_path,
    parse_inspect_output,
    parse_lldb_memory_bytes,
    parse_lldb_pc_values,
    parse_lldb_register_values,
    pick_known_registers,
    record_trace,
    resolve_lldb_path,
    run_inspect,
    run_lldb,
    select_thread_id,
    start_server,
    next_available_port,
)


def read_initial_pc(lldb_path: str, host: str, port: int, timeout: float) -> int:
    commands = [
        f"process connect --plugin gdb-remote connect://{host}:{port}",
        "register read pc",
    ]
    result = run_lldb(lldb_path, commands, timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"lldb initial pc failed: {result.returncode}\n{output}")
    pcs = parse_lldb_pc_values(output)
    if not pcs:
        raise AssertionError("no pc read in lldb output")
    return pcs[-1]


def step_and_read_registers(
    lldb_path: str,
    host: str,
    port: int,
    steps: int,
    reg_names: List[str],
    timeout: float,
) -> Dict[str, int]:
    commands = [f"process connect --plugin gdb-remote connect://{host}:{port}"]
    for _ in range(steps):
        commands.append("thread step-inst -c 1")
    commands.append("register read " + " ".join(reg_names))
    result = run_lldb(lldb_path, commands, timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"lldb register read failed: {result.returncode}\n{output}")
    return parse_lldb_register_values(output)


def step_and_read_memory(
    lldb_path: str,
    host: str,
    port: int,
    steps: int,
    address: int,
    count: int,
    timeout: float,
) -> List[int]:
    commands = [f"process connect --plugin gdb-remote connect://{host}:{port}"]
    for _ in range(steps):
        commands.append("thread step-inst -c 1")
    commands.append(f"memory read 0x{address:x} -c {count}")
    result = run_lldb(lldb_path, commands, timeout)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"lldb memory read failed: {result.returncode}\n{output}")
    return parse_lldb_memory_bytes(output, count)


def find_reg_step_index(steps, start_index: int) -> Tuple[int, Dict[str, int]]:
    for idx in range(start_index, len(steps)):
        if steps[idx].regs:
            picked = pick_known_registers(steps[idx].regs, 2)
            if len(picked) >= 2:
                return idx, dict(picked)
    raise AssertionError("no suitable register step found")


def find_mem_step_index(steps, start_index: int) -> Tuple[int, int]:
    for idx in range(start_index, len(steps)):
        sp = find_stack_pointer(steps[idx].regs)
        if sp is not None:
            return idx, sp
    raise AssertionError("no stack pointer found in inspect output")


def main() -> int:
    parser = argparse.ArgumentParser(description="w1replay LLDB state end-to-end test")
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

    host = "127.0.0.1"

    # Register trace scenario
    reg_trace = make_temp_trace_path("state_regs")
    record_trace(
        args.w1tool,
        reg_trace,
        [
            "record_instructions=true",
            "record_register_deltas=true",
            "memory=false",
        ],
        os.path.join(args.samples_dir, "rewind_demo_calls"),
        args.timeout,
    )
    thread_id = select_thread_id(args.w1replay, reg_trace, args.timeout)
    inspect_output = run_inspect(
        args.w1replay,
        reg_trace,
        thread_id,
        count=12,
        timeout=args.timeout,
        regs=True,
    )
    inspect_trace = parse_inspect_output(inspect_output)
    expected_pcs = inspect_trace.addresses()

    port = next_available_port(host)
    server = start_server(args.w1replay, reg_trace, port, inst=False, timeout=args.timeout)
    try:
        initial_pc = read_initial_pc(lldb_path, host, port, args.timeout)
    finally:
        server.terminate(timeout=1.0)
    align = find_first_matching_index(expected_pcs, initial_pc)
    if align is None:
        raise AssertionError("register trace: initial pc not found in inspect list")

    reg_step_index, expected_regs = find_reg_step_index(inspect_trace.steps, align)
    reg_names = list(expected_regs.keys())
    if reg_step_index < align:
        raise AssertionError("register trace: reg step index before align")
    delta = reg_step_index - align

    port = next_available_port(host)
    server = start_server(args.w1replay, reg_trace, port, inst=False, timeout=args.timeout)
    try:
        actual_regs = step_and_read_registers(
            lldb_path, host, port, delta, reg_names, args.timeout
        )
    finally:
        server.terminate(timeout=1.0)

    for name, expected in expected_regs.items():
        actual = actual_regs.get(name)
        if actual is None:
            raise AssertionError(f"register trace: missing {name} in LLDB output")
        if actual != expected:
            raise AssertionError(
                f"register trace: {name} mismatch: got 0x{actual:x}, expected 0x{expected:x}"
            )

    # Memory trace scenario
    mem_trace = make_temp_trace_path("state_mem")
    record_trace(
        args.w1tool,
        mem_trace,
        [
            "record_instructions=true",
            "record_register_deltas=true",
            "memory=true",
            "memory_reads=true",
            "memory_values=true",
            "stack_snapshot=4096",
            "snapshot_interval=1",
        ],
        os.path.join(args.samples_dir, "rewind_demo_memops"),
        args.timeout,
    )
    thread_id = select_thread_id(args.w1replay, mem_trace, args.timeout)
    inspect_output = run_inspect(
        args.w1replay,
        mem_trace,
        thread_id,
        count=12,
        timeout=args.timeout,
        regs=True,
    )
    inspect_trace = parse_inspect_output(inspect_output)
    expected_pcs = inspect_trace.addresses()

    port = next_available_port(host)
    server = start_server(args.w1replay, mem_trace, port, inst=False, timeout=args.timeout)
    try:
        initial_pc = read_initial_pc(lldb_path, host, port, args.timeout)
    finally:
        server.terminate(timeout=1.0)
    align = find_first_matching_index(expected_pcs, initial_pc)
    if align is None:
        raise AssertionError("memory trace: initial pc not found in inspect list")

    mem_step_index, sp_value = find_mem_step_index(inspect_trace.steps, align)
    mem_output = run_inspect(
        args.w1replay,
        mem_trace,
        thread_id,
        count=mem_step_index + 1,
        timeout=args.timeout,
        mem=f"{hex(sp_value)}:16",
    )
    mem_trace_inspect = parse_inspect_output(mem_output)
    if mem_step_index >= len(mem_trace_inspect.steps):
        raise AssertionError("memory trace: missing expected mem step")
    mem_step = mem_trace_inspect.steps[mem_step_index]
    if mem_step.memory is None:
        raise AssertionError("memory trace: no memory data for expected step")
    expected_bytes = mem_step.memory.bytes

    delta = mem_step_index - align
    port = next_available_port(host)
    server = start_server(args.w1replay, mem_trace, port, inst=False, timeout=args.timeout)
    try:
        actual_bytes = step_and_read_memory(
            lldb_path, host, port, delta, sp_value, len(expected_bytes), args.timeout
        )
    finally:
        server.terminate(timeout=1.0)

    if len(actual_bytes) < len(expected_bytes):
        raise AssertionError("memory trace: LLDB returned fewer bytes than expected")
    for idx, expected in enumerate(expected_bytes):
        if expected is None:
            continue
        if actual_bytes[idx] != expected:
            raise AssertionError(
                f"memory trace: byte {idx} mismatch: got 0x{actual_bytes[idx]:02x}, expected 0x{expected:02x}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
