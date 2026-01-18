#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import sys
from typing import List

from common import (
    ensure_binaries_exist,
    make_temp_trace_path,
    parse_inspect_output,
    record_trace,
    run_inspect,
    select_thread_id,
)


def require_steps(steps, name: str) -> None:
    if not steps:
        raise AssertionError(f"{name}: no inspect steps found")
    if any(step.addr == 0 for step in steps):
        raise AssertionError(f"{name}: found zero address in steps")


def main() -> int:
    parser = argparse.ArgumentParser(description="w1replay trace end-to-end test")
    parser.add_argument("--w1tool", required=True)
    parser.add_argument("--w1replay", required=True)
    parser.add_argument("--samples-dir", required=True)
    parser.add_argument("--timeout", type=float, default=40.0)
    args = parser.parse_args()

    ensure_binaries_exist([args.w1tool, args.w1replay])

    scenarios = [
        {
            "name": "pc_only",
            "configs": [
                "record_instructions=false",
                "record_register_deltas=false",
                "memory=false",
            ],
            "sample": "simple_demo",
            "expect_kind": "block",
            "check_regs": False,
            "check_mem": False,
        },
        {
            "name": "instruction",
            "configs": [
                "record_instructions=true",
                "record_register_deltas=false",
                "memory=false",
            ],
            "sample": "rewind_demo_basic",
            "expect_kind": "instruction",
            "check_regs": False,
            "check_mem": False,
        },
        {
            "name": "regs",
            "configs": [
                "record_instructions=true",
                "record_register_deltas=true",
                "memory=false",
            ],
            "sample": "rewind_demo_calls",
            "expect_kind": "instruction",
            "check_regs": True,
            "check_mem": False,
        },
        {
            "name": "memory",
            "configs": [
                "record_instructions=true",
                "record_register_deltas=true",
                "memory=true",
                "memory_reads=true",
                "memory_values=true",
                "stack_window=4096",
                "boundary_interval=1",
            ],
            "sample": "rewind_demo_memops",
            "expect_kind": "instruction",
            "check_regs": True,
            "check_mem": True,
        },
    ]

    for scenario in scenarios:
        trace_path = make_temp_trace_path(scenario["name"])
        sample_path = os.path.join(args.samples_dir, scenario["sample"])
        record_trace(args.w1tool, trace_path, scenario["configs"], sample_path, args.timeout)

        thread_id = select_thread_id(args.w1replay, trace_path, args.timeout)
        output = run_inspect(
            args.w1replay,
            trace_path,
            thread_id,
            count=6,
            timeout=args.timeout,
            inst=False,
            regs=scenario["check_regs"],
        )
        trace = parse_inspect_output(output)
        require_steps(trace.steps, scenario["name"])
        if scenario["expect_kind"]:
            if any(step.kind != scenario["expect_kind"] for step in trace.steps):
                raise AssertionError(
                    f"{scenario['name']}: expected kind {scenario['expect_kind']} for all steps"
                )

        if scenario["check_regs"]:
            if not any(step.regs for step in trace.steps):
                raise AssertionError(f"{scenario['name']}: expected at least one register value")

        if scenario["check_mem"]:
            first_with_regs = next((step for step in trace.steps if step.regs), None)
            if first_with_regs is None:
                raise AssertionError(f"{scenario['name']}: no registers to locate stack pointer")
            sp = first_with_regs.regs.get("sp") or first_with_regs.regs.get("rsp") or first_with_regs.regs.get("esp")
            if sp is None:
                raise AssertionError(f"{scenario['name']}: no stack pointer register found")
            mem_output = run_inspect(
                args.w1replay,
                trace_path,
                thread_id,
                count=1,
                timeout=args.timeout,
                regs=False,
                mem=f"{hex(sp)}:16",
            )
            mem_trace = parse_inspect_output(mem_output)
            if not mem_trace.steps or mem_trace.steps[0].memory is None:
                raise AssertionError(f"{scenario['name']}: memory output missing")
            if not any(byte is not None for byte in mem_trace.steps[0].memory.bytes):
                raise AssertionError(f"{scenario['name']}: memory output contains no concrete bytes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
