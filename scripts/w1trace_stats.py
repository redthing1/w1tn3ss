#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "typer",
# ]
# ///

"""
w1trace stats - minimalist analyzer for w1trace instruction traces

analyzes jsonl traces from w1trace to extract:
- execution statistics and module coverage
- control flow patterns (when tracked)
- hot code regions and instruction addresses

usage:
    python3 w1trace_stats.py <trace.jsonl>
"""

import json
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

import typer


class TraceStats:
    """analyze w1trace jsonl output"""

    def __init__(self, trace_file: str):
        self.trace_file = trace_file
        self.modules: List[Dict] = []
        self.module_map: Dict[Tuple[int, int], str] = {}  # (base, end) -> name
        self.instructions: List[Dict] = []
        self.branches: List[Dict] = []
        self.has_control_flow = False

    def load(self) -> None:
        """load and parse trace file"""
        with open(self.trace_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    event_type = data.get("type")

                    if event_type == "metadata":
                        self.modules = data.get("modules", [])
                        self._build_module_map()
                        self.has_control_flow = data.get("config", {}).get(
                            "track_control_flow", False
                        )
                    elif event_type == "insn":
                        self.instructions.append(data)
                    elif event_type == "branch":
                        self.branches.append(data)
                except json.JSONDecodeError:
                    continue

    def _build_module_map(self) -> None:
        """build efficient module lookup map"""
        for module in self.modules:
            base = module["base"]
            end = base + module["size"]
            self.module_map[(base, end)] = module["name"]

    def resolve_module(self, address: int) -> str:
        """resolve address to module name"""
        for (base, end), name in self.module_map.items():
            if base <= address < end:
                return name
        return "unknown"

    def print_summary(self) -> None:
        """print trace summary"""
        print(f"\ntrace: {self.trace_file}")
        print(f"instructions: {len(self.instructions):,}")

        if self.has_control_flow:
            print(f"branches: {len(self.branches):,}")

            # branch type breakdown
            if self.branches:
                branch_types = Counter(
                    b.get("branch_type", "unknown") for b in self.branches
                )
                print("\ncontrol flow:")
                for btype, count in sorted(branch_types.items()):
                    pct = count / len(self.branches) * 100
                    print(f"  {btype:8}: {count:5} ({pct:5.1f}%)")

    def print_modules(self) -> None:
        """print module execution statistics"""
        if not self.instructions:
            return

        # count instructions per module
        module_counts = Counter()
        for insn in self.instructions:
            addr = insn["address"]
            module = self.resolve_module(addr)
            module_counts[module] += 1

        print("\nmodule execution:")
        total = len(self.instructions)
        for module, count in module_counts.most_common(10):
            pct = count / total * 100
            print(f"  {module:30}: {count:7,} ({pct:5.1f}%)")

    def print_hotspots(self, top_n: int = 10) -> None:
        """identify hot code regions"""
        if not self.instructions:
            return

        # count instruction addresses
        addr_counts = Counter(insn["address"] for insn in self.instructions)

        print(f"\ntop {top_n} hot addresses:")
        for addr, count in addr_counts.most_common(top_n):
            module = self.resolve_module(addr)
            pct = count / len(self.instructions) * 100
            print(f"  0x{addr:016x}: {count:5} ({pct:5.1f}%) [{module}]")

    def print_flow_graph(self, limit: int = 20) -> None:
        """show control flow transitions"""
        if not self.branches or not self.has_control_flow:
            return

        print(f"\ncontrol flow graph (first {limit}):")
        for i, branch in enumerate(self.branches[:limit]):
            src = branch["source"]
            dst = branch["dest"]
            btype = branch.get("branch_type", "?")
            src_mod = self.resolve_module(src)
            dst_mod = self.resolve_module(dst)

            # show module transition if different
            if src_mod != dst_mod:
                print(
                    f"  {i:3}: {btype:4} 0x{src:08x} -> 0x{dst:08x} [{src_mod} -> {dst_mod}]"
                )
            else:
                print(f"  {i:3}: {btype:4} 0x{src:08x} -> 0x{dst:08x} [{src_mod}]")


def main(
    trace_file: str = typer.Argument(..., help="w1trace jsonl file"),
    hotspots: int = typer.Option(
        10, "--hot", "-h", help="number of hot addresses to show"
    ),
    flow: Optional[int] = typer.Option(
        None, "--flow", "-f", help="show control flow graph (limit entries)"
    ),
    modules: bool = typer.Option(
        True, "--modules/--no-modules", "-m/-M", help="show module statistics"
    ),
):
    """analyze w1trace instruction traces"""

    # load and analyze
    stats = TraceStats(trace_file)
    stats.load()

    # display results
    stats.print_summary()

    if modules:
        stats.print_modules()

    stats.print_hotspots(hotspots)

    if flow is not None:
        stats.print_flow_graph(flow if flow > 0 else 20)


if __name__ == "__main__":
    typer.run(main)
