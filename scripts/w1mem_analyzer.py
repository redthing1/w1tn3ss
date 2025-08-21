#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "typer",
# ]
# ///

"""
w1mem trace analyzer - simple analysis tool for w1mem memory traces

Analyzes JSONL memory traces produced by w1mem tracer to extract basic information about:
- Memory access patterns (reads/writes, sizes, addresses)
- Module attribution and memory layout
- Access frequency and hotspots

Usage:
    python3 w1mem_analyzer.py <trace_file.jsonl> [options]
"""

import json
import sys
import os
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import List, Dict, Optional

import typer


@dataclass
class MemoryAccess:
    """represents a single memory access event from w1mem trace"""
    instruction_addr: int
    memory_addr: int
    size: int
    access_type: int  # 1=read, 2=write
    instruction_count: int
    instruction_module: str
    memory_module: str
    value: int
    value_valid: bool
    
    @property
    def is_read(self) -> bool:
        return self.access_type == 1
        
    @property
    def is_write(self) -> bool:
        return self.access_type == 2


@dataclass 
class ModuleInfo:
    """represents a loaded module from trace metadata"""
    id: int
    name: str
    path: str
    base: int
    size: int
    type: str
    is_system: bool


class W1MemAnalyzer:
    """analyzes w1mem memory traces"""
    
    def __init__(self, trace_file: str):
        self.trace_file = trace_file
        self.modules: Dict[str, ModuleInfo] = {}
        self.accesses: List[MemoryAccess] = []
        self.module_by_id: Dict[int, ModuleInfo] = {}
        
    def load_trace(self) -> None:
        """load and parse the JSONL trace file"""
        if not os.path.exists(self.trace_file):
            print(f"error: trace file not found: {self.trace_file}", file=sys.stderr)
            sys.exit(1)
            
        try:
            with open(self.trace_file, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"error: failed to read trace file: {e}", file=sys.stderr)
            sys.exit(1)
            
        if not lines:
            print("error: empty trace file", file=sys.stderr)
            sys.exit(1)
            
        # parse metadata (first line)
        try:
            metadata = json.loads(lines[0])
        except json.JSONDecodeError as e:
            print(f"error: invalid JSON in metadata line: {e}", file=sys.stderr)
            sys.exit(1)
            
        if metadata.get('type') != 'metadata':
            print("error: first line must contain metadata with type='metadata'", file=sys.stderr)
            sys.exit(1)
            
        # load module information
        for mod_data in metadata.get('modules', []):
            module = ModuleInfo(
                id=mod_data['id'],
                name=mod_data['name'],
                path=mod_data['path'],
                base=mod_data['base'],
                size=mod_data['size'],
                type=mod_data['type'],
                is_system=mod_data['is_system']
            )
            self.modules[module.name] = module
            self.module_by_id[module.id] = module
            
        # parse memory access events
        for line_num, line in enumerate(lines[1:], 2):
            try:
                data = json.loads(line)
                if data.get('type') == 'event':
                    event_data = data['data']
                    access = MemoryAccess(
                        instruction_addr=event_data['instruction_addr'],
                        memory_addr=event_data['memory_addr'],
                        size=event_data['size'],
                        access_type=event_data['access_type'],
                        instruction_count=event_data['instruction_count'],
                        instruction_module=event_data['instruction_module'],
                        memory_module=event_data['memory_module'],
                        value=event_data['value'],
                        value_valid=event_data['value_valid']
                    )
                    self.accesses.append(access)
            except Exception as e:
                if line_num <= 10:  # only show first few parse errors
                    print(f"warning: failed to parse line {line_num}: {e}", file=sys.stderr)
                
        print(f"loaded {len(self.modules)} modules and {len(self.accesses)} memory accesses")
        
    def print_summary(self) -> None:
        """print high-level trace summary"""
        print("\n" + "="*60)
        print("MEMORY TRACE SUMMARY")
        print("="*60)
        
        total_accesses = len(self.accesses)
        if total_accesses == 0:
            print("no memory accesses found in trace")
            return
            
        reads = sum(1 for a in self.accesses if a.is_read)
        writes = sum(1 for a in self.accesses if a.is_write)
        valid_values = sum(1 for a in self.accesses if a.value_valid)
        
        print(f"trace file: {self.trace_file}")
        print(f"total memory accesses: {total_accesses}")
        print(f"  reads:      {reads:6} ({reads/total_accesses*100:.1f}%)")
        print(f"  writes:     {writes:6} ({writes/total_accesses*100:.1f}%)")
        print(f"  valid values: {valid_values:4} ({valid_values/total_accesses*100:.1f}%)")
        
        # instruction count range
        inst_counts = [a.instruction_count for a in self.accesses]
        if inst_counts:
            print(f"instruction count range: {min(inst_counts)} - {max(inst_counts)}")
        
        # size distribution
        size_counts = Counter(a.size for a in self.accesses)
        print(f"\naccess size distribution:")
        for size in sorted(size_counts.keys()):
            count = size_counts[size]
            print(f"  {size:2} bytes: {count:6} accesses ({count/total_accesses*100:.1f}%)")
            
        # module activity
        module_counts = Counter(a.instruction_module for a in self.accesses)
        print(f"\ntop instruction modules:")
        for i, (module, count) in enumerate(module_counts.most_common(10), 1):
            print(f"  {i:2}. {module:20}: {count:6} accesses ({count/total_accesses*100:.1f}%)")
            
        # memory regions
        memory_counts = Counter(a.memory_module for a in self.accesses)
        print(f"\ntop memory regions:")
        for i, (region, count) in enumerate(memory_counts.most_common(10), 1):
            print(f"  {i:2}. {region:20}: {count:6} accesses ({count/total_accesses*100:.1f}%)")
            
    def print_hotspots(self, top_n: int = 15) -> None:
        """find and display memory access hotspots"""
        print(f"\n" + "="*60)
        print("MEMORY HOTSPOT ANALYSIS")
        print("="*60)
        
        if not self.accesses:
            print("no memory accesses to analyze")
            return
            
        # memory address frequency
        addr_access_info = defaultdict(lambda: {'reads': 0, 'writes': 0, 'total': 0})
        for access in self.accesses:
            info = addr_access_info[access.memory_addr]
            if access.is_read:
                info['reads'] += 1
            else:
                info['writes'] += 1
            info['total'] += 1
            
        print(f"top {top_n} most accessed memory addresses:")
        sorted_addrs = sorted(addr_access_info.items(), key=lambda x: x[1]['total'], reverse=True)
        for i, (addr, info) in enumerate(sorted_addrs[:top_n], 1):
            total = info['total']
            reads = info['reads']
            writes = info['writes']
            pct = total / len(self.accesses) * 100
            print(f"  {i:2}. 0x{addr:016x}: {total:4} accesses ({pct:4.1f}%) | R: {reads:2} W: {writes:2}")
            
        # instruction address frequency
        inst_access_info = defaultdict(lambda: {'reads': 0, 'writes': 0, 'total': 0, 'module': '', 'addrs': set()})
        for access in self.accesses:
            info = inst_access_info[access.instruction_addr]
            if access.is_read:
                info['reads'] += 1
            else:
                info['writes'] += 1
            info['total'] += 1
            info['module'] = access.instruction_module
            info['addrs'].add(access.memory_addr)
            
        print(f"\ntop {top_n} most active instruction addresses:")
        sorted_insts = sorted(inst_access_info.items(), key=lambda x: x[1]['total'], reverse=True)
        for i, (addr, info) in enumerate(sorted_insts[:top_n], 1):
            total = info['total']
            reads = info['reads']
            writes = info['writes']
            num_addrs = len(info['addrs'])
            pct = total / len(self.accesses) * 100
            module = info['module'][:15]  # truncate long module names
            print(f"  {i:2}. 0x{addr:016x}: {total:4} accesses ({pct:4.1f}%) | R: {reads:2} W: {writes:2} | {num_addrs:3} addrs | {module}")
            
    def print_modules(self) -> None:
        """print module information"""
        print(f"\n" + "="*60)
        print("MODULE INFORMATION")
        print("="*60)
        
        if not self.modules:
            print("no module information available")
            return
            
        print(f"total modules: {len(self.modules)}")
        
        # categorize modules
        system_modules = [m for m in self.modules.values() if m.is_system]
        user_modules = [m for m in self.modules.values() if not m.is_system]
        main_modules = [m for m in self.modules.values() if m.type == 'main']
        
        print(f"  system modules: {len(system_modules)}")
        print(f"  user modules:   {len(user_modules)}")
        print(f"  main modules:   {len(main_modules)}")
        
        # show modules with memory accesses
        module_access_counts = Counter(a.instruction_module for a in self.accesses)
        active_modules = [(name, count) for name, count in module_access_counts.items() if count > 0]
        
        if active_modules:
            print(f"\nmodules with memory accesses:")
            for name, count in sorted(active_modules, key=lambda x: x[1], reverse=True):
                module = self.modules.get(name)
                if module:
                    type_str = module.type[:8]
                    system_str = "system" if module.is_system else "user"
                    pct = count / len(self.accesses) * 100
                    print(f"  {name:25}: {count:6} accesses ({pct:4.1f}%) | {type_str:8} | {system_str}")
                else:
                    print(f"  {name:25}: {count:6} accesses | unknown module")


def main(
    trace_file: str = typer.Argument(..., help="JSONL trace file from w1mem"),
    top_n: int = typer.Option(15, "--top-n", help="number of top results to show in hotspot analysis"),
    modules: bool = typer.Option(False, "--modules", help="include detailed module information")
):
    """analyze w1mem memory traces"""
    try:
        analyzer = W1MemAnalyzer(trace_file)
        analyzer.load_trace()
        analyzer.print_summary()
        analyzer.print_hotspots(top_n)
        
        if modules:
            analyzer.print_modules()
            
    except KeyboardInterrupt:
        print("\nanalysis interrupted by user", file=sys.stderr)
        raise typer.Exit(1)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise typer.Exit(1)


if __name__ == '__main__':
    typer.run(main)