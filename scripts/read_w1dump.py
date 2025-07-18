#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "msgpack",
# ]
# ///
"""
read_w1dump.py - a standalone script to read and parse w1dump files
supports x86, x86_64, and arm64 architectures with proper GPRState handling

can be used as both a command-line tool and a python module:

as a tool:
    ./scripts/read_w1dump.py dump.w1dump              # full analysis
    ./scripts/read_w1dump.py dump.w1dump --summary    # summary only
    ./scripts/read_w1dump.py dump.w1dump --full       # show all memory regions

as a module:
    from read_w1dump import load_dump, W1Dump

    dump = load_dump("process.w1dump")
    print(f"process: {dump.metadata.process_name}")
    print(f"pc: {dump.thread.gpr_state.pc:016x}")

    # find module at address
    module = dump.get_module_at(dump.thread.gpr_state.pc)
    if module:
        print(f"executing in: {module.name}")
"""

import json
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union, Any
from pathlib import Path
from enum import IntEnum
import msgpack


# public API exports
__all__ = [
    # main functions
    "load_dump",
    # core classes
    "W1Dump",
    "DumpMetadata",
    "ThreadState",
    "MemoryRegion",
    "ModuleInfo",
    # architecture states
    "GPRState_x86_64",
    "GPRState_x86",
    "GPRState_arm64",
    "GPRStateBase",
    # enums
    "MemoryPermissions",
    # constants
    "SUPPORTED_ARCHITECTURES",
]


# architecture registry for extensibility
SUPPORTED_ARCHITECTURES = {
    "x86_64": {"pointer_size": 8, "gpr_count": 20},
    "x86": {"pointer_size": 4, "gpr_count": 10},
    "arm64": {"pointer_size": 8, "gpr_count": 36},
    "aarch64": {"pointer_size": 8, "gpr_count": 36},  # alias for arm64
}


# base class for GPR states
@dataclass
class GPRStateBase:
    """base class for architecture-specific GPR states"""

    @classmethod
    def from_values(cls, values: List[int]):
        """create from list of values in QBDI order"""
        raise NotImplementedError("subclasses must implement from_values")

    @property
    def pc(self) -> int:
        """get program counter value"""
        raise NotImplementedError("subclasses must implement pc property")

    @property
    def sp(self) -> int:
        """get stack pointer value"""
        raise NotImplementedError("subclasses must implement sp property")


# architecture-specific GPRState definitions
@dataclass
class GPRState_x86_64(GPRStateBase):
    """x86_64 general purpose register state"""

    rax: int = 0
    rbx: int = 0
    rcx: int = 0
    rdx: int = 0
    rsi: int = 0
    rdi: int = 0
    r8: int = 0
    r9: int = 0
    r10: int = 0
    r11: int = 0
    r12: int = 0
    r13: int = 0
    r14: int = 0
    r15: int = 0
    rbp: int = 0
    rsp: int = 0
    rip: int = 0
    eflags: int = 0
    fs: int = 0
    gs: int = 0

    @classmethod
    def from_values(cls, values: List[int]) -> "GPRState_x86_64":
        """create from list of values in QBDI order"""
        if len(values) < 18:
            raise ValueError(
                f"Expected at least 18 values for x86_64, got {len(values)}"
            )
        return cls(
            rax=values[0],
            rbx=values[1],
            rcx=values[2],
            rdx=values[3],
            rsi=values[4],
            rdi=values[5],
            r8=values[6],
            r9=values[7],
            r10=values[8],
            r11=values[9],
            r12=values[10],
            r13=values[11],
            r14=values[12],
            r15=values[13],
            rbp=values[14],
            rsp=values[15],
            rip=values[16],
            eflags=values[17],
            fs=values[18] if len(values) > 18 else 0,
            gs=values[19] if len(values) > 19 else 0,
        )

    def __str__(self) -> str:
        lines = []
        lines.append(
            f"rax = {self.rax:016x}  rbx = {self.rbx:016x}  rcx = {self.rcx:016x}  rdx = {self.rdx:016x}"
        )
        lines.append(
            f"rsi = {self.rsi:016x}  rdi = {self.rdi:016x}  r8  = {self.r8:016x}  r9  = {self.r9:016x}"
        )
        lines.append(
            f"r10 = {self.r10:016x}  r11 = {self.r11:016x}  r12 = {self.r12:016x}  r13 = {self.r13:016x}"
        )
        lines.append(
            f"r14 = {self.r14:016x}  r15 = {self.r15:016x}  rbp = {self.rbp:016x}  rsp = {self.rsp:016x}"
        )
        lines.append(f"rip = {self.rip:016x}  eflags = {self.eflags:08x}")
        if self.fs or self.gs:
            lines.append(f"fs  = {self.fs:016x}  gs  = {self.gs:016x}")
        return "\n".join(lines)

    @property
    def pc(self) -> int:
        """get program counter value"""
        return self.rip

    @property
    def sp(self) -> int:
        """get stack pointer value"""
        return self.rsp


@dataclass
class GPRState_x86(GPRStateBase):
    """x86 (32-bit) general purpose register state"""

    eax: int = 0
    ebx: int = 0
    ecx: int = 0
    edx: int = 0
    esi: int = 0
    edi: int = 0
    ebp: int = 0
    esp: int = 0
    eip: int = 0
    eflags: int = 0

    @classmethod
    def from_values(cls, values: List[int]) -> "GPRState_x86":
        """create from list of values in QBDI order"""
        if len(values) < 10:
            raise ValueError(f"Expected at least 10 values for x86, got {len(values)}")
        return cls(
            eax=values[0],
            ebx=values[1],
            ecx=values[2],
            edx=values[3],
            esi=values[4],
            edi=values[5],
            ebp=values[6],
            esp=values[7],
            eip=values[8],
            eflags=values[9],
        )

    def __str__(self) -> str:
        lines = []
        lines.append(
            f"eax = {self.eax:08x}  ebx = {self.ebx:08x}  ecx = {self.ecx:08x}  edx = {self.edx:08x}"
        )
        lines.append(
            f"esi = {self.esi:08x}  edi = {self.edi:08x}  ebp = {self.ebp:08x}  esp = {self.esp:08x}"
        )
        lines.append(f"eip = {self.eip:08x}  eflags = {self.eflags:08x}")
        return "\n".join(lines)

    @property
    def pc(self) -> int:
        """get program counter value"""
        return self.eip

    @property
    def sp(self) -> int:
        """get stack pointer value"""
        return self.esp


@dataclass
class LocalMonitor:
    """arm64 local monitor state for exclusive load/store"""

    addr: int = 0
    enable: int = 0


@dataclass
class GPRState_arm64(GPRStateBase):
    """arm64 (aarch64) general purpose register state"""

    x0: int = 0
    x1: int = 0
    x2: int = 0
    x3: int = 0
    x4: int = 0
    x5: int = 0
    x6: int = 0
    x7: int = 0
    x8: int = 0
    x9: int = 0
    x10: int = 0
    x11: int = 0
    x12: int = 0
    x13: int = 0
    x14: int = 0
    x15: int = 0
    x16: int = 0
    x17: int = 0
    x18: int = 0
    x19: int = 0
    x20: int = 0
    x21: int = 0
    x22: int = 0
    x23: int = 0
    x24: int = 0
    x25: int = 0
    x26: int = 0
    x27: int = 0
    x28: int = 0
    x29: int = 0  # FP
    lr: int = 0  # x30
    sp: int = 0
    nzcv: int = 0
    pc: int = 0
    local_monitor: LocalMonitor = field(default_factory=LocalMonitor)

    @classmethod
    def from_values(cls, values: List[int]) -> "GPRState_arm64":
        """create from list of values in QBDI order"""
        if len(values) < 34:
            raise ValueError(
                f"Expected at least 34 values for arm64, got {len(values)}"
            )

        instance = cls(
            x0=values[0],
            x1=values[1],
            x2=values[2],
            x3=values[3],
            x4=values[4],
            x5=values[5],
            x6=values[6],
            x7=values[7],
            x8=values[8],
            x9=values[9],
            x10=values[10],
            x11=values[11],
            x12=values[12],
            x13=values[13],
            x14=values[14],
            x15=values[15],
            x16=values[16],
            x17=values[17],
            x18=values[18],
            x19=values[19],
            x20=values[20],
            x21=values[21],
            x22=values[22],
            x23=values[23],
            x24=values[24],
            x25=values[25],
            x26=values[26],
            x27=values[27],
            x28=values[28],
            x29=values[29],
            lr=values[30],
            sp=values[31],
            nzcv=values[32],
            pc=values[33],
        )

        # handle local monitor if present
        if len(values) >= 36:
            instance.local_monitor = LocalMonitor(addr=values[34], enable=values[35])

        return instance

    def __str__(self) -> str:
        lines = []
        # general purpose registers in neat rows
        for i in range(0, 28, 4):
            parts = []
            for j in range(4):
                if i + j < 28:
                    reg_val = getattr(self, f"x{i+j}")
                    parts.append(f"x{i+j:<2} = {reg_val:016x}")
            lines.append("  ".join(parts))

        # special registers
        lines.append(f"x28 = {self.x28:016x}  x29 = {self.x29:016x}")
        lines.append(f"x30 = {self.lr:016x}  sp  = {self.sp:016x}")
        lines.append(f"pc  = {self.pc:016x}  nzcv = {self.nzcv:08x}")

        # local monitor if enabled
        if self.local_monitor.enable:
            lines.append(f"local monitor: addr={self.local_monitor.addr:016x}")

        return "\n".join(lines)


# core dump data structures
@dataclass
class DumpMetadata:
    """dump file metadata"""

    version: int = 1
    timestamp: int = 0
    os: str = ""
    arch: str = ""
    pointer_size: int = 8
    pid: int = 0
    process_name: str = ""


@dataclass
class ThreadState:
    """thread state with registers"""

    thread_id: int
    gpr_values: List[int]
    fpr_values: List[int]
    gpr_state: Optional[Union[GPRState_x86, GPRState_x86_64, GPRState_arm64]] = None

    def __post_init__(self):
        """parse GPR values based on architecture (set later)"""
        pass


class MemoryPermissions(IntEnum):
    """qbdi memory permission flags"""

    NONE = 0
    READ = 1
    WRITE = 2
    EXEC = 4


@dataclass
class MemoryRegion:
    """memory region information"""

    start: int
    end: int
    permissions: int
    module_name: str = ""
    is_stack: bool = False
    is_code: bool = False
    is_data: bool = False
    is_anonymous: bool = False
    data: Optional[bytes] = None

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def perms_str(self) -> str:
        """get permissions as readable string"""
        perms = []
        if self.permissions & MemoryPermissions.READ:
            perms.append("r")
        else:
            perms.append("-")
        if self.permissions & MemoryPermissions.WRITE:
            perms.append("w")
        else:
            perms.append("-")
        if self.permissions & MemoryPermissions.EXEC:
            perms.append("x")
        else:
            perms.append("-")
        return "".join(perms)

    def __str__(self) -> str:
        flags = []
        if self.is_stack:
            flags.append("STACK")
        if self.is_code:
            flags.append("CODE")
        if self.is_data:
            flags.append("DATA")
        if self.is_anonymous:
            flags.append("ANON")

        flag_str = f" [{', '.join(flags)}]" if flags else ""
        module_str = f" ({self.module_name})" if self.module_name else ""

        return f"{self.start:016x}-{self.end:016x} {self.perms_str} {self.size:10} bytes{module_str}{flag_str}"


@dataclass
class ModuleInfo:
    """module/library information"""

    path: str
    name: str
    base_address: int
    size: int
    type: str
    is_system_library: bool
    permissions: int

    def __str__(self) -> str:
        system_str = " [SYSTEM]" if self.is_system_library else ""
        return f"{self.base_address:016x} {self.size:10} bytes {self.name} ({self.type}){system_str}"


@dataclass
class W1Dump:
    """complete w1dump structure"""

    metadata: DumpMetadata
    thread: ThreadState
    regions: List[MemoryRegion]
    modules: List[ModuleInfo]

    def __post_init__(self):
        """parse architecture-specific data after initialization"""
        # normalize architecture name
        arch = self.metadata.arch.lower()
        if arch == "aarch64":
            arch = "arm64"  # normalize aarch64 to arm64

        # validate architecture
        if arch not in SUPPORTED_ARCHITECTURES:
            import warnings

            warnings.warn(
                f"unknown architecture '{self.metadata.arch}', supported: {list(SUPPORTED_ARCHITECTURES.keys())}"
            )
            return

        # validate pointer size
        expected_ptr_size = SUPPORTED_ARCHITECTURES[arch]["pointer_size"]
        if self.metadata.pointer_size != expected_ptr_size:
            import warnings

            warnings.warn(
                f"unexpected pointer size {self.metadata.pointer_size} for {arch}, expected {expected_ptr_size}"
            )

        # parse GPR state based on architecture
        try:
            if arch == "x86_64":
                self.thread.gpr_state = GPRState_x86_64.from_values(
                    self.thread.gpr_values
                )
            elif arch == "x86":
                self.thread.gpr_state = GPRState_x86.from_values(self.thread.gpr_values)
            elif arch == "arm64":
                self.thread.gpr_state = GPRState_arm64.from_values(
                    self.thread.gpr_values
                )
        except ValueError as e:
            import warnings

            warnings.warn(f"failed to parse GPR state: {e}")

    def get_module_at(self, address: int) -> Optional[ModuleInfo]:
        """find module containing the given address"""
        for module in self.modules:
            if module.base_address <= address < module.base_address + module.size:
                return module
        return None

    def get_region_at(self, address: int) -> Optional[MemoryRegion]:
        """find memory region containing the given address"""
        for region in self.regions:
            if region.start <= address < region.end:
                return region
        return None

    def get_stack_regions(self) -> List[MemoryRegion]:
        """get all stack regions"""
        return [r for r in self.regions if r.is_stack]

    def get_code_regions(self) -> List[MemoryRegion]:
        """get all code regions"""
        return [r for r in self.regions if r.is_code]

    def get_module_regions(self, module_name: str) -> List[MemoryRegion]:
        """get all regions belonging to a specific module"""
        return [r for r in self.regions if r.module_name == module_name]

    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """read memory from dump if available"""
        region = self.get_region_at(address)
        if not region or not region.data:
            return None

        # calculate offset within region
        offset = address - region.start
        if offset + size > len(region.data):
            return None

        return region.data[offset : offset + size]

    @property
    def main_module(self) -> Optional[ModuleInfo]:
        """get the main executable module"""
        for module in self.modules:
            if module.type == "main_executable":
                return module
        return None

    def print_summary(self):
        """print a summary of the dump"""
        from datetime import datetime, timezone

        # use unicode box drawing chars that work cross-platform
        print("=" * 60)
        print("w1dump analysis")
        print("=" * 60)

        # process info
        print(f"process:      {self.metadata.process_name} (pid: {self.metadata.pid})")
        print(
            f"architecture: {self.metadata.arch} ({self.metadata.pointer_size * 8}-bit)"
        )
        print(f"platform:     {self.metadata.os}")

        # timestamp - handle milliseconds properly
        if self.metadata.timestamp > 0:
            # convert milliseconds to seconds for timestamp
            dt = datetime.fromtimestamp(
                self.metadata.timestamp / 1000.0, tz=timezone.utc
            )
            # format in local time
            print(f"captured:     {dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}")

        print(f"thread id:    {self.thread.thread_id}")
        print()

        # stats
        print("statistics:")
        print(f"  modules:         {len(self.modules):4d}")
        print(f"  memory regions:  {len(self.regions):4d}")

        # calculate memory stats
        total_size = sum(r.size for r in self.regions)
        code_size = sum(r.size for r in self.regions if r.is_code)
        data_size = sum(r.size for r in self.regions if r.is_data)
        stack_size = sum(r.size for r in self.regions if r.is_stack)
        anon_size = sum(r.size for r in self.regions if r.is_anonymous)

        def format_size(size):
            """format size in human readable form"""
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024.0:
                    return f"{size:6.1f} {unit}"
                size /= 1024.0
            return f"{size:6.1f} TB"

        print()
        print("memory breakdown:")
        print(f"  total:      {format_size(total_size):>12} ({total_size:,} bytes)")
        print(f"  code:       {format_size(code_size):>12} ({code_size:,} bytes)")
        print(f"  data:       {format_size(data_size):>12} ({data_size:,} bytes)")
        print(f"  stack:      {format_size(stack_size):>12} ({stack_size:,} bytes)")
        print(f"  anonymous:  {format_size(anon_size):>12} ({anon_size:,} bytes)")

    def print_registers(self):
        """print register state"""
        print()
        print("-" * 60)
        print("registers")
        print("-" * 60)
        if self.thread.gpr_state:
            print(self.thread.gpr_state)
        else:
            print("no parsed GPR state available")

    def print_modules(self):
        """print loaded modules"""
        print()
        print("-" * 60)
        print(f"modules ({len(self.modules)})")
        print("-" * 60)

        # group by type
        by_type = {}
        for module in self.modules:
            by_type.setdefault(module.type, []).append(module)

        for mod_type, modules in sorted(by_type.items()):
            if modules:
                print(f"\n{mod_type}:")
                for module in sorted(modules, key=lambda m: m.base_address):
                    system = " [system]" if module.is_system_library else ""
                    print(
                        f"  {module.base_address:016x}  {module.size:10,} bytes  {module.name}{system}"
                    )

    def print_memory_map(self):
        """print memory regions"""
        print()
        print("-" * 60)
        print(f"memory map ({len(self.regions)} regions)")
        print("-" * 60)

        # show first few regions and last few
        regions = sorted(self.regions, key=lambda r: r.start)

        if len(regions) <= 20:
            for region in regions:
                print(region)
        else:
            print(
                "\nshowing first 10 and last 10 regions (use --full for complete map):"
            )
            print()
            for region in regions[:10]:
                print(region)
            print(f"\n... {len(regions) - 20} more regions ...\n")
            for region in regions[-10:]:
                print(region)


def load_dump(path: Union[str, Path], validate: bool = True) -> W1Dump:
    """
    load a w1dump file from disk

    args:
        path: path to the dump file
        validate: whether to validate the dump structure (default: True)

    returns:
        W1Dump object containing the parsed dump

    raises:
        FileNotFoundError: if the dump file doesn't exist
        ValueError: if the dump file is invalid or corrupted
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"dump file not found: {path}")

    # check file size
    file_size = path.stat().st_size
    if file_size == 0:
        raise ValueError("dump file is empty")
    if file_size > 10 * 1024 * 1024 * 1024:  # 10GB sanity check
        raise ValueError(
            f"dump file unusually large ({file_size} bytes), may be corrupted"
        )

    # read the file
    try:
        with open(path, "rb") as f:
            data = f.read()
    except IOError as e:
        raise ValueError(f"failed to read dump file: {e}")

    # unpack from MessagePack
    try:
        dump_dict = msgpack.unpackb(data, raw=False, strict_map_key=False)
    except msgpack.exceptions.ExtraData as e:
        raise ValueError(f"dump file contains extra data, may be corrupted: {e}")
    except Exception as e:
        raise ValueError(f"failed to parse MessagePack format: {e}")

    # validate basic structure
    if validate:
        required_keys = {"metadata", "thread", "regions", "modules"}
        missing_keys = required_keys - set(dump_dict.keys())
        if missing_keys:
            raise ValueError(f"dump file missing required keys: {missing_keys}")

    # parse metadata
    try:
        metadata = DumpMetadata(**dump_dict["metadata"])
    except (KeyError, TypeError) as e:
        raise ValueError(f"invalid metadata section: {e}")

    # parse thread state
    try:
        thread = ThreadState(**dump_dict["thread"])
    except (KeyError, TypeError) as e:
        raise ValueError(f"invalid thread section: {e}")

    # parse memory regions
    regions = []
    try:
        for i, r in enumerate(dump_dict["regions"]):
            # convert data from list to bytes if present
            if "data" in r and r["data"] is not None:
                r["data"] = bytes(r["data"])
            regions.append(MemoryRegion(**r))
    except (KeyError, TypeError) as e:
        raise ValueError(f"invalid memory region at index {i}: {e}")

    # parse modules
    modules = []
    try:
        for i, m in enumerate(dump_dict["modules"]):
            modules.append(ModuleInfo(**m))
    except (KeyError, TypeError) as e:
        raise ValueError(f"invalid module at index {i}: {e}")

    # create and return dump object
    return W1Dump(metadata=metadata, thread=thread, regions=regions, modules=modules)


def main():
    """main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="read and analyze w1dump process dump files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s dump.w1dump              # show summary, registers, modules, and memory map
  %(prog)s dump.w1dump --summary    # show only summary
  %(prog)s dump.w1dump --full       # show full memory map (all regions)
  %(prog)s dump.w1dump --no-modules # skip module listing
""",
    )

    parser.add_argument("dump_file", help="path to w1dump file")
    parser.add_argument("--summary", action="store_true", help="show only summary")
    parser.add_argument("--full", action="store_true", help="show full memory map")
    parser.add_argument(
        "--no-registers", action="store_true", help="skip register display"
    )
    parser.add_argument("--no-modules", action="store_true", help="skip module listing")
    parser.add_argument("--no-memory", action="store_true", help="skip memory map")

    args = parser.parse_args()

    try:
        # load the dump
        dump = load_dump(args.dump_file)

        # always show summary
        dump.print_summary()

        # show other sections based on flags
        if not args.summary:
            if not args.no_registers:
                dump.print_registers()
            if not args.no_modules:
                dump.print_modules()
            if not args.no_memory:
                # pass full flag through
                if args.full:
                    # temporarily show all regions
                    regions = sorted(dump.regions, key=lambda r: r.start)
                    print()
                    print("-" * 60)
                    print(f"memory map ({len(dump.regions)} regions) - full listing")
                    print("-" * 60)
                    for region in regions:
                        print(region)
                else:
                    dump.print_memory_map()

    except Exception as e:
        print(f"error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
