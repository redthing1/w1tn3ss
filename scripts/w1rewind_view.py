#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "typer",
#     "rich",
#     "zstandard",
# ]
# ///

"""w1rewind trace viewer (v6)"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Union

import typer
from rich.console import Console
from rich.table import Table

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover - optional dependency for compressed traces
    zstd = None

console = Console()
app = typer.Typer(add_completion=False, no_args_is_help=True)

MAGIC = b"W1RWND6\x00"
HEADER_STRUCT = struct.Struct("<8sHHIQII")
CHUNK_HEADER_STRUCT = struct.Struct("<II")
RECORD_HEADER_STRUCT = struct.Struct("<HHI")
U8 = struct.Struct("<B")
U16 = struct.Struct("<H")
U32 = struct.Struct("<I")
U64 = struct.Struct("<Q")

TRACE_FLAG_INSTRUCTIONS = 1 << 0
TRACE_FLAG_REGISTER_DELTAS = 1 << 1
TRACE_FLAG_MEMORY_ACCESS = 1 << 2
TRACE_FLAG_MEMORY_VALUES = 1 << 3
TRACE_FLAG_BOUNDARIES = 1 << 4
TRACE_FLAG_STACK_WINDOW = 1 << 5
TRACE_FLAG_BLOCKS = 1 << 6

COMPRESSION_NONE = 0
COMPRESSION_ZSTD = 1

RECORD_REGISTER_TABLE = 1
RECORD_MODULE_TABLE = 2
RECORD_THREAD_START = 3
RECORD_INSTRUCTION = 4
RECORD_REGISTER_DELTAS = 5
RECORD_MEMORY_ACCESS = 6
RECORD_BOUNDARY = 7
RECORD_THREAD_END = 8
RECORD_BLOCK_DEFINITION = 9
RECORD_BLOCK_EXEC = 10


@dataclass
class TraceHeader:
    version: int
    architecture: int
    pointer_size: int
    flags: int
    compression: int
    chunk_size: int


@dataclass
class RegisterTableRecord:
    names: List[str]


@dataclass
class ModuleRecord:
    module_id: int
    base: int
    size: int
    permissions: int
    path: str


@dataclass
class ModuleTableRecord:
    modules: List[ModuleRecord]


@dataclass
class ThreadStartRecord:
    thread_id: int
    name: str


@dataclass
class InstructionRecord:
    sequence: int
    thread_id: int
    module_id: int
    module_offset: int
    size: int
    flags: int


@dataclass
class BlockDefinitionRecord:
    block_id: int
    module_id: int
    module_offset: int
    size: int


@dataclass
class BlockExecRecord:
    sequence: int
    thread_id: int
    block_id: int


@dataclass
class RegisterDelta:
    reg_id: int
    value: int


@dataclass
class RegisterDeltaRecord:
    sequence: int
    thread_id: int
    deltas: List[RegisterDelta]


@dataclass
class MemoryAccessRecord:
    sequence: int
    thread_id: int
    kind: int
    address: int
    size: int
    value_known: bool
    value_truncated: bool
    data: bytes = field(default_factory=bytes)


@dataclass
class BoundaryRecord:
    boundary_id: int
    sequence: int
    thread_id: int
    registers: List[RegisterDelta]
    stack_window: bytes
    reason: str


@dataclass
class ThreadEndRecord:
    thread_id: int


Record = Union[
    RegisterTableRecord,
    ModuleTableRecord,
    ThreadStartRecord,
    InstructionRecord,
    BlockDefinitionRecord,
    BlockExecRecord,
    RegisterDeltaRecord,
    MemoryAccessRecord,
    BoundaryRecord,
    ThreadEndRecord,
]


@dataclass
class TraceFile:
    header: TraceHeader
    register_table: List[str]
    module_table: List[ModuleRecord]
    block_table: List[BlockDefinitionRecord]
    records: List[Record]

    def per_thread_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for record in self.records:
            thread_id = _record_thread_id(record)
            if thread_id is None:
                continue
            counts[thread_id] = counts.get(thread_id, 0) + 1
        return counts


class TraceParserError(RuntimeError):
    pass


class RecordReader:
    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self._cursor = 0

    def _read(self, struct_obj: struct.Struct) -> int:
        try:
            value = struct_obj.unpack_from(self._data, self._cursor)[0]
        except struct.error as exc:
            raise TraceParserError("truncated record payload") from exc
        self._cursor += struct_obj.size
        return value

    def read_u8(self) -> int:
        return self._read(U8)

    def read_u16(self) -> int:
        return self._read(U16)

    def read_u32(self) -> int:
        return self._read(U32)

    def read_u64(self) -> int:
        return self._read(U64)

    def read_bytes(self, size: int) -> bytes:
        if self._cursor + size > len(self._data):
            raise TraceParserError("truncated record payload")
        data = bytes(self._data[self._cursor : self._cursor + size])
        self._cursor += size
        return data

    def read_string(self) -> str:
        length = self.read_u16()
        raw = self.read_bytes(length)
        return raw.decode("utf-8", errors="replace")


class TraceParser:
    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self._cursor = 0

    def parse(self) -> TraceFile:
        try:
            magic, version, arch, pointer_size, flags, compression, chunk_size = HEADER_STRUCT.unpack_from(
                self._data, self._cursor
            )
        except struct.error as exc:
            raise TraceParserError("truncated trace header") from exc
        self._cursor += HEADER_STRUCT.size

        if magic != MAGIC:
            raise TraceParserError(f"unexpected magic {magic!r}; not a v6 w1rewind trace")
        if version != 6:
            raise TraceParserError(f"unsupported trace version {version} (expected v6)")
        if chunk_size == 0:
            raise TraceParserError("invalid chunk size in trace header")

        header = TraceHeader(
            version=version,
            architecture=arch,
            pointer_size=pointer_size,
            flags=flags,
            compression=compression,
            chunk_size=chunk_size,
        )

        record_stream = self._expand_record_stream(compression)
        self._data = memoryview(record_stream)
        self._cursor = 0
        register_table: List[str] = []
        module_table: List[ModuleRecord] = []
        block_table: List[BlockDefinitionRecord] = []
        records: List[Record] = []

        while self._cursor < len(self._data):
            record = self._parse_record(register_table, module_table, block_table)
            records.append(record)

        return TraceFile(
            header=header,
            register_table=register_table,
            module_table=module_table,
            block_table=block_table,
            records=records,
        )

    def _expand_record_stream(self, compression: int) -> bytes:
        record_data = bytearray()
        decompressor = None
        if compression == COMPRESSION_ZSTD:
            if zstd is None:
                raise TraceParserError("trace uses zstd compression but zstandard is not installed")
            decompressor = zstd.ZstdDecompressor()

        while self._cursor < len(self._data):
            if self._cursor + CHUNK_HEADER_STRUCT.size > len(self._data):
                raise TraceParserError("truncated chunk header")
            compressed_size, uncompressed_size = CHUNK_HEADER_STRUCT.unpack_from(
                self._data, self._cursor
            )
            self._cursor += CHUNK_HEADER_STRUCT.size
            if compressed_size == 0 or uncompressed_size == 0:
                raise TraceParserError("invalid chunk header")
            if self._cursor + compressed_size > len(self._data):
                raise TraceParserError("truncated chunk payload")
            payload = bytes(self._data[self._cursor : self._cursor + compressed_size])
            self._cursor += compressed_size

            if compression == COMPRESSION_NONE:
                if compressed_size != uncompressed_size:
                    raise TraceParserError("uncompressed chunk size mismatch")
                record_data.extend(payload)
                continue

            if compression != COMPRESSION_ZSTD or decompressor is None:
                raise TraceParserError("unsupported trace compression mode")

            chunk = decompressor.decompress(payload, uncompressed_size)
            if len(chunk) != uncompressed_size:
                raise TraceParserError("zstd decompressed size mismatch")
            record_data.extend(chunk)

        return bytes(record_data)

    def _parse_record(
        self,
        register_table: List[str],
        module_table: List[ModuleRecord],
        block_table: List[BlockDefinitionRecord],
    ) -> Record:
        start = self._cursor
        try:
            kind, flags, size = RECORD_HEADER_STRUCT.unpack_from(
                self._data, self._cursor
            )
        except struct.error as exc:
            raise TraceParserError(f"truncated record header at offset {start}") from exc
        self._cursor += RECORD_HEADER_STRUCT.size

        if self._cursor + size > len(self._data):
            raise TraceParserError("truncated record payload")

        payload = bytes(self._data[self._cursor : self._cursor + size])
        self._cursor += size
        reader = RecordReader(payload)

        if kind == RECORD_REGISTER_TABLE:
            count = reader.read_u16()
            names = [reader.read_string() for _ in range(count)]
            register_table.clear()
            register_table.extend(names)
            return RegisterTableRecord(names=names)

        if kind == RECORD_MODULE_TABLE:
            count = reader.read_u32()
            modules = []
            for _ in range(count):
                module_id = reader.read_u64()
                base = reader.read_u64()
                size_value = reader.read_u64()
                permissions = reader.read_u32()
                path = reader.read_string()
                modules.append(
                    ModuleRecord(
                        module_id=module_id,
                        base=base,
                        size=size_value,
                        permissions=permissions,
                        path=path,
                    )
                )
            module_table.clear()
            module_table.extend(modules)
            return ModuleTableRecord(modules=modules)

        if kind == RECORD_THREAD_START:
            thread_id = reader.read_u64()
            name = reader.read_string()
            return ThreadStartRecord(thread_id=thread_id, name=name)

        if kind == RECORD_INSTRUCTION:
            sequence = reader.read_u64()
            thread_id = reader.read_u64()
            module_id = reader.read_u64()
            module_offset = reader.read_u64()
            size_value = reader.read_u32()
            flags_value = reader.read_u32()
            return InstructionRecord(
                sequence=sequence,
                thread_id=thread_id,
                module_id=module_id,
                module_offset=module_offset,
                size=size_value,
                flags=flags_value,
            )

        if kind == RECORD_BLOCK_DEFINITION:
            block_id = reader.read_u64()
            module_id = reader.read_u64()
            module_offset = reader.read_u64()
            size_value = reader.read_u32()
            record = BlockDefinitionRecord(
                block_id=block_id,
                module_id=module_id,
                module_offset=module_offset,
                size=size_value,
            )
            block_table.append(record)
            return record

        if kind == RECORD_BLOCK_EXEC:
            sequence = reader.read_u64()
            thread_id = reader.read_u64()
            block_id = reader.read_u64()
            return BlockExecRecord(sequence=sequence, thread_id=thread_id, block_id=block_id)

        if kind == RECORD_REGISTER_DELTAS:
            sequence = reader.read_u64()
            thread_id = reader.read_u64()
            count = reader.read_u16()
            deltas = []
            for _ in range(count):
                reg_id = reader.read_u16()
                value = reader.read_u64()
                deltas.append(RegisterDelta(reg_id=reg_id, value=value))
            return RegisterDeltaRecord(sequence=sequence, thread_id=thread_id, deltas=deltas)

        if kind == RECORD_MEMORY_ACCESS:
            sequence = reader.read_u64()
            thread_id = reader.read_u64()
            access_kind = reader.read_u8()
            value_known = reader.read_u8() != 0
            value_truncated = reader.read_u8() != 0
            reader.read_u8()
            address = reader.read_u64()
            size_value = reader.read_u32()
            data_size = reader.read_u32()
            data = reader.read_bytes(data_size) if data_size else b""
            return MemoryAccessRecord(
                sequence=sequence,
                thread_id=thread_id,
                kind=access_kind,
                address=address,
                size=size_value,
                value_known=value_known,
                value_truncated=value_truncated,
                data=data,
            )

        if kind == RECORD_BOUNDARY:
            boundary_id = reader.read_u64()
            sequence = reader.read_u64()
            thread_id = reader.read_u64()
            count = reader.read_u16()
            registers = []
            for _ in range(count):
                reg_id = reader.read_u16()
                value = reader.read_u64()
                registers.append(RegisterDelta(reg_id=reg_id, value=value))
            stack_size = reader.read_u32()
            stack_window = reader.read_bytes(stack_size) if stack_size else b""
            reason = reader.read_string()
            return BoundaryRecord(
                boundary_id=boundary_id,
                sequence=sequence,
                thread_id=thread_id,
                registers=registers,
                stack_window=stack_window,
                reason=reason,
            )

        if kind == RECORD_THREAD_END:
            thread_id = reader.read_u64()
            return ThreadEndRecord(thread_id=thread_id)

        raise TraceParserError(f"unsupported record kind {kind} at offset {start}")


def load_trace(path: Path) -> TraceFile:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TraceParserError(f"failed to read trace: {exc}") from exc
    parser = TraceParser(data)
    return parser.parse()


def format_architecture(arch: int) -> str:
    mapping = {
        0x0101: "x86_64",
        0x0102: "x86",
        0x0201: "aarch64",
        0x0202: "arm",
    }
    return mapping.get(arch, f"0x{arch:04x}")


def format_flags(flags: int) -> str:
    parts = []
    if flags & TRACE_FLAG_INSTRUCTIONS:
        parts.append("instructions")
    if flags & TRACE_FLAG_BLOCKS:
        parts.append("blocks")
    if flags & TRACE_FLAG_REGISTER_DELTAS:
        parts.append("register_deltas")
    if flags & TRACE_FLAG_MEMORY_ACCESS:
        parts.append("memory_access")
    if flags & TRACE_FLAG_MEMORY_VALUES:
        parts.append("memory_values")
    if flags & TRACE_FLAG_BOUNDARIES:
        parts.append("boundaries")
    if flags & TRACE_FLAG_STACK_WINDOW:
        parts.append("stack_window")
    return ", ".join(parts) if parts else "none"


def format_compression(compression: int) -> str:
    if compression == COMPRESSION_NONE:
        return "none"
    if compression == COMPRESSION_ZSTD:
        return "zstd"
    return f"0x{compression:x}"


def _record_thread_id(record: Record) -> Optional[int]:
    if isinstance(
        record,
        (
            InstructionRecord,
            BlockExecRecord,
            RegisterDeltaRecord,
            MemoryAccessRecord,
            BoundaryRecord,
        ),
    ):
        return record.thread_id
    if isinstance(record, (ThreadStartRecord, ThreadEndRecord)):
        return record.thread_id
    return None


def _module_by_id(modules: List[ModuleRecord]) -> dict[int, ModuleRecord]:
    return {module.module_id: module for module in modules}


def _block_by_id(blocks: List[BlockDefinitionRecord]) -> dict[int, BlockDefinitionRecord]:
    return {block.block_id: block for block in blocks}


@app.command()
def summary(
    trace_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a w1rewind trace file"
    ),
) -> None:
    """Print a high-level overview of the trace."""
    trace = load_trace(trace_path)

    console.print(f"[bold]trace[/] {trace_path}")
    console.print(f"  version     : {trace.header.version}")
    console.print(f"  architecture: {format_architecture(trace.header.architecture)}")
    console.print(f"  pointer size: {trace.header.pointer_size}")
    console.print(f"  flags       : {format_flags(trace.header.flags)}")
    console.print(f"  compression : {format_compression(trace.header.compression)}")
    console.print(f"  chunk size  : {trace.header.chunk_size}")
    console.print(f"  records     : {len(trace.records)}")

    flow = "unknown"
    if trace.header.flags & TRACE_FLAG_BLOCKS:
        flow = "blocks"
    elif trace.header.flags & TRACE_FLAG_INSTRUCTIONS:
        flow = "instructions"
    console.print(f"  flow        : {flow}")

    instruction_count = sum(isinstance(r, InstructionRecord) for r in trace.records)
    block_exec_count = sum(isinstance(r, BlockExecRecord) for r in trace.records)
    boundary_count = sum(isinstance(r, BoundaryRecord) for r in trace.records)
    memory_reads = sum(
        isinstance(r, MemoryAccessRecord) and r.kind == 1 for r in trace.records
    )
    memory_writes = sum(
        isinstance(r, MemoryAccessRecord) and r.kind == 2 for r in trace.records
    )

    if flow == "blocks":
        console.print(f"  blocks      : {block_exec_count}")
        console.print(f"  block defs  : {len(trace.block_table)}")
    else:
        console.print(f"  instructions: {instruction_count}")

    console.print(f"  boundaries  : {boundary_count}")
    if memory_reads or memory_writes:
        console.print(f"  memory reads : {memory_reads}")
        console.print(f"  memory writes: {memory_writes}")

    thread_counts = trace.per_thread_counts()
    if thread_counts:
        table = Table(title="Records per thread", show_lines=False)
        table.add_column("thread id", justify="right")
        table.add_column("records", justify="right")
        for thread_id, count in sorted(thread_counts.items()):
            table.add_row(str(thread_id), str(count))
        console.print(table)


@app.command()
def events(
    trace_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a w1rewind trace file"
    ),
    thread_id: Optional[int] = typer.Option(
        None, help="Limit output to a specific thread id"
    ),
    limit: Optional[int] = typer.Option(10, help="Maximum number of records to display"),
    show_reads: bool = typer.Option(False, help="Include memory read records"),
    show_writes: bool = typer.Option(True, help="Include memory write records"),
) -> None:
    """Pretty-print trace records."""
    trace = load_trace(trace_path)
    module_lookup = _module_by_id(trace.module_table)
    block_lookup = _block_by_id(trace.block_table)

    records = list(
        _iter_records(
            trace.records,
            thread_id=thread_id,
            limit=limit,
            show_reads=show_reads,
            show_writes=show_writes,
        )
    )
    if not records:
        console.print("[yellow]no records matched filters[/]")
        return

    table = Table(title=f"Records ({len(records)} displayed)")
    table.add_column("type", justify="left")
    table.add_column("seq", justify="right")
    table.add_column("thread", justify="right")
    table.add_column("addr", justify="right")
    table.add_column("size", justify="right")
    table.add_column("info", justify="left")

    for record in records:
        row = _record_row(record, module_lookup, block_lookup)
        table.add_row(*row)

    console.print(table)


def _iter_records(
    records: Iterable[Record],
    *,
    thread_id: Optional[int],
    limit: Optional[int],
    show_reads: bool,
    show_writes: bool,
) -> Iterable[Record]:
    count = 0
    for record in records:
        if isinstance(record, (RegisterTableRecord, ModuleTableRecord, BlockDefinitionRecord)):
            continue
        if isinstance(record, MemoryAccessRecord):
            if record.kind == 1 and not show_reads:
                continue
            if record.kind == 2 and not show_writes:
                continue
        if thread_id is not None:
            rec_thread = _record_thread_id(record)
            if rec_thread is None or rec_thread != thread_id:
                continue
        yield record
        count += 1
        if limit is not None and count >= limit:
            break


def _record_row(
    record: Record,
    module_lookup: dict[int, ModuleRecord],
    block_lookup: dict[int, BlockDefinitionRecord],
) -> List[str]:
    if isinstance(record, ThreadStartRecord):
        return ["thread_start", "", str(record.thread_id), "", "", record.name]
    if isinstance(record, ThreadEndRecord):
        return ["thread_end", "", str(record.thread_id), "", "", ""]
    if isinstance(record, InstructionRecord):
        module = module_lookup.get(record.module_id)
        addr = _format_instruction_addr(record, module)
        info = ""
        if module:
            info = Path(module.path).name
        return ["inst", str(record.sequence), str(record.thread_id), addr, str(record.size), info]
    if isinstance(record, BlockExecRecord):
        block = block_lookup.get(record.block_id)
        addr, size, info = _format_block_info(block, module_lookup)
        return ["block", str(record.sequence), str(record.thread_id), addr, size, info]
    if isinstance(record, RegisterDeltaRecord):
        return [
            "regs",
            str(record.sequence),
            str(record.thread_id),
            "",
            str(len(record.deltas)),
            "",
        ]
    if isinstance(record, MemoryAccessRecord):
        kind = "read" if record.kind == 1 else "write"
        info = kind
        if record.value_known:
            info += f" data={len(record.data)}"
            if record.value_truncated:
                info += " truncated"
        return [
            "mem",
            str(record.sequence),
            str(record.thread_id),
            f"0x{record.address:x}",
            str(record.size),
            info,
        ]
    if isinstance(record, BoundaryRecord):
        info = (
            f"id={record.boundary_id} regs={len(record.registers)} "
            f"stack={len(record.stack_window)} reason={record.reason}"
        )
        return [
            "boundary",
            str(record.sequence),
            str(record.thread_id),
            "",
            "",
            info,
        ]
    return ["unknown", "", "", "", "", ""]


def _format_instruction_addr(record: InstructionRecord, module: Optional[ModuleRecord]) -> str:
    if record.module_id == 0:
        return f"0x{record.module_offset:x}"
    if module is None:
        return f"m{record.module_id}+0x{record.module_offset:x}"
    absolute = module.base + record.module_offset
    return f"0x{absolute:x}"


def _format_block_info(
    block: Optional[BlockDefinitionRecord],
    module_lookup: dict[int, ModuleRecord],
) -> tuple[str, str, str]:
    if block is None:
        return "", "", ""
    module = module_lookup.get(block.module_id)
    if block.module_id == 0:
        addr = f"0x{block.module_offset:x}"
    elif module is None:
        addr = f"m{block.module_id}+0x{block.module_offset:x}"
    else:
        addr = f"0x{module.base + block.module_offset:x}"
    info = Path(module.path).name if module else ""
    return addr, str(block.size), info


if __name__ == "__main__":
    app()
