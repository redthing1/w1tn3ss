#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "typer",
#     "rich",
# ]
# ///

"""w1rewind trace viewer"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

import typer
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer(add_completion=False, no_args_is_help=True)

MAGIC = b"W1RWND\n\x00"
HEADER_STRUCT = struct.Struct("<8sIIII")
EVENT_HEADER_STRUCT = struct.Struct("<BQQQI")
REGISTER_NAME_LEN_STRUCT = struct.Struct("<H")
REGISTER_VALUE_STRUCT = struct.Struct("<Q")
MEMORY_RECORD_HEADER_STRUCT = struct.Struct("<QI")
BOOL_STRUCT = struct.Struct("<B")
COUNT_STRUCT = struct.Struct("<I")


@dataclass
class RegisterDelta:
    name: str
    value: int


@dataclass
class MemoryAccess:
    address: int
    size: int
    value_known: bool
    data: bytes = field(default_factory=bytes)


@dataclass
class BoundaryInfo:
    boundary_id: int
    flags: int
    reason: str


@dataclass
class TraceEvent:
    event_type: int
    thread_id: int
    sequence: int
    address: int
    size: int
    registers: List[RegisterDelta] = field(default_factory=list)
    reads: List[MemoryAccess] = field(default_factory=list)
    writes: List[MemoryAccess] = field(default_factory=list)
    boundary: Optional[BoundaryInfo] = None


@dataclass
class TraceFile:
    version: int
    flags: int
    architecture: int
    events: List[TraceEvent]

    def per_thread_counts(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for event in self.events:
            counts[event.thread_id] = counts.get(event.thread_id, 0) + 1
        return counts


class TraceParserError(RuntimeError):
    pass


class TraceParser:
    def __init__(self, data: bytes) -> None:
        self._data = memoryview(data)
        self._cursor = 0

    def parse(self) -> TraceFile:
        magic, version, flags, arch, _reserved = HEADER_STRUCT.unpack_from(
            self._data, self._cursor
        )
        self._cursor += HEADER_STRUCT.size
        if magic != MAGIC:
            raise TraceParserError(f"unexpected magic {magic!r}; not a w1rewind trace")
        if version != 3:
            raise TraceParserError(f"unsupported trace version {version} (expected v3)")

        events: List[TraceEvent] = []
        while self._cursor < len(self._data):
            event = self._parse_event()
            events.append(event)

        return TraceFile(version=version, flags=flags, architecture=arch, events=events)

    def _parse_event(self) -> TraceEvent:
        start = self._cursor
        try:
            event_type, thread_id, sequence, address, size = (
                EVENT_HEADER_STRUCT.unpack_from(self._data, self._cursor)
            )
            self._cursor += EVENT_HEADER_STRUCT.size
        except struct.error as exc:
            raise TraceParserError(f"truncated event header at offset {start}") from exc

        if event_type not in (1, 2):
            raise TraceParserError(
                f"unsupported event type {event_type} at offset {start}"
            )

        registers = self._parse_registers()
        reads: List[MemoryAccess] = self._parse_memory_list()
        writes = self._parse_memory_list()

        boundary_info: Optional[BoundaryInfo] = None
        try:
            has_boundary = BOOL_STRUCT.unpack_from(self._data, self._cursor)[0] != 0
            self._cursor += BOOL_STRUCT.size
        except struct.error as exc:
            raise TraceParserError("truncated boundary flag") from exc

        if has_boundary:
            try:
                boundary_id = REGISTER_VALUE_STRUCT.unpack_from(
                    self._data, self._cursor
                )[0]
                self._cursor += REGISTER_VALUE_STRUCT.size
                flags = COUNT_STRUCT.unpack_from(self._data, self._cursor)[0]
                self._cursor += COUNT_STRUCT.size
                reason_len = REGISTER_NAME_LEN_STRUCT.unpack_from(
                    self._data, self._cursor
                )[0]
                self._cursor += REGISTER_NAME_LEN_STRUCT.size
                reason_bytes = bytes(
                    self._data[self._cursor : self._cursor + reason_len]
                )
                self._cursor += reason_len
            except struct.error as exc:
                raise TraceParserError("truncated boundary metadata") from exc

            boundary_info = BoundaryInfo(
                boundary_id=boundary_id,
                flags=flags,
                reason=reason_bytes.decode("ascii"),
            )

        return TraceEvent(
            event_type=event_type,
            thread_id=thread_id,
            sequence=sequence,
            address=address,
            size=size,
            registers=registers,
            reads=reads,
            writes=writes,
            boundary=boundary_info,
        )

    def _parse_registers(self) -> List[RegisterDelta]:
        try:
            reg_count = COUNT_STRUCT.unpack_from(self._data, self._cursor)[0]
            self._cursor += COUNT_STRUCT.size
        except struct.error as exc:
            raise TraceParserError("truncated register count") from exc

        registers: List[RegisterDelta] = []
        for _ in range(reg_count):
            name_len = REGISTER_NAME_LEN_STRUCT.unpack_from(self._data, self._cursor)[0]
            self._cursor += REGISTER_NAME_LEN_STRUCT.size
            name_bytes = bytes(self._data[self._cursor : self._cursor + name_len])
            self._cursor += name_len
            value = REGISTER_VALUE_STRUCT.unpack_from(self._data, self._cursor)[0]
            self._cursor += REGISTER_VALUE_STRUCT.size
            registers.append(
                RegisterDelta(name=name_bytes.decode("ascii"), value=value)
            )
        return registers

    def _parse_memory_list(self) -> List[MemoryAccess]:
        try:
            count = COUNT_STRUCT.unpack_from(self._data, self._cursor)[0]
            self._cursor += COUNT_STRUCT.size
        except struct.error as exc:
            raise TraceParserError("truncated memory access count") from exc

        accesses: List[MemoryAccess] = []
        for _ in range(count):
            try:
                address, size = MEMORY_RECORD_HEADER_STRUCT.unpack_from(
                    self._data, self._cursor
                )
                self._cursor += MEMORY_RECORD_HEADER_STRUCT.size
                value_known = BOOL_STRUCT.unpack_from(self._data, self._cursor)[0] != 0
                self._cursor += BOOL_STRUCT.size
                data_len = COUNT_STRUCT.unpack_from(self._data, self._cursor)[0]
                self._cursor += COUNT_STRUCT.size
            except struct.error as exc:
                raise TraceParserError("truncated memory access header") from exc

            data = bytes(self._data[self._cursor : self._cursor + data_len])
            self._cursor += data_len
            accesses.append(
                MemoryAccess(
                    address=address, size=size, value_known=value_known, data=data
                )
            )
        return accesses


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


@app.command()
def summary(
    trace_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a w1rewind trace file"
    ),
) -> None:
    """Print a high-level overview of the trace."""
    trace = load_trace(trace_path)

    console.print(f"[bold]trace[/] {trace_path}")
    console.print(f"  version     : {trace.version}")
    console.print(f"  architecture: {format_architecture(trace.architecture)}")
    console.print(f"  events      : {len(trace.events)}")
    inst_events = sum(1 for e in trace.events if e.event_type == 1)
    boundary_events = sum(1 for e in trace.events if e.event_type == 2)
    console.print(f"  instructions : {inst_events}")
    console.print(f"  boundaries   : {boundary_events}")

    thread_counts = trace.per_thread_counts()
    table = Table(title="Events per thread", show_lines=False)
    table.add_column("thread id", justify="right")
    table.add_column("events", justify="right")
    for thread_id, count in sorted(thread_counts.items()):
        table.add_row(str(thread_id), str(count))
    console.print(table)

    total_regs = sum(len(e.registers) for e in trace.events if e.event_type == 1)
    boundary_regs = sum(len(e.registers) for e in trace.events if e.event_type == 2)
    total_reads = sum(len(e.reads) for e in trace.events)
    total_writes = sum(len(e.writes) for e in trace.events)
    console.print(f"  register deltas: {total_regs}")
    if boundary_regs:
        console.print(f"  boundary regs  : {boundary_regs}")
    console.print(f"  memory reads   : {total_reads}")
    console.print(f"  memory writes  : {total_writes}")


def _iter_events(
    trace: TraceFile,
    *,
    thread_id: Optional[int] = None,
    limit: Optional[int] = None,
) -> Iterable[TraceEvent]:
    count = 0
    for event in trace.events:
        if thread_id is not None and event.thread_id != thread_id:
            continue
        yield event
        count += 1
        if limit is not None and count >= limit:
            break


@app.command()
def events(
    trace_path: Path = typer.Argument(
        ..., exists=True, readable=True, help="Path to a w1rewind trace file"
    ),
    thread_id: Optional[int] = typer.Option(
        None, help="Limit output to a specific thread id"
    ),
    limit: Optional[int] = typer.Option(10, help="Maximum number of events to display"),
    show_reads: bool = typer.Option(False, help="Show memory reads for each event"),
    show_writes: bool = typer.Option(True, help="Show memory writes for each event"),
) -> None:
    """Pretty-print trace events."""
    trace = load_trace(trace_path)
    events = list(_iter_events(trace, thread_id=thread_id, limit=limit))
    if not events:
        console.print("[yellow]no events matched filters[/]")
        return

    table = Table(title=f"Events ({len(events)} displayed)")
    table.add_column("type", justify="left")
    table.add_column("seq", justify="right")
    table.add_column("thread", justify="right")
    table.add_column("addr", justify="right")
    table.add_column("size", justify="right")
    table.add_column("regs", justify="right")
    table.add_column("reads", justify="right")
    table.add_column("writes", justify="right")
    table.add_column("info", justify="left")

    for event in events:
        event_type = "inst" if event.event_type == 1 else "boundary"
        info = ""
        if event.boundary is not None:
            info = f"id={event.boundary.boundary_id} reason={event.boundary.reason}"
        table.add_row(
            event_type,
            str(event.sequence),
            str(event.thread_id),
            f"0x{event.address:x}",
            str(event.size),
            str(len(event.registers)),
            str(len(event.reads)),
            str(len(event.writes)),
            info,
        )
    console.print(table)

    if show_reads:
        _print_memory_section(events, label="Reads", accessor=lambda e: e.reads)
    if show_writes:
        _print_memory_section(events, label="Writes", accessor=lambda e: e.writes)


def _print_memory_section(
    events: Iterable[TraceEvent],
    *,
    label: str,
    accessor,
) -> None:
    for event in events:
        accesses = accessor(event)
        if not accesses:
            continue
        console.print(
            f"[bold]{label.lower()}[/] event seq={event.sequence} thread={event.thread_id}"
        )
        table = Table(show_header=True)
        table.add_column("address", justify="right")
        table.add_column("size", justify="right")
        table.add_column("known", justify="right")
        table.add_column("data", justify="left")
        for entry in accesses:
            data_preview = entry.data.hex()[:32] + ("…" if len(entry.data) > 16 else "")
            table.add_row(
                f"0x{entry.address:x}",
                str(entry.size),
                "yes" if entry.value_known else "no",
                data_preview,
            )
        console.print(table)


if __name__ == "__main__":
    app()
