#!/usr/bin/env python3

from __future__ import annotations

import os
import queue
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class ProcessResult:
    proc: subprocess.Popen[str]
    output_queue: "queue.Queue[str]"
    thread: threading.Thread

    def terminate(self, timeout: float) -> None:
        if self.proc.poll() is not None:
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=timeout)

    def drain_output(self) -> str:
        lines: list[str] = []
        while True:
            try:
                lines.append(self.output_queue.get_nowait())
            except queue.Empty:
                break
        return "".join(lines)


@dataclass
class MemoryDump:
    address: int
    bytes: List[Optional[int]]


@dataclass
class InspectStep:
    seq: int
    addr: int
    kind: str
    regs: Dict[str, int]
    memory: Optional[MemoryDump]


@dataclass
class InspectTrace:
    steps: List[InspectStep]

    def addresses(self) -> List[int]:
        return [step.addr for step in self.steps]


def run_cmd(args: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(args), text=True, capture_output=True, timeout=timeout)


def start_process(args: Sequence[str]) -> ProcessResult:
    proc = subprocess.Popen(
        list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    output_queue: "queue.Queue[str]" = queue.Queue()

    def reader() -> None:
        for line in proc.stdout:
            output_queue.put(line)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    return ProcessResult(proc=proc, output_queue=output_queue, thread=thread)


def wait_for_output_line(
    result: ProcessResult, predicate: Callable[[str], bool], timeout: float
) -> Optional[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result.proc.poll() is not None:
            return None
        try:
            line = result.output_queue.get(timeout=0.1)
        except queue.Empty:
            continue
        if predicate(line):
            return line
    return None


def next_available_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def record_trace(
    w1tool: str,
    trace_path: str,
    configs: Iterable[str],
    sample_path: str,
    timeout: float,
) -> None:
    cmd = [w1tool, "tracer", "-n", "w1rewind", "-s", "-o", trace_path]
    for cfg in configs:
        cmd.extend(["-c", cfg])
    cmd.extend(["--", sample_path])
    result = run_cmd(cmd, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            "trace recording failed: {code}\nstdout:\n{out}\nstderr:\n{err}".format(
                code=result.returncode, out=result.stdout, err=result.stderr
            )
        )


def select_thread_id(w1replay: str, trace_path: str, timeout: float) -> int:
    result = run_cmd([w1replay, "threads", "--trace", trace_path], timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"threads failed: {result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    for line in (result.stdout + result.stderr).splitlines():
        match = re.search(r"thread=(\d+)", line)
        if match:
            return int(match.group(1))
    raise RuntimeError("no thread id found in w1replay threads output")


def run_inspect(
    w1replay: str,
    trace_path: str,
    thread_id: int,
    count: int,
    timeout: float,
    inst: bool = False,
    regs: bool = False,
    mem: Optional[str] = None,
    start: Optional[int] = None,
) -> str:
    cmd = [
        w1replay,
        "inspect",
        "--trace",
        trace_path,
        "--thread",
        str(thread_id),
        "--count",
        str(count),
    ]
    if inst:
        cmd.append("--inst")
    if regs:
        cmd.append("--regs")
    if mem:
        cmd.extend(["--mem", mem])
    if start is not None:
        cmd.extend(["--start", str(start)])
    result = run_cmd(cmd, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            "inspect failed: {code}\nstdout:\n{out}\nstderr:\n{err}".format(
                code=result.returncode, out=result.stdout, err=result.stderr
            )
        )
    return result.stdout + result.stderr


def parse_inspect_output(output: str) -> InspectTrace:
    steps: List[InspectStep] = []
    current: Optional[InspectStep] = None

    step_re = re.compile(
        r"seq=(\d+)\s+addr=(0x[0-9a-fA-F]+)\s+module=(.+?)\s+kind=(\w+)"
    )
    regs_re = re.compile(r"^\s*regs:\s*(.*)$")
    mem_re = re.compile(r"^\s*mem\[(0x[0-9a-fA-F]+):(\d+)\]:\s*(.*)$")

    for line in output.splitlines():
        match = step_re.search(line)
        if match:
            seq = int(match.group(1))
            addr = int(match.group(2), 16)
            kind = match.group(4)
            current = InspectStep(seq=seq, addr=addr, kind=kind, regs={}, memory=None)
            steps.append(current)
            continue
        match = regs_re.search(line)
        if match and current is not None:
            payload = match.group(1)
            if payload and payload not in {"unknown", "unavailable"}:
                for token in payload.split():
                    if "=" not in token:
                        continue
                    name, value = token.split("=", 1)
                    try:
                        current.regs[name] = int(value, 16)
                    except ValueError:
                        continue
            continue
        match = mem_re.search(line)
        if match and current is not None:
            address = int(match.group(1), 16)
            bytes_part = match.group(3).strip()
            parsed: List[Optional[int]] = []
            if bytes_part:
                for token in bytes_part.split():
                    if token == "??":
                        parsed.append(None)
                    else:
                        try:
                            parsed.append(int(token, 16))
                        except ValueError:
                            parsed.append(None)
            current.memory = MemoryDump(address=address, bytes=parsed)
            continue

    return InspectTrace(steps=steps)


def find_first_matching_index(values: List[int], target: int) -> Optional[int]:
    for idx, value in enumerate(values):
        if value == target:
            return idx
    return None


def parse_lldb_register_values(output: str) -> Dict[str, int]:
    reg_re = re.compile(r"^\s*([a-zA-Z0-9_]+)\s*=\s*0x([0-9a-fA-F]+)")
    regs: Dict[str, int] = {}
    for line in output.splitlines():
        match = reg_re.match(line)
        if match:
            regs[match.group(1)] = int(match.group(2), 16)
    return regs


def parse_lldb_pc_values(output: str) -> List[int]:
    pc_re = re.compile(r"^\s*(pc|rip|eip)\s*=\s*0x([0-9a-fA-F]+)")
    pcs: List[int] = []
    for line in output.splitlines():
        match = pc_re.match(line)
        if match:
            pcs.append(int(match.group(2), 16))
    return pcs


def parse_lldb_memory_bytes(output: str, count: int) -> List[int]:
    line_re = re.compile(r"^0x[0-9a-fA-F]+:\s*(.*)$")
    bytes_out: List[int] = []
    for line in output.splitlines():
        match = line_re.match(line.strip())
        if not match:
            continue
        for token in match.group(1).split():
            if len(token) != 2:
                continue
            try:
                bytes_out.append(int(token, 16))
            except ValueError:
                continue
            if len(bytes_out) >= count:
                return bytes_out
    return bytes_out


def run_lldb(
    lldb_path: str, commands: Sequence[str], timeout: float
) -> subprocess.CompletedProcess[str]:
    args = [lldb_path, "--no-lldbinit", "-b"]
    for cmd in commands:
        args.extend(["-o", cmd])
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout)


def resolve_lldb_path(lldb_arg: str) -> Optional[str]:
    return shutil.which(lldb_arg)


def start_server(
    w1replay: str,
    trace_path: str,
    port: int,
    inst: bool,
    timeout: float,
    start: Optional[int] = None,
    thread_id: Optional[int] = None,
    module_mappings: Optional[Sequence[str]] = None,
    module_dirs: Optional[Sequence[str]] = None,
) -> ProcessResult:
    cmd = [w1replay, "server", "--gdb", f"127.0.0.1:{port}", "--trace", trace_path]
    if inst:
        cmd.append("--inst")
    if start is not None:
        cmd.extend(["--start", str(start)])
    if thread_id is not None and thread_id != 0:
        cmd.extend(["--thread", str(thread_id)])
    if module_mappings:
        for mapping in module_mappings:
            cmd.extend(["--module", mapping])
    if module_dirs:
        for directory in module_dirs:
            cmd.extend(["--module-dir", directory])
    result = start_process(cmd)
    line = wait_for_output_line(result, lambda l: "listening" in l, timeout)
    if line is None:
        output = result.drain_output()
        result.terminate(timeout=1.0)
        raise RuntimeError(f"server did not start\noutput:\n{output}")
    return result


def make_temp_trace_path(name: str) -> str:
    return os.path.join(tempfile.gettempdir(), f"w1replay_{name}.trace")


def ensure_binaries_exist(paths: Iterable[str]) -> None:
    missing = [path for path in paths if not os.path.exists(path)]
    if missing:
        raise RuntimeError("missing binaries: " + ", ".join(missing))


def pick_known_registers(regs: Dict[str, int], count: int) -> List[Tuple[str, int]]:
    exclude = {
        "pc",
        "sp",
        "nzcv",
        "cpsr",
        "rflags",
        "eflags",
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "lr",
    }
    general = set()
    for i in range(31):
        general.add(f"x{i}")
    for i in range(13):
        general.add(f"r{i}")
    for i in range(8, 16):
        general.add(f"r{i}")
    general.update(
        {
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
        }
    )
    items = [
        (name, value)
        for name, value in regs.items()
        if name not in exclude and name in general
    ]
    items.sort(key=lambda item: item[0])
    if len(items) >= count:
        return items[:count]
    fallback = [
        (name, value) for name, value in regs.items() if name not in exclude
    ]
    fallback.sort(key=lambda item: item[0])
    return fallback[:count]


def find_stack_pointer(regs: Dict[str, int]) -> Optional[int]:
    for name in ("sp", "rsp", "esp"):
        if name in regs:
            return regs[name]
    return None
