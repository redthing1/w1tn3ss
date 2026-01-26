#!/usr/bin/env python3

from __future__ import annotations

import json
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
    sample_path = resolve_executable_path(sample_path)
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
    json_output: bool = True,
    image_mappings: Optional[Sequence[str]] = None,
    image_dirs: Optional[Sequence[str]] = None,
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
    if json_output:
        cmd.append("--json")
    if image_mappings:
        for mapping in image_mappings:
            cmd.extend(["--image", mapping])
    if image_dirs:
        for directory in image_dirs:
            cmd.extend(["--image-dir", directory])
    result = run_cmd(cmd, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            "inspect failed: {code}\nstdout:\n{out}\nstderr:\n{err}".format(
                code=result.returncode, out=result.stdout, err=result.stderr
            )
        )
    return result.stdout + result.stderr


def parse_inspect_output(output: str) -> InspectTrace:
    trimmed = output.strip()
    start = trimmed.find("{")
    end = trimmed.rfind("}")
    if start != -1 and end != -1 and end > start:
        payload = trimmed[start : end + 1]
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict) and "steps" in data:
            steps: List[InspectStep] = []
            for step in data.get("steps", []):
                try:
                    seq = int(step.get("seq", 0))
                except (TypeError, ValueError):
                    seq = 0
                addr_raw = step.get("addr", "0x0")
                try:
                    addr = int(addr_raw, 0)
                except (TypeError, ValueError):
                    addr = 0
                kind = str(step.get("kind", ""))
                regs: Dict[str, int] = {}
                for name, value in (step.get("regs") or {}).items():
                    if not isinstance(value, str):
                        continue
                    try:
                        regs[name] = int(value, 0)
                    except ValueError:
                        continue
                mem_dump = None
                mem = step.get("mem")
                if isinstance(mem, dict):
                    addr_text = mem.get("addr", "0x0")
                    try:
                        mem_addr = int(addr_text, 0)
                    except (TypeError, ValueError):
                        mem_addr = 0
                    parsed: List[Optional[int]] = []
                    for entry in mem.get("bytes", []) or []:
                        if entry is None:
                            parsed.append(None)
                        elif isinstance(entry, str):
                            try:
                                parsed.append(int(entry, 16))
                            except ValueError:
                                parsed.append(None)
                    mem_dump = MemoryDump(address=mem_addr, bytes=parsed)
                steps.append(InspectStep(seq=seq, addr=addr, kind=kind, regs=regs, memory=mem_dump))
            return InspectTrace(steps=steps)

    steps = []
    current: Optional[InspectStep] = None

    seq_re = re.compile(r"\bseq=(\d+)\b")
    addr_re = re.compile(r"\baddr=(0x[0-9a-fA-F]+)\b")
    kind_re = re.compile(r"\bkind=(\w+)\b")
    regs_re = re.compile(r"^\s*regs:\s*(.*)$")
    mem_re = re.compile(r"^\s*mem\[(0x[0-9a-fA-F]+):(\d+)\]:\s*(.*)$")

    for line in output.splitlines():
        seq_match = seq_re.search(line)
        addr_match = addr_re.search(line)
        kind_match = kind_re.search(line)
        if seq_match and addr_match and kind_match:
            seq = int(seq_match.group(1))
            addr = int(addr_match.group(1), 16)
            kind = kind_match.group(1)
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
            parsed = []
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


def lldb_connect_commands(sample_path: str, host: str, port: int) -> List[str]:
    return [
        f"target create {sample_path}",
        f"process connect --plugin gdb-remote connect://{host}:{port}",
    ]


def resolve_executable_path(path: str) -> str:
    if os.name != "nt":
        return path
    root, ext = os.path.splitext(path)
    if ext:
        return path
    candidate = path + ".exe"
    if os.path.exists(candidate):
        return candidate
    return path


def start_server(
    w1replay: str,
    trace_path: str,
    port: int,
    inst: bool,
    timeout: float,
    start: Optional[int] = None,
    thread_id: Optional[int] = None,
    image_mappings: Optional[Sequence[str]] = None,
    image_dirs: Optional[Sequence[str]] = None,
) -> ProcessResult:
    cmd = [w1replay, "server", "--gdb", f"127.0.0.1:{port}", "--trace", trace_path]
    if inst:
        cmd.append("--inst")
    if start is not None:
        cmd.extend(["--start", str(start)])
    if thread_id is not None and thread_id != 0:
        cmd.extend(["--thread", str(thread_id)])
    if image_mappings:
        for mapping in image_mappings:
            cmd.extend(["--image", mapping])
    if image_dirs:
        for directory in image_dirs:
            cmd.extend(["--image-dir", directory])
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
