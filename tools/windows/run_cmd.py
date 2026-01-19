#!/usr/bin/env python3
"""
run_cmd.py: execute a command inside the VS dev shell.
"""
import argparse
import os
import subprocess
import sys
from typing import Iterable, Optional


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Run a command inside VS dev shell via run_dev_command.ps1"
    )
    p.add_argument(
        "--vs-path",
        help="Optional explicit VS install path (defaults to vswhere lookup)",
    )
    p.add_argument(
        "--devcmd-args",
        default=None,
        help="Arguments passed to Enter-VsDevShell (overrides --arch/--host-arch)",
    )
    p.add_argument(
        "--arch",
        choices=["x86", "x64", "amd64", "arm", "arm64"],
        help="Target architecture for DevShell (default: amd64)",
    )
    p.add_argument(
        "--host-arch",
        choices=["x86", "x64", "amd64", "arm", "arm64"],
        help="Host architecture for DevShell (optional)",
    )
    p.add_argument(
        "--no-cmd",
        action="store_true",
        help="Run via PowerShell Invoke-Expression instead of cmd /c (default uses cmd /c)",
    )
    p.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set an environment variable for the command (may be repeated)",
    )
    p.add_argument(
        "--prepend-path",
        action="append",
        default=[],
        metavar="PATH",
        help="Prepend entries to PATH for the command (may be repeated)",
    )
    p.add_argument(
        "--append-path",
        action="append",
        default=[],
        metavar="PATH",
        help="Append entries to PATH for the command (may be repeated)",
    )
    p.add_argument("--cwd", help="Working directory to run the command in")
    p.add_argument(
        "--print-command",
        action="store_true",
        help="Print the resolved command and DevShell args before running",
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (after --)")
    return p


def normalize_arch(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    mapping = {
        "x64": "amd64",
        "amd64": "amd64",
        "x86": "x86",
        "arm": "arm",
        "arm64": "arm64",
    }
    return mapping.get(value, value)


def build_devcmd_args(args: argparse.Namespace) -> str:
    if args.devcmd_args is not None:
        return args.devcmd_args
    arch = normalize_arch(args.arch) or "amd64"
    parts = [f"-arch={arch}"]
    host_arch = normalize_arch(args.host_arch)
    if host_arch:
        parts.append(f"-host_arch={host_arch}")
    return " ".join(parts)


def extend_ps_args(ps_args: list[str], flag: str, values: Iterable[str]) -> None:
    for value in values:
        ps_args.extend([flag, value])


def main(argv: list[str]) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.cmd:
        ap.error("Please provide a command to run (after --)")

    # If the user included a leading "--", drop it
    cmd_tokens = args.cmd
    if cmd_tokens and cmd_tokens[0] == "--":
        cmd_tokens = cmd_tokens[1:]
    if not cmd_tokens:
        ap.error("Please provide a command to run (after --)")

    # Build a single command string using Windows list2cmdline for correct quoting under cmd.exe
    command_str = subprocess.list2cmdline(cmd_tokens)

    script_path = os.path.join(os.path.dirname(__file__), "run_dev_command.ps1")
    if not os.path.exists(script_path):
        print(f"error: run_dev_command.ps1 not found at {script_path}", file=sys.stderr)
        return 1

    devcmd_args = build_devcmd_args(args)

    ps_args = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
        "-DevCmdArgs",
        devcmd_args,
    ]
    if args.vs_path:
        ps_args.extend(["-VsPath", args.vs_path])
    if args.no_cmd:
        ps_args.append("-UseCmd:$false")
    else:
        ps_args.append("-UseCmd")
    if args.cwd:
        ps_args.extend(["-WorkingDirectory", args.cwd])
    extend_ps_args(ps_args, "-Env", args.env)
    extend_ps_args(ps_args, "-PrependPath", args.prepend_path)
    extend_ps_args(ps_args, "-AppendPath", args.append_path)
    ps_args.extend(["-Command", command_str])

    if args.print_command:
        print("DevShell args:", devcmd_args)
        print("Command:", command_str)

    proc = subprocess.run(ps_args)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
