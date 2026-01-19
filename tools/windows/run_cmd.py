#!/usr/bin/env python3
"""
run_cmd.py - thin wrapper to execute a command inside the VS dev shell via run_dev_command.ps1.
"""
import argparse
import os
import subprocess
import sys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run a command inside VS dev shell via run_dev_command.ps1")
    p.add_argument("--vs-path", help="Optional explicit VS install path (defaults to vswhere lookup)")
    p.add_argument("--devcmd-args", default="-arch=amd64", help="Arguments passed to Enter-VsDevShell (default: -arch=amd64)")
    p.add_argument(
        "--no-cmd",
        action="store_true",
        help="Run via PowerShell Invoke-Expression instead of cmd /c (default uses cmd /c)",
    )
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (after --)")
    return p


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

    ps_args = [
        "powershell",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
        "-DevCmdArgs",
        args.devcmd_args,
    ]
    if args.vs_path:
        ps_args.extend(["-VsPath", args.vs_path])
    if args.no_cmd:
        ps_args.append("-UseCmd:$false")
    else:
        ps_args.append("-UseCmd")
    ps_args.extend(["-Command", command_str])

    proc = subprocess.run(ps_args)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
