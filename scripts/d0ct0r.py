#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#   "typer>=0.15.0",
#   "rich>=13.0.0",
#   "sh>=2.2.0",
# ]
# ///

import os
import sys
import platform
import stat
import subprocess
import shutil
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.logging import RichHandler
import logging

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

APP_NAME = "d0ct0r"
app = typer.Typer(
    name=APP_NAME,
    help=f"{APP_NAME}: intelligent p1llx wrapper with backup management and codesigning",
    no_args_is_help=True,
    context_settings=CONTEXT_SETTINGS,
    pretty_exceptions_short=True,
    pretty_exceptions_show_locals=False,
)

console = Console()

# global state for sudo and verbosity
global_sudo = False
global_verbose = 0


class BinaryFormat:
    """binary format detection utilities"""

    # magic numbers for different binary formats
    MACH_O_MAGIC = {
        0xFEEDFACE: "mach-o 32-bit",
        0xFEEDFACF: "mach-o 64-bit",
        0xCAFEBABE: "mach-o fat binary",
        0xCFFAEDFE: "mach-o 64-bit (reverse)",
        0xCEFAEDFE: "mach-o 32-bit (reverse)",
    }

    ELF_MAGIC = 0x7F454C46  # \x7fELF
    PE_MAGIC = 0x5A4D  # MZ

    @staticmethod
    def detect_format(file_path: Path) -> Tuple[str, bool]:
        """
        detect binary format from magic numbers
        returns (format_name, is_macho)
        """
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if len(magic) < 4:
                    return "unknown", False

                magic_int = int.from_bytes(magic, byteorder="little")

                # check mach-o formats
                if magic_int in BinaryFormat.MACH_O_MAGIC:
                    return BinaryFormat.MACH_O_MAGIC[magic_int], True

                # check big-endian mach-o
                magic_int_be = int.from_bytes(magic, byteorder="big")
                if magic_int_be in BinaryFormat.MACH_O_MAGIC:
                    return BinaryFormat.MACH_O_MAGIC[magic_int_be], True

                # check elf
                if magic_int == BinaryFormat.ELF_MAGIC:
                    return "elf", False

                # check pe
                if magic_int & 0xFFFF == BinaryFormat.PE_MAGIC:
                    return "pe/coff", False

                return "unknown", False

        except Exception as e:
            console.print(f"[red]error detecting format: {e}[/red]")
            return "unknown", False


class FileOperations:
    """cross-platform file operations with elevation support"""

    @staticmethod
    def copy_file(src: Path, dst: Path, use_elevation: bool = False) -> bool:
        """cross-platform file copy with optional elevation"""
        console.print(f"[cyan]copying: {src} -> {dst}[/cyan]")

        # try normal copy first (unless explicitly told to use elevation)
        if not use_elevation:
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                console.print(f"[green]✓ copied successfully[/green]")
                return True
            except PermissionError:
                if platform.system() == "Windows":
                    console.print(
                        "[red]permission denied - please run as administrator[/red]"
                    )
                    return False
                else:
                    console.print(
                        "[yellow]permission denied - retrying with sudo[/yellow]"
                    )
                    # fall through to elevated copy below
            except Exception as e:
                console.print(f"[red]copy failed: {e}[/red]")
                return False

        # elevated copy (either requested explicitly or after permission error)
        if platform.system() == "Windows":
            console.print(
                "[red]windows elevation required - please run as administrator[/red]"
            )
            return False
        else:
            # unix-like: use sudo cp with preserve attributes
            # first ensure destination directory exists with sudo
            dst_dir = dst.parent
            if not dst_dir.exists():
                mkdir_cmd = ["sudo", "mkdir", "-p", str(dst_dir)]
                try:
                    mkdir_result = subprocess.run(
                        mkdir_cmd, capture_output=True, text=True
                    )
                    if mkdir_result.returncode != 0:
                        console.print(
                            f"[red]failed to create directory with sudo: {mkdir_result.stderr}[/red]"
                        )
                        return False
                except Exception as e:
                    console.print(f"[red]sudo mkdir error: {e}[/red]")
                    return False

            # now copy with sudo
            cmd = ["sudo", "cp", "-p", str(src), str(dst)]
            try:
                console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    console.print(f"[green]✓ copied with sudo[/green]")
                    return True
                else:
                    console.print(f"[red]sudo copy failed: {result.stderr}[/red]")
                    return False
            except Exception as e:
                console.print(f"[red]sudo copy error: {e}[/red]")
                return False

    @staticmethod
    def set_permissions(
        file_path: Path, permissions: int, use_elevation: bool = False
    ) -> bool:
        """cross-platform permission setting with optional elevation"""
        # try normal chmod first (unless explicitly told to use elevation)
        if not use_elevation:
            try:
                file_path.chmod(permissions)
                console.print(
                    f"[green]✓ restored permissions: {oct(permissions)}[/green]"
                )
                return True
            except PermissionError:
                if platform.system() == "Windows":
                    console.print(
                        "[yellow]windows permission model differs - skipping[/yellow]"
                    )
                    return True  # windows permission model is different
                else:
                    console.print(
                        "[yellow]permission denied - retrying with sudo[/yellow]"
                    )
                    # fall through to elevated chmod below
            except Exception as e:
                console.print(f"[red]permission setting failed: {e}[/red]")
                return False

        # elevated chmod (either requested explicitly or after permission error)
        if platform.system() == "Windows":
            console.print(
                "[yellow]windows elevation for permissions not implemented[/yellow]"
            )
            return True  # windows permission model is different
        else:
            cmd = ["sudo", "chmod", oct(permissions)[2:], str(file_path)]
            try:
                console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    console.print(
                        f"[green]✓ restored permissions with sudo: {oct(permissions)}[/green]"
                    )
                    return True
                else:
                    console.print(f"[red]sudo chmod failed: {result.stderr}[/red]")
                    return False
            except Exception as e:
                console.print(f"[red]sudo chmod error: {e}[/red]")
                return False


class BackupManager:
    """smart backup management for d0ct0r operations"""

    @staticmethod
    def get_backup_path(file_path: Path) -> Path:
        """get the backup path for a given file"""
        return file_path.with_suffix(file_path.suffix + ".d0ct0r.bak")

    @staticmethod
    def create_backup(
        file_path: Path, force: bool = False, use_elevation: bool = False
    ) -> Path:
        """
        create a backup of the file if it doesn't exist
        returns the backup path
        """
        backup_path = BackupManager.get_backup_path(file_path)

        if backup_path.exists() and not force:
            console.print(f"[yellow]using existing backup: {backup_path.name}[/yellow]")
            return backup_path

        if not file_path.exists():
            raise FileNotFoundError(f"source file not found: {file_path}")

        console.print(
            f"[blue]creating backup: {file_path.name} -> {backup_path.name}[/blue]"
        )

        if not FileOperations.copy_file(file_path, backup_path, use_elevation):
            raise RuntimeError(f"failed to create backup: {backup_path}")

        return backup_path

    @staticmethod
    def should_use_backup(input_path: Path, output_path: Optional[Path] = None) -> bool:
        """
        determine if we should use backup-based workflow
        """
        if output_path is None:
            # in-place modification, definitely use backup
            return True

        if input_path.resolve() == output_path.resolve():
            # same file, use backup
            return True

        return False


class PermissionManager:
    """permission preservation utilities"""

    @staticmethod
    def get_permissions(file_path: Path) -> int:
        """get file permissions"""
        return stat.S_IMODE(file_path.stat().st_mode)

    @staticmethod
    def set_permissions(
        file_path: Path, permissions: int, use_elevation: bool = False
    ) -> bool:
        """set file permissions using file operations"""
        return FileOperations.set_permissions(file_path, permissions, use_elevation)


class CodesignManager:
    """macos codesigning utilities"""

    @staticmethod
    def should_codesign(file_path: Path) -> bool:
        """
        determine if file should be codesigned based on platform and format
        """
        if platform.system() != "Darwin":
            return False

        format_name, is_macho = BinaryFormat.detect_format(file_path)
        return is_macho

    @staticmethod
    def codesign(file_path: Path, sudo: bool = False) -> bool:
        """
        codesign a file with ad-hoc signature
        """
        if not CodesignManager.should_codesign(file_path):
            return True

        cmd = ["codesign", "-fs", "-", str(file_path)]
        if sudo:
            cmd = ["sudo"] + cmd

        try:
            console.print(f"[blue]codesigning: {file_path.name}[/blue]")
            console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                console.print(f"[green]✓ codesigned successfully[/green]")
                return True
            else:
                console.print(f"[red]codesigning failed: {result.stderr}[/red]")
                return False

        except Exception as e:
            console.print(f"[red]codesigning error: {e}[/red]")
            return False


class P1llxRunner:
    """p1llx command execution utilities"""

    @staticmethod
    def find_p1llx() -> Path:
        """find the p1llx executable"""
        script_dir = Path(__file__).parent
        p1llx_path = script_dir.parent / "build-release" / "p1llx"

        if not p1llx_path.exists():
            raise FileNotFoundError(f"p1llx not found at {p1llx_path}")

        return p1llx_path

    @staticmethod
    def run_p1llx(cmd_args: List[str], sudo: bool = False) -> bool:
        """
        run p1llx with given arguments
        """
        p1llx_path = P1llxRunner.find_p1llx()
        cmd = [str(p1llx_path)] + cmd_args

        if sudo:
            cmd = ["sudo"] + cmd

        try:
            console.print(f"[dim]$ {' '.join(cmd)}[/dim]")
            result = subprocess.run(cmd, text=True)

            if result.returncode == 0:
                console.print(f"[green]✓ p1llx completed successfully[/green]")
                return True
            else:
                console.print(
                    f"[red]p1llx failed with exit code: {result.returncode}[/red]"
                )
                return False

        except Exception as e:
            console.print(f"[red]p1llx execution error: {e}[/red]")
            return False


def setup_logging(verbose: int = 0):
    """setup logging based on verbosity level"""
    levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbose, len(levels) - 1)]

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@app.callback()
def main_callback(
    sudo: bool = typer.Option(False, "--sudo", help="run p1llx commands with sudo"),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="increase verbosity"
    ),
):
    """global options for d0ct0r"""
    global global_sudo, global_verbose
    global_sudo = sudo
    global_verbose = verbose

    setup_logging(verbose)

    if verbose > 0:
        console.print(f"[dim]verbose level: {verbose}[/dim]")
    if sudo:
        console.print(f"[dim]sudo mode enabled[/dim]")


@app.command()
def auto_cure(
    cure_script: str = typer.Option(..., "-c", "--cure", help="lua cure script path"),
    input_file: str = typer.Option(..., "-i", "--input", help="input file path"),
    output_file: Optional[str] = typer.Option(
        None, "-o", "--output", help="output file path"
    ),
    platform_override: Optional[str] = typer.Option(
        None, "-p", "--platform", help="platform override (e.g., darwin:arm64)"
    ),
    no_backup: bool = typer.Option(
        False, "--no-backup", help="disable backup creation"
    ),
):
    """
    smart wrapper for p1llx cure with automatic backup management and codesigning
    """
    setup_logging(global_verbose)

    input_path = Path(input_file)
    output_path = Path(output_file) if output_file else None

    console.print(
        Panel(
            f"[bold]d0ct0r auto-cure[/bold]\n"
            f"input: {input_path.name}\n"
            f"output: {output_path.name if output_path else 'in-place'}\n"
            f"script: {Path(cure_script).name}"
        )
    )

    # validate input file exists
    if not input_path.exists():
        console.print(f"[red]input file not found: {input_path}[/red]")
        raise typer.Exit(1)

    # prevent same input/output
    if output_path and input_path.resolve() == output_path.resolve():
        console.print(f"[red]input and output cannot be the same file[/red]")
        raise typer.Exit(1)

    # detect binary format
    format_name, is_macho = BinaryFormat.detect_format(input_path)
    console.print(f"[cyan]detected format: {format_name}[/cyan]")

    # preserve original permissions
    original_permissions = PermissionManager.get_permissions(input_path)

    # handle backup workflow
    if not no_backup and BackupManager.should_use_backup(input_path, output_path):
        backup_path = BackupManager.create_backup(
            input_path, force=False, use_elevation=global_sudo
        )
        actual_input = backup_path
    else:
        actual_input = input_path

    # build p1llx command
    cmd_args = ["cure", "-c", cure_script, "-i", str(actual_input)]

    # determine target file and ensure we don't modify backup in-place
    # critical: p1llx modifies input file when no -o is specified!
    # we must always specify -o when using backup to preserve backup integrity
    if output_path:
        cmd_args.extend(["-o", str(output_path)])
        target_file = output_path
    else:
        # in-place modification: always specify output to avoid corrupting backup
        if actual_input != input_path:  # we're using a backup
            cmd_args.extend(
                ["-o", str(input_path)]
            )  # output to original file, preserve backup
            target_file = input_path
        else:
            # no backup workflow, p1llx can modify in-place safely
            target_file = input_path

    if platform_override:
        cmd_args.extend(["-p", platform_override])

    # add verbosity to p1llx
    if global_verbose > 0:
        cmd_args.append("-" + "v" * global_verbose)

    # run p1llx
    if not P1llxRunner.run_p1llx(cmd_args, global_sudo):
        raise typer.Exit(1)

    # codesign if needed
    if not CodesignManager.codesign(target_file, global_sudo):
        console.print(f"[yellow]warning: codesigning failed[/yellow]")

    # restore permissions
    if not PermissionManager.set_permissions(
        target_file, original_permissions, global_sudo
    ):
        console.print(f"[yellow]warning: could not restore permissions[/yellow]")

    console.print(f"[green]✓ auto-cure completed successfully[/green]")


@app.command()
def cure(
    cure_script: str = typer.Option(..., "-c", "--cure", help="lua cure script path"),
    input_file: str = typer.Option(..., "-i", "--input", help="input file path"),
    output_file: Optional[str] = typer.Option(
        None, "-o", "--output", help="output file path"
    ),
    platform_override: Optional[str] = typer.Option(
        None, "-p", "--platform", help="platform override"
    ),
):
    """
    pass-through to p1llx cure with optional enhancements
    """
    cmd_args = ["cure", "-c", cure_script, "-i", input_file]

    if output_file:
        cmd_args.extend(["-o", output_file])

    if platform_override:
        cmd_args.extend(["-p", platform_override])

    if global_verbose > 0:
        cmd_args.append("-" + "v" * global_verbose)

    if not P1llxRunner.run_p1llx(cmd_args, global_sudo):
        raise typer.Exit(1)


@app.command()
def patch(
    address: str = typer.Option(..., "--address", help="address to patch (hex)"),
    replace: str = typer.Option(..., "--replace", help="replacement hex bytes"),
    input_file: str = typer.Option(..., "-i", "--input", help="input file path"),
    output_file: Optional[str] = typer.Option(
        None, "-o", "--output", help="output file path"
    ),
):
    """
    pass-through to p1llx patch
    """
    cmd_args = [
        "patch",
        f"--address={address}",
        f"--replace={replace}",
        "-i",
        input_file,
    ]

    if output_file:
        cmd_args.extend(["-o", output_file])

    if global_verbose > 0:
        cmd_args.append("-" + "v" * global_verbose)

    if not P1llxRunner.run_p1llx(cmd_args, global_sudo):
        raise typer.Exit(1)


@app.command()
def poison(
    cure_script: str = typer.Option(..., "-c", "--cure", help="lua cure script path"),
    spawn: bool = typer.Option(False, "-s", "--spawn", help="spawn target binary"),
    pid: Optional[int] = typer.Option(None, "--pid", help="target process pid"),
    process_name: Optional[str] = typer.Option(
        None, "--process-name", help="target process name"
    ),
    suspended: bool = typer.Option(
        False, "--suspended", help="start in suspended mode"
    ),
    args: Optional[List[str]] = typer.Argument(
        None, help="target binary and arguments"
    ),
):
    """
    pass-through to p1llx poison for dynamic patching
    """
    cmd_args = ["poison", "-c", cure_script]

    # target specification
    if spawn:
        cmd_args.append("-s")
    elif pid:
        cmd_args.extend(["--pid", str(pid)])
    elif process_name:
        cmd_args.extend(["--process-name", process_name])
    else:
        console.print(
            "[red]must specify target: --spawn, --pid, or --process-name[/red]"
        )
        raise typer.Exit(1)

    if suspended:
        cmd_args.append("--suspended")

    if global_verbose > 0:
        cmd_args.append("-" + "v" * global_verbose)

    if args:
        cmd_args.extend(args)

    if not P1llxRunner.run_p1llx(cmd_args, global_sudo):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
