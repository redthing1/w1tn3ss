#!/usr/bin/env python3

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT_MARKERS = (".git", "CMakeLists.txt", "pyproject.toml")


def _find_root(start: Path) -> Path | None:
    for parent in (start, *start.parents):
        for marker in ROOT_MARKERS:
            if (parent / marker).exists():
                return parent
    return None


def _has_flag(flag: str) -> bool:
    for arg in sys.argv[1:]:
        if arg == flag or arg.startswith(f"{flag}="):
            return True
    return False


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    repo_root = _find_root(script_dir)
    if repo_root is None:
        print("error: unable to locate repo root (use WINCROSS_ROOT)", file=sys.stderr)
        raise SystemExit(1)

    wincross_bin = repo_root / "tools" / "wincross" / "bin" / "wincross"
    if not wincross_bin.exists():
        print(f"error: wincross driver not found at {wincross_bin}", file=sys.stderr)
        raise SystemExit(1)

    env = os.environ.copy()
    default_config = repo_root / "tools" / "wincross-config" / "wincross.toml"
    if (
        default_config.exists()
        and not _has_flag("--project-config")
        and not env.get("WINCROSS_PROJECT_CONFIG")
    ):
        env["WINCROSS_PROJECT_CONFIG"] = str(default_config)
    if not _has_flag("--root") and not env.get("WINCROSS_ROOT"):
        env["WINCROSS_ROOT"] = str(repo_root)

    result = subprocess.run([str(wincross_bin), *sys.argv[1:]], env=env)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
