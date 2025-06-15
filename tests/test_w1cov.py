#!/usr/bin/env python3
"""
w1cov Testing Script
Tests coverage functionality with proper process handling and file detection.
Cross-platform support for macOS, Linux, and Windows.

Usage:
    python ./tests/test_w1cov.py --build-dir build-release
    python ./tests/test_w1cov.py --build-dir build-debug
    python ./tests/test_w1cov.py --build-dir build-linux
    python ./tests/test_w1cov.py --build-dir build-windows
"""

import argparse
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


def get_platform_specifics():
    """Get platform-specific file extensions and paths."""
    system = platform.system().lower()
    
    if system == "darwin":  # macOS
        return {
            "w1tool": "w1tool",
            "library_ext": ".dylib",
            "binary_ext": "",
            "library_name": "w1cov_qbdipreload.dylib"
        }
    elif system == "linux":
        return {
            "w1tool": "w1tool", 
            "library_ext": ".so",
            "binary_ext": "",
            "library_name": "w1cov_qbdipreload.so"
        }
    elif system == "windows":
        return {
            "w1tool": "w1tool.exe",
            "library_ext": ".dll", 
            "binary_ext": ".exe",
            "library_name": "w1cov_qbdipreload.dll"
        }
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def run_coverage_test(w1tool_path, library_path, binary_path, expected_file):
    """Run a coverage test and return the basic block count."""
    print(f"  Running: {binary_path.name}")
    
    # Clean up any existing coverage file
    if expected_file.exists():
        expected_file.unlink()
    
    try:
        # Run the w1tool cover command (updated to use cover instead of inject)
        cmd = [
            str(w1tool_path), "cover",
            "--w1cov-library", str(library_path),
            "--binary", str(binary_path),
            "--output", str(expected_file)
        ]
        
        if binary_path.name == "control_flow_1":
            # Interactive program needs input
            result = subprocess.run(cmd, input="\n", text=True, capture_output=True, timeout=30)
        else:
            # Regular programs
            result = subprocess.run(cmd, capture_output=True, timeout=30)
        
        # Check return code
        if result.returncode != 0:
            print(f"    COMMAND FAILED: {result.stderr.decode() if result.stderr else 'Unknown error'}")
            return 0, False
        
        # Wait a moment for file to be written
        time.sleep(1)
        
        # Check if coverage file was created
        if expected_file.exists():
            # Use w1tool read-drcov to analyze the file
            try:
                read_result = subprocess.run([
                    str(w1tool_path), "read-drcov", "--file", str(expected_file)
                ], capture_output=True, text=True, timeout=10)
                
                if read_result.returncode == 0:
                    # Extract basic block count from output
                    for line in read_result.stdout.split('\n'):
                        if "Total Basic Blocks:" in line:
                            bb_count = int(line.split()[-1])
                            return bb_count, True
                    return 0, False
                else:
                    return 0, False
            except Exception as e:
                print(f"    ANALYSIS ERROR: {e}")
                return 0, False
        else:
            print(f"    OUTPUT FILE NOT CREATED: {expected_file}")
            return 0, False
            
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT: {binary_path.name}")
        return 0, False
    except Exception as e:
        print(f"    ERROR: {e}")
        return 0, False


def main():
    parser = argparse.ArgumentParser(description="Test w1cov coverage functionality")
    parser.add_argument("--build-dir", required=True, 
                       help="Build directory (e.g., build-release, build-debug, build-linux, build-windows)")
    args = parser.parse_args()
    
    # Get platform-specific configurations
    try:
        platform_config = get_platform_specifics()
    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Validate build directory
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        print(f"Error: Build directory {build_dir} does not exist")
        sys.exit(1)
    
    # Set up paths with platform-specific extensions
    w1tool = build_dir / platform_config["w1tool"]
    library = build_dir / platform_config["library_name"]
    test_programs_dir = build_dir / "tests" / "programs"
    temp_dir = Path("temp")
    
    # Validate required files
    if not w1tool.exists():
        print(f"Error: w1tool not found at {w1tool}")
        sys.exit(1)
    
    if not library.exists():
        print(f"Error: w1cov library not found at {library}")
        sys.exit(1)
    
    if not test_programs_dir.exists():
        print(f"Error: Test programs directory not found at {test_programs_dir}")
        sys.exit(1)
    
    # Create temp directory
    temp_dir.mkdir(exist_ok=True)
    
    print(f"=== w1cov Testing ({args.build_dir}) ===")
    print(f"Platform: {platform.system()}")
    print(f"Library: {library.name}")
    
    # Test cases with platform-specific binary extensions
    binary_ext = platform_config["binary_ext"]
    test_cases = [
        (f"simple_target{binary_ext}", "simple_target.drcov"),
        (f"multi_threaded_target{binary_ext}", "multi_threaded_target.drcov"),
        (f"control_flow_1{binary_ext}", "control_flow_1.drcov")
    ]
    
    results = []
    all_passed = True
    
    for program_name, coverage_file in test_cases:
        binary_path = test_programs_dir / program_name
        coverage_path = temp_dir / coverage_file
        
        if not binary_path.exists():
            print(f"  {program_name}: SKIP (binary not found)")
            continue
        
        print(f"Testing {program_name}...")
        bb_count, success = run_coverage_test(w1tool, library, binary_path, coverage_path)
        
        if success:
            print(f"  {program_name}: SUCCESS - {bb_count} basic blocks")
            results.append((program_name, bb_count, True))
        else:
            print(f"  {program_name}: FAILED")
            all_passed = False
            results.append((program_name, 0, False))
    
    # Summary
    print("\n=== Test Results ===")
    for program_name, bb_count, success in results:
        status = "PASS" if success else "FAIL"
        if success:
            print(f"{program_name:25} {status:4} {bb_count:4} blocks")
        else:
            print(f"{program_name:25} {status:4}")
    
    print(f"\nBuild type: {args.build_dir}")
    print(f"Platform: {platform.system()}")
    print(f"Coverage files stored in: {temp_dir}/")
    
    if all_passed:
        print("All tests PASSED")
        sys.exit(0)
    else:
        print("Some tests FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()