#!/usr/bin/env python3
"""
W1COV Testing Script
Tests coverage functionality with proper process handling and file detection.

Usage:
    python ./tests/test_w1cov.py --build-dir build-release
    python ./tests/test_w1cov.py --build-dir build-debug
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path


def run_coverage_test(w1tool_path, library_path, binary_path, expected_file):
    """Run a coverage test and return the basic block count."""
    print(f"  Running: {binary_path.name}")
    
    # Clean up any existing coverage file
    if expected_file.exists():
        expected_file.unlink()
    
    try:
        # Run the w1tool inject command
        if binary_path.name == "control_flow_1":
            # Interactive program needs input
            result = subprocess.run([
                str(w1tool_path), "inject",
                "--tool", "w1cov",
                "--library", str(library_path),
                "--binary", str(binary_path)
            ], input="test input\n", text=True, capture_output=True, timeout=30)
        else:
            # Regular programs
            result = subprocess.run([
                str(w1tool_path), "inject",
                "--tool", "w1cov",
                "--library", str(library_path),
                "--binary", str(binary_path)
            ], capture_output=True, timeout=30)
        
        # Wait a moment for file to be written
        time.sleep(2)
        
        # Check if coverage file was created
        if expected_file.exists():
            # Extract basic block count
            try:
                output = subprocess.run(["strings", str(expected_file)], 
                                      capture_output=True, text=True)
                for line in output.stdout.split('\n'):
                    if "BB Table:" in line:
                        bb_count = line.split()[2]
                        return int(bb_count), True
                return 0, False
            except:
                return 0, False
        else:
            return 0, False
            
    except subprocess.TimeoutExpired:
        print(f"    TIMEOUT: {binary_path.name}")
        return 0, False
    except Exception as e:
        print(f"    ERROR: {e}")
        return 0, False


def main():
    parser = argparse.ArgumentParser(description="Test W1COV coverage functionality")
    parser.add_argument("--build-dir", required=True, 
                       help="Build directory (e.g., build-release, build-debug)")
    args = parser.parse_args()
    
    # Validate build directory
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        print(f"Error: Build directory {build_dir} does not exist")
        sys.exit(1)
    
    # Set up paths
    w1tool = build_dir / "w1tool"
    library = build_dir / "w1cov_qbdipreload.dylib"
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
    
    print(f"=== W1COV Testing ({args.build_dir}) ===")
    
    # Test cases
    test_cases = [
        ("simple_target", "simple_target.drcov"),
        ("multi_threaded_target", "multi_threaded_target.drcov"),
        ("control_flow_1", "control_flow_1.drcov")
    ]
    
    results = []
    all_passed = True
    
    for program_name, coverage_file in test_cases:
        binary_path = test_programs_dir / program_name
        coverage_path = Path(coverage_file)
        
        if not binary_path.exists():
            print(f"  {program_name}: SKIP (binary not found)")
            continue
        
        print(f"Testing {program_name}...")
        bb_count, success = run_coverage_test(w1tool, library, binary_path, coverage_path)
        
        if success:
            print(f"  {program_name}: SUCCESS - {bb_count} basic blocks")
            # Move coverage file to temp directory
            if coverage_path.exists():
                (temp_dir / coverage_file).write_bytes(coverage_path.read_bytes())
                coverage_path.unlink()
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
            print(f"{program_name:20} {status:4} {bb_count:4} blocks")
        else:
            print(f"{program_name:20} {status:4}")
    
    print(f"\nBuild type: {args.build_dir}")
    print(f"Coverage files stored in: {temp_dir}/")
    
    if all_passed:
        print("All tests PASSED")
        sys.exit(0)
    else:
        print("Some tests FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()