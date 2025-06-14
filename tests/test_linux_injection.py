#!/usr/bin/env python3
"""
Linux Injection Testing Script
Tests Linux injection functionality including runtime and preload injection.

Usage:
    python ./tests/test_linux_injection.py --build-dir build-linux
    python ./tests/test_linux_injection.py --build-dir build-linux --test-runtime
    python ./tests/test_linux_injection.py --build-dir build-linux --test-preload
    python ./tests/test_linux_injection.py --build-dir build-linux --verbose
"""

import argparse
import os
import subprocess
import sys
import time
import signal
import platform
from pathlib import Path
from typing import List, Tuple, Optional


class LinuxInjectionTester:
    """Linux injection testing framework."""
    
    def __init__(self, build_dir: Path, verbose: bool = False):
        self.build_dir = build_dir
        self.verbose = verbose
        self.w1tool = build_dir / "w1tool"
        self.test_programs_dir = build_dir / "tests" / "programs"
        self.test_libraries_dir = build_dir / "tests" / "libraries"
        self.temp_dir = Path("temp")
        
        # Platform detection
        self.arch = platform.machine()
        self.is_x86_64 = self.arch in ["x86_64", "AMD64"]
        self.is_arm64 = self.arch in ["aarch64", "arm64"]
        
        # Create temp directory
        self.temp_dir.mkdir(exist_ok=True)
        
    def log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def validate_environment(self) -> bool:
        """Validate that we're running on Linux with required tools."""
        if platform.system() != "Linux":
            print("ERROR: This test script requires Linux")
            return False
        
        if not self.w1tool.exists():
            print(f"ERROR: w1tool not found at {self.w1tool}")
            return False
        
        if not self.test_programs_dir.exists():
            print(f"ERROR: Test programs directory not found at {self.test_programs_dir}")
            return False
        
        if not self.test_libraries_dir.exists():
            print(f"ERROR: Test libraries directory not found at {self.test_libraries_dir}")
            return False
        
        return True
    
    def check_capabilities(self) -> dict:
        """Check Linux injection capabilities."""
        capabilities = {
            "ptrace": False,
            "preload": True,  # LD_PRELOAD should always work
            "root": os.geteuid() == 0,
            "cap_sys_ptrace": False
        }
        
        # Check if we can ptrace (basic check)
        try:
            # Try to get capability information
            result = subprocess.run(["capsh", "--print"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                if "cap_sys_ptrace" in result.stdout:
                    capabilities["cap_sys_ptrace"] = True
        except:
            pass
        
        # Check ptrace permissions
        try:
            # Check ptrace_scope
            with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f:
                ptrace_scope = int(f.read().strip())
                if ptrace_scope == 0 or capabilities["root"]:
                    capabilities["ptrace"] = True
        except:
            # If we can't read ptrace_scope, assume we can try
            capabilities["ptrace"] = True
        
        return capabilities
    
    def run_command(self, cmd: List[str], timeout: int = 30, 
                   input_data: str = None) -> Tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        self.log(f"Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                input=input_data
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired"
        except Exception as e:
            return -1, "", str(e)
    
    def find_test_library(self, name: str) -> Optional[Path]:
        """Find a test library file."""
        extensions = [".so", ".dylib"]  # Support both Linux and macOS
        
        for ext in extensions:
            lib_path = self.test_libraries_dir / f"{name}{ext}"
            if lib_path.exists():
                return lib_path
        
        return None
    
    def test_runtime_injection(self) -> List[Tuple[str, bool, str]]:
        """Test runtime injection functionality."""
        print("\n=== Testing Runtime Injection ===")
        results = []
        
        # Start a long-running target process
        target_binary = self.test_programs_dir / "long_running_target"
        if not target_binary.exists():
            print("ERROR: long_running_target not found")
            return [("runtime_injection", False, "Target binary not found")]
        
        # Find test library
        test_lib = self.find_test_library("tracer_lib")
        if not test_lib:
            print("ERROR: tracer_lib not found")
            return [("runtime_injection", False, "Test library not found")]
        
        # Start the target process
        self.log("Starting target process...")
        target_process = subprocess.Popen([str(target_binary)])
        time.sleep(2)  # Let it start
        
        try:
            # Attempt runtime injection
            cmd = [
                str(self.w1tool), "-vv", "inject",
                "--pid", str(target_process.pid),
                "--library", str(test_lib)
            ]
            
            returncode, stdout, stderr = self.run_command(cmd, timeout=15)
            
            success = returncode == 0
            message = f"PID: {target_process.pid}, RC: {returncode}"
            if not success:
                message += f", Error: {stderr}"
            
            results.append(("runtime_injection", success, message))
            
        finally:
            # Clean up target process
            try:
                target_process.terminate()
                target_process.wait(timeout=5)
            except:
                target_process.kill()
        
        return results
    
    def test_preload_injection(self) -> List[Tuple[str, bool, str]]:
        """Test preload injection functionality."""
        print("\n=== Testing Preload Injection ===")
        results = []
        
        # Test cases for preload injection
        test_cases = [
            ("simple_target", "tracer_lib", None),
            ("multi_threaded_target", "memory_lib", None),
            ("control_flow_1", "counter_lib", "test input\n")
        ]
        
        for binary_name, lib_name, input_data in test_cases:
            binary_path = self.test_programs_dir / binary_name
            if not binary_path.exists():
                results.append((f"preload_{binary_name}", False, "Binary not found"))
                continue
            
            test_lib = self.find_test_library(lib_name)
            if not test_lib:
                results.append((f"preload_{binary_name}", False, "Library not found"))
                continue
            
            # Run preload injection test
            cmd = [
                str(self.w1tool), "-vv", "inject",
                "--binary", str(binary_path),
                "--library", str(test_lib)
            ]
            
            returncode, stdout, stderr = self.run_command(cmd, timeout=20, input_data=input_data)
            
            success = returncode == 0
            message = f"RC: {returncode}"
            if not success:
                message += f", Error: {stderr}"
            
            results.append((f"preload_{binary_name}", success, message))
        
        return results
    
    def test_process_discovery(self) -> List[Tuple[str, bool, str]]:
        """Test process discovery and enumeration."""
        print("\n=== Testing Process Discovery ===")
        results = []
        
        # Test process listing
        cmd = [str(self.w1tool), "inspect", "--list-processes"]
        returncode, stdout, stderr = self.run_command(cmd, timeout=10)
        
        success = returncode == 0 and "PID" in stdout
        message = f"RC: {returncode}, Found processes: {success}"
        results.append(("process_listing", success, message))
        
        # Test finding specific process
        # Start a target process with a unique name
        target_binary = self.test_programs_dir / "simple_target"
        if target_binary.exists():
            # Use process name injection
            test_lib = self.find_test_library("tracer_lib")
            if test_lib:
                cmd = [
                    str(self.w1tool), "-vv", "inject",
                    "--process-name", "simple_target",
                    "--library", str(test_lib),
                    "--binary", str(target_binary)  # For preload fallback
                ]
                
                returncode, stdout, stderr = self.run_command(cmd, timeout=15)
                success = returncode == 0
                message = f"RC: {returncode}"
                if not success:
                    message += f", Error: {stderr}"
                
                results.append(("process_name_injection", success, message))
        
        return results
    
    def test_error_handling(self) -> List[Tuple[str, bool, str]]:
        """Test error handling scenarios."""
        print("\n=== Testing Error Handling ===")
        results = []
        
        # Test invalid PID
        cmd = [str(self.w1tool), "inject", "--pid", "99999", "--library", "/nonexistent.so"]
        returncode, stdout, stderr = self.run_command(cmd, timeout=10)
        success = returncode != 0  # Should fail
        results.append(("invalid_pid", success, f"RC: {returncode} (should fail)"))
        
        # Test invalid library
        target_binary = self.test_programs_dir / "simple_target"
        if target_binary.exists():
            cmd = [
                str(self.w1tool), "inject",
                "--binary", str(target_binary),
                "--library", "/nonexistent.so"
            ]
            returncode, stdout, stderr = self.run_command(cmd, timeout=10)
            success = returncode != 0  # Should fail
            results.append(("invalid_library", success, f"RC: {returncode} (should fail)"))
        
        # Test invalid binary
        test_lib = self.find_test_library("tracer_lib")
        if test_lib:
            cmd = [
                str(self.w1tool), "inject",
                "--binary", "/nonexistent_binary",
                "--library", str(test_lib)
            ]
            returncode, stdout, stderr = self.run_command(cmd, timeout=10)
            success = returncode != 0  # Should fail
            results.append(("invalid_binary", success, f"RC: {returncode} (should fail)"))
        
        return results
    
    def test_architecture_support(self) -> List[Tuple[str, bool, str]]:
        """Test architecture-specific functionality."""
        print("\n=== Testing Architecture Support ===")
        results = []
        
        # Test basic injection on current architecture
        binary_path = self.test_programs_dir / "simple_target"
        test_lib = self.find_test_library("tracer_lib")
        
        if binary_path.exists() and test_lib:
            cmd = [
                str(self.w1tool), "-vv", "inject",
                "--binary", str(binary_path),
                "--library", str(test_lib)
            ]
            
            returncode, stdout, stderr = self.run_command(cmd, timeout=15)
            success = returncode == 0
            message = f"Arch: {self.arch}, RC: {returncode}"
            
            results.append((f"arch_{self.arch}", success, message))
        
        return results
    
    def run_all_tests(self, test_runtime: bool = True, test_preload: bool = True) -> bool:
        """Run all Linux injection tests."""
        print(f"=== Linux Injection Testing ===")
        print(f"Architecture: {self.arch}")
        print(f"Build directory: {self.build_dir}")
        
        # Check capabilities
        capabilities = self.check_capabilities()
        print(f"Capabilities: {capabilities}")
        
        all_results = []
        
        # Run tests based on capabilities and user preferences
        if test_preload:
            all_results.extend(self.test_preload_injection())
        
        if test_runtime and capabilities["ptrace"]:
            all_results.extend(self.test_runtime_injection())
        elif test_runtime:
            print("WARNING: Runtime injection tests skipped (insufficient privileges)")
            all_results.append(("runtime_injection", False, "Insufficient privileges"))
        
        # Always run these tests
        all_results.extend(self.test_process_discovery())
        all_results.extend(self.test_error_handling())
        all_results.extend(self.test_architecture_support())
        
        # Print results
        print("\n=== Test Results ===")
        passed = 0
        total = len(all_results)
        
        for test_name, success, message in all_results:
            status = "PASS" if success else "FAIL"
            print(f"{test_name:25} {status:4} {message}")
            if success:
                passed += 1
        
        print(f"\nPassed: {passed}/{total}")
        print(f"Architecture: {self.arch}")
        print(f"Capabilities: {capabilities}")
        
        return passed == total


def main():
    parser = argparse.ArgumentParser(description="Test Linux injection functionality")
    parser.add_argument("--build-dir", required=True,
                       help="Build directory (e.g., build-linux)")
    parser.add_argument("--test-runtime", action="store_true",
                       help="Test runtime injection (requires privileges)")
    parser.add_argument("--test-preload", action="store_true", default=True,
                       help="Test preload injection (default: enabled)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    args = parser.parse_args()
    
    # Default to testing both if no specific tests requested
    if not args.test_runtime and args.test_preload:
        args.test_runtime = True
    
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        print(f"ERROR: Build directory {build_dir} does not exist")
        sys.exit(1)
    
    tester = LinuxInjectionTester(build_dir, args.verbose)
    
    if not tester.validate_environment():
        sys.exit(1)
    
    success = tester.run_all_tests(args.test_runtime, args.test_preload)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()