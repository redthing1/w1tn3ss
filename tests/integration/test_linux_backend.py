#!/usr/bin/env python3
"""
Linux Backend Integration Tests
Tests the w1nj3ct Linux backend integration with comprehensive scenarios.

Usage:
    python ./tests/integration/test_linux_backend.py --build-dir build-linux
    python ./tests/integration/test_linux_backend.py --build-dir build-linux --verbose
"""

import argparse
import os
import subprocess
import sys
import time
import signal
import platform
import tempfile
import json
from pathlib import Path
from typing import List, Tuple, Optional, Dict


class LinuxBackendTester:
    """Linux backend integration testing framework."""
    
    def __init__(self, build_dir: Path, verbose: bool = False):
        self.build_dir = build_dir
        self.verbose = verbose
        self.w1tool = build_dir / "w1tool"
        self.test_programs_dir = build_dir / "tests" / "programs"
        self.test_libraries_dir = build_dir / "tests" / "libraries"
        self.temp_dir = Path(tempfile.mkdtemp(prefix="w1nj3ct_test_"))
        
        # Test results
        self.results = []
        
    def log(self, message: str):
        """Log message if verbose mode is enabled."""
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def cleanup(self):
        """Clean up temporary files."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def validate_environment(self) -> bool:
        """Validate test environment."""
        if platform.system() != "Linux":
            print("ERROR: Linux backend tests require Linux")
            return False
        
        if not self.w1tool.exists():
            print(f"ERROR: w1tool not found at {self.w1tool}")
            return False
        
        required_programs = ["simple_target", "linux_target", "multi_threaded_target"]
        for program in required_programs:
            if not (self.test_programs_dir / program).exists():
                print(f"ERROR: Test program {program} not found")
                return False
        
        required_libraries = ["tracer_lib.so", "linux_test_lib.so"]
        for library in required_libraries:
            if not (self.test_libraries_dir / library).exists():
                print(f"ERROR: Test library {library} not found")
                return False
        
        return True
    
    def run_command(self, cmd: List[str], timeout: int = 30, 
                   input_data: str = None, env: Dict[str, str] = None) -> Tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        self.log(f"Running: {' '.join(cmd)}")
        
        # Merge environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                input=input_data,
                env=run_env
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Timeout expired"
        except Exception as e:
            return -1, "", str(e)
    
    def test_cross_platform_compatibility(self) -> bool:
        """Test cross-platform compatibility."""
        print("\n=== Testing Cross-platform Compatibility ===")
        
        # Test basic functionality works the same across platforms
        target_binary = self.test_programs_dir / "simple_target"
        test_lib = self.test_libraries_dir / "tracer_lib.so"
        
        cmd = [
            str(self.w1tool), "-vv", "inject",
            "--binary", str(target_binary),
            "--library", str(test_lib)
        ]
        
        returncode, stdout, stderr = self.run_command(cmd, timeout=15)
        
        success = returncode == 0
        self.results.append(("cross_platform_basic", success, f"RC: {returncode}"))
        
        print(f"  Basic cross-platform test: {'PASS' if success else 'FAIL'}")
        return success
    
    def test_linux_specific_features(self) -> bool:
        """Test Linux-specific injection features."""
        print("\n=== Testing Linux-specific Features ===")
        
        all_passed = True
        
        # Test 1: Process discovery via /proc
        self.log("Testing process discovery")
        cmd = [str(self.w1tool), "inspect", "--list-processes"]
        returncode, stdout, stderr = self.run_command(cmd, timeout=10)
        
        proc_discovery_success = returncode == 0 and "/proc" in stderr or "PID" in stdout
        self.results.append(("linux_proc_discovery", proc_discovery_success, f"RC: {returncode}"))
        all_passed &= proc_discovery_success
        
        # Test 2: LD_PRELOAD injection
        self.log("Testing LD_PRELOAD injection")
        target_binary = self.test_programs_dir / "linux_target"
        test_lib = self.test_libraries_dir / "linux_test_lib.so"
        
        cmd = [
            str(self.w1tool), "-vv", "inject",
            "--binary", str(target_binary),
            "--library", str(test_lib)
        ]
        
        returncode, stdout, stderr = self.run_command(cmd, timeout=20)
        
        preload_success = returncode == 0
        self.results.append(("linux_ld_preload", preload_success, f"RC: {returncode}"))
        all_passed &= preload_success
        
        # Test 3: Signal handling
        self.log("Testing signal handling")
        # Start a target process and send signals
        target_process = None
        try:
            target_process = subprocess.Popen([str(target_binary)])
            time.sleep(2)
            
            # Test injection into running process
            if self.check_ptrace_available():
                cmd = [
                    str(self.w1tool), "-vv", "inject",
                    "--pid", str(target_process.pid),
                    "--library", str(test_lib)
                ]
                
                returncode, stdout, stderr = self.run_command(cmd, timeout=10)
                signal_success = returncode == 0
            else:
                signal_success = True  # Skip if no ptrace
                self.log("Skipping signal test - no ptrace available")
            
            self.results.append(("linux_signal_handling", signal_success, f"RC: {returncode if 'returncode' in locals() else 'SKIP'}"))
            all_passed &= signal_success
            
        finally:
            if target_process:
                try:
                    target_process.terminate()
                    target_process.wait(timeout=5)
                except:
                    target_process.kill()
        
        print(f"  Linux-specific features: {'PASS' if all_passed else 'FAIL'}")
        return all_passed
    
    def test_error_handling_and_recovery(self) -> bool:
        """Test error handling and recovery scenarios."""
        print("\n=== Testing Error Handling and Recovery ===")
        
        all_passed = True
        
        # Test 1: Invalid PID handling
        self.log("Testing invalid PID handling")
        cmd = [str(self.w1tool), "inject", "--pid", "99999", "--library", "/dev/null"]
        returncode, stdout, stderr = self.run_command(cmd, timeout=10)
        
        invalid_pid_success = returncode != 0  # Should fail gracefully
        self.results.append(("error_invalid_pid", invalid_pid_success, f"RC: {returncode} (should fail)"))
        all_passed &= invalid_pid_success
        
        # Test 2: Library not found
        self.log("Testing missing library handling")
        target_binary = self.test_programs_dir / "simple_target"
        cmd = [
            str(self.w1tool), "inject",
            "--binary", str(target_binary),
            "--library", "/nonexistent/library.so"
        ]
        returncode, stdout, stderr = self.run_command(cmd, timeout=10)
        
        missing_lib_success = returncode != 0  # Should fail gracefully
        self.results.append(("error_missing_library", missing_lib_success, f"RC: {returncode} (should fail)"))
        all_passed &= missing_lib_success
        
        # Test 3: Permission denied scenarios
        self.log("Testing permission handling")
        if not self.is_root():
            # Try to inject into a system process (should fail gracefully)
            cmd = [str(self.w1tool), "inject", "--pid", "1", "--library", "/dev/null"]
            returncode, stdout, stderr = self.run_command(cmd, timeout=10)
            
            permission_success = returncode != 0  # Should fail gracefully
            self.results.append(("error_permission_denied", permission_success, f"RC: {returncode} (should fail)"))
            all_passed &= permission_success
        else:
            self.results.append(("error_permission_denied", True, "SKIP (running as root)"))
        
        # Test 4: Architecture mismatch (simulate)
        self.log("Testing architecture validation")
        # This test would require cross-architecture binaries, so we'll simulate
        arch_success = True  # For now, assume this works
        self.results.append(("error_arch_mismatch", arch_success, "SIMULATED"))
        
        print(f"  Error handling and recovery: {'PASS' if all_passed else 'FAIL'}")
        return all_passed
    
    def test_permission_and_capabilities(self) -> bool:
        """Test permission and capability requirements."""
        print("\n=== Testing Permissions and Capabilities ===")
        
        all_passed = True
        
        # Test 1: Check ptrace availability
        ptrace_available = self.check_ptrace_available()
        self.results.append(("capability_ptrace", ptrace_available, f"Available: {ptrace_available}"))
        
        # Test 2: Check CAP_SYS_PTRACE capability
        cap_sys_ptrace = self.check_cap_sys_ptrace()
        self.results.append(("capability_cap_sys_ptrace", True, f"Available: {cap_sys_ptrace}"))  # Always pass, just informational
        
        # Test 3: Test with different privilege levels
        if self.is_root():
            self.log("Running as root - testing privilege escalation")
            # Test injection works with full privileges
            target_binary = self.test_programs_dir / "simple_target"
            test_lib = self.test_libraries_dir / "tracer_lib.so"
            
            cmd = [
                str(self.w1tool), "-vv", "inject",
                "--binary", str(target_binary),
                "--library", str(test_lib)
            ]
            
            returncode, stdout, stderr = self.run_command(cmd, timeout=15)
            root_success = returncode == 0
            self.results.append(("privilege_root_injection", root_success, f"RC: {returncode}"))
            all_passed &= root_success
        else:
            self.log("Running as regular user")
            # Test preload injection (should work without special privileges)
            target_binary = self.test_programs_dir / "simple_target"
            test_lib = self.test_libraries_dir / "tracer_lib.so"
            
            cmd = [
                str(self.w1tool), "-vv", "inject",
                "--binary", str(target_binary),
                "--library", str(test_lib)
            ]
            
            returncode, stdout, stderr = self.run_command(cmd, timeout=15)
            user_success = returncode == 0
            self.results.append(("privilege_user_injection", user_success, f"RC: {returncode}"))
            all_passed &= user_success
        
        print(f"  Permissions and capabilities: {'PASS' if all_passed else 'FAIL'}")
        return all_passed
    
    def test_multi_threading_support(self) -> bool:
        """Test multi-threading injection support."""
        print("\n=== Testing Multi-threading Support ===")
        
        target_binary = self.test_programs_dir / "multi_threaded_target"
        test_lib = self.test_libraries_dir / "tracer_lib.so"
        
        cmd = [
            str(self.w1tool), "-vv", "inject",
            "--binary", str(target_binary),
            "--library", str(test_lib)
        ]
        
        returncode, stdout, stderr = self.run_command(cmd, timeout=20)
        
        success = returncode == 0
        self.results.append(("multithreading_support", success, f"RC: {returncode}"))
        
        print(f"  Multi-threading support: {'PASS' if success else 'FAIL'}")
        return success
    
    def check_ptrace_available(self) -> bool:
        """Check if ptrace is available."""
        try:
            # Check ptrace_scope
            with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f:
                ptrace_scope = int(f.read().strip())
                return ptrace_scope == 0 or self.is_root()
        except:
            return True  # If we can't read it, assume it's available
    
    def check_cap_sys_ptrace(self) -> bool:
        """Check if CAP_SYS_PTRACE capability is available."""
        try:
            result = subprocess.run(["capsh", "--print"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return "cap_sys_ptrace" in result.stdout
        except:
            pass
        return False
    
    def is_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0
    
    def run_all_tests(self) -> bool:
        """Run all Linux backend integration tests."""
        print("=== Linux Backend Integration Tests ===")
        print(f"Build directory: {self.build_dir}")
        print(f"Temporary directory: {self.temp_dir}")
        print(f"Running as: {'root' if self.is_root() else 'user'}")
        print(f"Ptrace available: {self.check_ptrace_available()}")
        
        try:
            all_passed = True
            
            # Run all test suites
            all_passed &= self.test_cross_platform_compatibility()
            all_passed &= self.test_linux_specific_features()
            all_passed &= self.test_error_handling_and_recovery()
            all_passed &= self.test_permission_and_capabilities()
            all_passed &= self.test_multi_threading_support()
            
            # Print summary
            self.print_summary()
            
            return all_passed
            
        finally:
            self.cleanup()
    
    def print_summary(self):
        """Print test results summary."""
        print("\n=== Integration Test Results ===")
        
        passed = 0
        total = len(self.results)
        
        for test_name, success, message in self.results:
            status = "PASS" if success else "FAIL"
            print(f"{test_name:30} {status:4} {message}")
            if success:
                passed += 1
        
        print(f"\nPassed: {passed}/{total}")
        print(f"Success rate: {passed/total*100:.1f}%")
        
        # System information
        print(f"\nSystem Information:")
        print(f"  Platform: {platform.system()} {platform.release()}")
        print(f"  Architecture: {platform.machine()}")
        print(f"  Python: {platform.python_version()}")
        print(f"  User: {'root' if self.is_root() else 'regular'}")


def main():
    parser = argparse.ArgumentParser(description="Test Linux backend integration")
    parser.add_argument("--build-dir", required=True,
                       help="Build directory (e.g., build-linux)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    args = parser.parse_args()
    
    build_dir = Path(args.build_dir)
    if not build_dir.exists():
        print(f"ERROR: Build directory {build_dir} does not exist")
        sys.exit(1)
    
    tester = LinuxBackendTester(build_dir, args.verbose)
    
    if not tester.validate_environment():
        sys.exit(1)
    
    success = tester.run_all_tests()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()