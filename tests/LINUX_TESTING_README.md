# Linux Testing Infrastructure

This document describes the comprehensive Linux testing infrastructure created for w1tn3ss injection functionality.

## Overview

The Linux testing infrastructure provides comprehensive testing for:
- Runtime injection using ptrace
- Preload injection using LD_PRELOAD  
- Process discovery and enumeration
- Error handling scenarios
- Cross-platform compatibility
- Architecture-specific functionality (x86_64/ARM64)

## Test Components

### 1. Test Scripts

#### `/tests/test_linux_injection.py`
Comprehensive Linux injection functionality testing script.

**Features:**
- Tests both runtime and preload injection modes
- Process discovery and enumeration testing
- Error handling scenario validation
- Architecture compatibility testing
- Permission and capability checking
- Detailed logging and reporting

**Usage:**
```bash
# Basic testing (preload only)
python3 ./tests/test_linux_injection.py --build-dir build-linux

# Full testing including runtime injection (requires privileges)
python3 ./tests/test_linux_injection.py --build-dir build-linux --test-runtime --verbose

# Preload testing only
python3 ./tests/test_linux_injection.py --build-dir build-linux --test-preload
```

#### `/tests/integration/test_linux_backend.py`
Linux backend integration testing for w1nj3ct.

**Features:**
- Cross-platform compatibility validation
- Linux-specific feature testing
- Error handling and recovery testing
- Permission and capability validation
- Multi-threading support verification

**Usage:**
```bash
python3 ./tests/integration/test_linux_backend.py --build-dir build-linux --verbose
```

#### `/tests/run_linux_tests.sh`
Comprehensive test runner that orchestrates all Linux testing.

**Features:**
- Colored output and progress tracking
- Capability detection and reporting
- Permission requirement checking
- Comprehensive test suite execution
- Results summary and recommendations

**Usage:**
```bash
# Basic test suite
./tests/run_linux_tests.sh --build-dir build-linux

# Full test suite with runtime injection
./tests/run_linux_tests.sh --build-dir build-linux --test-runtime --verbose

# Get help
./tests/run_linux_tests.sh --help
```

### 2. Test Programs

#### `/tests/programs/linux_target.c`
Linux-specific target program for injection testing.

**Features:**
- Linux-specific syscall testing
- Signal handling verification
- ptrace detection capabilities
- Process information reporting
- LD_PRELOAD detection
- Memory operation testing

#### `/tests/programs/linux_daemon.c`
Daemon-like target for testing background process injection.

**Features:**
- Process daemonization
- Syslog integration
- PID file management
- Signal handling
- Background operation simulation
- Foreground mode for testing

### 3. Test Libraries

#### `/tests/libraries/linux_test_lib.c`
Linux-specific test library for injection validation.

**Features:**
- Function hooking demonstrations
- System call interception
- Logging to file and syslog
- Constructor/destructor testing
- dlsym function resolution
- Dynamic loading verification

## Test Scenarios

### 1. Injection Mode Testing

**Preload Injection (LD_PRELOAD):**
- Works without special privileges
- Tests library loading at process startup
- Validates environment variable propagation
- Verifies cross-architecture compatibility

**Runtime Injection (ptrace):**
- Requires CAP_SYS_PTRACE capability or root
- Tests injection into running processes
- Validates permission handling
- Tests process state preservation

### 2. Process Discovery Testing

- `/proc` filesystem enumeration
- Process name resolution
- PID validation
- Process state checking
- Command line parsing

### 3. Error Handling Testing

- Invalid PID handling
- Missing library scenarios
- Permission denied cases
- Architecture mismatch detection
- Resource cleanup verification

### 4. Architecture Testing

- x86_64 compatibility
- ARM64 support (conditional)
- Cross-architecture validation
- Library format verification

## Permission Requirements

### For Preload Injection
- No special privileges required
- Regular user permissions sufficient
- Library must be readable by target process

### For Runtime Injection
Requires one of:
- Root privileges (`sudo`)
- `CAP_SYS_PTRACE` capability
- ptrace_scope=0 setting

### Setting Up Permissions

```bash
# Grant CAP_SYS_PTRACE to w1tool (recommended)
sudo setcap cap_sys_ptrace+ep ./build-linux/w1tool

# Temporarily allow ptrace for all processes
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Check current ptrace scope
cat /proc/sys/kernel/yama/ptrace_scope
```

## Test Results and Validation

### Success Criteria
- All preload injection tests pass
- Runtime injection tests pass (with appropriate privileges)
- Error handling behaves correctly
- Process discovery functions properly
- Cross-platform compatibility verified

### Typical Results
```
=== Linux Injection Testing ===
Architecture: x86_64
Capabilities: {'ptrace': True, 'preload': True, 'root': False, 'cap_sys_ptrace': True}

preload_simple_target         PASS RC: 0
preload_multi_threaded_target PASS RC: 0
preload_control_flow_1        PASS RC: 0
runtime_injection             PASS RC: 0
process_listing               PASS RC: 0
process_name_injection        PASS RC: 0
error_invalid_pid             PASS RC: 1 (should fail)
error_invalid_library         PASS RC: 1 (should fail)
error_invalid_binary          PASS RC: 1 (should fail)
arch_x86_64                   PASS RC: 0

Passed: 10/10
```

## Integration with Build System

### CMakeLists.txt Updates

**Test Programs (`/tests/programs/CMakeLists.txt`):**
- Added `linux_target` and `linux_daemon` executables
- Linux-specific build conditions (`UNIX AND NOT APPLE`)
- Proper sanitizer integration for debug builds
- Cross-platform install targets

**Test Libraries (`/tests/libraries/CMakeLists.txt`):**
- Added `linux_test_lib` shared library
- Dynamic loading support (`${CMAKE_DL_LIBS}`)
- Proper `.so` extension handling
- Sanitizer exclusion for injection libraries

## Usage Examples

### Basic Linux Testing
```bash
# Build for Linux
cmake -B build-linux
cmake --build build-linux --parallel

# Run comprehensive test suite
./tests/run_linux_tests.sh --build-dir build-linux
```

### Advanced Testing Scenarios
```bash
# Test with verbose output
./tests/test_linux_injection.py --build-dir build-linux --verbose

# Test runtime injection (requires privileges)
sudo ./tests/test_linux_injection.py --build-dir build-linux --test-runtime

# Integration testing
./tests/integration/test_linux_backend.py --build-dir build-linux
```

### Manual Testing
```bash
# Test preload injection
./build-linux/w1tool inject -L ./build-linux/tests/libraries/linux_test_lib.so -b ./build-linux/tests/programs/linux_target

# Test runtime injection (requires privileges)
sudo ./build-linux/w1tool inject --pid $(pgrep linux_target) -L ./build-linux/tests/libraries/linux_test_lib.so

# Test process discovery
./build-linux/w1tool inspect --list-processes
```

## Troubleshooting

### Common Issues

1. **Permission Denied for Runtime Injection**
   ```
   Solution: Check ptrace_scope or run with sudo/CAP_SYS_PTRACE
   ```

2. **Library Not Found**
   ```
   Solution: Use absolute paths and ensure .so extension
   ```

3. **Process Discovery Fails**
   ```
   Solution: Ensure /proc filesystem is mounted and accessible
   ```

4. **Architecture Mismatch**
   ```
   Solution: Verify target and library have same architecture
   ```

### Debug Information
```bash
# Enable verbose logging
./build-linux/w1tool -vvv inject -L ./library.so -b ./target

# Check system capabilities
./tests/run_linux_tests.sh --build-dir build-linux --verbose
```

## Files Created

### Test Scripts
- `/tests/test_linux_injection.py` - Main Linux injection test script
- `/tests/integration/test_linux_backend.py` - Backend integration tests
- `/tests/run_linux_tests.sh` - Comprehensive test runner

### Test Programs
- `/tests/programs/linux_target.c` - Linux-specific test target
- `/tests/programs/linux_daemon.c` - Daemon injection test target

### Test Libraries  
- `/tests/libraries/linux_test_lib.c` - Linux-specific test library

### Documentation
- `/tests/LINUX_TESTING_README.md` - This documentation
- Updated `/CLAUDE.md` with Linux-specific sections

### Build System Updates
- Updated `/tests/programs/CMakeLists.txt`
- Updated `/tests/libraries/CMakeLists.txt`

This comprehensive Linux testing infrastructure ensures that w1tn3ss injection functionality works correctly across different Linux distributions, architectures, and permission scenarios.