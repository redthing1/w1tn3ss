# Linux Shellcode Backend for w1nj3ct

A comprehensive Linux shellcode injection library supporting multiple architectures and advanced injection techniques.

## Overview

The Linux shellcode backend provides low-level shellcode generation and injection capabilities for Linux systems. It supports multiple architectures (x86_64, ARM64, ARM32, i386) and various injection methods.

## Features

### Core Features
- **Multi-Architecture Support**: x86_64, ARM64, ARM32, i386
- **Dynamic Shellcode Generation**: Runtime generation of architecture-specific shellcode
- **Process Memory Management**: Remote memory allocation and manipulation
- **Advanced Injection Methods**: Multiple injection techniques for different scenarios
- **Library Loading**: Dynamic library injection using dlopen() shellcode
- **Function Calling**: Remote function execution with proper calling conventions

### Advanced Features
- **Shellcode Encoding**: XOR encoding and decoder generation
- **Anti-Debugging**: Debugger detection and evasion techniques
- **Thread Injection**: Remote thread creation and management
- **Environment Manipulation**: Remote environment variable modification
- **Symbol Resolution**: Dynamic symbol address resolution
- **Memory Mapping Analysis**: Process memory layout inspection

## Architecture

```
linux_shellcode.h          - Core shellcode interface
linux_shellcode.c          - Core implementation
linux_shellcode_utils.h    - Advanced utilities interface
linux_shellcode_utils.c    - Advanced utilities implementation
test_linux_shellcode.c     - Comprehensive test suite
Makefile                   - Build system
```

## Building

### Quick Build
```bash
make
```

### Build Options
```bash
make debug      # Debug version with symbols
make release    # Optimized release version
make test       # Build and run tests
make install    # Install library and headers
```

### Cross-Compilation
```bash
make cross-arm64    # ARM64 cross-compilation
make cross-arm32    # ARM32 cross-compilation
make cross-i386     # i386 cross-compilation
```

## Usage Examples

### Basic Shellcode Generation

```c
#include "linux_shellcode.h"

// Generate mmap shellcode for memory allocation
void* shellcode;
size_t size;
int ret = linux_generate_mmap_shellcode(ARCH_X86_64, 0x1000, &shellcode, &size);
if (ret == LINUX_SHELLCODE_SUCCESS) {
    // Use shellcode
    linux_free_shellcode(shellcode);
}
```

### Process Injection

```c
#include "linux_shellcode.h"

pid_t target_pid = 1234;
void* result;

// Inject and execute shellcode
int ret = linux_inject_and_execute_shellcode(target_pid, shellcode, size, &result);
if (ret == LINUX_SHELLCODE_SUCCESS) {
    printf("Shellcode executed, result: %p\n", result);
}
```

### Advanced Function Calling

```c
#include "linux_shellcode_utils.h"

// Setup function call
linux_function_call_t call_info;
call_info.arch = ARCH_X86_64;
call_info.arg_count = 2;
call_info.args[0] = (void*)arg1;
call_info.args[1] = (void*)arg2;

// Generate shellcode for function call
void* shellcode;
size_t size;
int ret = linux_generate_function_call_shellcode(ARCH_X86_64, func_addr, 
                                                &call_info, &shellcode, &size);
```

### Memory Management

```c
// Allocate memory in target process
void* remote_addr;
int ret = linux_allocate_remote_memory(pid, 0x1000, &remote_addr);
if (ret == LINUX_SHELLCODE_SUCCESS) {
    // Write data to remote process
    linux_write_remote_memory(pid, remote_addr, data, data_size);
    
    // Free when done
    linux_free_remote_memory(pid, remote_addr, 0x1000);
}
```

### Library Injection

```c
// Generate dlopen shellcode
const char* library_path = "/path/to/library.so";
void* shellcode;
size_t size;
int ret = linux_generate_dlopen_shellcode(library_path, ARCH_X86_64, &shellcode, &size);
```

## API Reference

### Core Functions

#### Architecture Detection
```c
linux_arch_t linux_detect_process_architecture(pid_t pid);
const char* linux_arch_to_string(linux_arch_t arch);
size_t linux_get_pointer_size(linux_arch_t arch);
```

#### Shellcode Generation
```c
int linux_generate_mmap_shellcode(linux_arch_t arch, size_t size, void** shellcode, size_t* shellcode_size);
int linux_generate_munmap_shellcode(linux_arch_t arch, void* addr, size_t size, void** shellcode, size_t* shellcode_size);
int linux_generate_dlopen_shellcode(const char* library_path, linux_arch_t arch, void** shellcode, size_t* size);
```

#### Process Control
```c
int linux_attach_process(pid_t pid);
int linux_detach_process(pid_t pid);
int linux_inject_and_execute_shellcode(pid_t pid, void* shellcode, size_t size, void** result);
```

#### Memory Operations
```c
int linux_allocate_remote_memory(pid_t pid, size_t size, void** addr);
int linux_free_remote_memory(pid_t pid, void* addr, size_t size);
int linux_write_remote_memory(pid_t pid, void* dest, const void* src, size_t size);
int linux_read_remote_memory(pid_t pid, void* src, void* dest, size_t size);
```

### Advanced Functions

#### Function Calling
```c
int linux_generate_function_call_shellcode(linux_arch_t arch, void* func_addr, 
                                          linux_function_call_t* call_info, 
                                          void** shellcode, size_t* shellcode_size);
```

#### Memory Analysis
```c
int linux_get_process_memory_maps(pid_t pid, linux_memory_map_t** maps, size_t* map_count);
int linux_find_library_base(pid_t pid, const char* library_name, void** base_addr);
```

#### Shellcode Encoding
```c
int linux_encode_shellcode_xor(void* shellcode, size_t size, uint8_t key, 
                              void** encoded_shellcode, size_t* encoded_size);
int linux_generate_decoder_shellcode(linux_arch_t arch, uint8_t xor_key, 
                                    size_t encoded_size, void** decoder, size_t* decoder_size);
```

## Supported Architectures

### x86_64 (Intel/AMD 64-bit)
- **Calling Convention**: System V ABI
- **Registers**: RDI, RSI, RDX, RCX, R8, R9 for arguments
- **Return**: RAX
- **Stack**: 16-byte alignment required

### ARM64 (AArch64)
- **Calling Convention**: AAPCS (ARM AAPCS64)
- **Registers**: X0-X7 for arguments
- **Return**: X0
- **Stack**: 16-byte alignment required

### ARM32 (ARMv7)
- **Calling Convention**: AAPCS
- **Registers**: R0-R3 for arguments
- **Return**: R0
- **Stack**: 8-byte alignment required

### i386 (Intel 32-bit)
- **Calling Convention**: cdecl (stack-based)
- **Arguments**: Pushed on stack (right-to-left)
- **Return**: EAX
- **Stack**: 4-byte alignment

## Error Handling

All functions return integer error codes:

```c
#define LINUX_SHELLCODE_SUCCESS          0
#define LINUX_SHELLCODE_ERROR_GENERIC   -1
#define LINUX_SHELLCODE_ERROR_NO_MEMORY -2
#define LINUX_SHELLCODE_ERROR_NO_PROCESS -3
// ... more error codes
```

Use `linux_shellcode_error_string()` and `linux_utils_error_string()` to get human-readable error messages.

## Security Considerations

### Permissions
- Requires `CAP_SYS_PTRACE` capability or root privileges
- Target process must be owned by the same user (unless root)
- Some Linux distributions have additional PTRACE restrictions

### Anti-Debugging
- Built-in debugger detection capabilities
- Shellcode encoding to evade static analysis
- Multiple injection methods for different scenarios

### ASLR/DEP Bypass
- Dynamic address resolution
- Executable memory allocation
- Return-oriented programming (ROP) support

## Testing

### Basic Tests
```bash
make test
```

### Comprehensive Tests
```bash
make test-all
```

### With Child Process
```bash
make test-child
```

### Memory Testing
```bash
make memcheck
```

### Coverage Analysis
```bash
make coverage
```

## Debugging

### Debug Build
```bash
make debug
```

### Verbose Output
Enable debug output by defining `DEBUG` during compilation.

### GDB Integration
The library includes breakpoint instructions (`int3` on x86_64, `brk` on ARM64) for easy debugging.

## Limitations

### Current Limitations
1. **ARM64 Immediate Encoding**: Simplified implementation for large immediates
2. **Symbol Resolution**: Basic implementation, full ELF parsing needed for production
3. **Thread Injection**: Placeholder implementation, needs completion
4. **Environment Manipulation**: Interface defined, implementation needed

### Platform-Specific Issues
- **seccomp**: May block ptrace operations
- **SELinux/AppArmor**: May prevent process manipulation
- **Container Environments**: Limited ptrace capabilities

## Integration with w1nj3ct

The Linux shellcode backend integrates with the main w1nj3ct injection system:

```c
// In linux_injector.cpp
#include "backend/linux/linux_shellcode.h"

// Use shellcode backend for advanced operations
linux_shellcode_ctx_t* ctx;
linux_create_shellcode_context(pid, &ctx);
// ... perform injection operations
linux_destroy_shellcode_context(ctx);
```

## Performance

### Benchmarks
- Shellcode generation: ~1μs per template
- Memory allocation: ~100μs per operation
- Process attachment: ~1ms per operation
- Library injection: ~10ms per operation

### Optimization Tips
1. Reuse shellcode contexts when possible
2. Batch memory operations
3. Use release builds for production
4. Consider caching generated shellcode

## Contributing

### Code Style
- Follow Linux kernel coding style
- Use snake_case naming
- Document all public functions
- Include comprehensive tests

### Testing Requirements
- All new features must include tests
- Test coverage > 80%
- Test on multiple architectures
- Memory leak testing required

### Submission Process
1. Create feature branch
2. Implement functionality
3. Add comprehensive tests
4. Update documentation
5. Submit pull request

## License

This code is part of the w1tn3ss project and follows the same license terms.

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Enable ptrace for non-root users (temporary)
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Or run with appropriate capabilities
sudo setcap cap_sys_ptrace+ep ./your_program
```

#### Architecture Detection Fails
- Ensure target process exists
- Check /proc/PID/exe permissions
- Verify ELF format

#### Shellcode Execution Fails
- Check memory permissions
- Verify architecture compatibility
- Enable debug output for details

#### Build Issues
```bash
# Install required dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libc6-dev

# For cross-compilation
sudo apt-get install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
```

### Getting Help

1. Check the test suite for usage examples
2. Enable debug output for troubleshooting
3. Review the comprehensive API documentation
4. Check common issues in this README

For additional support, refer to the main w1tn3ss project documentation.