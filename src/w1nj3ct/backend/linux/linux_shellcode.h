#pragma once

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// architecture types
typedef enum {
    ARCH_UNKNOWN = 0,
    ARCH_X86_64,
    ARCH_ARM64,
    ARCH_ARM32,
    ARCH_I386
} linux_arch_t;

// shellcode context
typedef struct {
    linux_arch_t arch;
    pid_t pid;
    void* original_regs;  // platform-specific register state
    void* shellcode_addr; // address where shellcode was injected
    size_t shellcode_size;
} linux_shellcode_ctx_t;

// shellcode generation and execution
int linux_generate_dlopen_shellcode(const char* library_path, linux_arch_t arch, void** shellcode, size_t* size);
int linux_inject_and_execute_shellcode(pid_t pid, void* shellcode, size_t size, void** result);
void linux_free_shellcode(void* shellcode);

// architecture-specific helpers
int linux_call_remote_function(pid_t pid, void* func_addr, void** args, size_t arg_count, void** result);
int linux_allocate_remote_memory(pid_t pid, size_t size, void** addr);
int linux_free_remote_memory(pid_t pid, void* addr, size_t size);

// remote memory operations
int linux_write_remote_memory(pid_t pid, void* dest, const void* src, size_t size);
int linux_read_remote_memory(pid_t pid, void* src, void* dest, size_t size);

// process control
int linux_attach_process(pid_t pid);
int linux_detach_process(pid_t pid);
int linux_get_process_registers(pid_t pid, void** regs);
int linux_set_process_registers(pid_t pid, void* regs);
int linux_continue_process(pid_t pid);
int linux_wait_for_process(pid_t pid);

// architecture detection and utilities
linux_arch_t linux_detect_process_architecture(pid_t pid);
const char* linux_arch_to_string(linux_arch_t arch);
size_t linux_get_pointer_size(linux_arch_t arch);
size_t linux_get_register_size(linux_arch_t arch);

// shellcode templates for different architectures
int linux_generate_mmap_shellcode(linux_arch_t arch, size_t size, void** shellcode, size_t* shellcode_size);
int linux_generate_munmap_shellcode(linux_arch_t arch, void* addr, size_t size, void** shellcode, size_t* shellcode_size);
int linux_generate_dlopen_call_shellcode(linux_arch_t arch, void* dlopen_addr, void* path_addr, int flags, void** shellcode, size_t* shellcode_size);

// advanced shellcode operations
int linux_create_shellcode_context(pid_t pid, linux_shellcode_ctx_t** ctx);
void linux_destroy_shellcode_context(linux_shellcode_ctx_t* ctx);
int linux_execute_shellcode_in_context(linux_shellcode_ctx_t* ctx, void* shellcode, size_t size, void** result);

// error handling
const char* linux_shellcode_error_string(int error_code);

// error codes
#define LINUX_SHELLCODE_SUCCESS         0
#define LINUX_SHELLCODE_ERROR_GENERIC  -1
#define LINUX_SHELLCODE_ERROR_NO_MEMORY -2
#define LINUX_SHELLCODE_ERROR_NO_PROCESS -3
#define LINUX_SHELLCODE_ERROR_PERMISSION -4
#define LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH -5
#define LINUX_SHELLCODE_ERROR_INVALID_ARGS -6
#define LINUX_SHELLCODE_ERROR_PTRACE_FAILED -7
#define LINUX_SHELLCODE_ERROR_MEMORY_WRITE_FAILED -8
#define LINUX_SHELLCODE_ERROR_MEMORY_READ_FAILED -9
#define LINUX_SHELLCODE_ERROR_PROCESS_WAIT_FAILED -10

#ifdef __cplusplus
}
#endif