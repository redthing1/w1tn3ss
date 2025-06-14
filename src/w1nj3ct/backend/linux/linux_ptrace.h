#pragma once

#include <sys/types.h>
#include <sys/user.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// linux ptrace operations
int linux_ptrace_attach(pid_t pid);
int linux_ptrace_detach(pid_t pid);
int linux_ptrace_read_memory(pid_t pid, void* addr, void* buffer, size_t size);
int linux_ptrace_write_memory(pid_t pid, void* addr, const void* data, size_t size);
int linux_ptrace_continue(pid_t pid);

// architecture-specific register operations
#if defined(__x86_64__)
struct linux_user_regs {
    struct user_regs_struct regs;
};
int linux_ptrace_get_registers(pid_t pid, struct linux_user_regs* regs);
int linux_ptrace_set_registers(pid_t pid, const struct linux_user_regs* regs);

// function call setup for x86_64
int linux_ptrace_setup_function_call_x86_64(pid_t pid, 
                                           void* func_addr,
                                           void* arg1, void* arg2, void* arg3,
                                           void* arg4, void* arg5, void* arg6,
                                           void** return_addr);

#elif defined(__aarch64__)
struct linux_user_regs {
    struct user_regs_struct regs;
};
int linux_ptrace_get_registers(pid_t pid, struct linux_user_regs* regs);
int linux_ptrace_set_registers(pid_t pid, const struct linux_user_regs* regs);

// function call setup for aarch64
int linux_ptrace_setup_function_call_aarch64(pid_t pid,
                                            void* func_addr,
                                            void* arg1, void* arg2, void* arg3,
                                            void* arg4, void* arg5, void* arg6,
                                            void** return_addr);

#else
#error "Unsupported architecture for Linux ptrace backend"
#endif

// utility functions
int linux_ptrace_wait_for_signal(pid_t pid, int* status);
int linux_ptrace_single_step(pid_t pid);
int linux_ptrace_peek_data(pid_t pid, void* addr, long* data);
int linux_ptrace_poke_data(pid_t pid, void* addr, long data);

// error handling
const char* linux_ptrace_strerror(int error_code);

// error codes
#define LINUX_PTRACE_SUCCESS       0
#define LINUX_PTRACE_ERROR         -1
#define LINUX_PTRACE_NO_PROCESS    -2
#define LINUX_PTRACE_PERMISSION    -3
#define LINUX_PTRACE_INVALID_ADDR  -4
#define LINUX_PTRACE_TIMEOUT       -5
#define LINUX_PTRACE_SIGNAL        -6

#ifdef __cplusplus
}
#endif