#include "linux_ptrace.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#ifdef __aarch64__
#include <linux/elf.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#endif

// global error state
static int g_last_error = LINUX_PTRACE_SUCCESS;
static char g_error_buffer[256];

static void set_error(int error_code, const char* message) {
    g_last_error = error_code;
    snprintf(g_error_buffer, sizeof(g_error_buffer), "%s: %s", message, strerror(errno));
}

static void clear_error() {
    g_last_error = LINUX_PTRACE_SUCCESS;
    g_error_buffer[0] = '\0';
}

// basic ptrace operations
int linux_ptrace_attach(pid_t pid) {
    clear_error();
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to attach to process");
                break;
        }
        return g_last_error;
    }
    
    // wait for the process to stop
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        set_error(LINUX_PTRACE_ERROR, "Failed to wait for process");
        return g_last_error;
    }
    
    if (!WIFSTOPPED(status)) {
        set_error(LINUX_PTRACE_ERROR, "Process did not stop after attach");
        return LINUX_PTRACE_ERROR;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_detach(pid_t pid) {
    clear_error();
    
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to detach from process");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_continue(pid_t pid) {
    clear_error();
    
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to continue process");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_single_step(pid_t pid) {
    clear_error();
    
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to single step process");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

// memory operations
int linux_ptrace_peek_data(pid_t pid, void* addr, long* data) {
    clear_error();
    errno = 0;
    
    long result = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (result == -1 && errno != 0) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EFAULT:
                set_error(LINUX_PTRACE_INVALID_ADDR, "Invalid memory address");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to read memory");
                break;
        }
        return g_last_error;
    }
    
    *data = result;
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_poke_data(pid_t pid, void* addr, long data) {
    clear_error();
    
    if (ptrace(PTRACE_POKEDATA, pid, addr, data) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EFAULT:
                set_error(LINUX_PTRACE_INVALID_ADDR, "Invalid memory address");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to write memory");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_read_memory(pid_t pid, void* addr, void* buffer, size_t size) {
    clear_error();
    
    // use process_vm_readv if available (faster for large reads)
    struct iovec local_iov = {
        .iov_base = buffer,
        .iov_len = size
    };
    struct iovec remote_iov = {
        .iov_base = addr,
        .iov_len = size
    };
    
    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == (ssize_t)size) {
        return LINUX_PTRACE_SUCCESS;
    }
    
    // fallback to ptrace PEEKDATA for word-by-word reading
    char* buf = (char*)buffer;
    size_t bytes_remaining = size;
    void* current_addr = addr;
    
    while (bytes_remaining > 0) {
        long word;
        int result = linux_ptrace_peek_data(pid, current_addr, &word);
        if (result != LINUX_PTRACE_SUCCESS) {
            return result;
        }
        
        size_t bytes_to_copy = (bytes_remaining >= sizeof(long)) ? sizeof(long) : bytes_remaining;
        memcpy(buf, &word, bytes_to_copy);
        
        buf += bytes_to_copy;
        current_addr = (char*)current_addr + sizeof(long);
        bytes_remaining -= bytes_to_copy;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_write_memory(pid_t pid, void* addr, const void* data, size_t size) {
    clear_error();
    
    // use process_vm_writev if available (faster for large writes)
    struct iovec local_iov = {
        .iov_base = (void*)data,
        .iov_len = size
    };
    struct iovec remote_iov = {
        .iov_base = addr,
        .iov_len = size
    };
    
    ssize_t bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_written == (ssize_t)size) {
        return LINUX_PTRACE_SUCCESS;
    }
    
    // fallback to ptrace POKEDATA for word-by-word writing
    const char* buf = (const char*)data;
    size_t bytes_remaining = size;
    void* current_addr = addr;
    
    while (bytes_remaining > 0) {
        long word = 0;
        
        // if we're not writing a full word, we need to read-modify-write
        if (bytes_remaining < sizeof(long)) {
            int result = linux_ptrace_peek_data(pid, current_addr, &word);
            if (result != LINUX_PTRACE_SUCCESS) {
                return result;
            }
        }
        
        size_t bytes_to_copy = (bytes_remaining >= sizeof(long)) ? sizeof(long) : bytes_remaining;
        memcpy(&word, buf, bytes_to_copy);
        
        int result = linux_ptrace_poke_data(pid, current_addr, word);
        if (result != LINUX_PTRACE_SUCCESS) {
            return result;
        }
        
        buf += bytes_to_copy;
        current_addr = (char*)current_addr + sizeof(long);
        bytes_remaining -= bytes_to_copy;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

// wait for process signal
int linux_ptrace_wait_for_signal(pid_t pid, int* status) {
    clear_error();
    
    pid_t result = waitpid(pid, status, 0);
    if (result == -1) {
        switch (errno) {
            case ECHILD:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found or not a child");
                break;
            case EINTR:
                set_error(LINUX_PTRACE_SIGNAL, "Interrupted by signal");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to wait for process");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

// architecture-specific implementations
#if defined(__x86_64__)

int linux_ptrace_get_registers(pid_t pid, struct linux_user_regs* regs) {
    clear_error();
    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs->regs) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to get registers");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_set_registers(pid_t pid, const struct linux_user_regs* regs) {
    clear_error();
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs->regs) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to set registers");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_setup_function_call_x86_64(pid_t pid, 
                                           void* func_addr,
                                           void* arg1, void* arg2, void* arg3,
                                           void* arg4, void* arg5, void* arg6,
                                           void** return_addr) {
    clear_error();
    
    struct linux_user_regs regs;
    int result = linux_ptrace_get_registers(pid, &regs);
    if (result != LINUX_PTRACE_SUCCESS) {
        return result;
    }
    
    // save current return address
    if (return_addr) {
        *return_addr = (void*)regs.regs.rip;
    }
    
    // set up x86_64 system v abi calling convention
    regs.regs.rip = (unsigned long long)func_addr;
    regs.regs.rdi = (unsigned long long)arg1;  // first argument
    regs.regs.rsi = (unsigned long long)arg2;  // second argument
    regs.regs.rdx = (unsigned long long)arg3;  // third argument
    regs.regs.rcx = (unsigned long long)arg4;  // fourth argument
    regs.regs.r8  = (unsigned long long)arg5;  // fifth argument
    regs.regs.r9  = (unsigned long long)arg6;  // sixth argument
    
    // align stack to 16-byte boundary (required by x86_64 abi)
    regs.regs.rsp = (regs.regs.rsp & ~0xf) - 8;
    
    return linux_ptrace_set_registers(pid, &regs);
}

#elif defined(__aarch64__)

int linux_ptrace_get_registers(pid_t pid, struct linux_user_regs* regs) {
    clear_error();
    
    struct iovec iov = {
        .iov_base = &regs->regs,
        .iov_len = sizeof(regs->regs)
    };
    
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to get registers");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_set_registers(pid_t pid, const struct linux_user_regs* regs) {
    clear_error();
    
    struct iovec iov = {
        .iov_base = (void*)&regs->regs,
        .iov_len = sizeof(regs->regs)
    };
    
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        switch (errno) {
            case ESRCH:
                set_error(LINUX_PTRACE_NO_PROCESS, "Process not found");
                break;
            case EPERM:
                set_error(LINUX_PTRACE_PERMISSION, "Permission denied");
                break;
            default:
                set_error(LINUX_PTRACE_ERROR, "Failed to set registers");
                break;
        }
        return g_last_error;
    }
    
    return LINUX_PTRACE_SUCCESS;
}

int linux_ptrace_setup_function_call_aarch64(pid_t pid,
                                            void* func_addr,
                                            void* arg1, void* arg2, void* arg3,
                                            void* arg4, void* arg5, void* arg6,
                                            void** return_addr) {
    clear_error();
    
    struct linux_user_regs regs;
    int result = linux_ptrace_get_registers(pid, &regs);
    if (result != LINUX_PTRACE_SUCCESS) {
        return result;
    }
    
    // save current return address
    if (return_addr) {
        *return_addr = (void*)regs.regs.pc;
    }
    
    // set up aarch64 procedure call standard
    regs.regs.pc = (unsigned long long)func_addr;
    regs.regs.regs[0] = (unsigned long long)arg1;  // x0 - first argument
    regs.regs.regs[1] = (unsigned long long)arg2;  // x1 - second argument
    regs.regs.regs[2] = (unsigned long long)arg3;  // x2 - third argument
    regs.regs.regs[3] = (unsigned long long)arg4;  // x3 - fourth argument
    regs.regs.regs[4] = (unsigned long long)arg5;  // x4 - fifth argument
    regs.regs.regs[5] = (unsigned long long)arg6;  // x5 - sixth argument
    
    // x30 is the link register - set to a known value to detect return
    regs.regs.regs[30] = 0;
    
    return linux_ptrace_set_registers(pid, &regs);
}

#endif

// error handling
const char* linux_ptrace_strerror(int error_code) {
    switch (error_code) {
        case LINUX_PTRACE_SUCCESS:
            return "Success";
        case LINUX_PTRACE_ERROR:
            return g_error_buffer[0] ? g_error_buffer : "Unknown error";
        case LINUX_PTRACE_NO_PROCESS:
            return "Process not found";
        case LINUX_PTRACE_PERMISSION:
            return "Permission denied";
        case LINUX_PTRACE_INVALID_ADDR:
            return "Invalid memory address";
        case LINUX_PTRACE_TIMEOUT:
            return "Operation timed out";
        case LINUX_PTRACE_SIGNAL:
            return "Interrupted by signal";
        default:
            return "Unknown error code";
    }
}