#define _GNU_SOURCE
#include "linux_shellcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <elf.h>
#include <fcntl.h>

// Architecture-specific includes
#if defined(__aarch64__) || defined(__arm__)
#include <asm/ptrace.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
// Define ARM64 register structure if not available
#ifndef __has_include
#define __has_include(x) 0
#endif
#if defined(__aarch64__) && !__has_include(<asm/ptrace.h>)
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
#endif
#endif

// Cross-architecture ptrace compatibility
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETREGSET
#define PTRACE_GETREGSET 0x4204
#endif
#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

// Architecture-specific register structures
typedef union {
    struct user_regs_struct x86_regs;
#if defined(__aarch64__)
    struct user_pt_regs arm_regs;
#endif
} unified_regs_t;

// x86_64 shellcode templates
static const unsigned char x86_64_mmap_shellcode[] = {
    // mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    0x48, 0x31, 0xc0,                   // xor rax, rax
    0x48, 0x31, 0xff,                   // xor rdi, rdi      ; addr = NULL
    0x48, 0xbe, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, size (placeholder)
    0x48, 0xc7, 0xc2, 0x07, 0x00, 0x00, 0x00, // mov rdx, 7     ; PROT_READ|PROT_WRITE|PROT_EXEC
    0x48, 0xc7, 0xc1, 0x22, 0x00, 0x00, 0x00, // mov rcx, 0x22  ; MAP_PRIVATE|MAP_ANONYMOUS
    0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff, // mov r8, -1     ; fd = -1
    0x4d, 0x31, 0xc9,                   // xor r9, r9        ; offset = 0
    0x48, 0xc7, 0xc0, 0x09, 0x00, 0x00, 0x00, // mov rax, 9    ; SYS_mmap
    0x0f, 0x05,                         // syscall
    0xcc                                // int3 (breakpoint)
};

static const unsigned char x86_64_dlopen_shellcode[] = {
    // setup stack frame
    0x55,                               // push rbp
    0x48, 0x89, 0xe5,                   // mov rbp, rsp
    0x48, 0x83, 0xec, 0x10,             // sub rsp, 16
    
    // call dlopen(path, flags)
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, path_addr (placeholder)
    0x48, 0xbe, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, RTLD_NOW (placeholder)
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, dlopen_addr (placeholder)
    0xff, 0xd0,                         // call rax
    
    // cleanup and return
    0x48, 0x89, 0xc3,                   // mov rbx, rax (save return value)
    0x48, 0x89, 0xec,                   // mov rsp, rbp
    0x5d,                               // pop rbp
    0xcc                                // int3 (breakpoint)
};

// ARM64 shellcode templates
static const unsigned char arm64_mmap_shellcode[] = {
    // mmap(NULL, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    0x00, 0x00, 0x80, 0xd2,             // mov x0, #0        ; addr = NULL
    0x01, 0x00, 0x80, 0xd2,             // mov x1, #size     ; size (placeholder)
    0xe2, 0x00, 0x80, 0x52,             // mov w2, #7        ; PROT_READ|PROT_WRITE|PROT_EXEC
    0x43, 0x04, 0x80, 0x52,             // mov w3, #0x22     ; MAP_PRIVATE|MAP_ANONYMOUS
    0xe4, 0x03, 0x9f, 0x52,             // mov w4, #-1       ; fd = -1
    0x05, 0x00, 0x80, 0xd2,             // mov x5, #0        ; offset = 0
    0x28, 0x08, 0x80, 0xd2,             // mov x8, #0x41     ; SYS_mmap (222)
    0x01, 0x00, 0x00, 0xd4,             // svc #0            ; syscall
    0x20, 0x00, 0x20, 0xd4              // brk #1            ; breakpoint
};

static const unsigned char arm64_dlopen_shellcode[] = {
    // setup stack frame
    0xfd, 0x7b, 0xbf, 0xa9,             // stp x29, x30, [sp, #-16]!
    0xfd, 0x03, 0x00, 0x91,             // mov x29, sp
    
    // call dlopen(path, flags)
    0x00, 0x00, 0x80, 0xd2,             // mov x0, path_addr (placeholder)
    0x41, 0x00, 0x80, 0x52,             // mov w1, #2        ; RTLD_NOW
    0x02, 0x00, 0x80, 0xd2,             // mov x2, dlopen_addr (placeholder)
    0x40, 0x00, 0x3f, 0xd6,             // blr x2
    
    // cleanup and return
    0xfd, 0x7b, 0xc1, 0xa8,             // ldp x29, x30, [sp], #16
    0x20, 0x00, 0x20, 0xd4              // brk #1            ; breakpoint
};

// utility functions
static const char* error_messages[] = {
    "Success",
    "Generic error",
    "Out of memory",
    "Process not found",
    "Permission denied",
    "Unsupported architecture",
    "Invalid arguments",
    "Ptrace operation failed",
    "Memory write failed",
    "Memory read failed",
    "Process wait failed"
};

const char* linux_shellcode_error_string(int error_code) {
    int index = -error_code;
    if (index < 0 || index >= sizeof(error_messages) / sizeof(error_messages[0])) {
        return "Unknown error";
    }
    return error_messages[index];
}

linux_arch_t linux_detect_process_architecture(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return ARCH_UNKNOWN;
    }
    
    unsigned char elf_header[64];
    if (read(fd, elf_header, sizeof(elf_header)) < 16) {
        close(fd);
        return ARCH_UNKNOWN;
    }
    
    close(fd);
    
    // check ELF magic
    if (memcmp(elf_header, ELFMAG, SELFMAG) != 0) {
        return ARCH_UNKNOWN;
    }
    
    // check architecture
    uint16_t machine = *(uint16_t*)(elf_header + 18);
    switch (machine) {
        case EM_X86_64:
            return ARCH_X86_64;
        case EM_AARCH64:
            return ARCH_ARM64;
        case EM_ARM:
            return ARCH_ARM32;
        case EM_386:
            return ARCH_I386;
        default:
            return ARCH_UNKNOWN;
    }
}

const char* linux_arch_to_string(linux_arch_t arch) {
    switch (arch) {
        case ARCH_X86_64: return "x86_64";
        case ARCH_ARM64: return "arm64";
        case ARCH_ARM32: return "arm32";
        case ARCH_I386: return "i386";
        default: return "unknown";
    }
}

size_t linux_get_pointer_size(linux_arch_t arch) {
    switch (arch) {
        case ARCH_X86_64:
        case ARCH_ARM64:
            return 8;
        case ARCH_ARM32:
        case ARCH_I386:
            return 4;
        default:
            return 0;
    }
}

size_t linux_get_register_size(linux_arch_t arch) {
    const linux_arch_info_t* info = linux_get_arch_info(arch);
    return info ? info->reg_size : 0;
}

int linux_attach_process(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
    }
    
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return LINUX_SHELLCODE_ERROR_PROCESS_WAIT_FAILED;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_detach_process(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
        return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_get_process_registers(pid_t pid, void** regs) {
    linux_arch_t arch = linux_detect_process_architecture(pid);
    size_t reg_size = linux_get_register_size(arch);
    
    if (reg_size == 0) {
        return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    *regs = malloc(reg_size);
    if (!*regs) {
        return LINUX_SHELLCODE_ERROR_NO_MEMORY;
    }
    
    // Use runtime architecture detection instead of compile-time
    switch (arch) {
        case ARCH_X86_64:
        case ARCH_I386:
            if (ptrace(PTRACE_GETREGS, pid, NULL, *regs) < 0) {
                free(*regs);
                *regs = NULL;
                return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
            }
            break;
            
        case ARCH_ARM64:
        case ARCH_ARM32: {
#if defined(__aarch64__) || defined(__arm__)
            struct iovec iov = { .iov_base = *regs, .iov_len = reg_size };
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
                free(*regs);
                *regs = NULL;
                return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
            }
#else
            // Cross-compilation case - try GETREGSET first, fallback to GETREGS
            struct iovec iov = { .iov_base = *regs, .iov_len = reg_size };
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
                if (ptrace(PTRACE_GETREGS, pid, NULL, *regs) < 0) {
                    free(*regs);
                    *regs = NULL;
                    return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
                }
            }
#endif
            break;
        }
        
        default:
            free(*regs);
            *regs = NULL;
            return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_set_process_registers(pid_t pid, void* regs) {
    linux_arch_t arch = linux_detect_process_architecture(pid);
    size_t reg_size = linux_get_register_size(arch);
    
    switch (arch) {
        case ARCH_X86_64:
        case ARCH_I386:
            if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
                return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
            }
            break;
            
        case ARCH_ARM64:
        case ARCH_ARM32: {
#if defined(__aarch64__) || defined(__arm__)
            struct iovec iov = { .iov_base = regs, .iov_len = reg_size };
            if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
                return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
            }
#else
            // Cross-compilation case - try SETREGSET first, fallback to SETREGS
            struct iovec iov = { .iov_base = regs, .iov_len = reg_size };
            if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
                if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
                    return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
                }
            }
#endif
            break;
        }
        
        default:
            return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_continue_process(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        return LINUX_SHELLCODE_ERROR_PTRACE_FAILED;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_wait_for_process(pid_t pid) {
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        return LINUX_SHELLCODE_ERROR_PROCESS_WAIT_FAILED;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_write_remote_memory(pid_t pid, void* dest, const void* src, size_t size) {
    struct iovec local_iov = { .iov_base = (void*)src, .iov_len = size };
    struct iovec remote_iov = { .iov_base = dest, .iov_len = size };
    
    ssize_t bytes_written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_written < 0 || (size_t)bytes_written != size) {
        // fallback to ptrace if process_vm_writev fails
        for (size_t i = 0; i < size; i += sizeof(long)) {
            long word = 0;
            size_t remaining = size - i;
            size_t copy_size = remaining < sizeof(long) ? remaining : sizeof(long);
            
            // read existing word if we're not writing a full word
            if (copy_size < sizeof(long)) {
                errno = 0;
                word = ptrace(PTRACE_PEEKDATA, pid, (char*)dest + i, NULL);
                if (errno != 0) {
                    return LINUX_SHELLCODE_ERROR_MEMORY_READ_FAILED;
                }
            }
            
            // copy our data into the word
            memcpy(&word, (char*)src + i, copy_size);
            
            // write the word
            if (ptrace(PTRACE_POKEDATA, pid, (char*)dest + i, word) < 0) {
                return LINUX_SHELLCODE_ERROR_MEMORY_WRITE_FAILED;
            }
        }
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_read_remote_memory(pid_t pid, void* src, void* dest, size_t size) {
    struct iovec local_iov = { .iov_base = dest, .iov_len = size };
    struct iovec remote_iov = { .iov_base = src, .iov_len = size };
    
    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read < 0 || (size_t)bytes_read != size) {
        // fallback to ptrace if process_vm_readv fails
        for (size_t i = 0; i < size; i += sizeof(long)) {
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, pid, (char*)src + i, NULL);
            if (errno != 0) {
                return LINUX_SHELLCODE_ERROR_MEMORY_READ_FAILED;
            }
            
            size_t remaining = size - i;
            size_t copy_size = remaining < sizeof(long) ? remaining : sizeof(long);
            memcpy((char*)dest + i, &word, copy_size);
        }
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_allocate_remote_memory(pid_t pid, size_t size, void** addr) {
    linux_arch_t arch = linux_detect_process_architecture(pid);
    
    // generate mmap shellcode
    void* shellcode;
    size_t shellcode_size;
    int ret = linux_generate_mmap_shellcode(arch, size, &shellcode, &shellcode_size);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        return ret;
    }
    
    // execute shellcode to allocate memory
    void* result;
    ret = linux_inject_and_execute_shellcode(pid, shellcode, shellcode_size, &result);
    linux_free_shellcode(shellcode);
    
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        return ret;
    }
    
    // check if mmap succeeded (returns MAP_FAILED on error)
    if (result == MAP_FAILED) {
        return LINUX_SHELLCODE_ERROR_NO_MEMORY;
    }
    
    *addr = result;
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_free_remote_memory(pid_t pid, void* addr, size_t size) {
    linux_arch_t arch = linux_detect_process_architecture(pid);
    
    // generate munmap shellcode
    void* shellcode;
    size_t shellcode_size;
    int ret = linux_generate_munmap_shellcode(arch, addr, size, &shellcode, &shellcode_size);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        return ret;
    }
    
    // execute shellcode to free memory
    void* result;
    ret = linux_inject_and_execute_shellcode(pid, shellcode, shellcode_size, &result);
    linux_free_shellcode(shellcode);
    
    return ret;
}

int linux_generate_mmap_shellcode(linux_arch_t arch, size_t size, void** shellcode, size_t* shellcode_size) {
    if (!shellcode || !shellcode_size) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    switch (arch) {
        case ARCH_X86_64: {
            *shellcode_size = sizeof(x86_64_mmap_shellcode);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, x86_64_mmap_shellcode, *shellcode_size);
            
            // patch size parameter (offset 8 in the shellcode)
            *(uint64_t*)((char*)*shellcode + 8) = size;
            break;
        }
        
        case ARCH_ARM64: {
            *shellcode_size = sizeof(arm64_mmap_shellcode);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, arm64_mmap_shellcode, *shellcode_size);
            
            // patch size parameter (modify the mov instruction)
            // ARM64 immediate encoding is complex, so we'll use a simple approach
            // for sizes that fit in 16 bits
            if (size <= 0xFFFF) {
                uint32_t* instr = (uint32_t*)((char*)*shellcode + 4);
                *instr = 0xd2800001 | ((size & 0xFFFF) << 5); // mov x1, #size
            } else {
                // for larger sizes, we'd need more complex immediate encoding
                free(*shellcode);
                return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
            }
            break;
        }
        
        default:
            return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_generate_munmap_shellcode(linux_arch_t arch, void* addr, size_t size, void** shellcode, size_t* shellcode_size) {
    if (!shellcode || !shellcode_size) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    // simplified munmap shellcode templates
    static const unsigned char x86_64_munmap_template[] = {
        0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, addr
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, size
        0x48, 0xc7, 0xc0, 0x0b, 0x00, 0x00, 0x00,                   // mov rax, 11 (SYS_munmap)
        0x0f, 0x05,                                                 // syscall
        0xcc                                                        // int3
    };
    
    static const unsigned char arm64_munmap_template[] = {
        0x00, 0x00, 0x80, 0xd2,             // mov x0, addr (placeholder)
        0x01, 0x00, 0x80, 0xd2,             // mov x1, size (placeholder)
        0x68, 0x01, 0x80, 0xd2,             // mov x8, 11 (SYS_munmap)
        0x01, 0x00, 0x00, 0xd4,             // svc #0
        0x20, 0x00, 0x20, 0xd4              // brk #1
    };
    
    switch (arch) {
        case ARCH_X86_64: {
            *shellcode_size = sizeof(x86_64_munmap_template);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, x86_64_munmap_template, *shellcode_size);
            
            // patch addr and size parameters
            *(uint64_t*)((char*)*shellcode + 2) = (uint64_t)addr;
            *(uint64_t*)((char*)*shellcode + 12) = size;
            break;
        }
        
        case ARCH_ARM64: {
            *shellcode_size = sizeof(arm64_munmap_template);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, arm64_munmap_template, *shellcode_size);
            
            // patch addr and size (simplified for demonstration)
            // in real implementation, would need proper ARM64 immediate encoding
            break;
        }
        
        default:
            return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_generate_dlopen_call_shellcode(linux_arch_t arch, void* dlopen_addr, void* path_addr, int flags, void** shellcode, size_t* shellcode_size) {
    if (!shellcode || !shellcode_size || !dlopen_addr || !path_addr) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    switch (arch) {
        case ARCH_X86_64: {
            *shellcode_size = sizeof(x86_64_dlopen_shellcode);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, x86_64_dlopen_shellcode, *shellcode_size);
            
            // patch parameters
            *(uint64_t*)((char*)*shellcode + 9) = (uint64_t)path_addr;    // path_addr
            *(uint64_t*)((char*)*shellcode + 19) = (uint64_t)flags;       // flags
            *(uint64_t*)((char*)*shellcode + 29) = (uint64_t)dlopen_addr; // dlopen_addr
            break;
        }
        
        case ARCH_ARM64: {
            *shellcode_size = sizeof(arm64_dlopen_shellcode);
            *shellcode = malloc(*shellcode_size);
            if (!*shellcode) {
                return LINUX_SHELLCODE_ERROR_NO_MEMORY;
            }
            
            memcpy(*shellcode, arm64_dlopen_shellcode, *shellcode_size);
            
            // patch parameters (simplified implementation)
            // would need proper ARM64 immediate encoding for full implementation
            break;
        }
        
        default:
            return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_generate_dlopen_shellcode(const char* library_path, linux_arch_t arch, void** shellcode, size_t* size) {
    if (!library_path || !shellcode || !size) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    // this is a simplified implementation
    // full implementation would need to resolve dlopen address and create complete shellcode
    return LINUX_SHELLCODE_ERROR_GENERIC;
}

int linux_inject_and_execute_shellcode(pid_t pid, void* shellcode, size_t size, void** result) {
    if (!shellcode || size == 0) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    int ret;
    void* orig_regs = NULL;
    void* remote_addr = NULL;
    
    // attach to process
    ret = linux_attach_process(pid);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        return ret;
    }
    
    // save original registers
    ret = linux_get_process_registers(pid, &orig_regs);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // allocate memory in target process
    ret = linux_allocate_remote_memory(pid, size, &remote_addr);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // write shellcode to target process
    ret = linux_write_remote_memory(pid, remote_addr, shellcode, size);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // modify registers to point to shellcode
    linux_arch_t arch = linux_detect_process_architecture(pid);
    if (arch == ARCH_X86_64) {
        struct user_regs_struct* regs = (struct user_regs_struct*)orig_regs;
        // Set instruction pointer based on target architecture, not host
        switch (arch) {
            case ARCH_X86_64:
#ifdef __x86_64__
                ((struct user_regs_struct*)regs)->rip = (unsigned long)remote_addr;
#else
                *((uint64_t*)((char*)regs + 128)) = (unsigned long)remote_addr;
#endif
                break;
            case ARCH_I386:
                // Use offset-based access for cross-platform compatibility
                *((uint32_t*)((char*)regs + 48)) = (unsigned long)remote_addr; // eip offset
                break;
            case ARCH_ARM64:
#ifdef __aarch64__
                // On ARM64, user_regs_struct has pc field
                ((struct user_regs_struct*)regs)->pc = (unsigned long)remote_addr;
#else
                // Cross-compilation: ARM64 pc is at offset 248 in user_pt_regs
                *((uint64_t*)((char*)regs + 248)) = (unsigned long)remote_addr;
#endif
                break;
            case ARCH_ARM32:
                // ARM32 PC is at offset 60 in user_regs
                *((uint32_t*)((char*)regs + 60)) = (unsigned long)remote_addr;
                break;
            default:
                return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
        }
    } 
#if defined(__aarch64__)
    else if (arch == ARCH_ARM64) {
        struct user_pt_regs* regs = (struct user_pt_regs*)orig_regs;
        regs->pc = (unsigned long)remote_addr;
    } 
#endif
    else {
        ret = LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
        goto cleanup;
    }
    
    // set modified registers
    ret = linux_set_process_registers(pid, orig_regs);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // continue execution
    ret = linux_continue_process(pid);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // wait for breakpoint
    ret = linux_wait_for_process(pid);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    // get result from return register
    void* current_regs;
    ret = linux_get_process_registers(pid, &current_regs);
    if (ret != LINUX_SHELLCODE_SUCCESS) {
        goto cleanup;
    }
    
    if (result) {
        if (arch == ARCH_X86_64) {
            struct user_regs_struct* regs = (struct user_regs_struct*)current_regs;
            // Get return value using offset-based access for cross-platform compatibility
            switch (arch) {
                case ARCH_X86_64:
#ifdef __x86_64__
                    *result = (void*)((struct user_regs_struct*)regs)->rax;
#else
                    *result = (void*)*((uint64_t*)((char*)regs + 80)); // rax offset
#endif
                    break;
                case ARCH_I386:
                    *result = (void*)(uintptr_t)*((uint32_t*)((char*)regs + 24)); // eax offset
                    break;
                case ARCH_ARM64:
#ifdef __aarch64__
                    // On ARM64, user_regs_struct.regs[0] is x0 return register
                    *result = (void*)((struct user_regs_struct*)regs)->regs[0];
#else
                    // Cross-compilation: ARM64 x0 register is at offset 0
                    *result = (void*)*((uint64_t*)regs);
#endif
                    break;
                case ARCH_ARM32:
                    // ARM32 r0 is at offset 0
                    *result = (void*)(uintptr_t)*((uint32_t*)regs);
                    break;
                default:
                    *result = NULL;
                    break;
            }
        } 
#if defined(__aarch64__)
        else if (arch == ARCH_ARM64) {
            struct user_pt_regs* regs = (struct user_pt_regs*)current_regs;
            *result = (void*)regs->regs[0];
        }
#endif
    }
    
    free(current_regs);

cleanup:
    if (remote_addr) {
        linux_free_remote_memory(pid, remote_addr, size);
    }
    
    if (orig_regs) {
        free(orig_regs);
    }
    
    linux_detach_process(pid);
    return ret;
}

int linux_call_remote_function(pid_t pid, void* func_addr, void** args, size_t arg_count, void** result) {
    if (!func_addr || arg_count > 6) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    linux_arch_t arch = linux_detect_process_architecture(pid);
    
    // generate function call shellcode
    void* shellcode;
    size_t shellcode_size;
    
    // this would need a proper implementation for function calls
    // with argument setup according to calling conventions
    return LINUX_SHELLCODE_ERROR_GENERIC;
}

void linux_free_shellcode(void* shellcode) {
    if (shellcode) {
        free(shellcode);
    }
}

int linux_create_shellcode_context(pid_t pid, linux_shellcode_ctx_t** ctx) {
    if (!ctx) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    *ctx = malloc(sizeof(linux_shellcode_ctx_t));
    if (!*ctx) {
        return LINUX_SHELLCODE_ERROR_NO_MEMORY;
    }
    
    memset(*ctx, 0, sizeof(linux_shellcode_ctx_t));
    
    (*ctx)->pid = pid;
    (*ctx)->arch = linux_detect_process_architecture(pid);
    
    if ((*ctx)->arch == ARCH_UNKNOWN) {
        free(*ctx);
        *ctx = NULL;
        return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

void linux_destroy_shellcode_context(linux_shellcode_ctx_t* ctx) {
    if (ctx) {
        if (ctx->original_regs) {
            free(ctx->original_regs);
        }
        free(ctx);
    }
}

int linux_execute_shellcode_in_context(linux_shellcode_ctx_t* ctx, void* shellcode, size_t size, void** result) {
    if (!ctx || !shellcode || size == 0) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    return linux_inject_and_execute_shellcode(ctx->pid, shellcode, size, result);
}