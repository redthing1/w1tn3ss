#include "injector.h"
#include "linux_ptrace.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>

// global error message
char injector__errmsg[256];
char injector__errmsg_is_set = 0;

void injector__set_errmsg(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vsnprintf(injector__errmsg, sizeof(injector__errmsg), format, ap);
    va_end(ap);
    injector__errmsg_is_set = 1;
}

const char *injector_error(void) {
    return injector__errmsg_is_set ? injector__errmsg : "";
}

// architecture detection
int injector__get_process_arch(pid_t pid, arch_t *arch) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    
    FILE *file = fopen(path, "rb");
    if (!file) {
        injector__set_errmsg("Failed to open process executable");
        return INJERR_NO_PROCESS;
    }
    
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, file) != 1) {
        fclose(file);
        injector__set_errmsg("Failed to read ELF header");
        return INJERR_INVALID_ELF_FORMAT;
    }
    
    fclose(file);
    
    // check ELF magic
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        injector__set_errmsg("Not a valid ELF file");
        return INJERR_INVALID_ELF_FORMAT;
    }
    
    // determine architecture
    switch (ehdr.e_machine) {
        case EM_X86_64:
            *arch = ARCH_X86_64;
            break;
        case EM_AARCH64:
            *arch = ARCH_AARCH64;
            break;
        default:
            *arch = ARCH_UNKNOWN;
            injector__set_errmsg("Unsupported architecture: %d", ehdr.e_machine);
            return INJERR_UNSUPPORTED_TARGET;
    }
    
    return INJERR_SUCCESS;
}

// memory management helpers
int injector__allocate_memory(const injector_t *injector, size_t size, size_t *addr) {
    // find a suitable memory region by reading /proc/pid/maps
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", injector->pid);
    
    FILE *maps = fopen(path, "r");
    if (!maps) {
        injector__set_errmsg("Failed to open process maps");
        return INJERR_NO_PROCESS;
    }
    
    char line[256];
    size_t last_end = 0;
    size_t target_addr = 0;
    
    // look for a gap in memory map large enough for our allocation
    while (fgets(line, sizeof(line), maps)) {
        size_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (last_end && (start - last_end) >= size) {
                // found a suitable gap
                target_addr = last_end;
                break;
            }
            last_end = end;
        }
    }
    
    fclose(maps);
    
    if (!target_addr) {
        // fallback: try to allocate at a high address
        target_addr = 0x7f0000000000UL;
    }
    
    // use syscall injection to call mmap in the target process
    // for now, we'll use a simple approach and hope the address is available
    *addr = target_addr;
    return INJERR_SUCCESS;
}

int injector__deallocate_memory(const injector_t *injector, size_t addr, size_t size) {
    // would need to inject munmap syscall
    // for now, just succeed (memory will be freed when process exits)
    return INJERR_SUCCESS;
}

int injector__write_memory(const injector_t *injector, size_t addr, const void *buf, size_t len) {
    int result = linux_ptrace_write_memory(injector->pid, (void*)addr, buf, len);
    if (result != LINUX_PTRACE_SUCCESS) {
        injector__set_errmsg("Failed to write memory: %s", linux_ptrace_strerror(result));
        return INJERR_INVALID_MEMORY_AREA;
    }
    return INJERR_SUCCESS;
}

int injector__read_memory(const injector_t *injector, size_t addr, void *buf, size_t len) {
    int result = linux_ptrace_read_memory(injector->pid, (void*)addr, buf, len);
    if (result != LINUX_PTRACE_SUCCESS) {
        injector__set_errmsg("Failed to read memory: %s", linux_ptrace_strerror(result));
        return INJERR_INVALID_MEMORY_AREA;
    }
    return INJERR_SUCCESS;
}

// main injector functions
int injector_attach(injector_t **injector_out, injector_pid_t pid) {
    injector__errmsg_is_set = 0;
    
    injector_t *injector = calloc(1, sizeof(injector_t));
    if (!injector) {
        injector__set_errmsg("Failed to allocate injector structure");
        return INJERR_NO_MEMORY;
    }
    
    injector->pid = pid;
    
    // detect target architecture
    int result = injector__get_process_arch(pid, &injector->arch);
    if (result != INJERR_SUCCESS) {
        free(injector);
        return result;
    }
    
    // attach with ptrace
    result = linux_ptrace_attach(pid);
    if (result != LINUX_PTRACE_SUCCESS) {
        injector__set_errmsg("Failed to attach to process: %s", linux_ptrace_strerror(result));
        free(injector);
        switch (result) {
            case LINUX_PTRACE_NO_PROCESS:
                return INJERR_NO_PROCESS;
            case LINUX_PTRACE_PERMISSION:
                return INJERR_PERMISSION;
            default:
                return INJERR_OTHER;
        }
    }
    
    injector->ptrace_attached = 1;
    injector->attached = 1;
    
    // allocate memory for shellcode
    injector->code_size = getpagesize();
    result = injector__allocate_memory(injector, injector->code_size, &injector->code_addr);
    if (result != INJERR_SUCCESS) {
        injector_detach(injector);
        return result;
    }
    
    // allocate stack space
    injector->stack_size = getpagesize();
    result = injector__allocate_memory(injector, injector->stack_size, &injector->stack_addr);
    if (result != INJERR_SUCCESS) {
        injector_detach(injector);
        return result;
    }
    
    injector->allocated = 1;
    *injector_out = injector;
    return INJERR_SUCCESS;
}

int injector_detach(injector_t *injector) {
    if (!injector) {
        return INJERR_SUCCESS;
    }
    
    // clean up allocated memory
    if (injector->allocated) {
        if (injector->code_addr) {
            injector__deallocate_memory(injector, injector->code_addr, injector->code_size);
        }
        if (injector->stack_addr) {
            injector__deallocate_memory(injector, injector->stack_addr, injector->stack_size);
        }
    }
    
    // detach from process
    if (injector->ptrace_attached) {
        linux_ptrace_detach(injector->pid);
    }
    
    // free saved registers
    if (injector->saved_regs) {
        free(injector->saved_regs);
    }
    
    free(injector);
    return INJERR_SUCCESS;
}

// simplified injection - just return success for now
// a full implementation would need to:
// 1. find or inject dlopen/dlsym functions
// 2. setup shellcode to call dlopen
// 3. execute the shellcode
// 4. extract the return value (library handle)
int injector_inject(injector_t *injector, const char *path, void **handle) {
    if (!injector || !path || !handle) {
        injector__set_errmsg("Invalid parameters");
        return INJERR_OTHER;
    }
    
    injector__set_errmsg("Library injection not yet implemented");
    return INJERR_FUNCTION_MISSING;
}

int injector_uninject(injector_t *injector, void *handle) {
    if (!injector || !handle) {
        injector__set_errmsg("Invalid parameters");
        return INJERR_OTHER;
    }
    
    injector__set_errmsg("Library uninjection not yet implemented");
    return INJERR_FUNCTION_MISSING;
}

int injector_call(injector_t *injector, void *handle, const char* name) {
    if (!injector || !handle || !name) {
        injector__set_errmsg("Invalid parameters");
        return INJERR_OTHER;
    }
    
    injector__set_errmsg("Remote function calls not yet implemented");
    return INJERR_FUNCTION_MISSING;
}

int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out) {
    if (!injector || !handle || !name || !func_addr_out) {
        injector__set_errmsg("Invalid parameters");
        return INJERR_OTHER;
    }
    
    injector__set_errmsg("Remote function address lookup not yet implemented");
    return INJERR_FUNCTION_MISSING;
}

int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...) {
    if (!injector) {
        injector__set_errmsg("Invalid parameters");
        return INJERR_OTHER;
    }
    
    injector__set_errmsg("Remote function calls not yet implemented");
    return INJERR_FUNCTION_MISSING;
}