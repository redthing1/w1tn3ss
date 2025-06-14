#include "injector.h"
#include "linux_ptrace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

const char *injector__arch2name(arch_t arch) {
    switch (arch) {
        case ARCH_X86_64:
            return "x86_64";
        case ARCH_AARCH64:
            return "aarch64";
        default:
            return "unknown";
    }
}

arch_t injector__get_system_arch(void) {
#if defined(__x86_64__)
    return ARCH_X86_64;
#elif defined(__aarch64__)
    return ARCH_AARCH64;
#else
    return ARCH_UNKNOWN;
#endif
}

// check if a process exists and is accessible
int injector__check_process_exists(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    
    struct stat st;
    if (stat(path, &st) != 0) {
        return 0; // process doesn't exist
    }
    
    return S_ISDIR(st.st_mode);
}

// get process command line
int injector__get_process_cmdline(pid_t pid, char *buffer, size_t buffer_size) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    
    FILE *file = fopen(path, "r");
    if (!file) {
        return -1;
    }
    
    size_t bytes_read = fread(buffer, 1, buffer_size - 1, file);
    fclose(file);
    
    if (bytes_read == 0) {
        return -1;
    }
    
    buffer[bytes_read] = '\0';
    
    // replace null bytes with spaces for readability
    for (size_t i = 0; i < bytes_read; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }
    
    return 0;
}

// find library base address in target process
size_t injector__find_library_base(pid_t pid, const char *library_name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *maps = fopen(path, "r");
    if (!maps) {
        return 0;
    }
    
    char line[512];
    size_t base_addr = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, library_name)) {
            // parse the address range
            if (sscanf(line, "%lx-", &base_addr) == 1) {
                break;
            }
        }
    }
    
    fclose(maps);
    return base_addr;
}

// read string from target process memory
int injector__read_string(const injector_t *injector, size_t addr, char *buffer, size_t buffer_size) {
    if (!injector || !buffer || buffer_size == 0) {
        return -1;
    }
    
    size_t bytes_read = 0;
    while (bytes_read < buffer_size - 1) {
        char byte;
        if (injector__read_memory(injector, addr + bytes_read, &byte, 1) != INJERR_SUCCESS) {
            return -1;
        }
        
        buffer[bytes_read] = byte;
        bytes_read++;
        
        if (byte == '\0') {
            break;
        }
    }
    
    buffer[bytes_read] = '\0';
    return bytes_read;
}

// write string to target process memory
int injector__write_string(const injector_t *injector, size_t addr, const char *str) {
    if (!injector || !str) {
        return -1;
    }
    
    size_t len = strlen(str) + 1; // include null terminator
    return injector__write_memory(injector, addr, str, len);
}