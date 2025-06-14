/* -*- indent-tabs-mode: nil -*-
 *
 * w1tn3ss - Linux process injection backend
 *
 * ------------------------------------------------------
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */
#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// error codes compatible with darwin backend
#define INJERR_SUCCESS 0
#define INJERR_OTHER -1
#define INJERR_NO_MEMORY -2
#define INJERR_NO_PROCESS -3
#define INJERR_NO_LIBRARY -4
#define INJERR_NO_FUNCTION -4
#define INJERR_ERROR_IN_TARGET -5
#define INJERR_FILE_NOT_FOUND -6
#define INJERR_INVALID_MEMORY_AREA -7
#define INJERR_PERMISSION -8
#define INJERR_UNSUPPORTED_TARGET -9
#define INJERR_INVALID_ELF_FORMAT -10
#define INJERR_WAIT_TRACEE -11
#define INJERR_FUNCTION_MISSING -12

typedef struct injector injector_t;
typedef pid_t injector_pid_t;

// basic injector operations
int injector_attach(injector_t **injector, injector_pid_t pid);
int injector_detach(injector_t *injector);
int injector_inject(injector_t *injector, const char *path, void **handle);
int injector_uninject(injector_t *injector, void *handle);

// remote function calls
int injector_call(injector_t *injector, void *handle, const char* name);
int injector_remote_func_addr(injector_t *injector, void *handle, const char* name, size_t *func_addr_out);
int injector_remote_call(injector_t *injector, intptr_t *retval, size_t func_addr, ...);

// error handling
const char *injector_error(void);

// internal linux-specific functions
typedef enum {
    ARCH_X86_64,    
    ARCH_AARCH64,
    ARCH_UNKNOWN
} arch_t;

struct injector {
    pid_t pid;
    uint8_t attached;
    uint8_t allocated;
    uint8_t ptrace_attached;
    
    // memory regions
    size_t code_addr;
    size_t code_size;
    size_t stack_addr;
    size_t stack_size;
    
    // architecture info
    arch_t arch;
    
    // saved state
    void* saved_regs;
    uint8_t state_saved;
    
    // function call state
    long func_addr;
    long args[6];
    long retval;
    int call_error;
};

// internal utility functions
int injector__get_process_arch(pid_t pid, arch_t *arch);
int injector__allocate_memory(const injector_t *injector, size_t size, size_t *addr);
int injector__deallocate_memory(const injector_t *injector, size_t addr, size_t size);
int injector__write_memory(const injector_t *injector, size_t addr, const void *buf, size_t len);
int injector__read_memory(const injector_t *injector, size_t addr, void *buf, size_t len);
int injector__call_function(injector_t *injector, long *retval, long function_addr, ...);

// error message management
extern char injector__errmsg[];
extern char injector__errmsg_is_set;
void injector__set_errmsg(const char *format, ...);

#ifdef __cplusplus
}
#endif