#pragma once

#include "linux_shellcode.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// calling convention structures
typedef struct {
    void* args[6];    // maximum 6 arguments for most calling conventions
    size_t arg_count;
    linux_arch_t arch;
} linux_function_call_t;

// symbol resolution
typedef struct {
    void* base_address;
    char* library_name;
    void* dlopen_addr;
    void* dlsym_addr;
    void* dlclose_addr;
} linux_symbol_info_t;

// advanced shellcode generation
int linux_generate_function_call_shellcode(linux_arch_t arch, void* func_addr, 
                                          linux_function_call_t* call_info, 
                                          void** shellcode, size_t* shellcode_size);

int linux_generate_symbol_resolution_shellcode(linux_arch_t arch, 
                                              const char* library_name,
                                              const char* symbol_name,
                                              void** shellcode, size_t* shellcode_size);

// process memory mapping analysis
typedef struct {
    void* start_addr;
    void* end_addr;
    char permissions[8];  // rwxp format
    char* path;
} linux_memory_map_t;

int linux_get_process_memory_maps(pid_t pid, linux_memory_map_t** maps, size_t* map_count);
void linux_free_memory_maps(linux_memory_map_t* maps, size_t map_count);

// library loading utilities
int linux_find_library_base(pid_t pid, const char* library_name, void** base_addr);
int linux_resolve_symbol_address(pid_t pid, const char* library_name, 
                                const char* symbol_name, void** symbol_addr);

// shellcode encoding and obfuscation
int linux_encode_shellcode_xor(void* shellcode, size_t size, uint8_t key, 
                              void** encoded_shellcode, size_t* encoded_size);

int linux_generate_decoder_shellcode(linux_arch_t arch, uint8_t xor_key, 
                                    size_t encoded_size, void** decoder, size_t* decoder_size);

// injection methods
typedef enum {
    INJECTION_METHOD_PTRACE,
    INJECTION_METHOD_PROC_MEM,
    INJECTION_METHOD_SHARED_MEMORY,
    INJECTION_METHOD_SIGNAL_HANDLER
} linux_injection_method_t;

int linux_inject_using_method(pid_t pid, void* shellcode, size_t size, 
                             linux_injection_method_t method, void** result);

// anti-debugging and evasion
int linux_check_debugger_presence(pid_t pid, int* is_debugged);
int linux_generate_anti_debug_shellcode(linux_arch_t arch, void** shellcode, size_t* shellcode_size);

// process environment manipulation
int linux_set_remote_environment_variable(pid_t pid, const char* name, const char* value);
int linux_get_remote_environment_variable(pid_t pid, const char* name, char** value);

// thread injection
typedef struct {
    pid_t tid;
    void* stack_addr;
    size_t stack_size;
    void* entry_point;
} linux_thread_info_t;

int linux_create_remote_thread(pid_t pid, void* entry_point, void* parameter, 
                              linux_thread_info_t** thread_info);
int linux_wait_for_remote_thread(linux_thread_info_t* thread_info, void** exit_code);
void linux_destroy_thread_info(linux_thread_info_t* thread_info);

// shellcode templates for complex operations
extern const unsigned char linux_x86_64_thread_create_shellcode[];
extern const size_t linux_x86_64_thread_create_shellcode_size;

extern const unsigned char linux_arm64_thread_create_shellcode[];
extern const size_t linux_arm64_thread_create_shellcode_size;

extern const unsigned char linux_x86_64_env_manipulation_shellcode[];
extern const size_t linux_x86_64_env_manipulation_shellcode_size;

extern const unsigned char linux_arm64_env_manipulation_shellcode[];
extern const size_t linux_arm64_env_manipulation_shellcode_size;

// error handling for utilities
#define LINUX_UTILS_SUCCESS                    0
#define LINUX_UTILS_ERROR_INVALID_ARGS       -1
#define LINUX_UTILS_ERROR_NO_MEMORY          -2
#define LINUX_UTILS_ERROR_SYMBOL_NOT_FOUND   -3
#define LINUX_UTILS_ERROR_LIBRARY_NOT_FOUND  -4
#define LINUX_UTILS_ERROR_ENCODING_FAILED    -5
#define LINUX_UTILS_ERROR_THREAD_CREATION_FAILED -6

const char* linux_utils_error_string(int error_code);

#ifdef __cplusplus
}
#endif