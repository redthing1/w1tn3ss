#include "linux_shellcode_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>

// advanced shellcode templates
const unsigned char linux_x86_64_thread_create_shellcode[] = {
    // pthread_create shellcode for x86_64
    0x55,                                           // push rbp
    0x48, 0x89, 0xe5,                               // mov rbp, rsp
    0x48, 0x83, 0xec, 0x20,                         // sub rsp, 32
    
    // prepare arguments for pthread_create
    0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,       // mov rdi, 0 (thread ptr placeholder)
    0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00,       // mov rsi, 0 (attr)
    0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, entry_point (placeholder)
    0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, parameter (placeholder)
    
    // call pthread_create
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, pthread_create_addr (placeholder)
    0xff, 0xd0,                                     // call rax
    
    // cleanup and return
    0x48, 0x89, 0xec,                               // mov rsp, rbp
    0x5d,                                           // pop rbp
    0xcc                                            // int3
};

const size_t linux_x86_64_thread_create_shellcode_size = sizeof(linux_x86_64_thread_create_shellcode);

const unsigned char linux_arm64_thread_create_shellcode[] = {
    // pthread_create shellcode for ARM64
    0xfd, 0x7b, 0xbf, 0xa9,                         // stp x29, x30, [sp, #-16]!
    0xfd, 0x03, 0x00, 0x91,                         // mov x29, sp
    
    // prepare arguments for pthread_create
    0x00, 0x00, 0x80, 0xd2,                         // mov x0, 0 (thread ptr placeholder)
    0x01, 0x00, 0x80, 0xd2,                         // mov x1, 0 (attr)
    0x02, 0x00, 0x80, 0xd2,                         // mov x2, entry_point (placeholder)
    0x03, 0x00, 0x80, 0xd2,                         // mov x3, parameter (placeholder)
    
    // call pthread_create
    0x10, 0x00, 0x80, 0xd2,                         // mov x16, pthread_create_addr (placeholder)
    0x00, 0x02, 0x3f, 0xd6,                         // blr x16
    
    // cleanup and return
    0xfd, 0x7b, 0xc1, 0xa8,                         // ldp x29, x30, [sp], #16
    0x20, 0x00, 0x20, 0xd4                          // brk #1
};

const size_t linux_arm64_thread_create_shellcode_size = sizeof(linux_arm64_thread_create_shellcode);

const unsigned char linux_x86_64_env_manipulation_shellcode[] = {
    // setenv/getenv shellcode for x86_64
    0x55,                                           // push rbp
    0x48, 0x89, 0xe5,                               // mov rbp, rsp
    0x48, 0x83, 0xec, 0x10,                         // sub rsp, 16
    
    // call setenv(name, value, 1)
    0x48, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdi, name_addr (placeholder)
    0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, value_addr (placeholder)
    0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00,       // mov rdx, 1 (overwrite)
    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, setenv_addr (placeholder)
    0xff, 0xd0,                                     // call rax
    
    // cleanup and return
    0x48, 0x89, 0xec,                               // mov rsp, rbp
    0x5d,                                           // pop rbp
    0xcc                                            // int3
};

const size_t linux_x86_64_env_manipulation_shellcode_size = sizeof(linux_x86_64_env_manipulation_shellcode);

const unsigned char linux_arm64_env_manipulation_shellcode[] = {
    // setenv/getenv shellcode for ARM64
    0xfd, 0x7b, 0xbf, 0xa9,                         // stp x29, x30, [sp, #-16]!
    0xfd, 0x03, 0x00, 0x91,                         // mov x29, sp
    
    // call setenv(name, value, 1)
    0x00, 0x00, 0x80, 0xd2,                         // mov x0, name_addr (placeholder)
    0x01, 0x00, 0x80, 0xd2,                         // mov x1, value_addr (placeholder)
    0x22, 0x00, 0x80, 0x52,                         // mov w2, 1 (overwrite)
    0x10, 0x00, 0x80, 0xd2,                         // mov x16, setenv_addr (placeholder)
    0x00, 0x02, 0x3f, 0xd6,                         // blr x16
    
    // cleanup and return
    0xfd, 0x7b, 0xc1, 0xa8,                         // ldp x29, x30, [sp], #16
    0x20, 0x00, 0x20, 0xd4                          // brk #1
};

const size_t linux_arm64_env_manipulation_shellcode_size = sizeof(linux_arm64_env_manipulation_shellcode);

static const char* utils_error_messages[] = {
    "Success",
    "Invalid arguments",
    "Out of memory",
    "Symbol not found",
    "Library not found",
    "Encoding failed",
    "Thread creation failed"
};

const char* linux_utils_error_string(int error_code) {
    int index = -error_code;
    if (index < 0 || index >= sizeof(utils_error_messages) / sizeof(utils_error_messages[0])) {
        return "Unknown error";
    }
    return utils_error_messages[index];
}

int linux_generate_function_call_shellcode(linux_arch_t arch, void* func_addr, 
                                          linux_function_call_t* call_info, 
                                          void** shellcode, size_t* shellcode_size) {
    if (!func_addr || !call_info || !shellcode || !shellcode_size) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    if (call_info->arg_count > 6) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    switch (arch) {
        case ARCH_X86_64: {
            // x86_64 System V ABI: RDI, RSI, RDX, RCX, R8, R9
            size_t template_size = 256; // estimated size
            *shellcode = malloc(template_size);
            if (!*shellcode) {
                return LINUX_UTILS_ERROR_NO_MEMORY;
            }
            
            unsigned char* code = (unsigned char*)*shellcode;
            size_t offset = 0;
            
            // prologue
            code[offset++] = 0x55;                      // push rbp
            code[offset++] = 0x48; code[offset++] = 0x89; code[offset++] = 0xe5; // mov rbp, rsp
            
            // set up arguments in registers
            for (size_t i = 0; i < call_info->arg_count; i++) {
                uint64_t arg = (uint64_t)call_info->args[i];
                
                switch (i) {
                    case 0: // RDI
                        code[offset++] = 0x48; code[offset++] = 0xbf; // mov rdi, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                    case 1: // RSI
                        code[offset++] = 0x48; code[offset++] = 0xbe; // mov rsi, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                    case 2: // RDX
                        code[offset++] = 0x48; code[offset++] = 0xba; // mov rdx, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                    case 3: // RCX
                        code[offset++] = 0x48; code[offset++] = 0xb9; // mov rcx, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                    case 4: // R8
                        code[offset++] = 0x49; code[offset++] = 0xb8; // mov r8, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                    case 5: // R9
                        code[offset++] = 0x49; code[offset++] = 0xb9; // mov r9, imm64
                        memcpy(&code[offset], &arg, 8); offset += 8;
                        break;
                }
            }
            
            // call function
            code[offset++] = 0x48; code[offset++] = 0xb8; // mov rax, func_addr
            memcpy(&code[offset], &func_addr, 8); offset += 8;
            code[offset++] = 0xff; code[offset++] = 0xd0; // call rax
            
            // epilogue
            code[offset++] = 0x48; code[offset++] = 0x89; code[offset++] = 0xec; // mov rsp, rbp
            code[offset++] = 0x5d;                      // pop rbp
            code[offset++] = 0xcc;                      // int3
            
            *shellcode_size = offset;
            break;
        }
        
        case ARCH_ARM64: {
            // ARM64 AAPCS: X0-X7 for arguments
            size_t template_size = 256;
            *shellcode = malloc(template_size);
            if (!*shellcode) {
                return LINUX_UTILS_ERROR_NO_MEMORY;
            }
            
            unsigned char* code = (unsigned char*)*shellcode;
            size_t offset = 0;
            
            // prologue
            uint32_t* instr = (uint32_t*)code;
            instr[offset++] = 0xa9bf7bfd; // stp x29, x30, [sp, #-16]!
            instr[offset++] = 0x910003fd; // mov x29, sp
            
            // set up arguments (simplified - would need proper immediate encoding)
            for (size_t i = 0; i < call_info->arg_count && i < 8; i++) {
                // mov xi, #imm (simplified)
                instr[offset++] = 0xd2800000 | i; // placeholder
            }
            
            // call function (simplified)
            instr[offset++] = 0xd2800010; // mov x16, func_addr (placeholder)
            instr[offset++] = 0xd63f0200; // blr x16
            
            // epilogue
            instr[offset++] = 0xa8c17bfd; // ldp x29, x30, [sp], #16
            instr[offset++] = 0xd4200020; // brk #1
            
            *shellcode_size = offset * 4;
            break;
        }
        
        default:
            return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    return LINUX_UTILS_SUCCESS;
}

int linux_get_process_memory_maps(pid_t pid, linux_memory_map_t** maps, size_t* map_count) {
    if (!maps || !map_count) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    FILE* maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // count lines first
    size_t line_count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), maps_file)) {
        line_count++;
    }
    
    rewind(maps_file);
    
    *maps = malloc(line_count * sizeof(linux_memory_map_t));
    if (!*maps) {
        fclose(maps_file);
        return LINUX_UTILS_ERROR_NO_MEMORY;
    }
    
    *map_count = 0;
    while (fgets(line, sizeof(line), maps_file) && *map_count < line_count) {
        linux_memory_map_t* map = &(*maps)[*map_count];
        memset(map, 0, sizeof(linux_memory_map_t));
        
        unsigned long start, end;
        char perms[8];
        char path[512] = {0};
        
        if (sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %511s", 
                   &start, &end, perms, path) >= 3) {
            map->start_addr = (void*)start;
            map->end_addr = (void*)end;
            strncpy(map->permissions, perms, sizeof(map->permissions) - 1);
            
            if (strlen(path) > 0) {
                map->path = strdup(path);
            }
            
            (*map_count)++;
        }
    }
    
    fclose(maps_file);
    return LINUX_UTILS_SUCCESS;
}

void linux_free_memory_maps(linux_memory_map_t* maps, size_t map_count) {
    if (maps) {
        for (size_t i = 0; i < map_count; i++) {
            if (maps[i].path) {
                free(maps[i].path);
            }
        }
        free(maps);
    }
}

int linux_find_library_base(pid_t pid, const char* library_name, void** base_addr) {
    if (!library_name || !base_addr) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    linux_memory_map_t* maps;
    size_t map_count;
    
    int ret = linux_get_process_memory_maps(pid, &maps, &map_count);
    if (ret != LINUX_UTILS_SUCCESS) {
        return ret;
    }
    
    *base_addr = NULL;
    for (size_t i = 0; i < map_count; i++) {
        if (maps[i].path && strstr(maps[i].path, library_name)) {
            *base_addr = maps[i].start_addr;
            break;
        }
    }
    
    linux_free_memory_maps(maps, map_count);
    
    if (!*base_addr) {
        return LINUX_UTILS_ERROR_LIBRARY_NOT_FOUND;
    }
    
    return LINUX_UTILS_SUCCESS;
}

int linux_resolve_symbol_address(pid_t pid, const char* library_name, 
                                const char* symbol_name, void** symbol_addr) {
    if (!library_name || !symbol_name || !symbol_addr) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // simplified implementation - would need full ELF parsing
    // for production use, would parse ELF headers and symbol tables
    
    void* base_addr;
    int ret = linux_find_library_base(pid, library_name, &base_addr);
    if (ret != LINUX_UTILS_SUCCESS) {
        return ret;
    }
    
    // this is a placeholder - real implementation would:
    // 1. read ELF header from target process
    // 2. parse program headers to find dynamic section
    // 3. parse dynamic section to find symbol table
    // 4. search symbol table for the requested symbol
    
    return LINUX_UTILS_ERROR_SYMBOL_NOT_FOUND;
}

int linux_encode_shellcode_xor(void* shellcode, size_t size, uint8_t key, 
                              void** encoded_shellcode, size_t* encoded_size) {
    if (!shellcode || size == 0 || !encoded_shellcode || !encoded_size) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    *encoded_shellcode = malloc(size);
    if (!*encoded_shellcode) {
        return LINUX_UTILS_ERROR_NO_MEMORY;
    }
    
    unsigned char* src = (unsigned char*)shellcode;
    unsigned char* dst = (unsigned char*)*encoded_shellcode;
    
    for (size_t i = 0; i < size; i++) {
        dst[i] = src[i] ^ key;
    }
    
    *encoded_size = size;
    return LINUX_UTILS_SUCCESS;
}

int linux_generate_decoder_shellcode(linux_arch_t arch, uint8_t xor_key, 
                                    size_t encoded_size, void** decoder, size_t* decoder_size) {
    if (!decoder || !decoder_size || encoded_size == 0) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    switch (arch) {
        case ARCH_X86_64: {
            // simple XOR decoder for x86_64
            unsigned char decoder_template[] = {
                0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, encoded_addr
                0x48, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00,                   // mov rcx, size
                0xb0, 0x00,                                                 // mov al, key
                0xac,                                                       // lodsb
                0x30, 0xc0,                                                 // xor al, al (becomes: xor al, key)
                0xaa,                                                       // stosb
                0xe2, 0xfa,                                                 // loop decode_loop
                0xc3                                                        // ret
            };
            
            *decoder_size = sizeof(decoder_template);
            *decoder = malloc(*decoder_size);
            if (!*decoder) {
                return LINUX_UTILS_ERROR_NO_MEMORY;
            }
            
            memcpy(*decoder, decoder_template, *decoder_size);
            
            // patch size and key
            *(uint32_t*)((char*)*decoder + 13) = (uint32_t)encoded_size;
            *((char*)*decoder + 18) = xor_key;
            *((char*)*decoder + 21) = xor_key; // fix XOR instruction
            
            break;
        }
        
        default:
            return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    return LINUX_UTILS_SUCCESS;
}

int linux_inject_using_method(pid_t pid, void* shellcode, size_t size, 
                             linux_injection_method_t method, void** result) {
    if (!shellcode || size == 0) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    switch (method) {
        case INJECTION_METHOD_PTRACE:
            return linux_inject_and_execute_shellcode(pid, shellcode, size, result);
            
        case INJECTION_METHOD_PROC_MEM: {
            // injection via /proc/pid/mem
            char mem_path[256];
            snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
            
            int mem_fd = open(mem_path, O_RDWR);
            if (mem_fd < 0) {
                return LINUX_UTILS_ERROR_INVALID_ARGS;
            }
            
            // find suitable memory region
            void* target_addr = NULL;
            // ... implementation would find executable memory region
            
            close(mem_fd);
            return LINUX_UTILS_ERROR_INVALID_ARGS; // placeholder
        }
        
        default:
            return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
}

int linux_check_debugger_presence(pid_t pid, int* is_debugged) {
    if (!is_debugged) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    char status_path[256];
    snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
    
    FILE* status_file = fopen(status_path, "r");
    if (!status_file) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    char line[256];
    *is_debugged = 0;
    
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = 0;
            if (sscanf(line + 10, "%d", &tracer_pid) == 1 && tracer_pid != 0) {
                *is_debugged = 1;
            }
            break;
        }
    }
    
    fclose(status_file);
    return LINUX_UTILS_SUCCESS;
}

int linux_create_remote_thread(pid_t pid, void* entry_point, void* parameter, 
                              linux_thread_info_t** thread_info) {
    if (!entry_point || !thread_info) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    *thread_info = malloc(sizeof(linux_thread_info_t));
    if (!*thread_info) {
        return LINUX_UTILS_ERROR_NO_MEMORY;
    }
    
    memset(*thread_info, 0, sizeof(linux_thread_info_t));
    
    // simplified implementation - would need to:
    // 1. allocate stack in target process
    // 2. generate thread creation shellcode
    // 3. execute shellcode to create thread
    
    (*thread_info)->entry_point = entry_point;
    (*thread_info)->stack_size = 0x10000; // 64KB stack
    
    return LINUX_UTILS_ERROR_THREAD_CREATION_FAILED; // placeholder
}

int linux_wait_for_remote_thread(linux_thread_info_t* thread_info, void** exit_code) {
    if (!thread_info) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // placeholder implementation
    return LINUX_UTILS_ERROR_INVALID_ARGS;
}

void linux_destroy_thread_info(linux_thread_info_t* thread_info) {
    if (thread_info) {
        free(thread_info);
    }
}

int linux_set_remote_environment_variable(pid_t pid, const char* name, const char* value) {
    if (!name || !value) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // would need to:
    // 1. find setenv function in target process
    // 2. allocate memory for name and value strings
    // 3. generate and execute shellcode to call setenv
    
    return LINUX_UTILS_ERROR_INVALID_ARGS; // placeholder
}

int linux_get_remote_environment_variable(pid_t pid, const char* name, char** value) {
    if (!name || !value) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // would need to:
    // 1. find getenv function in target process
    // 2. allocate memory for name string
    // 3. generate and execute shellcode to call getenv
    // 4. read result from target process memory
    
    return LINUX_UTILS_ERROR_INVALID_ARGS; // placeholder
}

int linux_generate_symbol_resolution_shellcode(linux_arch_t arch, 
                                              const char* library_name,
                                              const char* symbol_name,
                                              void** shellcode, size_t* shellcode_size) {
    if (!library_name || !symbol_name || !shellcode || !shellcode_size) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // would generate shellcode to:
    // 1. call dlopen to load library
    // 2. call dlsym to resolve symbol
    // 3. return symbol address
    
    return LINUX_UTILS_ERROR_INVALID_ARGS; // placeholder
}

int linux_generate_anti_debug_shellcode(linux_arch_t arch, void** shellcode, size_t* shellcode_size) {
    if (!shellcode || !shellcode_size) {
        return LINUX_UTILS_ERROR_INVALID_ARGS;
    }
    
    // would generate shellcode to:
    // 1. check for debugger presence
    // 2. exit or behave differently if debugger detected
    
    return LINUX_UTILS_ERROR_INVALID_ARGS; // placeholder
}