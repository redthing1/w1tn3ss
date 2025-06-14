#pragma once

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void* start_addr;
    void* end_addr; 
    char* path;
    char* permissions;
} linux_memory_map_t;

typedef struct {
    char* name;
    void* address;
    size_t size;
    int bind;    // STB_LOCAL, STB_GLOBAL, STB_WEAK
    int type;    // STT_NOTYPE, STT_OBJECT, STT_FUNC, etc.
} linux_symbol_t;

typedef struct {
    void* base_addr;
    void* end_addr;
    char* path;
    linux_symbol_t* symbols;
    size_t symbol_count;
} linux_module_t;

// error codes
#define LINUX_ELF_SUCCESS 0
#define LINUX_ELF_ERROR_INVALID_PID -1
#define LINUX_ELF_ERROR_NO_MEMORY -2
#define LINUX_ELF_ERROR_IO_ERROR -3
#define LINUX_ELF_ERROR_INVALID_ELF -4
#define LINUX_ELF_ERROR_SYMBOL_NOT_FOUND -5
#define LINUX_ELF_ERROR_LIBRARY_NOT_FOUND -6
#define LINUX_ELF_ERROR_PERMISSION_DENIED -7

// ELF and symbol resolution
int linux_find_symbol(pid_t pid, const char* lib_name, const char* symbol_name, void** symbol_addr);
int linux_find_library_base(pid_t pid, const char* lib_name, void** base_addr);
int linux_parse_proc_maps(pid_t pid, linux_memory_map_t** maps, size_t* count);
void linux_free_memory_maps(linux_memory_map_t* maps, size_t count);

// extended symbol resolution functions
int linux_find_all_symbols(pid_t pid, const char* lib_name, linux_symbol_t** symbols, size_t* count);
int linux_resolve_symbol_by_address(pid_t pid, void* address, linux_symbol_t* symbol);
int linux_get_loaded_modules(pid_t pid, linux_module_t** modules, size_t* count);
void linux_free_symbols(linux_symbol_t* symbols, size_t count);
void linux_free_modules(linux_module_t* modules, size_t count);

// low-level ELF parsing functions
int linux_read_elf_header(pid_t pid, void* base_addr, void* elf_header, size_t header_size);
int linux_find_dynamic_section(pid_t pid, void* base_addr, void** dyn_addr, size_t* dyn_size);
int linux_parse_symbol_table(pid_t pid, void* base_addr, void* symtab_addr, void* strtab_addr, 
                             size_t symtab_size, size_t strtab_size, linux_symbol_t** symbols, size_t* count);

// utility functions
const char* linux_elf_error_string(int error_code);
int linux_is_elf_file(const char* path);
int linux_get_process_arch(pid_t pid, int* is_64bit);

#ifdef __cplusplus
}
#endif