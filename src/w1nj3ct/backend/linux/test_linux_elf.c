#include "linux_elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static void print_symbol(const linux_symbol_t* symbol) {
    if (!symbol) return;
    
    const char* bind_str = "UNKNOWN";
    switch (symbol->bind) {
        case STB_LOCAL: bind_str = "LOCAL"; break;
        case STB_GLOBAL: bind_str = "GLOBAL"; break;
        case STB_WEAK: bind_str = "WEAK"; break;
    }
    
    const char* type_str = "UNKNOWN";
    switch (symbol->type) {
        case STT_NOTYPE: type_str = "NOTYPE"; break;
        case STT_OBJECT: type_str = "OBJECT"; break;
        case STT_FUNC: type_str = "FUNC"; break;
        case STT_SECTION: type_str = "SECTION"; break;
        case STT_FILE: type_str = "FILE"; break;
    }
    
    printf("  %s: addr=%p size=%zu bind=%s type=%s\n", 
           symbol->name ? symbol->name : "<unnamed>",
           symbol->address, symbol->size, bind_str, type_str);
}

static void test_proc_maps(pid_t pid) {
    printf("=== Testing /proc/maps parsing for PID %d ===\n", pid);
    
    linux_memory_map_t* maps = NULL;
    size_t count = 0;
    
    int result = linux_parse_proc_maps(pid, &maps, &count);
    if (result != LINUX_ELF_SUCCESS) {
        printf("Error parsing /proc/maps: %s\n", linux_elf_error_string(result));
        return;
    }
    
    printf("Found %zu memory mappings:\n", count);
    for (size_t i = 0; i < count && i < 10; i++) { // limit output
        printf("  %p-%p %s %s\n", 
               maps[i].start_addr, maps[i].end_addr,
               maps[i].permissions ? maps[i].permissions : "????",
               maps[i].path ? maps[i].path : "[anonymous]");
    }
    if (count > 10) {
        printf("  ... and %zu more\n", count - 10);
    }
    
    linux_free_memory_maps(maps, count);
}

static void test_library_base(pid_t pid, const char* lib_name) {
    printf("=== Testing library base address for '%s' ===\n", lib_name);
    
    void* base_addr = NULL;
    int result = linux_find_library_base(pid, lib_name, &base_addr);
    
    if (result == LINUX_ELF_SUCCESS) {
        printf("Library '%s' base address: %p\n", lib_name, base_addr);
    } else {
        printf("Error finding library '%s': %s\n", lib_name, linux_elf_error_string(result));
    }
}

static void test_symbol_resolution(pid_t pid, const char* lib_name, const char* symbol_name) {
    printf("=== Testing symbol resolution: %s in %s ===\n", symbol_name, lib_name);
    
    void* symbol_addr = NULL;
    int result = linux_find_symbol(pid, lib_name, symbol_name, &symbol_addr);
    
    if (result == LINUX_ELF_SUCCESS) {
        printf("Symbol '%s' found at address: %p\n", symbol_name, symbol_addr);
    } else {
        printf("Error finding symbol '%s': %s\n", symbol_name, linux_elf_error_string(result));
    }
}

static void test_all_symbols(pid_t pid, const char* lib_name) {
    printf("=== Testing all symbols enumeration for '%s' ===\n", lib_name);
    
    linux_symbol_t* symbols = NULL;
    size_t count = 0;
    
    int result = linux_find_all_symbols(pid, lib_name, &symbols, &count);
    if (result != LINUX_ELF_SUCCESS) {
        printf("Error enumerating symbols: %s\n", linux_elf_error_string(result));
        return;
    }
    
    printf("Found %zu symbols in '%s':\n", count, lib_name);
    for (size_t i = 0; i < count && i < 20; i++) { // limit output
        print_symbol(&symbols[i]);
    }
    if (count > 20) {
        printf("  ... and %zu more symbols\n", count - 20);
    }
    
    linux_free_symbols(symbols, count);
}

static void test_loaded_modules(pid_t pid) {
    printf("=== Testing loaded modules enumeration ===\n");
    
    linux_module_t* modules = NULL;
    size_t count = 0;
    
    int result = linux_get_loaded_modules(pid, &modules, &count);
    if (result != LINUX_ELF_SUCCESS) {
        printf("Error enumerating modules: %s\n", linux_elf_error_string(result));
        return;
    }
    
    printf("Found %zu loaded modules:\n", count);
    for (size_t i = 0; i < count && i < 10; i++) { // limit output
        printf("  %s: base=%p end=%p symbols=%zu\n",
               modules[i].path ? modules[i].path : "<unknown>",
               modules[i].base_addr, modules[i].end_addr,
               modules[i].symbol_count);
    }
    if (count > 10) {
        printf("  ... and %zu more modules\n", count - 10);
    }
    
    linux_free_modules(modules, count);
}

static void test_process_arch(pid_t pid) {
    printf("=== Testing process architecture detection ===\n");
    
    int is_64bit = 0;
    int result = linux_get_process_arch(pid, &is_64bit);
    
    if (result == LINUX_ELF_SUCCESS) {
        printf("Process %d architecture: %s\n", pid, is_64bit ? "64-bit" : "32-bit");
    } else {
        printf("Error detecting architecture: %s\n", linux_elf_error_string(result));
    }
}

int main(int argc, char* argv[]) {
    pid_t test_pid = getpid(); // test on ourselves by default
    
    if (argc > 1) {
        test_pid = atoi(argv[1]);
        if (test_pid <= 0) {
            printf("Invalid PID: %s\n", argv[1]);
            return 1;
        }
    }
    
    printf("Linux ELF Backend Test Program\n");
    printf("Testing on PID: %d\n\n", test_pid);
    
    // run tests
    test_proc_maps(test_pid);
    printf("\n");
    
    test_process_arch(test_pid);
    printf("\n");
    
    test_library_base(test_pid, "libc.so");
    printf("\n");
    
    test_symbol_resolution(test_pid, "libc.so", "printf");
    printf("\n");
    
    test_symbol_resolution(test_pid, "libc.so", "malloc");
    printf("\n");
    
    test_all_symbols(test_pid, "libc.so");
    printf("\n");
    
    test_loaded_modules(test_pid);
    printf("\n");
    
    printf("Test completed!\n");
    return 0;
}