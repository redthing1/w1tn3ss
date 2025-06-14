#include "linux_elf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <link.h>

// platform-specific includes
#ifdef __x86_64__
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Sym Elf64_Sym
#define Elf_Dyn Elf64_Dyn
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_TYPE ELF64_ST_TYPE
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Sym Elf32_Sym
#define Elf_Dyn Elf32_Dyn
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_TYPE ELF32_ST_TYPE
#endif

// forward declarations for internal helpers
static int read_process_memory_ext(pid_t pid, void* addr, void* buffer, size_t size);
static int find_closest_symbol(linux_symbol_t* symbols, size_t count, void* address, linux_symbol_t* result);

int linux_resolve_symbol_by_address(pid_t pid, void* address, linux_symbol_t* symbol) {
    if (!address || !symbol) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    linux_memory_map_t* maps = NULL;
    size_t map_count = 0;
    int result = linux_parse_proc_maps(pid, &maps, &map_count);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // find which library contains this address
    linux_memory_map_t* containing_map = NULL;
    for (size_t i = 0; i < map_count; i++) {
        if (address >= maps[i].start_addr && address < maps[i].end_addr) {
            // prefer executable regions with paths
            if (maps[i].path && maps[i].permissions && strchr(maps[i].permissions, 'x')) {
                containing_map = &maps[i];
                break;
            }
        }
    }

    if (!containing_map || !containing_map->path) {
        linux_free_memory_maps(maps, map_count);
        return LINUX_ELF_ERROR_LIBRARY_NOT_FOUND;
    }

    // extract library name from path
    char* lib_name = strrchr(containing_map->path, '/');
    if (lib_name) {
        lib_name++; // skip the '/'
    } else {
        lib_name = containing_map->path;
    }

    // get all symbols from the library
    linux_symbol_t* symbols = NULL;
    size_t symbol_count = 0;
    result = linux_find_all_symbols(pid, lib_name, &symbols, &symbol_count);
    
    linux_free_memory_maps(maps, map_count);
    
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // find the closest symbol to the address
    result = find_closest_symbol(symbols, symbol_count, address, symbol);
    
    linux_free_symbols(symbols, symbol_count);
    return result;
}

int linux_get_loaded_modules(pid_t pid, linux_module_t** modules, size_t* count) {
    if (!modules || !count) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    linux_memory_map_t* maps = NULL;
    size_t map_count = 0;
    int result = linux_parse_proc_maps(pid, &maps, &map_count);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // count unique libraries
    char** unique_libs = NULL;
    size_t unique_count = 0;
    
    for (size_t i = 0; i < map_count; i++) {
        if (maps[i].path && maps[i].permissions && strchr(maps[i].permissions, 'x')) {
            // check if we've already seen this library
            int already_seen = 0;
            for (size_t j = 0; j < unique_count; j++) {
                if (strcmp(unique_libs[j], maps[i].path) == 0) {
                    already_seen = 1;
                    break;
                }
            }
            
            if (!already_seen) {
                unique_libs = realloc(unique_libs, (unique_count + 1) * sizeof(char*));
                if (!unique_libs) {
                    linux_free_memory_maps(maps, map_count);
                    return LINUX_ELF_ERROR_NO_MEMORY;
                }
                unique_libs[unique_count] = strdup(maps[i].path);
                unique_count++;
            }
        }
    }

    // allocate modules array
    linux_module_t* module_array = calloc(unique_count, sizeof(linux_module_t));
    if (!module_array) {
        for (size_t i = 0; i < unique_count; i++) {
            free(unique_libs[i]);
        }
        free(unique_libs);
        linux_free_memory_maps(maps, map_count);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    // populate modules
    size_t successful_modules = 0;
    for (size_t i = 0; i < unique_count; i++) {
        char* lib_name = strrchr(unique_libs[i], '/');
        if (lib_name) {
            lib_name++; // skip the '/'
        } else {
            lib_name = unique_libs[i];
        }

        // find base address
        void* base_addr = NULL;
        if (linux_find_library_base(pid, lib_name, &base_addr) == LINUX_ELF_SUCCESS) {
            module_array[successful_modules].path = strdup(unique_libs[i]);
            module_array[successful_modules].base_addr = base_addr;
            
            // find end address
            for (size_t j = 0; j < map_count; j++) {
                if (maps[j].path && strcmp(maps[j].path, unique_libs[i]) == 0) {
                    if (maps[j].end_addr > module_array[successful_modules].end_addr) {
                        module_array[successful_modules].end_addr = maps[j].end_addr;
                    }
                }
            }

            // get symbols
            linux_find_all_symbols(pid, lib_name, 
                                   &module_array[successful_modules].symbols,
                                   &module_array[successful_modules].symbol_count);

            successful_modules++;
        }
        
        free(unique_libs[i]);
    }

    free(unique_libs);
    linux_free_memory_maps(maps, map_count);

    *modules = module_array;
    *count = successful_modules;
    return LINUX_ELF_SUCCESS;
}

void linux_free_modules(linux_module_t* modules, size_t count) {
    if (!modules) return;

    for (size_t i = 0; i < count; i++) {
        free(modules[i].path);
        linux_free_symbols(modules[i].symbols, modules[i].symbol_count);
    }
    free(modules);
}

int linux_read_elf_header(pid_t pid, void* base_addr, void* elf_header, size_t header_size) {
    if (!base_addr || !elf_header || header_size < sizeof(Elf_Ehdr)) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    return read_process_memory_ext(pid, base_addr, elf_header, header_size);
}

int linux_find_dynamic_section(pid_t pid, void* base_addr, void** dyn_addr, size_t* dyn_size) {
    if (!base_addr || !dyn_addr || !dyn_size) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    Elf_Ehdr ehdr;
    int result = read_process_memory_ext(pid, base_addr, &ehdr, sizeof(ehdr));
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        return LINUX_ELF_ERROR_INVALID_ELF;
    }

    // read program headers
    size_t phdr_size = ehdr.e_phentsize * ehdr.e_phnum;
    Elf_Phdr* phdrs = malloc(phdr_size);
    if (!phdrs) {
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    void* phdr_addr = (char*)base_addr + ehdr.e_phoff;
    result = read_process_memory_ext(pid, phdr_addr, phdrs, phdr_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(phdrs);
        return result;
    }

    // find PT_DYNAMIC segment
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            *dyn_addr = (char*)base_addr + phdrs[i].p_vaddr;
            *dyn_size = phdrs[i].p_memsz;
            free(phdrs);
            return LINUX_ELF_SUCCESS;
        }
    }

    free(phdrs);
    return LINUX_ELF_ERROR_SYMBOL_NOT_FOUND;
}

int linux_parse_symbol_table(pid_t pid, void* base_addr, void* symtab_addr, void* strtab_addr, 
                             size_t symtab_size, size_t strtab_size, linux_symbol_t** symbols, size_t* count) {
    if (!base_addr || !symtab_addr || !strtab_addr || !symbols || !count) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    // read symbol table
    Elf_Sym* elf_symbols = malloc(symtab_size);
    if (!elf_symbols) {
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    int result = read_process_memory_ext(pid, symtab_addr, elf_symbols, symtab_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(elf_symbols);
        return result;
    }

    // read string table
    char* string_table = malloc(strtab_size);
    if (!string_table) {
        free(elf_symbols);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    result = read_process_memory_ext(pid, strtab_addr, string_table, strtab_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(string_table);
        free(elf_symbols);
        return result;
    }

    // convert symbols
    size_t sym_count = symtab_size / sizeof(Elf_Sym);
    linux_symbol_t* result_symbols = calloc(sym_count, sizeof(linux_symbol_t));
    if (!result_symbols) {
        free(string_table);
        free(elf_symbols);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    size_t valid_symbols = 0;
    for (size_t i = 0; i < sym_count; i++) {
        if (elf_symbols[i].st_name > 0 && elf_symbols[i].st_name < strtab_size) {
            char* name = &string_table[elf_symbols[i].st_name];
            if (strlen(name) > 0) {
                result_symbols[valid_symbols].name = strdup(name);
                result_symbols[valid_symbols].address = (char*)base_addr + elf_symbols[i].st_value;
                result_symbols[valid_symbols].size = elf_symbols[i].st_size;
                result_symbols[valid_symbols].bind = ELF_ST_BIND(elf_symbols[i].st_info);
                result_symbols[valid_symbols].type = ELF_ST_TYPE(elf_symbols[i].st_info);
                valid_symbols++;
            }
        }
    }

    free(string_table);
    free(elf_symbols);

    *symbols = result_symbols;
    *count = valid_symbols;
    return LINUX_ELF_SUCCESS;
}

// internal helper implementations

static int read_process_memory_ext(pid_t pid, void* addr, void* buffer, size_t size) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int fd = open(mem_path, O_RDONLY);
    if (fd < 0) {
        return errno == EACCES ? LINUX_ELF_ERROR_PERMISSION_DENIED : LINUX_ELF_ERROR_IO_ERROR;
    }

    off_t offset = (off_t)(uintptr_t)addr;
    if (lseek(fd, offset, SEEK_SET) == -1) {
        close(fd);
        return LINUX_ELF_ERROR_IO_ERROR;
    }

    ssize_t bytes_read = read(fd, buffer, size);
    close(fd);

    if (bytes_read != (ssize_t)size) {
        return LINUX_ELF_ERROR_IO_ERROR;
    }

    return LINUX_ELF_SUCCESS;
}

static int find_closest_symbol(linux_symbol_t* symbols, size_t count, void* address, linux_symbol_t* result) {
    if (!symbols || !result || count == 0) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    linux_symbol_t* closest = NULL;
    size_t min_distance = SIZE_MAX;

    for (size_t i = 0; i < count; i++) {
        if (symbols[i].address <= address) {
            size_t distance = (uintptr_t)address - (uintptr_t)symbols[i].address;
            if (distance < min_distance) {
                min_distance = distance;
                closest = &symbols[i];
            }
        }
    }

    if (!closest) {
        return LINUX_ELF_ERROR_SYMBOL_NOT_FOUND;
    }

    // copy the symbol
    result->name = strdup(closest->name);
    result->address = closest->address;
    result->size = closest->size;
    result->bind = closest->bind;
    result->type = closest->type;

    return LINUX_ELF_SUCCESS;
}