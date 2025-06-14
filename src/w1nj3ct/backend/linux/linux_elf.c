#include "linux_elf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/uio.h>
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

// internal helper functions
static int read_process_memory(pid_t pid, void* addr, void* buffer, size_t size);
static int parse_maps_line(const char* line, linux_memory_map_t* map);
static void* find_library_in_maps(linux_memory_map_t* maps, size_t count, const char* lib_name);
static int read_elf_section_headers(pid_t pid, void* base_addr, Elf_Ehdr* ehdr, Elf_Shdr** sections);
static int find_symbol_in_section(pid_t pid, void* base_addr, Elf_Shdr* symtab, Elf_Shdr* strtab, 
                                  const char* symbol_name, void** symbol_addr);

// global error message buffer
static char error_buffer[256] = {0};

const char* linux_elf_error_string(int error_code) {
    switch (error_code) {
        case LINUX_ELF_SUCCESS:
            return "Success";
        case LINUX_ELF_ERROR_INVALID_PID:
            return "Invalid process ID";
        case LINUX_ELF_ERROR_NO_MEMORY:
            return "Out of memory";
        case LINUX_ELF_ERROR_IO_ERROR:
            return "I/O error";
        case LINUX_ELF_ERROR_INVALID_ELF:
            return "Invalid ELF format";
        case LINUX_ELF_ERROR_SYMBOL_NOT_FOUND:
            return "Symbol not found";
        case LINUX_ELF_ERROR_LIBRARY_NOT_FOUND:
            return "Library not found";
        case LINUX_ELF_ERROR_PERMISSION_DENIED:
            return "Permission denied";
        default:
            snprintf(error_buffer, sizeof(error_buffer), "Unknown error code: %d", error_code);
            return error_buffer;
    }
}

int linux_parse_proc_maps(pid_t pid, linux_memory_map_t** maps, size_t* count) {
    if (!maps || !count) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE* file = fopen(maps_path, "r");
    if (!file) {
        if (errno == EACCES) {
            return LINUX_ELF_ERROR_PERMISSION_DENIED;
        }
        return LINUX_ELF_ERROR_IO_ERROR;
    }

    // first pass: count entries
    size_t map_count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        map_count++;
    }

    if (map_count == 0) {
        fclose(file);
        *maps = NULL;
        *count = 0;
        return LINUX_ELF_SUCCESS;
    }

    // allocate memory for maps
    linux_memory_map_t* map_array = calloc(map_count, sizeof(linux_memory_map_t));
    if (!map_array) {
        fclose(file);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    // second pass: parse entries
    rewind(file);
    size_t parsed_count = 0;
    while (fgets(line, sizeof(line), file) && parsed_count < map_count) {
        if (parse_maps_line(line, &map_array[parsed_count]) == LINUX_ELF_SUCCESS) {
            parsed_count++;
        }
    }

    fclose(file);
    *maps = map_array;
    *count = parsed_count;
    return LINUX_ELF_SUCCESS;
}

void linux_free_memory_maps(linux_memory_map_t* maps, size_t count) {
    if (!maps) return;

    for (size_t i = 0; i < count; i++) {
        free(maps[i].path);
        free(maps[i].permissions);
    }
    free(maps);
}

int linux_find_library_base(pid_t pid, const char* lib_name, void** base_addr) {
    if (!lib_name || !base_addr) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    linux_memory_map_t* maps = NULL;
    size_t count = 0;
    int result = linux_parse_proc_maps(pid, &maps, &count);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    void* found_addr = find_library_in_maps(maps, count, lib_name);
    linux_free_memory_maps(maps, count);

    if (!found_addr) {
        return LINUX_ELF_ERROR_LIBRARY_NOT_FOUND;
    }

    *base_addr = found_addr;
    return LINUX_ELF_SUCCESS;
}

int linux_find_symbol(pid_t pid, const char* lib_name, const char* symbol_name, void** symbol_addr) {
    if (!lib_name || !symbol_name || !symbol_addr) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    // find library base address
    void* base_addr = NULL;
    int result = linux_find_library_base(pid, lib_name, &base_addr);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // read ELF header
    Elf_Ehdr ehdr;
    result = read_process_memory(pid, base_addr, &ehdr, sizeof(ehdr));
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // validate ELF header
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        return LINUX_ELF_ERROR_INVALID_ELF;
    }

    // read section headers
    Elf_Shdr* sections = NULL;
    result = read_elf_section_headers(pid, base_addr, &ehdr, &sections);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // find symbol in dynamic symbol table
    Elf_Shdr* dynsym = NULL;
    Elf_Shdr* dynstr = NULL;
    Elf_Shdr* symtab = NULL;
    Elf_Shdr* strtab = NULL;

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (sections[i].sh_type == SHT_DYNSYM) {
            dynsym = &sections[i];
        } else if (sections[i].sh_type == SHT_STRTAB && !dynstr) {
            dynstr = &sections[i];
        } else if (sections[i].sh_type == SHT_SYMTAB) {
            symtab = &sections[i];
        } else if (sections[i].sh_type == SHT_STRTAB && dynstr) {
            strtab = &sections[i];
        }
    }

    void* found_addr = NULL;
    
    // try dynamic symbol table first
    if (dynsym && dynstr) {
        result = find_symbol_in_section(pid, base_addr, dynsym, dynstr, symbol_name, &found_addr);
        if (result == LINUX_ELF_SUCCESS) {
            *symbol_addr = found_addr;
            free(sections);
            return LINUX_ELF_SUCCESS;
        }
    }

    // try static symbol table
    if (symtab && strtab) {
        result = find_symbol_in_section(pid, base_addr, symtab, strtab, symbol_name, &found_addr);
        if (result == LINUX_ELF_SUCCESS) {
            *symbol_addr = found_addr;
            free(sections);
            return LINUX_ELF_SUCCESS;
        }
    }

    free(sections);
    return LINUX_ELF_ERROR_SYMBOL_NOT_FOUND;
}

int linux_find_all_symbols(pid_t pid, const char* lib_name, linux_symbol_t** symbols, size_t* count) {
    if (!lib_name || !symbols || !count) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    void* base_addr = NULL;
    int result = linux_find_library_base(pid, lib_name, &base_addr);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    Elf_Ehdr ehdr;
    result = read_process_memory(pid, base_addr, &ehdr, sizeof(ehdr));
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        return LINUX_ELF_ERROR_INVALID_ELF;
    }

    Elf_Shdr* sections = NULL;
    result = read_elf_section_headers(pid, base_addr, &ehdr, &sections);
    if (result != LINUX_ELF_SUCCESS) {
        return result;
    }

    // find symbol tables
    Elf_Shdr* dynsym = NULL;
    Elf_Shdr* dynstr = NULL;
    
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (sections[i].sh_type == SHT_DYNSYM) {
            dynsym = &sections[i];
        } else if (sections[i].sh_type == SHT_STRTAB && sections[i].sh_link == (dynsym ? (dynsym - sections) : 0)) {
            dynstr = &sections[i];
        }
    }

    if (!dynsym || !dynstr) {
        free(sections);
        return LINUX_ELF_ERROR_SYMBOL_NOT_FOUND;
    }

    // read symbols
    size_t sym_count = dynsym->sh_size / sizeof(Elf_Sym);
    Elf_Sym* elf_symbols = malloc(dynsym->sh_size);
    if (!elf_symbols) {
        free(sections);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    result = read_process_memory(pid, (char*)base_addr + dynsym->sh_offset, elf_symbols, dynsym->sh_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(elf_symbols);
        free(sections);
        return result;
    }

    // read string table
    char* string_table = malloc(dynstr->sh_size);
    if (!string_table) {
        free(elf_symbols);
        free(sections);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    result = read_process_memory(pid, (char*)base_addr + dynstr->sh_offset, string_table, dynstr->sh_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(string_table);
        free(elf_symbols);
        free(sections);
        return result;
    }

    // convert to our symbol format
    linux_symbol_t* result_symbols = calloc(sym_count, sizeof(linux_symbol_t));
    if (!result_symbols) {
        free(string_table);
        free(elf_symbols);
        free(sections);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    size_t valid_symbols = 0;
    for (size_t i = 0; i < sym_count; i++) {
        if (elf_symbols[i].st_name > 0 && elf_symbols[i].st_name < dynstr->sh_size) {
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
    free(sections);

    *symbols = result_symbols;
    *count = valid_symbols;
    return LINUX_ELF_SUCCESS;
}

void linux_free_symbols(linux_symbol_t* symbols, size_t count) {
    if (!symbols) return;

    for (size_t i = 0; i < count; i++) {
        free(symbols[i].name);
    }
    free(symbols);
}

int linux_is_elf_file(const char* path) {
    if (!path) return 0;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    unsigned char elf_magic[4];
    ssize_t bytes_read = read(fd, elf_magic, 4);
    close(fd);

    if (bytes_read != 4) return 0;
    
    return memcmp(elf_magic, ELFMAG, SELFMAG) == 0;
}

int linux_get_process_arch(pid_t pid, int* is_64bit) {
    if (!is_64bit) return LINUX_ELF_ERROR_INVALID_PID;

    char exe_path[256];
    snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

    int fd = open(exe_path, O_RDONLY);
    if (fd < 0) {
        return errno == EACCES ? LINUX_ELF_ERROR_PERMISSION_DENIED : LINUX_ELF_ERROR_IO_ERROR;
    }

    unsigned char elf_header[16];
    ssize_t bytes_read = read(fd, elf_header, sizeof(elf_header));
    close(fd);

    if (bytes_read != sizeof(elf_header)) {
        return LINUX_ELF_ERROR_IO_ERROR;
    }

    if (memcmp(elf_header, ELFMAG, SELFMAG) != 0) {
        return LINUX_ELF_ERROR_INVALID_ELF;
    }

    *is_64bit = (elf_header[EI_CLASS] == ELFCLASS64);
    return LINUX_ELF_SUCCESS;
}

// internal helper function implementations

static int read_process_memory(pid_t pid, void* addr, void* buffer, size_t size) {
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

static int parse_maps_line(const char* line, linux_memory_map_t* map) {
    if (!line || !map) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    unsigned long start, end;
    char perms[8];
    char path[1024] = {0};

    // parse: start-end permissions offset device inode path
    int matches = sscanf(line, "%lx-%lx %7s %*x %*x:%*x %*d %1023s", &start, &end, perms, path);
    
    if (matches < 3) {
        return LINUX_ELF_ERROR_IO_ERROR;
    }

    map->start_addr = (void*)start;
    map->end_addr = (void*)end;
    map->permissions = strdup(perms);
    
    if (matches >= 4 && strlen(path) > 0) {
        map->path = strdup(path);
    } else {
        map->path = strdup("[anonymous]");
    }

    return LINUX_ELF_SUCCESS;
}

static void* find_library_in_maps(linux_memory_map_t* maps, size_t count, const char* lib_name) {
    if (!maps || !lib_name) return NULL;

    for (size_t i = 0; i < count; i++) {
        if (maps[i].path && strstr(maps[i].path, lib_name)) {
            // make sure it's executable
            if (maps[i].permissions && strchr(maps[i].permissions, 'x')) {
                return maps[i].start_addr;
            }
        }
    }

    return NULL;
}

static int read_elf_section_headers(pid_t pid, void* base_addr, Elf_Ehdr* ehdr, Elf_Shdr** sections) {
    if (!ehdr || !sections) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    size_t shdr_size = ehdr->e_shentsize * ehdr->e_shnum;
    Elf_Shdr* section_headers = malloc(shdr_size);
    if (!section_headers) {
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    void* shdr_addr = (char*)base_addr + ehdr->e_shoff;
    int result = read_process_memory(pid, shdr_addr, section_headers, shdr_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(section_headers);
        return result;
    }

    *sections = section_headers;
    return LINUX_ELF_SUCCESS;
}

static int find_symbol_in_section(pid_t pid, void* base_addr, Elf_Shdr* symtab, Elf_Shdr* strtab, 
                                  const char* symbol_name, void** symbol_addr) {
    if (!symtab || !strtab || !symbol_name || !symbol_addr) {
        return LINUX_ELF_ERROR_INVALID_PID;
    }

    // read symbol table
    size_t sym_count = symtab->sh_size / sizeof(Elf_Sym);
    Elf_Sym* symbols = malloc(symtab->sh_size);
    if (!symbols) {
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    int result = read_process_memory(pid, (char*)base_addr + symtab->sh_offset, symbols, symtab->sh_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(symbols);
        return result;
    }

    // read string table
    char* strings = malloc(strtab->sh_size);
    if (!strings) {
        free(symbols);
        return LINUX_ELF_ERROR_NO_MEMORY;
    }

    result = read_process_memory(pid, (char*)base_addr + strtab->sh_offset, strings, strtab->sh_size);
    if (result != LINUX_ELF_SUCCESS) {
        free(strings);
        free(symbols);
        return result;
    }

    // search for symbol
    for (size_t i = 0; i < sym_count; i++) {
        if (symbols[i].st_name < strtab->sh_size) {
            char* name = &strings[symbols[i].st_name];
            if (strcmp(name, symbol_name) == 0) {
                *symbol_addr = (char*)base_addr + symbols[i].st_value;
                free(strings);
                free(symbols);
                return LINUX_ELF_SUCCESS;
            }
        }
    }

    free(strings);
    free(symbols);
    return LINUX_ELF_ERROR_SYMBOL_NOT_FOUND;
}