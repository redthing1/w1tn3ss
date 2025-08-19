/**
 * @file p1ll_c.h
 * @brief C API for p1ll binary patching and memory manipulation library
 * 
 * provides core memory scanning, patching, and pattern matching primitives
 * for use from pure C programs
 */

#ifndef P1LL_C_H
#define P1LL_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// memory protection flags
#define P1LL_PROT_NONE    0x00
#define P1LL_PROT_READ    0x01
#define P1LL_PROT_WRITE   0x02
#define P1LL_PROT_EXEC    0x04

// return codes
#define P1LL_SUCCESS  0
#define P1LL_ERROR   -1

// opaque handle types
typedef struct p1ll_scanner* p1ll_scanner_t;

/**
 * memory region information
 */
typedef struct {
    uint64_t base_address;
    size_t size;
    int protection;      // P1LL_PROT_* flags
    char name[256];
    int is_executable;   // 1 if region contains executable code, 0 otherwise
    int is_system;       // 1 if system module, 0 otherwise
} p1ll_memory_region_t;

/**
 * pattern match result
 */
typedef struct {
    uint64_t address;
    char region_name[256];
} p1ll_match_t;

/**
 * compiled pattern with mask for wildcards
 */
typedef struct {
    uint8_t* bytes;
    uint8_t* mask;  // 1 = exact match, 0 = wildcard
    size_t size;
} p1ll_compiled_pattern_t;

// --- scanner lifecycle ---

/**
 * create memory scanner instance
 * @return scanner handle or NULL on failure
 */
p1ll_scanner_t p1ll_scanner_create(void);

/**
 * destroy memory scanner and free resources
 * @param scanner scanner handle (can be NULL)
 */
void p1ll_scanner_destroy(p1ll_scanner_t scanner);

// --- memory region enumeration ---

/**
 * enumerate all memory regions in current process
 * @param scanner scanner handle
 * @param out_regions pointer to receive regions array (caller must free)
 * @param out_count pointer to receive number of regions
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_get_memory_regions(p1ll_scanner_t scanner,
                            p1ll_memory_region_t** out_regions,
                            size_t* out_count);

/**
 * get memory region info for specific address
 * @param scanner scanner handle
 * @param address address to query
 * @param out_region pointer to receive region info
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_get_region_at_address(p1ll_scanner_t scanner,
                               uint64_t address,
                               p1ll_memory_region_t* out_region);

/**
 * free memory regions array
 * @param regions regions array from p1ll_get_memory_regions
 */
void p1ll_free_memory_regions(p1ll_memory_region_t* regions);

// --- memory protection management ---

/**
 * change memory protection for region
 * @param scanner scanner handle
 * @param address starting address
 * @param size size in bytes
 * @param protection new protection flags (P1LL_PROT_*)
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_set_memory_protection(p1ll_scanner_t scanner,
                               uint64_t address,
                               size_t size,
                               int protection);

/**
 * get system page size
 * @param scanner scanner handle
 * @return page size in bytes, or 0 on error
 */
size_t p1ll_get_page_size(p1ll_scanner_t scanner);

// --- direct memory access ---

/**
 * read memory from process
 * @param scanner scanner handle
 * @param address address to read from
 * @param buffer buffer to receive data
 * @param size number of bytes to read
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_read_memory(p1ll_scanner_t scanner,
                     uint64_t address,
                     uint8_t* buffer,
                     size_t size);

/**
 * write memory to process
 * @param scanner scanner handle
 * @param address address to write to
 * @param data data to write
 * @param size number of bytes to write
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_write_memory(p1ll_scanner_t scanner,
                      uint64_t address,
                      const uint8_t* data,
                      size_t size);

/**
 * patch memory with hex pattern
 * @param scanner scanner handle
 * @param address address to patch
 * @param hex_pattern hex pattern like "90 90 eb 00"
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_patch_memory(p1ll_scanner_t scanner,
                      uint64_t address,
                      const char* hex_pattern);

// --- memory allocation ---

/**
 * allocate memory with specific protection
 * @param scanner scanner handle
 * @param size size in bytes
 * @param protection protection flags (P1LL_PROT_*)
 * @return allocated address or NULL on failure
 */
void* p1ll_allocate_memory(p1ll_scanner_t scanner,
                           size_t size,
                           int protection);

/**
 * free previously allocated memory
 * @param scanner scanner handle
 * @param address address to free
 * @param size size that was allocated
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_free_memory(p1ll_scanner_t scanner,
                     void* address,
                     size_t size);

// --- pattern searching ---

/**
 * search for hex pattern in all memory regions
 * @param scanner scanner handle
 * @param hex_pattern hex pattern with wildcards like "48 89 e5 ?? ??"
 * @param out_matches pointer to receive matches array (caller must free)
 * @param out_count pointer to receive number of matches
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_search_pattern(p1ll_scanner_t scanner,
                        const char* hex_pattern,
                        p1ll_match_t** out_matches,
                        size_t* out_count);

/**
 * search for hex pattern in specific memory region
 * @param scanner scanner handle
 * @param region_base base address of region to search
 * @param hex_pattern hex pattern with wildcards
 * @param out_matches pointer to receive matches array (caller must free)
 * @param out_count pointer to receive number of matches
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_search_in_region(p1ll_scanner_t scanner,
                          uint64_t region_base,
                          const char* hex_pattern,
                          p1ll_match_t** out_matches,
                          size_t* out_count);

/**
 * search for pattern in buffer (no scanner needed)
 * @param buffer buffer to search in
 * @param buffer_size size of buffer
 * @param hex_pattern hex pattern with wildcards
 * @param out_offsets pointer to receive offsets array (caller must free)
 * @param out_count pointer to receive number of matches
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_search_in_buffer(const uint8_t* buffer,
                          size_t buffer_size,
                          const char* hex_pattern,
                          size_t** out_offsets,
                          size_t* out_count);

/**
 * free search matches array
 * @param matches matches array from search functions
 */
void p1ll_free_matches(p1ll_match_t* matches);

/**
 * free offsets array
 * @param offsets offsets array from p1ll_search_in_buffer
 */
void p1ll_free_offsets(size_t* offsets);

// --- pattern compilation & validation ---

/**
 * compile hex pattern to bytes and mask
 * @param hex_pattern hex pattern with wildcards like "ff d0 ?? 74"
 * @param out_pattern pointer to receive compiled pattern (caller must free)
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_compile_pattern(const char* hex_pattern,
                         p1ll_compiled_pattern_t* out_pattern);

/**
 * free compiled pattern resources
 * @param pattern pattern from p1ll_compile_pattern
 */
void p1ll_free_compiled_pattern(p1ll_compiled_pattern_t* pattern);

/**
 * validate hex pattern syntax
 * @param hex_pattern hex pattern to validate
 * @return 1 if valid, 0 if invalid
 */
int p1ll_validate_pattern(const char* hex_pattern);

// --- utility functions ---

/**
 * convert hex string to byte array
 * @param hex hex string like "48894e08"
 * @param out_bytes pointer to receive bytes array (caller must free)
 * @param out_size pointer to receive array size
 * @return P1LL_SUCCESS or P1LL_ERROR
 */
int p1ll_hex_string_to_bytes(const char* hex,
                             uint8_t** out_bytes,
                             size_t* out_size);

/**
 * convert byte array to hex string
 * @param bytes byte array
 * @param size array size
 * @return hex string (caller must free) or NULL on error
 */
char* p1ll_bytes_to_hex_string(const uint8_t* bytes, size_t size);

/**
 * format address as string
 * @param address address value
 * @return formatted address string (caller must free) or NULL on error
 */
char* p1ll_format_address(uint64_t address);

/**
 * free byte array
 * @param bytes byte array from hex conversion
 */
void p1ll_free_bytes(uint8_t* bytes);

/**
 * free string
 * @param str string from formatting functions
 */
void p1ll_free_string(char* str);

// --- error handling ---

/**
 * get last error message
 * @return error message string (do not free)
 */
const char* p1ll_get_last_error(void);

// --- capability queries ---

/**
 * check if scripting support is compiled in
 * @return 1 if available, 0 otherwise
 */
int p1ll_has_scripting_support(void);

#ifdef __cplusplus
}
#endif

#endif /* P1LL_C_H */