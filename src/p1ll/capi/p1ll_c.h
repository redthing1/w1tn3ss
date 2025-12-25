/**
 * @file p1ll_c.h
 * @brief C API for the p1ll engine session interface
 */

#ifndef P1LL_C_H
#define P1LL_C_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define P1LL_SUCCESS 0
#define P1LL_ERROR -1

// opaque handle for engine sessions
typedef struct p1ll_session* p1ll_session_t;

// scan filtering options
typedef struct {
  const char* name_regex;
  int only_executable;
  int exclude_system;
  size_t min_size;
  int has_min_address;
  uint64_t min_address;
  int has_max_address;
  uint64_t max_address;
} p1ll_scan_filter_t;

typedef struct {
  p1ll_scan_filter_t filter;
  int single;
  size_t max_matches;
} p1ll_scan_options_t;

typedef struct {
  uint64_t address;
  char region_name[256];
} p1ll_scan_result_t;

// signature and patch specs for recipe construction
typedef struct {
  const char* pattern;
  p1ll_scan_options_t options;
  const char** platforms;
  size_t platform_count;
  int required;
} p1ll_signature_spec_t;

typedef struct {
  p1ll_signature_spec_t signature;
  int64_t offset;
  const char* patch;
  const char** platforms;
  size_t platform_count;
  int required;
} p1ll_patch_spec_t;

typedef struct {
  const char* name;
  const char** platforms;
  size_t platform_count;
  const p1ll_signature_spec_t* validations;
  size_t validation_count;
  const p1ll_patch_spec_t* patches;
  size_t patch_count;
} p1ll_recipe_t;

typedef struct {
  uint64_t address;
  uint8_t* patch_bytes;
  uint8_t* patch_mask;
  size_t size;
  int required;
} p1ll_plan_entry_t;

typedef struct {
  int success;
  size_t applied;
  size_t failed;
} p1ll_apply_report_t;

// session lifecycle
p1ll_session_t p1ll_session_create_process(void);
p1ll_session_t p1ll_session_create_buffer(uint8_t* buffer, size_t size);
p1ll_session_t p1ll_session_create_buffer_with_platform(uint8_t* buffer, size_t size, const char* platform_key);
void p1ll_session_destroy(p1ll_session_t session);

// scanning and planning
int p1ll_scan(
    p1ll_session_t session, const char* pattern, const p1ll_scan_options_t* options, p1ll_scan_result_t** out_results,
    size_t* out_count
);
void p1ll_free_scan_results(p1ll_scan_result_t* results);

int p1ll_plan(p1ll_session_t session, const p1ll_recipe_t* recipe, p1ll_plan_entry_t** out_entries, size_t* out_count);
void p1ll_free_plan_entries(p1ll_plan_entry_t* entries, size_t count);

int p1ll_apply(
    p1ll_session_t session, const p1ll_plan_entry_t* entries, size_t count, p1ll_apply_report_t* out_report
);

// utilities
int p1ll_validate_pattern(const char* hex_pattern);
int p1ll_hex_string_to_bytes(const char* hex, uint8_t** out_bytes, size_t* out_size);
char* p1ll_bytes_to_hex_string(const uint8_t* bytes, size_t size);
char* p1ll_format_address(uint64_t address);
void p1ll_free_bytes(uint8_t* bytes);
void p1ll_free_string(char* str);

// capability and error helpers
int p1ll_has_scripting_support(void);
const char* p1ll_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* P1LL_C_H */
