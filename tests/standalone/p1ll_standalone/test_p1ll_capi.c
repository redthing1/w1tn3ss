/**
 * @file test_p1ll_capi.c
 * @brief sanity test for the p1ll C API session interface
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <p1ll_c.h>

#define TEST_BUFFER_SIZE 256

static void print_error(const char* context) {
  const char* error = p1ll_get_last_error();
  if (error && strlen(error) > 0) {
    printf("[error] %s: %s\n", context, error);
  } else {
    printf("[error] %s: unknown error\n", context);
  }
}

static void test_capabilities(void) {
  printf("=== capability tests ===\n");

  int has_scripting = p1ll_has_scripting_support();
  printf("scripting support: %s\n", has_scripting ? "yes" : "no");
  printf("[ok] capability queries\n\n");
}

static void test_pattern_validation(void) {
  printf("=== pattern validation tests ===\n");

  const char* valid_patterns[] = {"48 89 e5", "ff d0 ?? 74", "90 90 90 90", "48 ?? ?? ?? 74 ??", "c3"};

  for (size_t i = 0; i < sizeof(valid_patterns) / sizeof(valid_patterns[0]); ++i) {
    int valid = p1ll_validate_pattern(valid_patterns[i]);
    assert(valid == 1);
    printf("[ok] validated pattern: '%s'\n", valid_patterns[i]);
  }

  const char* invalid_patterns[] = {"zz 90", "4", "", "90 gg 74"};

  for (size_t i = 0; i < sizeof(invalid_patterns) / sizeof(invalid_patterns[0]); ++i) {
    int valid = p1ll_validate_pattern(invalid_patterns[i]);
    assert(valid == 0);
    printf("[ok] rejected invalid pattern: '%s'\n", invalid_patterns[i]);
  }

  printf("[ok] pattern validation\n\n");
}

static void test_hex_utilities(void) {
  printf("=== hex utility tests ===\n");

  const char* hex_string = "48894e08";
  uint8_t* bytes = NULL;
  size_t byte_count = 0;

  int result = p1ll_hex_string_to_bytes(hex_string, &bytes, &byte_count);
  assert(result == P1LL_SUCCESS);
  assert(bytes != NULL);
  assert(byte_count == 4);
  assert(bytes[0] == 0x48);
  assert(bytes[1] == 0x89);
  assert(bytes[2] == 0x4e);
  assert(bytes[3] == 0x08);
  printf("[ok] hex string '%s' -> %zu bytes\n", hex_string, byte_count);

  char* hex_result = p1ll_bytes_to_hex_string(bytes, byte_count);
  assert(hex_result != NULL);
  printf("[ok] bytes -> hex string: '%s'\n", hex_result);

  p1ll_free_bytes(bytes);
  p1ll_free_string(hex_result);

  uint64_t test_addresses[] = {0x7fff12345678ULL, 0x1000ULL, 0x0ULL, 0xfffffffffffff000ULL};
  for (size_t i = 0; i < sizeof(test_addresses) / sizeof(test_addresses[0]); ++i) {
    char* addr_str = p1ll_format_address(test_addresses[i]);
    assert(addr_str != NULL);
    printf("[ok] address 0x%llx -> '%s'\n", (unsigned long long) test_addresses[i], addr_str);
    p1ll_free_string(addr_str);
  }

  printf("[ok] hex utilities\n\n");
}

static void test_buffer_scan_and_apply(void) {
  printf("=== buffer scan/apply tests ===\n");

  uint8_t buffer[TEST_BUFFER_SIZE];
  memset(buffer, 0x90, sizeof(buffer));

  buffer[32] = 0xde;
  buffer[33] = 0xad;
  buffer[34] = 0xbe;
  buffer[35] = 0xef;

  buffer[64] = 0x48;
  buffer[65] = 0x89;
  buffer[66] = 0xe5;
  buffer[128] = 0x48;
  buffer[129] = 0x89;
  buffer[130] = 0xe5;

  p1ll_session_t session = p1ll_session_create_buffer(buffer, sizeof(buffer));
  assert(session != NULL);

  p1ll_scan_result_t* results = NULL;
  size_t result_count = 0;
  p1ll_scan_options_t scan_opts;
  memset(&scan_opts, 0, sizeof(scan_opts));

  int rc = p1ll_scan(session, "48 89 e5", &scan_opts, &results, &result_count);
  assert(rc == P1LL_SUCCESS);
  assert(result_count >= 2);
  printf("[ok] scan found %zu matches\n", result_count);

  if (result_count > 0) {
    printf("[ok] first result region: '%s'\n", results[0].region_name);
  }

  p1ll_free_scan_results(results);

  p1ll_scan_options_t single_opts;
  memset(&single_opts, 0, sizeof(single_opts));
  single_opts.single = 1;

  rc = p1ll_scan(session, "48 89 e5", &single_opts, &results, &result_count);
  assert(rc == P1LL_ERROR);
  print_error("single scan");

  p1ll_scan_options_t validation_opts;
  memset(&validation_opts, 0, sizeof(validation_opts));
  validation_opts.single = 1;

  p1ll_signature_spec_t validation;
  memset(&validation, 0, sizeof(validation));
  validation.pattern = "de ad be ef";
  validation.options = validation_opts;
  validation.required = 1;

  p1ll_patch_spec_t patches[2];
  memset(patches, 0, sizeof(patches));
  patches[0].signature = validation;
  patches[0].offset = 0;
  patches[0].patch = "11 22 33 44";
  patches[0].required = 1;

  patches[1].signature.pattern = "00 11 22 33";
  patches[1].signature.options.single = 1;
  patches[1].patch = "ff ff ff ff";
  patches[1].required = 0;

  p1ll_recipe_t recipe;
  memset(&recipe, 0, sizeof(recipe));
  recipe.name = "buffer_patch";
  recipe.validations = &validation;
  recipe.validation_count = 1;
  recipe.patches = patches;
  recipe.patch_count = 2;

  p1ll_plan_entry_t* entries = NULL;
  size_t entry_count = 0;
  rc = p1ll_plan(session, &recipe, &entries, &entry_count);
  if (rc != P1LL_SUCCESS) {
    print_error("plan");
    assert(rc == P1LL_SUCCESS);
  }
  assert(entry_count == 1);

  p1ll_apply_report_t report;
  memset(&report, 0, sizeof(report));
  rc = p1ll_apply(session, entries, entry_count, &report);
  if (rc != P1LL_SUCCESS) {
    print_error("apply");
    assert(rc == P1LL_SUCCESS);
  }
  assert(report.success);
  assert(report.applied == 1);
  assert(report.failed == 0);

  p1ll_free_plan_entries(entries, entry_count);

  assert(buffer[32] == 0x11);
  assert(buffer[33] == 0x22);
  assert(buffer[34] == 0x33);
  assert(buffer[35] == 0x44);
  printf("[ok] patch applied to buffer\n");

  p1ll_session_destroy(session);

  printf("[ok] buffer scan/apply\n\n");
}

int main(void) {
  test_capabilities();
  test_pattern_validation();
  test_hex_utilities();
  test_buffer_scan_and_apply();

  printf("all p1ll C API tests passed\n");
  return 0;
}
