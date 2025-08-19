/**
 * @file main.c
 * @brief comprehensive test of p1ll C API functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <p1ll_c.h>

#define TEST_BUFFER_SIZE 256

static void print_error(const char* context) {
  const char* error = p1ll_get_last_error();
  if (error && strlen(error) > 0) {
    printf("✗ %s: %s\n", context, error);
  } else {
    printf("✗ %s: unknown error\n", context);
  }
}

static void test_capabilities(void) {
  printf("=== capability tests ===\n");

  int has_scripting = p1ll_has_scripting_support();
  printf("scripting support: %s\n", has_scripting ? "yes" : "no");
  printf("✓ capability queries work\n\n");
}

static void test_pattern_validation(void) {
  printf("=== pattern validation tests ===\n");

  // test valid patterns
  const char* valid_patterns[] = {"48 89 e5", "ff d0 ?? 74", "90 90 90 90", "48 ?? ?? ?? 74 ??", "c3"};

  for (size_t i = 0; i < sizeof(valid_patterns) / sizeof(valid_patterns[0]); ++i) {
    int valid = p1ll_validate_pattern(valid_patterns[i]);
    assert(valid == 1);
    printf("✓ validated pattern: '%s'\n", valid_patterns[i]);
  }

  // test invalid patterns
  const char* invalid_patterns[] = {
      "zz 90",   // invalid hex
      "4",       // incomplete byte
      "",        // empty pattern
      "90 gg 74" // invalid character
  };

  for (size_t i = 0; i < sizeof(invalid_patterns) / sizeof(invalid_patterns[0]); ++i) {
    int valid = p1ll_validate_pattern(invalid_patterns[i]);
    assert(valid == 0);
    printf("✓ rejected invalid pattern: '%s'\n", invalid_patterns[i]);
  }

  printf("✓ pattern validation working\n\n");
}

static void test_pattern_compilation(void) {
  printf("=== pattern compilation tests ===\n");

  const char* test_patterns[] = {
      "48 89 e5",          // simple pattern
      "48 89 e5 ?? 90",    // with wildcard
      "ff d0 ?? ?? 74 ??", // multiple wildcards
      "90 90 90 90"        // nop sled
  };

  for (size_t i = 0; i < sizeof(test_patterns) / sizeof(test_patterns[0]); ++i) {
    p1ll_compiled_pattern_t pattern = {0};
    int result = p1ll_compile_pattern(test_patterns[i], &pattern);
    assert(result == P1LL_SUCCESS);
    assert(pattern.bytes != NULL);
    assert(pattern.mask != NULL);
    assert(pattern.size > 0);

    printf("✓ compiled pattern '%s' -> %zu bytes\n", test_patterns[i], pattern.size);

    // verify mask logic
    for (size_t j = 0; j < pattern.size; ++j) {
      printf("  byte %zu: 0x%02x mask=%d\n", j, pattern.bytes[j], pattern.mask[j]);
    }

    p1ll_free_compiled_pattern(&pattern);
  }

  printf("✓ pattern compilation working\n\n");
}

static void test_hex_utilities(void) {
  printf("=== hex utility tests ===\n");

  // test hex string to bytes conversion
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
  printf("✓ hex string '%s' -> %zu bytes\n", hex_string, byte_count);

  // test bytes to hex string conversion
  char* hex_result = p1ll_bytes_to_hex_string(bytes, byte_count);
  assert(hex_result != NULL);
  printf("✓ bytes -> hex string: '%s'\n", hex_result);

  p1ll_free_bytes(bytes);
  p1ll_free_string(hex_result);

  // test address formatting
  uint64_t test_addresses[] = {0x7fff12345678, 0x1000, 0x0, 0xfffffffffffff000};

  for (size_t i = 0; i < sizeof(test_addresses) / sizeof(test_addresses[0]); ++i) {
    char* addr_str = p1ll_format_address(test_addresses[i]);
    assert(addr_str != NULL);
    printf("✓ address 0x%llx -> '%s'\n", (unsigned long long) test_addresses[i], addr_str);
    p1ll_free_string(addr_str);
  }

  printf("✓ hex utilities working\n\n");
}

static void test_buffer_search(void) {
  printf("=== buffer search tests ===\n");

  // create test buffer with known patterns
  uint8_t test_buffer[TEST_BUFFER_SIZE];

  // fill with pattern: nops, then call rax, test eax eax, jz +5
  memset(test_buffer, 0x90, TEST_BUFFER_SIZE); // fill with nops

  // embed some patterns at known locations
  test_buffer[50] = 0x48;
  test_buffer[51] = 0x89;
  test_buffer[52] = 0xe5; // mov rbp, rsp
  test_buffer[100] = 0xff;
  test_buffer[101] = 0xd0; // call rax
  test_buffer[150] = 0x48;
  test_buffer[151] = 0x89;
  test_buffer[152] = 0xe5; // another mov rbp, rsp

  // search for nop pattern
  size_t* offsets = NULL;
  size_t offset_count = 0;

  int result = p1ll_search_in_buffer(test_buffer, TEST_BUFFER_SIZE, "90 90 90", &offsets, &offset_count);
  assert(result == P1LL_SUCCESS);
  printf("✓ found %zu matches for '90 90 90' pattern\n", offset_count);

  if (offset_count > 0) {
    printf("  first few matches: ");
    for (size_t i = 0; i < offset_count && i < 5; ++i) {
      printf("%zu ", offsets[i]);
    }
    printf("\n");
  }

  p1ll_free_offsets(offsets);

  // search for mov rbp, rsp pattern
  result = p1ll_search_in_buffer(test_buffer, TEST_BUFFER_SIZE, "48 89 e5", &offsets, &offset_count);
  assert(result == P1LL_SUCCESS);
  printf("✓ found %zu matches for '48 89 e5' pattern\n", offset_count);

  // should find matches at offsets 50 and 150
  assert(offset_count >= 2);
  int found_50 = 0, found_150 = 0;
  for (size_t i = 0; i < offset_count; ++i) {
    printf("  match at offset: %zu\n", offsets[i]);
    if (offsets[i] == 50) {
      found_50 = 1;
    }
    if (offsets[i] == 150) {
      found_150 = 1;
    }
  }
  assert(found_50 && found_150);

  p1ll_free_offsets(offsets);

  // search for pattern with wildcards
  result = p1ll_search_in_buffer(test_buffer, TEST_BUFFER_SIZE, "ff ?? 85", &offsets, &offset_count);
  assert(result == P1LL_SUCCESS);
  printf("✓ wildcard search completed, found %zu matches\n", offset_count);
  p1ll_free_offsets(offsets);

  printf("✓ buffer search working\n\n");
}

static void test_scanner_creation(void) {
  printf("=== scanner creation tests ===\n");

  // test scanner creation and destruction
  p1ll_scanner_t scanner = p1ll_scanner_create();
  assert(scanner != NULL);
  printf("✓ scanner created successfully\n");

  // test page size query
  size_t page_size = p1ll_get_page_size(scanner);
  assert(page_size > 0);
  assert(page_size >= 4096); // minimum expected page size
  printf("✓ system page size: %zu bytes\n", page_size);

  p1ll_scanner_destroy(scanner);
  printf("✓ scanner destroyed successfully\n\n");
}

static void test_memory_regions(void) {
  printf("=== memory region enumeration tests ===\n");

  p1ll_scanner_t scanner = p1ll_scanner_create();
  assert(scanner != NULL);

  p1ll_memory_region_t* regions = NULL;
  size_t region_count = 0;

  int result = p1ll_get_memory_regions(scanner, &regions, &region_count);
  if (result == P1LL_SUCCESS) {
    printf("✓ found %zu memory regions\n", region_count);

    if (region_count > 0) {
      printf("first few regions:\n");
      for (size_t i = 0; i < region_count && i < 10; ++i) {
        const p1ll_memory_region_t* r = &regions[i];
        printf(
            "  [%zu] base=0x%llx size=%zu prot=0x%x exec=%d sys=%d name='%s'\n", i,
            (unsigned long long) r->base_address, r->size, r->protection, r->is_executable, r->is_system, r->name
        );
      }

      // test getting region info for specific address
      p1ll_memory_region_t test_region = {0};
      uint64_t test_addr = regions[0].base_address + 100;
      result = p1ll_get_region_at_address(scanner, test_addr, &test_region);
      if (result == P1LL_SUCCESS) {
        printf("✓ region lookup for 0x%llx successful\n", (unsigned long long) test_addr);
      } else {
        print_error("region lookup");
      }
    }

    p1ll_free_memory_regions(regions);
    printf("✓ memory region enumeration working\n");
  } else {
    print_error("memory region enumeration");
    printf("note: this may fail in some test environments\n");
  }

  p1ll_scanner_destroy(scanner);
  printf("\n");
}

static void test_memory_operations(void) {
  printf("=== memory operation tests ===\n");

  p1ll_scanner_t scanner = p1ll_scanner_create();
  assert(scanner != NULL);

  // test memory allocation (use page size)
  size_t page_size = p1ll_get_page_size(scanner);
  void* allocated = p1ll_allocate_memory(scanner, page_size, P1LL_PROT_READ | P1LL_PROT_WRITE);
  if (allocated != NULL) {
    printf("✓ allocated %zu bytes at %p\n", page_size, allocated);

    // test writing to allocated memory
    uint8_t test_data[] = {0x48, 0x89, 0xe5, 0x90, 0x90, 0x90, 0xc3};
    size_t test_size = sizeof(test_data);

    int write_result = p1ll_write_memory(scanner, (uint64_t) allocated, test_data, test_size);
    if (write_result == P1LL_SUCCESS) {
      printf("✓ wrote %zu bytes to allocated memory\n", test_size);

      // test reading back
      uint8_t read_buffer[16] = {0};
      int read_result = p1ll_read_memory(scanner, (uint64_t) allocated, read_buffer, test_size);
      if (read_result == P1LL_SUCCESS) {
        printf("✓ read back %zu bytes from allocated memory\n", test_size);

        // verify data
        if (memcmp(test_data, read_buffer, test_size) == 0) {
          printf("✓ read data matches written data\n");
        } else {
          printf("✗ read data does not match written data\n");
        }
      } else {
        print_error("memory read");
      }

      // test pattern search in our allocated memory
      p1ll_match_t* matches = NULL;
      size_t match_count = 0;

      int search_result = p1ll_search_in_region(scanner, (uint64_t) allocated, "48 89 e5", &matches, &match_count);
      if (search_result == P1LL_SUCCESS) {
        printf("✓ pattern search in allocated memory: %zu matches\n", match_count);
        if (match_count > 0) {
          printf("  match at address: 0x%llx\n", (unsigned long long) matches[0].address);
        }
        p1ll_free_matches(matches);
      } else {
        print_error("pattern search in region");
      }

      // test hex pattern patching
      int patch_result = p1ll_patch_memory(scanner, (uint64_t) allocated, "90 90 90");
      if (patch_result == P1LL_SUCCESS) {
        printf("✓ patched memory with hex pattern\n");
      } else {
        print_error("memory patching");
      }
    } else {
      print_error("memory write");
    }

    // cleanup
    int free_result = p1ll_free_memory(scanner, allocated, page_size);
    if (free_result == P1LL_SUCCESS) {
      printf("✓ freed allocated memory\n");
    } else {
      print_error("memory free");
    }
  } else {
    print_error("memory allocation");
    printf("note: memory allocation may fail in some test environments\n");
  }

  p1ll_scanner_destroy(scanner);
  printf("✓ memory operation tests completed\n\n");
}

int main() {
  printf("=== p1ll c api comprehensive test ===\n\n");

  // run all test suites
  test_capabilities();
  test_pattern_validation();
  test_pattern_compilation();
  test_hex_utilities();
  test_buffer_search();
  test_scanner_creation();
  test_memory_regions();
  test_memory_operations();

  printf("=== all p1ll c api tests completed successfully! ===\n");
  return 0;
}