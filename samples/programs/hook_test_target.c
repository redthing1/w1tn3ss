#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "signature_helper.h"

// create unique signatures using inline asm with different constants
#if defined(__x86_64__)
#define UNIQUE_SIGNATURE(id) __asm__ volatile("movabs $0xDEADBEEF0000" #id ", %%rax\n\t" : : : "rax")
#elif defined(__aarch64__)
#define UNIQUE_SIGNATURE(id)                                                                                           \
  __asm__ volatile("mov x0, #0x" #id "\n\t"                                                                            \
                   "movk x0, #0xBEEF, lsl #16\n\t"                                                                     \
                   "movk x0, #0xDEAD, lsl #32\n\t"                                                                     \
                   :                                                                                                   \
                   :                                                                                                   \
                   : "x0")
#else
#define UNIQUE_SIGNATURE(id) ASM_SIGNATURE_HELPER()
#endif

// test function 1: simple arithmetic with signature
NOINLINE int calculate_secret(int a, int b) {
  UNIQUE_SIGNATURE(1111);
  printf("[calculate_secret] computing %d * 3 + %d * 2\n", a, b);
  return 3 * a + 2 * b;
}

// test function 2: string operation with signature
#define MAX_BUFFER_SIZE 256
NOINLINE void format_message(char buffer[MAX_BUFFER_SIZE], const char* name, int value) {
  UNIQUE_SIGNATURE(2222);
  snprintf(buffer, MAX_BUFFER_SIZE, "hello %s, your magic number is %d", name, value);
  printf("[format_message] formatted: %s\n", buffer);
}

// test function 3: memory allocation with signature
NOINLINE void* allocate_buffer(size_t size) {
  UNIQUE_SIGNATURE(3333);
  printf("[allocate_buffer] allocating %zu bytes\n", size);
  void* ptr = malloc(size);
  if (ptr) {
    memset(ptr, 0, size);
  }
  return ptr;
}

// test function 4: comparison with signature
NOINLINE int compare_strings(const char* str1, const char* str2) {
  UNIQUE_SIGNATURE(4444);
  printf("[compare_strings] comparing \"%s\" with \"%s\"\n", str1, str2);
  return strcmp(str1, str2);
}

// test function 5: vulnerable function for security testing
NOINLINE void unsafe_copy(char* dst, const char* src) {
  UNIQUE_SIGNATURE(5555);
  // intentionally unsafe for testing security monitoring
  strcpy(dst, src);
  printf("[unsafe_copy] copied: %s\n", dst);
}

// utility functions that can be called via gadgeting

// function to get string length (useful for gadgeting)
NOINLINE size_t get_string_length(const char* str) {
  UNIQUE_SIGNATURE(6666);
  if (!str) {
    return 0;
  }
  return strlen(str);
}

// function to check if buffer contains pattern (useful for analysis)
NOINLINE int contains_pattern(const char* buffer, const char* pattern) {
  UNIQUE_SIGNATURE(7777);
  if (!buffer || !pattern) {
    return 0;
  }
  return strstr(buffer, pattern) != NULL;
}

// function to compute hash (useful for integrity checks)
NOINLINE unsigned int compute_hash(const void* data, size_t len) {
  UNIQUE_SIGNATURE(8888);
  const unsigned char* bytes = (const unsigned char*) data;
  unsigned int hash = 5381;
  for (size_t i = 0; i < len; i++) {
    hash = ((hash << 5) + hash) + bytes[i];
  }
  return hash;
}

// function to get process info (useful for context)
NOINLINE int get_process_id(void) {
  UNIQUE_SIGNATURE(9999);
  return getpid();
}

// function to validate pointer (useful for safety checks)
NOINLINE int is_valid_pointer(const void* ptr) {
  UNIQUE_SIGNATURE(aaaa);
  if (!ptr) {
    return 0;
  }
  // simple heuristic - check if it's in reasonable address range
  uintptr_t addr = (uintptr_t) ptr;
  return addr > 0x1000 && addr < 0x7fffffffffff;
}

int main(int argc, char* argv[]) {
  printf("=== hook test target program ===\n");
  printf("this program contains functions with asm signatures for testing\n\n");

  // test 1: calculate secret
  int x = 10, y = 20;
  int result = calculate_secret(x, y);
  printf("result: %d\n\n", result);

  // test 2: format message
  char message[MAX_BUFFER_SIZE];
  format_message(message, "tester", 42);
  printf("message: %s\n\n", message);

  // test 3: allocate buffer
  void* buffer = allocate_buffer(128);
  if (buffer) {
    printf("buffer allocated at: %p\n", buffer);
    free(buffer);
  }
  printf("\n");

  // test 4: compare strings
  const char* str1 = "hello";
  const char* str2 = "world";
  int cmp_result = compare_strings(str1, str2);
  printf("comparison result: %d\n\n", cmp_result);

  // test 5: unsafe copy (if argument provided)
  if (argc > 1) {
    char dest[64]; // small buffer for testing
    printf("performing unsafe copy of argument: %s\n", argv[1]);
    unsafe_copy(dest, argv[1]);
  }

  printf("=== test complete ===\n");
  return 0;
}