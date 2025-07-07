#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "signature_helper.h"

// Create unique signatures using inline asm with different constants
#if defined(__x86_64__)
#define UNIQUE_SIGNATURE(id) \
    __asm__ volatile("movabs $0xDEADBEEF0000" #id ", %rax\n\t" : : : "rax")
#elif defined(__aarch64__)
#define UNIQUE_SIGNATURE(id) \
    __asm__ volatile( \
        "mov x0, #0x" #id "\n\t" \
        "movk x0, #0xBEEF, lsl #16\n\t" \
        "movk x0, #0xDEAD, lsl #32\n\t" \
        : : : "x0")
#else
#define UNIQUE_SIGNATURE(id) ASM_SIGNATURE_HELPER()
#endif

// Test function 1: Simple arithmetic with signature
NOINLINE int calculate_secret(int a, int b) {
    UNIQUE_SIGNATURE(1111);
    printf("[calculate_secret] Computing %d * 3 + %d * 2\n", a, b);
    return 3 * a + 2 * b;
}

// Test function 2: String operation with signature
#define MAX_BUFFER_SIZE 256
NOINLINE void format_message(char buffer[MAX_BUFFER_SIZE], const char* name, int value) {
    UNIQUE_SIGNATURE(2222);
    snprintf(buffer, MAX_BUFFER_SIZE, "Hello %s, your magic number is %d", name, value);
    printf("[format_message] Formatted: %s\n", buffer);
}

// Test function 3: Memory allocation with signature
NOINLINE void* allocate_buffer(size_t size) {
    UNIQUE_SIGNATURE(3333);
    printf("[allocate_buffer] Allocating %zu bytes\n", size);
    void* ptr = malloc(size);
    if (ptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

// Test function 4: Comparison with signature
NOINLINE int compare_strings(const char* str1, const char* str2) {
    UNIQUE_SIGNATURE(4444);
    printf("[compare_strings] Comparing \"%s\" with \"%s\"\n", str1, str2);
    return strcmp(str1, str2);
}

// Test function 5: Vulnerable function for security testing
NOINLINE void unsafe_copy(char* dst, const char* src) {
    UNIQUE_SIGNATURE(5555);
    // Intentionally unsafe for testing security monitoring
    strcpy(dst, src);
    printf("[unsafe_copy] Copied: %s\n", dst);
}

int main(int argc, char* argv[]) {
    printf("=== Hook Test Target Program ===\n");
    printf("This program contains functions with ASM signatures for testing\n\n");

    // Test 1: Calculate secret
    int x = 10, y = 20;
    int result = calculate_secret(x, y);
    printf("Result: %d\n\n", result);

    // Test 2: Format message
    char message[MAX_BUFFER_SIZE];
    format_message(message, "Tester", 42);
    printf("Message: %s\n\n", message);

    // Test 3: Allocate buffer
    void* buffer = allocate_buffer(128);
    if (buffer) {
        printf("Buffer allocated at: %p\n", buffer);
        free(buffer);
    }
    printf("\n");

    // Test 4: Compare strings
    const char* str1 = "hello";
    const char* str2 = "world";
    int cmp_result = compare_strings(str1, str2);
    printf("Comparison result: %d\n\n", cmp_result);

    // Test 5: Unsafe copy (if argument provided)
    if (argc > 1) {
        char dest[64];  // Small buffer for testing
        printf("Performing unsafe copy of argument: %s\n", argv[1]);
        unsafe_copy(dest, argv[1]);
    }

    printf("=== Test Complete ===\n");
    return 0;
}