#pragma once

#include <stdint.h>

// prevent inlining
#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif

/*
 * ASM_SIGNATURE_HELPER Macro (Thank you Claude 3.5 Sonnet)
 *
 * Purpose:
 * This macro inserts a unique, easily identifiable assembly code sequence
 * into a function. It's designed to assist in debugging, function detouring,
 * and memory analysis by providing a consistent, platform-specific signature
 * that can be used to locate functions in memory.
 *
 * Supported Platforms:
 * - MSVC x64
 * - MSVC ARM64
 * - Clang x64
 * - Clang ARM64
 * - GCC x64
 * - GCC ARM64
 *
 * Key Features:
 * 1. Platform-Specific Implementation: Uses conditional compilation to provide
 *    appropriate assembly for each supported platform and architecture.
 * 2. Unique Signature: Utilizes easily recognizable constants (0xDEADBEEFCAFEBABE
 *    and 0xCAFEBABEDEADBEEF) to create a distinct pattern in memory.
 * 3. Optimization Resistance: Employs various techniques to prevent compiler
 *    optimization from removing or altering the signature code.
 *
 * Optimization Prevention Techniques:
 * - Volatile Assembly: Marks assembly as volatile to indicate potential side effects.
 * - Memory Barriers: Prevents instruction reordering around the signature.
 * - Dummy Variables: Forces the compiler to consider the computation results.
 * - Output Constraints: Ensures the assembly results are used (for Clang and GCC).
 * - Memory Clobbering: Indicates potential memory access to the compiler.
 * - Stack Operations: Simulates memory side effects (especially for ARM).
 *
 * Usage:
 * Insert ASM_SIGNATURE_HELPER(); at the beginning of any function you want to mark.
 * Example:
 *     void my_function() {
 *         ASM_SIGNATURE_HELPER();
 *         // Rest of the function code...
 *     }
 *
 * Finding the Function Start:
 * 1. Locate the signature in memory.
 * 2. Scan backwards for the function prologue:
 *    - x64: Look for instructions like "push rbp; mov rbp, rsp"
 *    - ARM64: Look for instructions like "stp x29, x30, [sp, #-16]!"
 * 3. The first instruction of the prologue is likely the true function start.
 *
 * Note:
 * While this macro is designed to be optimization-resistant, it's not guaranteed
 * to work with all optimization levels or future compiler versions. Always test
 * thoroughly with your specific build configuration.
 */
#if defined(_MSC_VER) && defined(_M_X64)
// MSVC for x64
#define ASM_SIGNATURE_HELPER()                                                  \
    do {                                                                        \
        volatile uint64_t dummy1 = 0xDEADBEEFCAFEBABE;                          \
        volatile uint64_t dummy2 = 0xCAFEBABEDEADBEEF;                          \
        volatile uint64_t result;                                               \
        result = dummy1 ^ dummy2;                                               \
        dummy1 = result;                                                        \
        _ReadWriteBarrier();                                                    \
        _mm_mfence();                                                           \
        (void)dummy1; /* Prevent 'unused variable' warnings */                  \
        (void)dummy2;                                                           \
    } while (0)
#elif defined(_MSC_VER) && defined(_M_ARM64)
// MSVC for ARM64
#define ASM_SIGNATURE_HELPER()                                                  \
    do {                                                                        \
        volatile uint64_t dummy1 = 0xDEADBEEFCAFEBABE;                          \
        volatile uint64_t dummy2 = 0xCAFEBABEDEADBEEF;                          \
        volatile uint64_t result;                                               \
        result = dummy1 ^ dummy2;                                               \
        dummy1 = result;                                                        \
        __dmb(_ARM64_BARRIER_ISH);  /* Data Memory Barrier */                   \
        __iso_volatile_load64(&dummy1);  /* Volatile read to prevent optimization */ \
        (void)dummy2;                                                           \
    } while (0)
#elif defined(__clang__)
#if defined(__x86_64__)
// Clang for x64
#define ASM_SIGNATURE_HELPER()                                                                                         \
  do {                                                                                                                 \
    uint64_t dummy;                                                                                                    \
    __asm__ volatile("nop\n\t"                                                                                         \
                     "movabs $0xDEADBEEFCAFEBABE, %%rax\n\t"                                                           \
                     "movabs $0xCAFEBABEDEADBEEF, %%rbx\n\t"                                                           \
                     "xorq %%rbx, %%rax\n\t"                                                                           \
                     "movq %%rax, %0\n\t"                                                                              \
                     "nop\n\t"                                                                                         \
                     : "=r"(dummy)                                                                                     \
                     :                                                                                                 \
                     : "rax", "rbx", "memory");                                                                        \
    __asm__ volatile("" : : : "memory");                                                                               \
    (void) dummy;                                                                                                      \
  } while (0)
#elif defined(__aarch64__)
// Clang for ARM64
#define ASM_SIGNATURE_HELPER()                                                                                         \
  do {                                                                                                                 \
    uint64_t dummy;                                                                                                    \
    __asm__ volatile("nop\n\t"                                                                                         \
                     "mov x0, #0xDEAD\n\t"                                                                             \
                     "movk x0, #0xBEEF, lsl #16\n\t"                                                                   \
                     "movk x0, #0xCAFE, lsl #32\n\t"                                                                   \
                     "movk x0, #0xBABE, lsl #48\n\t"                                                                   \
                     "mov x1, #0xCAFE\n\t"                                                                             \
                     "movk x1, #0xBABE, lsl #16\n\t"                                                                   \
                     "movk x1, #0xDEAD, lsl #32\n\t"                                                                   \
                     "movk x1, #0xBEEF, lsl #48\n\t"                                                                   \
                     "eor x0, x0, x1\n\t"                                                                              \
                     "str x0, [sp, #-16]!\n\t"                                                                         \
                     "ldr x0, [sp], #16\n\t"                                                                           \
                     "mov %0, x0\n\t"                                                                                  \
                     "nop\n\t"                                                                                         \
                     : "=r"(dummy)                                                                                     \
                     :                                                                                                 \
                     : "x0", "x1", "memory");                                                                          \
    __asm__ volatile("" : : : "memory");                                                                               \
    (void) dummy;                                                                                                      \
  } while (0)
#else
#error "Unsupported architecture for ASM_SIGNATURE_HELPER"
#endif
#elif defined(__GNUC__)
#if defined(__x86_64__)
// GCC for x64
#define ASM_SIGNATURE_HELPER()                                                                                         \
  do {                                                                                                                 \
    uint64_t dummy;                                                                                                    \
    __asm__ volatile("nop\n\t"                                                                                         \
                     "movabs $0xDEADBEEFCAFEBABE, %%rax\n\t"                                                           \
                     "movabs $0xCAFEBABEDEADBEEF, %%rbx\n\t"                                                           \
                     "xorq %%rbx, %%rax\n\t"                                                                           \
                     "movq %%rax, %0\n\t"                                                                              \
                     "nop\n\t"                                                                                         \
                     : "=r"(dummy)                                                                                     \
                     :                                                                                                 \
                     : "rax", "rbx", "memory");                                                                        \
    __asm__ volatile("" : : : "memory");                                                                               \
    (void) dummy;                                                                                                      \
  } while (0)
#elif defined(__aarch64__)
// GCC for ARM64
#define ASM_SIGNATURE_HELPER()                                                                                         \
  do {                                                                                                                 \
    uint64_t dummy;                                                                                                    \
    __asm__ volatile("nop\n\t"                                                                                         \
                     "mov x0, #0xDEAD\n\t"                                                                             \
                     "movk x0, #0xBEEF, lsl #16\n\t"                                                                   \
                     "movk x0, #0xCAFE, lsl #32\n\t"                                                                   \
                     "movk x0, #0xBABE, lsl #48\n\t"                                                                   \
                     "mov x1, #0xCAFE\n\t"                                                                             \
                     "movk x1, #0xBABE, lsl #16\n\t"                                                                   \
                     "movk x1, #0xDEAD, lsl #32\n\t"                                                                   \
                     "movk x1, #0xBEEF, lsl #48\n\t"                                                                   \
                     "eor x0, x0, x1\n\t"                                                                              \
                     "str x0, [sp, #-16]!\n\t"                                                                         \
                     "ldr x0, [sp], #16\n\t"                                                                           \
                     "mov %0, x0\n\t"                                                                                  \
                     "nop\n\t"                                                                                         \
                     : "=r"(dummy)                                                                                     \
                     :                                                                                                 \
                     : "x0", "x1", "memory");                                                                          \
    __asm__ volatile("" : : : "memory");                                                                               \
    (void) dummy;                                                                                                      \
  } while (0)
#else
#error "Unsupported architecture for ASM_SIGNATURE_HELPER"
#endif
#else
#error "Unsupported compiler for ASM_SIGNATURE_HELPER"
#endif
