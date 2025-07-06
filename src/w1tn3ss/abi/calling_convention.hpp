#pragma once

#include <QBDI.h>
#include <optional>
#include <vector>

namespace w1::abi {

class calling_convention {
public:
    // Simple argument extraction
    static std::vector<uint64_t> extract_args(
        QBDI::GPRState* gpr,
        QBDI::VMInstanceRef vm,
        size_t count);
    
    // Extract with type awareness
    enum class arg_type {
        INTEGER,    // Integer or pointer
        FLOAT,      // Single precision
        DOUBLE,     // Double precision
        SIMD        // Vector type
    };
    
    struct typed_arg {
        arg_type type;
        union {
            uint64_t integer;
            float f32;
            double f64;
            uint8_t simd[16];
        } value;
    };
    
    static std::vector<typed_arg> extract_typed_args(
        QBDI::GPRState* gpr,
        QBDI::FPRState* fpr,
        QBDI::VMInstanceRef vm,
        const std::vector<arg_type>& types);
    
    // Return value extraction
    static uint64_t extract_integer_return(QBDI::GPRState* gpr);
    
    static double extract_float_return(QBDI::FPRState* fpr);
    
    // Stack pointer access
    static uint64_t get_stack_pointer(QBDI::GPRState* gpr);
    
    // Return address calculation for different call types
    static uint64_t calculate_return_address(
        uint64_t call_site,
        QBDI::GPRState* gpr,
        const QBDI::InstAnalysis* inst = nullptr);
    
    // Variadic function support
    struct variadic_info {
        size_t fixed_args;
        uint64_t va_list_ptr;  // Platform-specific
    };
    
    static std::optional<variadic_info> get_variadic_info(
        QBDI::GPRState* gpr,
        QBDI::VMInstanceRef vm,
        size_t fixed_arg_count);
};

namespace detail {
    // Platform detection and selection
    #if defined(_WIN64)
        struct x86_64_windows;
        using current_platform = x86_64_windows;
    #elif defined(__x86_64__)
        struct x86_64_sysv;
        using current_platform = x86_64_sysv;
    #elif defined(__aarch64__)
        struct aarch64;
        using current_platform = aarch64;
    #elif defined(__arm__)
        struct arm32;
        using current_platform = arm32;
    #elif defined(__i386__)
        struct x86_32;
        using current_platform = x86_32;
    #else
        #error "Unsupported platform"
    #endif
}

} // namespace w1::abi