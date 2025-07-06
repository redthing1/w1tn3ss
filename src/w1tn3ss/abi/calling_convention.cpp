#include "calling_convention.hpp"

// Include platform-specific implementations
#if defined(_WIN64)
    #include "detail/x86_64_windows.hpp"
#elif defined(__x86_64__)
    #include "detail/x86_64_sysv.hpp"
#elif defined(__aarch64__)
    #include "detail/aarch64.hpp"
#elif defined(__arm__)
    #include "detail/arm32.hpp"
#elif defined(__i386__)
    #include "detail/x86_32.hpp"
#else
    #error "Unsupported platform"
#endif

namespace w1::abi {

std::vector<uint64_t> calling_convention::extract_args(
    QBDI::GPRState* gpr,
    QBDI::VMInstanceRef vm,
    size_t count) {
    
    return detail::current_platform::extract_integer_args(gpr, vm, count);
}

std::vector<calling_convention::typed_arg> calling_convention::extract_typed_args(
    QBDI::GPRState* gpr,
    QBDI::FPRState* fpr,
    QBDI::VMInstanceRef vm,
    const std::vector<arg_type>& types) {
    
    return detail::current_platform::extract_typed_args(gpr, fpr, vm, types);
}

uint64_t calling_convention::extract_integer_return(QBDI::GPRState* gpr) {
    return detail::current_platform::get_integer_return(gpr);
}

double calling_convention::extract_float_return(QBDI::FPRState* fpr) {
    return detail::current_platform::get_float_return(fpr);
}

uint64_t calling_convention::get_stack_pointer(QBDI::GPRState* gpr) {
    return detail::current_platform::get_stack_pointer(gpr);
}

uint64_t calling_convention::calculate_return_address(
    uint64_t call_site,
    QBDI::GPRState* gpr,
    const QBDI::InstAnalysis* inst) {
    
    return detail::current_platform::calculate_return_address(
        call_site, gpr, inst);
}

std::optional<calling_convention::variadic_info> 
calling_convention::get_variadic_info(
    QBDI::GPRState* gpr,
    QBDI::VMInstanceRef vm,
    size_t fixed_arg_count) {
    
    // TODO: Implement variadic support
    return std::nullopt;
}

} // namespace w1::abi