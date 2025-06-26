#pragma once

#include <redlog/redlog.hpp>

// Windows DLL export/import declarations
#ifdef _WIN32
#ifdef W1TN3SS_EXPORTS
#define W1TN3SS_API __declspec(dllexport)
#elif defined(W1TN3SS_IMPORTS)
#define W1TN3SS_API __declspec(dllimport)
#else
#define W1TN3SS_API
#endif
#else
#define W1TN3SS_API
#endif

namespace w1 {

/**
 * @brief W1tn3ss library information and utilities
 * 
 * This class provides library version information and basic utilities.
 */
class W1TN3SS_API w1tn3ss {
public:
    /**
     * @brief Get library version string
     */
    static const char* version();
    
    /**
     * @brief Get library build information
     */
    static const char* build_info();
    
    /**
     * @brief Print library information
     */
    static void print_info();

private:
    // Static utility class - no instances needed
    w1tn3ss() = delete;
    ~w1tn3ss() = delete;
    w1tn3ss(const w1tn3ss&) = delete;
    w1tn3ss& operator=(const w1tn3ss&) = delete;
};

} // namespace w1