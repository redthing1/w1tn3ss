#pragma once

#include <string>

#ifdef _WIN32
#define P01S0N_API __declspec(dllexport)
#else
#define P01S0N_API __attribute__((visibility("default")))
#endif

namespace p01s0n {

/**
 * @brief Main entry point for p01s0n dynamic patching
 *
 * This function is called automatically when the library is loaded
 * via preload injection. It reads the P1LL_CURE environment variable
 * and applies the specified cure script to the current process.
 *
 * @return 0 on success, non-zero on failure
 */
P01S0N_API int p01s0n_run();

} // namespace p01s0n