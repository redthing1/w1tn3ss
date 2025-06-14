#pragma once

#include "w1nj3ct.hpp"
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace w1::inject {
// error code to string conversion
std::string error_code_to_string(error_code code);

// platform-specific error translation
error_code translate_platform_error(int platform_error);

#ifdef _WIN32
std::string translate_platform_error(DWORD error_code);
#endif

// recoverable vs non-recoverable error classification
bool is_recoverable_error(error_code code);

// detailed error message formatting with context
std::string format_error_message(error_code code, const std::string& context = "");

// create result with platform error translation
result make_error_result(error_code code, const std::string& context = "", int platform_error = 0);

// helper for creating success result
result make_success_result(int target_pid = -1);
} // namespace w1::inject