#pragma once

#include <string>
#include <optional>

namespace w1::debugger {

// error codes matching w1nj3ct pattern
enum class error_code {
  success,

  // target errors
  target_not_found,
  target_access_denied,
  target_invalid_arch,

  // permission errors
  insufficient_privileges,
  debugger_entitlement_missing, // macos
  ptrace_scope_restricted,      // linux yama
  debug_privilege_missing,      // windows sedebugprivilege

  // operation errors
  operation_failed,
  not_implemented,
  invalid_state,
  timeout,

  // system errors
  out_of_memory,
  system_error,

  unknown_error
};

// result type
struct result {
  error_code code;
  std::string error_message;
  std::optional<int> system_error_code;

  bool success() const { return code == error_code::success; }
  operator bool() const { return success(); }
};

// error utilities
std::string error_code_to_string(error_code code);
result make_error_result(error_code code, const std::string& context = "", int system_error = 0);
result make_success_result();
bool is_recoverable_error(error_code code);

} // namespace w1::debugger
