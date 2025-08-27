#include "error.hpp"

namespace w1::debugger {

std::string error_code_to_string(error_code code) {
  switch (code) {
  case error_code::success:
    return "success";
  case error_code::target_not_found:
    return "target not found";
  case error_code::target_access_denied:
    return "target access denied";
  case error_code::target_invalid_arch:
    return "target invalid architecture";
  case error_code::insufficient_privileges:
    return "insufficient privileges";
  case error_code::debugger_entitlement_missing:
    return "debugger entitlement missing";
  case error_code::ptrace_scope_restricted:
    return "ptrace scope restricted";
  case error_code::debug_privilege_missing:
    return "debug privilege missing";
  case error_code::operation_failed:
    return "operation failed";
  case error_code::not_implemented:
    return "not implemented";
  case error_code::invalid_state:
    return "invalid state";
  case error_code::timeout:
    return "timeout";
  case error_code::out_of_memory:
    return "out of memory";
  case error_code::system_error:
    return "system error";
  case error_code::unknown_error:
    return "unknown error";
  default:
    return "unknown error code";
  }
}

result make_error_result(error_code code, const std::string& context, int system_error) {
  result r;
  r.code = code;
  r.error_message = error_code_to_string(code);
  if (!context.empty()) {
    r.error_message += ": " + context;
  }
  if (system_error != 0) {
    r.system_error_code = system_error;
    r.error_message += " (system error: " + std::to_string(system_error) + ")";
  }
  return r;
}

result make_success_result() { return result{error_code::success, "", std::nullopt}; }

bool is_recoverable_error(error_code code) {
  switch (code) {
  case error_code::timeout:
  case error_code::target_not_found:
    return true;
  default:
    return false;
  }
}

} // namespace w1::debugger
