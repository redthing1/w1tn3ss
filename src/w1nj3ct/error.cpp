#include "error.hpp"

#ifdef _WIN32
#include <w1base/windows_clean.hpp>
#elif defined(__APPLE__)
#include <errno.h>
#include <mach/mach.h>
#elif defined(__linux__)
#include <errno.h>
#endif

namespace w1::inject {

std::string error_code_to_string(error_code code) {
  switch (code) {
  case error_code::success:
    return "success";
  case error_code::target_not_found:
    return "target process not found";
  case error_code::multiple_targets_found:
    return "multiple target processes found";
  case error_code::target_access_denied:
    return "access denied to target process";
  case error_code::target_invalid_architecture:
    return "target process has incompatible architecture";
  case error_code::library_not_found:
    return "library file not found";
  case error_code::library_invalid:
    return "library file is invalid";
  case error_code::library_incompatible:
    return "library is incompatible with target process";
  case error_code::injection_failed:
    return "injection operation failed";
  case error_code::injection_timeout:
    return "injection operation timed out";
  case error_code::injection_already_loaded:
    return "library is already loaded in target process";
  case error_code::platform_not_supported:
    return "platform not supported";
  case error_code::technique_not_supported:
    return "injection technique not supported";
  case error_code::insufficient_privileges:
    return "insufficient privileges for injection";
  case error_code::out_of_memory:
    return "out of memory";
  case error_code::system_error:
    return "system error";
  case error_code::configuration_invalid:
    return "invalid configuration";
  case error_code::launch_failed:
    return "failed to launch process";
  case error_code::launch_timeout:
    return "process launch timed out";
  case error_code::unknown_error:
  default:
    return "unknown error";
  }
}

error_code translate_platform_error(int platform_error) {
#ifdef _WIN32
  switch (platform_error) {
  case ERROR_ACCESS_DENIED:
    return error_code::target_access_denied;
  case ERROR_FILE_NOT_FOUND:
  case ERROR_PATH_NOT_FOUND:
    return error_code::library_not_found;
  case ERROR_INVALID_HANDLE:
    return error_code::target_not_found;
  case ERROR_NOT_ENOUGH_MEMORY:
  case ERROR_OUTOFMEMORY:
    return error_code::out_of_memory;
  case ERROR_INVALID_PARAMETER:
    return error_code::configuration_invalid;
  case ERROR_TIMEOUT:
    return error_code::injection_timeout;
  default:
    return error_code::system_error;
  }
#elif defined(__APPLE__)
  switch (platform_error) {
  case KERN_PROTECTION_FAILURE:
    return error_code::target_access_denied;
  case KERN_INVALID_ARGUMENT:
    return error_code::configuration_invalid;
  case KERN_NO_SPACE:
  case KERN_RESOURCE_SHORTAGE:
    return error_code::out_of_memory;
  case KERN_FAILURE:
    return error_code::injection_failed;
  default:
    // also check errno for posix errors
    switch (errno) {
    case EACCES:
    case EPERM:
      return error_code::target_access_denied;
    case ENOENT:
      return error_code::library_not_found;
    case ESRCH:
      return error_code::target_not_found;
    case ENOMEM:
      return error_code::out_of_memory;
    case ETIMEDOUT:
      return error_code::injection_timeout;
    default:
      return error_code::system_error;
    }
  }
#elif defined(__linux__)
  switch (platform_error) {
  case EACCES:
  case EPERM:
    return error_code::target_access_denied;
  case ENOENT:
    return error_code::library_not_found;
  case ESRCH:
    return error_code::target_not_found;
  case ENOMEM:
    return error_code::out_of_memory;
  case EINVAL:
    return error_code::configuration_invalid;
  case ETIMEDOUT:
    return error_code::injection_timeout;
  default:
    return error_code::system_error;
  }
#endif
  return error_code::system_error;
}

bool is_recoverable_error(error_code code) {
  switch (code) {
  case error_code::injection_timeout:
  case error_code::target_not_found:
  case error_code::multiple_targets_found:
  case error_code::library_not_found:
  case error_code::injection_already_loaded:
    return true;
  default:
    return false;
  }
}

std::string format_error_message(error_code code, const std::string& context) {
  std::string base_message = error_code_to_string(code);

  switch (code) {
  case error_code::insufficient_privileges:
#ifdef _WIN32
    return base_message + ". try running as administrator";
#else
    return base_message + ". try running as root or with appropriate capabilities";
#endif
  case error_code::multiple_targets_found:
    return base_message + ". use find_processes() to list all matches and select specific pid";
  case error_code::target_access_denied:
#ifdef __APPLE__
    return base_message + ". check code signing entitlements and sip status";
#else
    return base_message + ". check process permissions and ptrace scope";
#endif
  case error_code::platform_not_supported:
    return base_message + ". this platform is not yet supported by w1nj3ct";
  case error_code::technique_not_supported:
#ifdef _WIN32
    return base_message + ". try a different windows_technique";
#else
    return base_message + ". preload injection not supported on this platform";
#endif
  default:
    break;
  }

  return base_message + (context.empty() ? "" : " (" + context + ")");
}

result make_error_result(error_code code, const std::string& context, int platform_error) {
  result res;
  res.code = code;
  res.error_message = format_error_message(code, context);
  if (platform_error != 0) {
    res.system_error_code = platform_error;
  }
  return res;
}

result make_success_result(int target_pid) {
  result res;
  res.code = error_code::success;
  res.target_pid = target_pid;
  return res;
}

} // namespace w1::inject