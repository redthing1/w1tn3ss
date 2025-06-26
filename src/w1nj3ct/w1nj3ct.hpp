#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace w1::inject {
// injection methods
enum class method {
  runtime, // inject into running process
  launch   // launch new process with library preloaded
};

// platform-specific technique enums
#ifdef _WIN32
enum class windows_technique {
  create_remote_thread,
  set_windows_hook,
  rtl_create_user_thread,
  reflective_loader,
  launch_suspended
};
#endif

// comprehensive cross-platform error codes
enum class error_code {
  success,

  // target errors
  target_not_found,
  multiple_targets_found,
  target_access_denied,
  target_invalid_architecture,

  // library errors
  library_not_found,
  library_invalid,
  library_incompatible,

  // injection errors
  injection_failed,
  injection_timeout,
  injection_already_loaded,

  // platform errors
  platform_not_supported,
  technique_not_supported,
  insufficient_privileges,

  // system errors
  out_of_memory,
  system_error,
  configuration_invalid,

  // launch errors
  launch_failed,
  launch_timeout,

  unknown_error
};

// process info for discovery
struct process_info {
  int pid;
  std::string name;
  std::string full_path;
  std::string command_line;

  bool operator==(const process_info& other) const { return pid == other.pid; }
};

// configuration
struct config {
  // REQUIRED
  std::string library_path;
  method injection_method; // user must explicitly choose

  // TARGET (exactly one required)
  std::optional<int> pid;
  std::optional<std::string> process_name;
  std::optional<std::string> binary_path;

  // BEHAVIOR
  std::chrono::milliseconds timeout{5000};
  bool suspended = false; // start process in suspended state (launch method only)

  // LAUNCH OPTIONS (when using binary_path)
  std::vector<std::string> args;
  std::map<std::string, std::string> env_vars;

  // PLATFORM-SPECIFIC
#ifdef _WIN32
  windows_technique windows_technique = windows_technique::create_remote_thread;
  bool windows_elevate = false;
#endif

#ifdef __linux__
  std::string linux_namespace;
#endif

  // DEBUGGING
  bool verbose = false;
};

// result
struct result {
  error_code code;
  int target_pid = -1;
  std::string error_message;
  std::optional<int> system_error_code;

  // convenience
  bool success() const { return code == error_code::success; }
  operator bool() const { return success(); }
};

// MAIN INJECTION FUNCTION
result inject(const config& cfg);

// CONVENIENCE FUNCTIONS
inline result inject_library_runtime(const std::string& library_path, int pid);
inline result inject_library_runtime(const std::string& library_path, const std::string& process_name);
inline result inject_library_launch(
    const std::string& binary_path, const std::string& library_path, const std::vector<std::string>& args = {}
);

// PROCESS DISCOVERY
std::vector<process_info> list_processes();
std::vector<process_info> find_processes(const std::string& name);
std::optional<process_info> get_process_info(int pid);

// UTILITIES
bool check_injection_capabilities();
std::vector<std::string> get_supported_platforms();
bool is_library_compatible(const std::string& library_path, int pid);
std::string error_code_to_string(error_code code);
bool is_recoverable_error(error_code code);

// CONVENIENCE FUNCTION IMPLEMENTATIONS
inline result inject_library_runtime(const std::string& library_path, int pid) {
  config cfg;
  cfg.library_path = library_path;
  cfg.injection_method = method::runtime;
  cfg.pid = pid;
  return inject(cfg);
}

inline result inject_library_runtime(const std::string& library_path, const std::string& process_name) {
  config cfg;
  cfg.library_path = library_path;
  cfg.injection_method = method::runtime;
  cfg.process_name = process_name;
  return inject(cfg);
}

inline result inject_library_launch(
    const std::string& binary_path, const std::string& library_path, const std::vector<std::string>& args
) {
  config cfg;
  cfg.library_path = library_path;
  cfg.injection_method = method::launch;
  cfg.binary_path = binary_path;
  cfg.args = args;
  return inject(cfg);
}
} // namespace w1::inject