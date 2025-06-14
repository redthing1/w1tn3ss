#include "w1nj3ct.hpp"
#include "error.hpp"
#include <redlog/redlog.hpp>

// platform-specific includes
#ifdef __APPLE__
#include "platform/darwin/darwin_injector.hpp"
#elif defined(__linux__)
#include "platform/linux/linux_injector.hpp"
#elif defined(_WIN32)
#include "platform/windows/windows_injector.hpp"
#endif

#include <filesystem>

namespace w1::inject {

// validate configuration before injection
error_code validate_config(const config& cfg) {
  auto log = redlog::get_logger("w1nj3ct.validation");

  log.debug("validating injection configuration");

  // check exactly one target specified
  int target_count = 0;
  if (cfg.pid) {
    target_count++;
  }
  if (cfg.process_name) {
    target_count++;
  }
  if (cfg.binary_path) {
    target_count++;
  }

  log.trace(
      "target specification check", redlog::field("targets", target_count),
      redlog::field("has_pid", static_cast<bool>(cfg.pid)),
      redlog::field("has_process_name", static_cast<bool>(cfg.process_name)),
      redlog::field("has_binary_path", static_cast<bool>(cfg.binary_path))
  );

  if (target_count != 1) {
    log.error("invalid target specification - exactly one target required", redlog::field("targets", target_count));
    return error_code::configuration_invalid;
  }

  // validate library path exists and is accessible
  log.debug("validating library path", redlog::field("library_path", cfg.library_path));

  if (!std::filesystem::exists(cfg.library_path)) {
    log.error("injection library not found", redlog::field("library_path", cfg.library_path));
    return error_code::library_not_found;
  }

  // check library permissions
  std::error_code fs_error;
  auto file_status = std::filesystem::status(cfg.library_path, fs_error);
  if (fs_error) {
    log.error(
        "failed to get library file status", redlog::field("library_path", cfg.library_path),
        redlog::field("error", fs_error.message())
    );
    return error_code::library_not_found;
  }

  if (!std::filesystem::is_regular_file(file_status)) {
    log.error("library path is not a regular file", redlog::field("library_path", cfg.library_path));
    return error_code::library_not_found;
  }

  log.verbose(
      "library validation passed", redlog::field("library_path", cfg.library_path),
      redlog::field("bytes", std::filesystem::file_size(cfg.library_path, fs_error))
  );

  // check method compatibility with target type
  const char* method_str = (cfg.injection_method == method::runtime) ? "runtime" : "preload";
  log.debug("validating method compatibility", redlog::field("method", method_str));

  if (cfg.injection_method == method::launch && !cfg.binary_path) {
    log.error("launch injection method requires binary_path", redlog::field("method", method_str));
    return error_code::configuration_invalid;
  }

  if (cfg.injection_method == method::runtime && cfg.binary_path) {
    log.error("runtime injection method incompatible with binary_path", redlog::field("method", method_str));
    return error_code::configuration_invalid;
  }

  // platform-specific validation
  const char* platform_str =
#ifdef __APPLE__
      "darwin";
#elif defined(__linux__)
      "linux";
#elif defined(_WIN32)
      "windows";
#else
      "unknown";
#endif

  log.debug(
      "performing platform-specific validation", redlog::field("platform", platform_str),
      redlog::field("method", method_str)
  );

#ifdef _WIN32
  if (cfg.injection_method == method::launch) {
    log.error(
        "launch injection method not supported on windows", redlog::field("platform", platform_str),
        redlog::field("method", method_str)
    );
    return error_code::technique_not_supported;
  }
#endif

  log.debug("configuration validation completed successfully");
  return error_code::success;
}

result inject(const config& cfg) {
  auto log = redlog::get_logger("w1nj3ct");

  const char* method_str = (cfg.injection_method == method::runtime) ? "runtime" : "preload";
  const char* platform_str =
#ifdef __APPLE__
      "darwin";
#elif defined(__linux__)
      "linux";
#elif defined(_WIN32)
      "windows";
#else
      "unknown";
#endif

  log.info(
      "injection request received", redlog::field("method", method_str), redlog::field("platform", platform_str),
      redlog::field("library_path", cfg.library_path)
  );

  // log target information
  if (cfg.pid) {
    log.debug("target specified by pid", redlog::field("pid", *cfg.pid));
  } else if (cfg.process_name) {
    log.debug("target specified by process name", redlog::field("name", *cfg.process_name));
  } else if (cfg.binary_path) {
    log.debug("target specified by binary path", redlog::field("path", *cfg.binary_path));
  }

  // log environment configuration if present
  if (!cfg.env_vars.empty()) {
    log.verbose("environment variables configured", redlog::field("vars", cfg.env_vars.size()));
    for (const auto& [key, value] : cfg.env_vars) {
      log.trace("environment variable", redlog::field("key", key), redlog::field("value", value));
    }
  }

  // 1. validate configuration
  log.debug("validating injection configuration");
  error_code validation_result = validate_config(cfg);
  if (validation_result != error_code::success) {
    std::string error_detail = error_code_to_string(validation_result);
    log.error(
        "configuration validation failed", redlog::field("error_code", static_cast<int>(validation_result)),
        redlog::field("detail", error_detail), redlog::field("method", method_str),
        redlog::field("library_path", cfg.library_path)
    );
    return make_error_result(validation_result, "configuration validation failed: " + error_detail);
  }

  log.debug("configuration validated successfully");

  // 2. check platform capabilities
  log.debug("checking injection capabilities for platform", redlog::field("platform", platform_str));

  bool capabilities_ok = check_injection_capabilities();
  if (!capabilities_ok) {
    log.warn(
        "injection capabilities limited on this platform", redlog::field("platform", platform_str),
        redlog::field("method", method_str)
    );
  }

  // 3. platform detection and dispatch
  log.debug(
      "dispatching to platform-specific injection implementation", redlog::field("platform", platform_str),
      redlog::field("method", method_str)
  );

  result injection_result;

#ifdef __APPLE__
  if (cfg.injection_method == method::runtime) {
    injection_result = darwin::inject_runtime(cfg);
  } else {
    injection_result = darwin::inject_preload(cfg);
  }
#elif defined(__linux__)
  if (cfg.injection_method == method::runtime) {
    injection_result = linux_impl::inject_runtime(cfg);
  } else {
    injection_result = linux_impl::inject_preload(cfg);
  }
#elif defined(_WIN32)
  if (cfg.injection_method == method::runtime) {
    injection_result = windows::inject_runtime(cfg);
  } else {
    injection_result = windows::inject_preload(cfg);
  }
#else
  log.error("platform not supported for injection", redlog::field("platform", platform_str));
  injection_result = make_error_result(
      error_code::platform_not_supported, "injection not supported on platform: " + std::string(platform_str)
  );
#endif

  // 4. log final result
  if (injection_result.success()) {
    log.info(
        "injection completed successfully", redlog::field("method", method_str),
        redlog::field("platform", platform_str), redlog::field("pid", injection_result.target_pid),
        redlog::field("library_path", cfg.library_path)
    );
  } else {
    log.error(
        "injection failed", redlog::field("method", method_str), redlog::field("platform", platform_str),
        redlog::field("error_code", static_cast<int>(injection_result.code)),
        redlog::field("error_msg", injection_result.error_message),
        redlog::field("system_error", injection_result.system_error_code),
        redlog::field("library_path", cfg.library_path)
    );
  }

  return injection_result;
}

std::vector<process_info> list_processes() {
#ifdef __APPLE__
  return darwin::list_processes();
#elif defined(__linux__)
  return linux_impl::list_processes();
#elif defined(_WIN32)
  return windows::list_processes();
#else
  return {};
#endif
}

std::vector<process_info> find_processes(const std::string& name) {
#ifdef __APPLE__
  return darwin::find_processes_by_name(name);
#elif defined(__linux__)
  return linux_impl::find_processes_by_name(name);
#elif defined(_WIN32)
  return windows::find_processes_by_name(name);
#else
  return {};
#endif
}

std::optional<process_info> get_process_info(int pid) {
#ifdef __APPLE__
  return darwin::get_process_info(pid);
#elif defined(__linux__)
  return linux_impl::get_process_info(pid);
#elif defined(_WIN32)
  return windows::get_process_info(pid);
#else
  return std::nullopt;
#endif
}

bool check_injection_capabilities() {
#ifdef __APPLE__
  return darwin::check_injection_capabilities();
#elif defined(__linux__)
  return linux_impl::check_injection_capabilities();
#elif defined(_WIN32)
  return windows::check_injection_capabilities();
#else
  return false;
#endif
}

std::vector<std::string> get_supported_platforms() {
  std::vector<std::string> platforms;
#ifdef __APPLE__
  platforms.push_back("macOS");
#endif
#ifdef __linux__
  platforms.push_back("Linux");
#endif
#ifdef _WIN32
  platforms.push_back("Windows");
#endif
  return platforms;
}

bool is_library_compatible(const std::string& library_path, int pid) {
  // basic check - library exists
  if (!std::filesystem::exists(library_path)) {
    return false;
  }

  // TODO: implement architecture compatibility checking
  // for now, assume compatible
  return true;
}

} // namespace w1::inject