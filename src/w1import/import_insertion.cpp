#include "import_insertion.hpp"
#include <redlog.hpp>

// platform-specific includes
#ifdef __APPLE__
#include "platform/macos/macos_import_inserter.hpp"
#elif defined(__linux__)
#include "platform/linux/linux_import_inserter.hpp"
#elif defined(_WIN32)
#include "platform/windows/windows_import_inserter.hpp"
#endif

#include <filesystem>

namespace fs = std::filesystem;

namespace w1::import_insertion {

// validate configuration before import insertion
error_code validate_config(const config& cfg) {
  auto log = redlog::get_logger("w1.import_insertion.validation");

  log.debug("validating import insertion configuration");

  // validate required fields
  if (cfg.library_path.empty()) {
    log.error("library_path is required");
    return error_code::configuration_invalid;
  }

  if (cfg.target_binary.empty()) {
    log.error("target_binary is required");
    return error_code::configuration_invalid;
  }

  log.debug(
      "validating paths", redlog::field("library_path", cfg.library_path),
      redlog::field("target_binary", cfg.target_binary)
  );

  // validate target binary exists
  if (!fs::exists(cfg.target_binary)) {
    log.error("target binary does not exist", redlog::field("path", cfg.target_binary));
    return error_code::file_not_found;
  }

  // validate output path configuration
  if (cfg.in_place && cfg.output_path.has_value()) {
    log.error("in_place=true is incompatible with output_path");
    return error_code::configuration_invalid;
  }

  // validate library path (special paths starting with @ are allowed even if they don't exist)
  if (cfg.library_path[0] != '@' && !fs::exists(cfg.library_path)) {
    if (!cfg.assume_yes) {
      log.error("library path does not exist", redlog::field("path", cfg.library_path));
      return error_code::library_path_invalid;
    } else {
      log.debug("library path does not exist but assume_yes=true", redlog::field("path", cfg.library_path));
    }
  }

  log.debug("configuration validation completed successfully");
  return error_code::success;
}

result insert_library_import(const config& cfg) {
  auto log = redlog::get_logger("w1.import_insertion");

  log.info(
      "starting library import insertion", redlog::field("library_path", cfg.library_path),
      redlog::field("target_binary", cfg.target_binary), redlog::field("weak_import", cfg.weak_import)
  );

  // validate configuration
  auto validation_error = validate_config(cfg);
  if (validation_error != error_code::success) {
    log.error("configuration validation failed");
    return result{.code = validation_error, .error_message = "configuration validation failed"};
  }

  // determine platform for logging
  const char* platform_str =
#ifdef __APPLE__
      "macos";
#elif defined(__linux__)
      "linux";
#elif defined(_WIN32)
      "windows";
#else
      "unknown";
#endif

  log.debug("performing platform-specific import insertion", redlog::field("platform", platform_str));

  // platform dispatch
  result insertion_result;

#ifdef __APPLE__
  insertion_result = macos::insert_library_import(cfg);
#elif defined(__linux__)
  insertion_result = linux_impl::insert_library_import(cfg);
#elif defined(_WIN32)
  insertion_result = windows::insert_library_import(cfg);
#else
  log.error("platform not supported for library import insertion", redlog::field("platform", platform_str));
  insertion_result = result{
      .code = error_code::platform_not_supported, .error_message = "platform not supported for library import insertion"
  };
#endif

  if (insertion_result.success()) {
    log.info("library import insertion completed successfully");
  } else {
    log.error(
        "library import insertion failed", redlog::field("error_code", static_cast<int>(insertion_result.code)),
        redlog::field("error_message", insertion_result.error_message)
    );
  }

  return insertion_result;
}

std::string error_code_to_string(error_code code) {
  switch (code) {
  case error_code::success:
    return "success";
  case error_code::file_not_found:
    return "file_not_found";
  case error_code::file_access_denied:
    return "file_access_denied";
  case error_code::invalid_output_path:
    return "invalid_output_path";
  case error_code::output_already_exists:
    return "output_already_exists";
  case error_code::invalid_binary_format:
    return "invalid_binary_format";
  case error_code::unknown_magic_number:
    return "unknown_magic_number";
  case error_code::unsupported_architecture:
    return "unsupported_architecture";
  case error_code::corrupted_header:
    return "corrupted_header";
  case error_code::duplicate_library:
    return "duplicate_library";
  case error_code::library_path_invalid:
    return "library_path_invalid";
  case error_code::insufficient_space:
    return "insufficient_space";
  case error_code::code_signature_conflict:
    return "code_signature_conflict";
  case error_code::code_signature_removal_failed:
    return "code_signature_removal_failed";
  case error_code::user_declined:
    return "user_declined";
  case error_code::interactive_prompt_failed:
    return "interactive_prompt_failed";
  case error_code::platform_not_supported:
    return "platform_not_supported";
  case error_code::insufficient_privileges:
    return "insufficient_privileges";
  case error_code::out_of_memory:
    return "out_of_memory";
  case error_code::system_error:
    return "system_error";
  case error_code::configuration_invalid:
    return "configuration_invalid";
  case error_code::unknown_error:
    return "unknown_error";
  default:
    return "unknown_error_code";
  }
}

bool is_recoverable_error(error_code code) {
  switch (code) {
  case error_code::success:
  case error_code::file_not_found:
  case error_code::invalid_binary_format:
  case error_code::platform_not_supported:
  case error_code::configuration_invalid:
    return false;

  case error_code::file_access_denied:
  case error_code::output_already_exists:
  case error_code::duplicate_library:
  case error_code::insufficient_space:
  case error_code::code_signature_conflict:
  case error_code::user_declined:
    return true;

  default:
    return false;
  }
}

bool is_platform_supported() {
#ifdef __APPLE__
  return macos::check_import_capabilities(); // always available on macos via native macho processor
#elif defined(__linux__)
  return linux_impl::check_import_capabilities(); // available when LIEF is enabled
#elif defined(_WIN32)
  return windows::check_import_capabilities(); // available when LIEF is enabled
#else
  return false; // unsupported platform
#endif
}

std::string get_platform_support_info() {
  std::string info = "platform support status:\n";

#ifdef __APPLE__
  info += "  macos (mach-o): supported (native implementation)\n";
#else
  info += "  macos (mach-o): not available (only on macos)\n";
#endif

#ifdef WITNESS_LIEF_ENABLED
  info += "  windows (pe): supported (via LIEF)\n";
  info += "  linux (elf): supported (via LIEF)\n";
#else
  info += "  windows (pe): requires LIEF (build with -DWITNESS_LIEF=ON)\n";
  info += "  linux (elf): requires LIEF (build with -DWITNESS_LIEF=ON)\n";
#endif

  const char* current_platform =
#ifdef __APPLE__
      "macos";
#elif defined(__linux__)
      "linux";
#elif defined(_WIN32)
      "windows";
#else
      "unknown";
#endif

  info += "  current platform: ";
  info += current_platform;
  info += " (";
  info += (is_platform_supported() ? "supported" : "not supported");
  info += ")";

  return info;
}

} // namespace w1::import_insertion