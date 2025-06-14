#include "w1cov_config.hpp"
#include <cstdlib>
#include <cstring>

namespace w1::coverage {

namespace {
/// Helper to check if environment variable is set to "1"
bool is_env_flag_enabled(const char* env_name) {
  const char* value = std::getenv(env_name);
  return value && std::strcmp(value, "1") == 0;
}

/// Helper to get environment string with fallback
std::string get_env_string(const char* env_name, const std::string& fallback = "") {
  const char* value = std::getenv(env_name);
  return value ? std::string(value) : fallback;
}
} // namespace

coverage_config load_coverage_config_from_environment() {
  coverage_config config;

  config.is_enabled = is_env_flag_enabled("W1COV_ENABLED");
  config.debug_enabled = is_env_flag_enabled("W1COV_DEBUG");
  config.should_track_full_module_paths = is_env_flag_enabled("W1COV_TRACK_FULL_PATHS");

  // W1COV_EXCLUDE_SYSTEM defaults to true, can be disabled
  const char* exclude_system = std::getenv("W1COV_EXCLUDE_SYSTEM");
  if (exclude_system) {
    config.should_exclude_system_modules = std::strcmp(exclude_system, "1") == 0;
  }

  config.output_file_path = get_env_string("W1COV_OUTPUT_FILE", "w1cov.drcov");
  config.output_format = get_env_string("W1COV_FORMAT", "drcov");

  return config;
}

void configure_coverage_logging(const coverage_config& config) {
  // Injection-safe logging configuration
  // Avoid complex C++ logging in injection contexts
  if (config.debug_enabled) {
    // Could set global debug flags for safe_printf usage
  }
}

} // namespace w1::coverage