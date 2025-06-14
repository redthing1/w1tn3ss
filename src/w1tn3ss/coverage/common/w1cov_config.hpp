#pragma once

#include <string>

namespace w1::coverage {

/// Coverage collection configuration loaded from environment variables
struct coverage_config {
  /// Enable/disable coverage collection (W1COV_ENABLED)
  bool is_enabled = false;

  /// Enable verbose debug output (W1COV_DEBUG)
  bool debug_enabled = false;

  /// Exclude system libraries from instrumentation (W1COV_EXCLUDE_SYSTEM)
  bool should_exclude_system_modules = true;

  /// Store full module paths vs basenames only (W1COV_TRACK_FULL_PATHS)
  bool should_track_full_module_paths = false;

  /// Coverage data output file path (W1COV_OUTPUT_FILE)
  std::string output_file_path = "w1cov.drcov";

  /// Output format: "drcov" or "text" (W1COV_FORMAT)
  std::string output_format = "drcov";

  /// Validate configuration settings
  bool is_valid() const { return !output_file_path.empty() && (output_format == "drcov" || output_format == "text"); }
};

/// Load coverage configuration from environment variables
coverage_config load_coverage_config_from_environment();

/// Configure logging based on coverage settings (injection-safe)
void configure_coverage_logging(const coverage_config& config);

} // namespace w1::coverage