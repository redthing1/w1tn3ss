#include "cover.hpp"
#include "common/platform_utils.hpp"
#include "w1nj3ct.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int cover(
    args::ValueFlag<std::string>& binary_flag, args::ValueFlag<int>& pid_flag, args::ValueFlag<std::string>& name_flag,
    args::ValueFlag<std::string>& output_flag, args::Flag& exclude_system_flag, args::Flag& debug_flag,
    args::ValueFlag<std::string>& format_flag
) {

  auto log = redlog::get_logger("w1tool.cover");

  // Log platform information for debugging
  std::string platform = w1::common::platform_utils::get_platform_name();
  log.debug("platform detected", redlog::field("platform", platform));

  if (!w1::common::platform_utils::supports_runtime_injection()) {
    log.warn("runtime injection may not be supported on this platform", redlog::field("platform", platform));
  }

  // Determine coverage library path (cross-platform)
  std::string lib_path;
  const char* env_lib_path = std::getenv("W1COV_LIBRARY_PATH");
  if (env_lib_path) {
    lib_path = env_lib_path;
    log.debug("using library path from environment", redlog::field("path", lib_path));
  } else {
    // Generate platform-appropriate default path
    std::string lib_extension = w1::common::platform_utils::get_library_extension();
    lib_path = "./build-release/w1cov_qbdipreload" + lib_extension;
    log.debug("using default library path", redlog::field("path", lib_path), redlog::field("extension", lib_extension));
  }

  // Validate target specification
  int target_count = 0;
  if (binary_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.error("exactly one target required: specify --binary, --pid, or --name");
    return 1;
  }

  // Prepare injection configuration
  w1::inject::config cfg;
  cfg.library_path = lib_path;

  // Set environment variables for w1cov
  cfg.env_vars["W1COV_ENABLED"] = "1";

  if (exclude_system_flag) {
    cfg.env_vars["W1COV_EXCLUDE_SYSTEM"] = "1";
  }

  if (debug_flag) {
    cfg.env_vars["W1COV_DEBUG"] = "1";
  }

  // Set output format
  std::string format = "drcov"; // default
  if (format_flag) {
    format = args::get(format_flag);
    if (format != "drcov" && format != "text") {
      log.error("invalid format, supported: drcov, text", redlog::field("format", format));
      return 1;
    }
  }
  cfg.env_vars["W1COV_FORMAT"] = format;

  // Set output file
  std::string output_file;
  if (output_flag) {
    output_file = args::get(output_flag);
  } else {
    // Generate default output filename using cross-platform path handling
    if (binary_flag) {
      std::string binary_path = args::get(binary_flag);
      std::filesystem::path fs_path(binary_path);
      std::string binary_name = fs_path.filename().string();
      output_file = binary_name + "_coverage." + format;
    } else {
      output_file = "coverage." + format;
    }
  }
  cfg.env_vars["W1COV_OUTPUT_FILE"] = output_file;

  log.info(
      "coverage tracing configuration", redlog::field("output_file", output_file), redlog::field("format", format),
      redlog::field("exclude_system", exclude_system_flag ? "true" : "false"),
      redlog::field("debug", debug_flag ? "true" : "false")
  );

  w1::inject::result result;

  // Execute coverage tracing based on target type
  if (binary_flag) {
    // Launch-time coverage
    std::string binary_path = args::get(binary_flag);
    log.info("starting launch-time coverage tracing", redlog::field("binary", binary_path));

    cfg.injection_method = w1::inject::method::launch;
    cfg.binary_path = binary_path;

    result = w1::inject::inject(cfg);

  } else if (pid_flag) {
    // Runtime coverage by PID
    int target_pid = args::get(pid_flag);
    log.info(
        "starting runtime coverage tracing", redlog::field("method", "pid"), redlog::field("target_pid", target_pid)
    );

    result = w1::inject::inject_library_runtime(lib_path, target_pid);

  } else if (name_flag) {
    // Runtime coverage by process name
    std::string process_name = args::get(name_flag);
    log.info(
        "starting runtime coverage tracing", redlog::field("method", "name"),
        redlog::field("process_name", process_name)
    );

    result = w1::inject::inject_library_runtime(lib_path, process_name);
  }

  // Handle result
  if (result.success()) {
    log.info("coverage tracing completed successfully", redlog::field("output_file", output_file));
    if (result.target_pid > 0) {
      log.info("target process", redlog::field("pid", result.target_pid));
    }

    std::cout << "Coverage tracing completed successfully.\n";
    std::cout << "Output file: " << output_file << "\n";
    if (format == "drcov") {
      std::cout << "Use 'w1tool read-drcov --file " << output_file << "' to analyze results.\n";
    }

    return 0;
  } else {
    log.error("coverage tracing failed", redlog::field("error", result.error_message));
    return 1;
  }
}

} // namespace w1tool::commands