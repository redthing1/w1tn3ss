#include "cover.hpp"
#include "common/platform_utils.hpp"
#include "w1nj3ct.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <redlog/redlog.hpp>

namespace w1tool::commands {

/**
 * @brief Automatically find the w1cov_qbdipreload library relative to the executable
 * @param executable_path Path to the current executable
 * @return Path to the library if found, empty string otherwise
 */
std::string find_qbdipreload_library(const std::string& executable_path) {
  auto log = redlog::get_logger("w1tool.cover.autodiscovery");

  // Convert executable path to absolute path to handle relative paths like "./w1tool"
  std::filesystem::path exec_path;
  try {
    exec_path = std::filesystem::canonical(executable_path);
  } catch (const std::exception& e) {
    log.debug(
        "failed to canonicalize executable path, using as-is", redlog::field("path", executable_path),
        redlog::field("error", e.what())
    );
    exec_path = std::filesystem::path(executable_path);
  }

  std::filesystem::path exec_dir = exec_path.parent_path();

  // Get platform-specific library extension
  std::string lib_ext = w1::common::platform_utils::get_library_extension();
  std::string lib_name = "w1cov_qbdipreload" + lib_ext;

  log.debug(
      "searching for library", redlog::field("library_name", lib_name), redlog::field("exec_dir", exec_dir.string())
  );

  // Search paths relative to executable directory
  std::vector<std::filesystem::path> search_paths = {
      exec_dir / lib_name,                // Same directory as executable
      exec_dir / ".." / "lib" / lib_name, // ../lib/ (for installed layouts)
      exec_dir / "lib" / lib_name,        // lib/ subdirectory
      exec_dir / ".." / lib_name,         // Parent directory
  };

  for (const auto& candidate_path : search_paths) {
    log.debug("checking candidate path", redlog::field("path", candidate_path.string()));

    if (std::filesystem::exists(candidate_path) && std::filesystem::is_regular_file(candidate_path)) {
      std::string found_path = std::filesystem::canonical(candidate_path).string();
      log.info("found qbdipreload library", redlog::field("path", found_path));
      return found_path;
    }
  }

  log.debug("qbdipreload library not found in standard locations");
  return "";
}

int cover(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& name_flag, args::ValueFlag<std::string>& output_flag, args::Flag& exclude_system_flag,
    args::Flag& debug_flag, args::ValueFlag<std::string>& format_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list, const std::string& executable_path
) {

  auto log = redlog::get_logger("w1tool.cover");

  // Log platform information for debugging
  std::string platform = w1::common::platform_utils::get_platform_name();
  log.debug("platform detected", redlog::field("platform", platform));

  if (!w1::common::platform_utils::supports_runtime_injection()) {
    log.warn("runtime injection may not be supported on this platform", redlog::field("platform", platform));
  }

  // Determine library path - use specified path or auto-discover
  std::string lib_path;
  if (library_flag) {
    lib_path = args::get(library_flag);
    log.debug("using w1cov library", redlog::field("path", lib_path));
  } else {
    // Auto-discover library path
    log.debug("attempting to auto-discover w1cov library");

    lib_path = find_qbdipreload_library(executable_path);

    if (lib_path.empty()) {
      log.error("w1cov_qbdipreload library not found. Please specify with -L/--w1cov-library");
      log.info("searched for library next to executable and in common build locations");
      return 1;
    }

    log.info("auto-discovered library", redlog::field("path", lib_path));
  }

  // Validate target specification
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.error("exactly one target required: specify -s/--spawn, --pid, or --name");
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !spawn_flag) {
    log.error("--suspended can only be used with -s/--spawn (launch tracing)");
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
  } else {
    // Normal operation - suppress verbose logging from coverage components
    cfg.env_vars["W1COV_QUIET"] = "1";
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
    if (spawn_flag && !args_list.Get().empty()) {
      std::vector<std::string> all_args = args::get(args_list);
      std::string binary_path = all_args[0];
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
  if (spawn_flag) {
    // Launch-time coverage with positional arguments
    if (args_list.Get().empty()) {
      log.error("binary path required when using -s/--spawn flag");
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    std::string binary_path = all_args[0];

    // Extract arguments after the binary (everything after first arg)
    std::vector<std::string> binary_args;
    if (all_args.size() > 1) {
      binary_args.assign(all_args.begin() + 1, all_args.end());
    }

    log.info(
        "starting launch-time coverage tracing", redlog::field("binary", binary_path),
        redlog::field("args_count", binary_args.size()), redlog::field("suspended", suspended_flag ? "true" : "false")
    );

    cfg.injection_method = w1::inject::method::launch;
    cfg.binary_path = binary_path;
    cfg.args = binary_args;
    cfg.suspended = suspended_flag;
    cfg.wait_for_completion = true; // cover command should wait for completion

    result = w1::inject::inject(cfg);

  } else if (pid_flag) {
    // Runtime coverage by PID
    int target_pid = args::get(pid_flag);
    log.info(
        "starting runtime coverage tracing", redlog::field("method", "pid"), redlog::field("target_pid", target_pid)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.pid = target_pid;
    // Note: wait_for_completion not applicable for runtime injection
    result = w1::inject::inject(cfg);

  } else if (name_flag) {
    // Runtime coverage by process name
    std::string process_name = args::get(name_flag);
    log.info(
        "starting runtime coverage tracing", redlog::field("method", "name"),
        redlog::field("process_name", process_name)
    );

    cfg.injection_method = w1::inject::method::runtime;
    cfg.process_name = process_name;
    // Note: wait_for_completion not applicable for runtime injection
    result = w1::inject::inject(cfg);
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