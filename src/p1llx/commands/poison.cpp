#include "poison.hpp"

#include <iostream>
#include <filesystem>
#include <cstdlib>

#include <redlog/redlog.hpp>
#include "w1nj3ct.hpp"
#include "common/platform_utils.hpp"

namespace p1llx::commands {

int poison(
    const std::string& script_path, const std::string& binary_path, const std::vector<std::string>& binary_args,
    bool suspended, const std::string& executable_path, int verbosity_level
) {

  auto log = redlog::get_logger("p1llx.poison");

  log.inf(
      "starting p01s0n injection", redlog::field("script", script_path), redlog::field("binary", binary_path),
      redlog::field("suspended", suspended ? "true" : "false")
  );

  // validate script file exists
  if (!std::filesystem::exists(script_path)) {
    log.err("cure script file does not exist", redlog::field("path", script_path));
    std::cerr << "error: cure script not found: " << script_path << std::endl;
    return 1;
  }

  // validate binary exists
  if (!std::filesystem::exists(binary_path)) {
    log.err("target binary does not exist", redlog::field("path", binary_path));
    std::cerr << "error: target binary not found: " << binary_path << std::endl;
    return 1;
  }

  // find p01s0n library using same discovery pattern as tracers
  std::string p01s0n_lib_name = "p01s0n";
  std::string lib_ext = w1::common::platform_utils::get_library_extension();
  std::string p01s0n_filename = p01s0n_lib_name + lib_ext;

  // get executable directory for relative search (same as tracer discovery)
  std::filesystem::path exec_path;
  try {
    if (!executable_path.empty()) {
      exec_path = std::filesystem::canonical(executable_path);
    } else {
      exec_path = std::filesystem::current_path();
    }
  } catch (const std::exception& e) {
    log.dbg(
        "failed to canonicalize executable path, using as-is", redlog::field("path", executable_path),
        redlog::field("error", e.what())
    );
    exec_path = !executable_path.empty() ? std::filesystem::path(executable_path) : std::filesystem::path(".");
  }

  std::filesystem::path exec_dir = exec_path.parent_path();

  log.dbg(
      "searching for p01s0n library", redlog::field("filename", p01s0n_filename),
      redlog::field("exec_dir", exec_path.string())
  );

  // search paths relative to executable directory (same as tracer discovery)
  std::vector<std::filesystem::path> search_dirs = {
      exec_dir,                // same directory as executable
      exec_dir / "lib",        // lib/ subdirectory
      exec_dir / ".." / "lib", // ../lib/ (for installed layouts)
      exec_dir / "..",         // parent directory
  };

  std::string found_lib_path;
  for (const auto& search_dir : search_dirs) {
    if (!std::filesystem::exists(search_dir) || !std::filesystem::is_directory(search_dir)) {
      continue;
    }

    auto candidate_path = search_dir / p01s0n_filename;
    if (std::filesystem::exists(candidate_path)) {
      found_lib_path = std::filesystem::canonical(candidate_path).string();
      log.dbg("found p01s0n library", redlog::field("path", found_lib_path));
      break;
    }
  }

  if (found_lib_path.empty()) {
    log.err("p01s0n library not found", redlog::field("filename", p01s0n_filename));
    std::cerr << "error: p01s0n library not found (" << p01s0n_filename << ")" << std::endl;
    std::cerr << "searched directories:" << std::endl;
    for (const auto& dir : search_dirs) {
      std::cerr << "  " << dir.string() << std::endl;
    }
    return 1;
  }

  log.inf("found p01s0n library", redlog::field("path", found_lib_path));

  // convert script path to absolute path for environment variable
  std::string abs_script_path = std::filesystem::absolute(script_path).string();

  // prepare injection configuration
  w1::inject::config cfg;
  cfg.library_path = found_lib_path;
  cfg.injection_method = w1::inject::method::preload; // preload injection
  cfg.binary_path = binary_path;
  cfg.args = binary_args;
  cfg.suspended = suspended;
  cfg.wait_for_completion = true;

  // set P1LL_CURE environment variable for p01s0n
  cfg.env_vars["P1LL_CURE"] = abs_script_path;

  // set POISON_VERBOSE environment variable for p01s0n verbosity
  if (verbosity_level > 0) {
    cfg.env_vars["POISON_VERBOSE"] = std::to_string(verbosity_level);
  }

  log.inf(
      "injection configuration", redlog::field("library", found_lib_path), redlog::field("binary", binary_path),
      redlog::field("args_count", binary_args.size()), redlog::field("cure_script", abs_script_path)
  );

  // check platform support
  const std::string platform = w1::common::platform_utils::get_platform_name();
  if (!w1::common::platform_utils::supports_runtime_injection()) {
    log.warn("runtime injection may not be supported", redlog::field("platform", platform));
  }

  // perform injection
  auto result = w1::inject::inject(cfg);

  if (result.success()) {
    log.inf("p01s0n injection completed successfully", redlog::field("target_pid", result.target_pid));

    std::cout << "p01s0n injection successful" << std::endl;
    if (result.target_pid > 0) {
      std::cout << "target process pid: " << result.target_pid << std::endl;
    }

    return 0;
  } else {
    log.err("p01s0n injection failed", redlog::field("error", result.error_message));
    std::cerr << "error: injection failed: " << result.error_message << std::endl;
    return 1;
  }
}

} // namespace p1llx::commands