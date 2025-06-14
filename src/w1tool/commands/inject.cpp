#include "inject.hpp"
#include "w1nj3ct.hpp"
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int inject(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& binary_flag, args::ValueFlag<std::string>& tool_flag
) {

  auto log = redlog::get_logger("w1tool.inject");

  // validate required arguments
  if (!library_flag) {
    log.error("library path required");
    return 1;
  }

  std::string lib_path = args::get(library_flag);
  w1::inject::result result;

  // tool-specific configuration is handled per injection method below
  if (tool_flag) {
    std::string tool_name = args::get(tool_flag);
    log.info("tool specified", redlog::field("tool", tool_name));
  }

  // determine injection method based on arguments
  if (binary_flag) {
    // launch injection
    std::string binary_path = args::get(binary_flag);
    log.info("launch injection starting", redlog::field("binary", binary_path), redlog::field("library", lib_path));

    // use full config to pass environment variables
    w1::inject::config cfg;
    cfg.library_path = lib_path;
    cfg.injection_method = w1::inject::method::launch;
    cfg.binary_path = binary_path;

    // add environment variables if tool was specified
    if (tool_flag) {
      std::string tool_name = args::get(tool_flag);
      if (tool_name == "w1cov") {
        cfg.env_vars["W1COV_ENABLED"] = "1";
        cfg.env_vars["W1COV_EXCLUDE_SYSTEM"] = "1";
        cfg.env_vars["W1COV_DEBUG"] = "1"; // Enable debug output

        std::string output_file = "coverage.drcov";
        size_t last_slash = binary_path.find_last_of("/\\");
        std::string binary_name = (last_slash != std::string::npos) ? binary_path.substr(last_slash + 1) : binary_path;
        output_file = binary_name + ".drcov";
        cfg.env_vars["W1COV_OUTPUT_FILE"] = output_file;

        log.info("w1cov environment added to injection config", redlog::field("output_file", output_file));
      }
    }

    result = w1::inject::inject(cfg);

  } else if (pid_flag) {
    // runtime injection by pid
    int target_pid = args::get(pid_flag);
    log.info(
        "runtime injection starting", redlog::field("method", "pid"), redlog::field("target_pid", target_pid),
        redlog::field("library", lib_path)
    );

    result = w1::inject::inject_library_runtime(lib_path, target_pid);

  } else if (name_flag) {
    // runtime injection by process name
    std::string process_name = args::get(name_flag);
    log.info(
        "runtime injection starting", redlog::field("method", "name"), redlog::field("process_name", process_name),
        redlog::field("library", lib_path)
    );

    result = w1::inject::inject_library_runtime(lib_path, process_name);

  } else {
    log.error("target required: specify --pid, --name, or --binary");
    return 1;
  }

  // handle result
  if (result.success()) {
    if (result.target_pid > 0) {
      log.info("injection completed successfully", redlog::field("target_pid", result.target_pid));
    } else {
      log.info("injection completed successfully");
    }
    return 0;
  } else {
    log.error("injection failed", redlog::field("error", result.error_message));
    return 1;
  }
}

} // namespace w1tool::commands