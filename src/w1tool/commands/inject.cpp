#include "inject.hpp"
#include "w1nj3ct.hpp"
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int inject(
    args::ValueFlag<std::string>& library_flag, args::ValueFlag<std::string>& name_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& binary_flag, args::Flag& suspended_flag
) {

  auto log = redlog::get_logger("w1tool.inject");

  // validate required arguments
  if (!library_flag) {
    log.error("library path required");
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !binary_flag) {
    log.error("--suspended can only be used with --binary (launch injection)");
    return 1;
  }

  std::string lib_path = args::get(library_flag);
  bool is_suspended = suspended_flag;
  w1::inject::result result;

  // determine injection method based on arguments
  if (binary_flag) {
    // launch injection
    std::string binary_path = args::get(binary_flag);
    log.info(
        "launch injection starting", redlog::field("binary", binary_path), redlog::field("library", lib_path),
        redlog::field("suspended", is_suspended)
    );

    // use full config for launch injection to support suspended flag
    w1::inject::config cfg;
    cfg.library_path = lib_path;
    cfg.injection_method = w1::inject::method::launch;
    cfg.binary_path = binary_path;
    cfg.suspended = is_suspended;

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