#include "inject.hpp"
#include "w1nj3ct.hpp"
#include <redlog/redlog.hpp>

namespace w1tool::commands {

int inject(
    args::ValueFlag<std::string>& library_flag, args::Flag& spawn_flag, args::ValueFlag<int>& pid_flag,
    args::ValueFlag<std::string>& process_name_flag, args::Flag& suspended_flag,
    args::PositionalList<std::string>& args_list
) {

  auto log = redlog::get_logger("w1tool.inject");

  // validate required arguments
  if (!library_flag) {
    log.err("library path required");
    return 1;
  }

  // validate target specification
  int target_count = 0;
  if (spawn_flag) {
    target_count++;
  }
  if (pid_flag) {
    target_count++;
  }
  if (process_name_flag) {
    target_count++;
  }

  if (target_count != 1) {
    log.err("exactly one target required: specify -s/--spawn, --pid, or --process-name");
    return 1;
  }

  // validate suspended flag usage
  if (suspended_flag && !spawn_flag) {
    log.err("--suspended can only be used with -s/--spawn (launch injection)");
    return 1;
  }

  std::string lib_path = args::get(library_flag);
  w1::inject::result result;

  // determine injection method based on arguments
  if (spawn_flag) {
    // launch injection with positional arguments
    if (args_list.Get().empty()) {
      log.err("binary path required when using -s/--spawn flag");
      return 1;
    }

    std::vector<std::string> all_args = args::get(args_list);
    std::string binary_path = all_args[0];

    // extract arguments after the binary (everything after first arg)
    std::vector<std::string> binary_args;
    if (all_args.size() > 1) {
      binary_args.assign(all_args.begin() + 1, all_args.end());
    }

    // spawn always uses preload injection
    w1::inject::method injection_method = w1::inject::method::launch;
    std::string method_name = "preload";

    log.info(
        "spawn injection starting", redlog::field("method", method_name), redlog::field("binary", binary_path),
        redlog::field("library", lib_path), redlog::field("args_count", binary_args.size()),
        redlog::field("suspended", suspended_flag ? "true" : "false")
    );

    // use full config for spawn injection to support arguments and suspended flag
    w1::inject::config cfg;
    cfg.library_path = lib_path;
    cfg.injection_method = injection_method;
    cfg.binary_path = binary_path;
    cfg.args = binary_args;
    cfg.suspended = suspended_flag;
    cfg.wait_for_completion = true; // inject command should wait for completion

    result = w1::inject::inject(cfg);

  } else if (pid_flag) {
    // runtime injection by pid
    int target_pid = args::get(pid_flag);
    log.info(
        "runtime injection starting", redlog::field("method", "pid"), redlog::field("target_pid", target_pid),
        redlog::field("library", lib_path)
    );

    w1::inject::config cfg;
    cfg.library_path = lib_path;
    cfg.injection_method = w1::inject::method::runtime;
    cfg.pid = target_pid;

    result = w1::inject::inject(cfg);

  } else if (process_name_flag) {
    // runtime injection by process name
    std::string process_name = args::get(process_name_flag);
    log.info(
        "runtime injection starting", redlog::field("method", "name"), redlog::field("process_name", process_name),
        redlog::field("library", lib_path)
    );

    w1::inject::config cfg;
    cfg.library_path = lib_path;
    cfg.injection_method = w1::inject::method::runtime;
    cfg.process_name = process_name;

    result = w1::inject::inject(cfg);

  } else {
    log.err("target required: specify -s/--spawn, --pid, or --process-name");
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
    log.err("injection failed", redlog::field("error", result.error_message));
    return 1;
  }
}

} // namespace w1tool::commands