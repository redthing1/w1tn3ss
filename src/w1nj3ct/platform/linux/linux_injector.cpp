#include "linux_injector.hpp"
#include "../../error.hpp"
#include <chrono>
#include <redlog/redlog.hpp>

// include the kubo injector backend
extern "C" {
#include "../../backend/linux/injector.h"
}

#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace w1::inject::linux_impl {

result inject_runtime(const config& cfg) {
  auto log = redlog::get_logger("w1nj3ct.linux");

  log.info("linux runtime injection starting", redlog::field("library_path", cfg.library_path));

  // validate we have a target
  if (!cfg.pid && !cfg.process_name) {
    log.error("no target specified for runtime injection");
    return make_error_result(error_code::configuration_invalid, "no target specified");
  }

  int target_pid = -1;

  // resolve process name to pid if needed
  if (cfg.process_name) {
    log.debug("resolving process name to pid", redlog::field("name", *cfg.process_name));

    auto processes = find_processes_by_name(*cfg.process_name);
    if (processes.empty()) {
      log.error("no processes found with specified name", redlog::field("name", *cfg.process_name));
      return make_error_result(error_code::target_not_found, *cfg.process_name);
    }
    if (processes.size() > 1) {
      log.error(
          "multiple processes found with specified name", redlog::field("name", *cfg.process_name),
          redlog::field("count", processes.size())
      );
      return make_error_result(error_code::multiple_targets_found, *cfg.process_name);
    }
    target_pid = processes[0].pid;
  } else {
    target_pid = *cfg.pid;
  }

  log.info("targeting process for injection", redlog::field("pid", target_pid));

  // validate library exists
  if (access(cfg.library_path.c_str(), F_OK) != 0) {
    log.error("library file not found", redlog::field("library_path", cfg.library_path), redlog::field("errno", errno));
    return make_error_result(error_code::library_not_found, "library not found: " + cfg.library_path);
  }

  log.debug("library file validated", redlog::field("library_path", cfg.library_path));

  // attach to process using kubo injector
  auto attach_start = std::chrono::steady_clock::now();
  injector_t* injector = nullptr;
  int attach_result = injector_attach(&injector, target_pid);

  if (attach_result != INJERR_SUCCESS) {
    const char* error_msg = injector_error();
    log.error(
        "failed to attach to target process", redlog::field("pid", target_pid),
        redlog::field("error_code", attach_result), redlog::field("error_msg", error_msg ? error_msg : "unknown")
    );

    // map injector error codes to our error codes
    error_code mapped_error;
    switch (attach_result) {
    case INJERR_NO_PROCESS:
      mapped_error = error_code::target_not_found;
      break;
    case INJERR_PERMISSION:
      mapped_error = error_code::target_access_denied;
      break;
    case INJERR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      break;
    case INJERR_UNSUPPORTED_TARGET:
      mapped_error = error_code::target_invalid_architecture;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }

    return make_error_result(mapped_error, error_msg ? error_msg : "attach failed", attach_result);
  }

  auto attach_duration = std::chrono::steady_clock::now() - attach_start;
  auto attach_ms = std::chrono::duration_cast<std::chrono::milliseconds>(attach_duration).count();
  log.debug(
      "successfully attached to target process", redlog::field("pid", target_pid),
      redlog::field("attach_time_ms", attach_ms)
  );

  // inject library
  auto inject_start = std::chrono::steady_clock::now();
  void* handle = nullptr;
  int inject_result = injector_inject(injector, cfg.library_path.c_str(), &handle);

  if (inject_result != INJERR_SUCCESS) {
    const char* error_msg = injector_error();
    log.error(
        "library injection failed", redlog::field("pid", target_pid), redlog::field("library_path", cfg.library_path),
        redlog::field("error_code", inject_result), redlog::field("error_msg", error_msg ? error_msg : "unknown")
    );

    // detach before returning error
    injector_detach(injector);

    // map injector error codes to our error codes
    error_code mapped_error;
    switch (inject_result) {
    case INJERR_FILE_NOT_FOUND:
      mapped_error = error_code::library_not_found;
      break;
    case INJERR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      break;
    case INJERR_ERROR_IN_TARGET:
      mapped_error = error_code::injection_failed;
      break;
    case INJERR_PERMISSION:
      mapped_error = error_code::target_access_denied;
      break;
    case INJERR_UNSUPPORTED_TARGET:
      mapped_error = error_code::target_invalid_architecture;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }

    return make_error_result(mapped_error, error_msg ? error_msg : "injection failed", inject_result);
  }

  // detach from process
  int detach_result = injector_detach(injector);
  if (detach_result != INJERR_SUCCESS) {
    const char* error_msg = injector_error();
    log.warn(
        "failed to detach from target process", redlog::field("pid", target_pid),
        redlog::field("error_code", detach_result), redlog::field("error_msg", error_msg ? error_msg : "unknown")
    );
    // continue anyway since injection succeeded
  }

  auto inject_duration = std::chrono::steady_clock::now() - inject_start;
  auto inject_ms = std::chrono::duration_cast<std::chrono::milliseconds>(inject_duration).count();
  auto total_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - attach_start).count();

  log.info(
      "runtime injection completed successfully", redlog::field("pid", target_pid),
      redlog::field("library_path", cfg.library_path), redlog::field("handle", handle),
      redlog::field("inject_time_ms", inject_ms), redlog::field("total_time_ms", total_ms)
  );

  return make_success_result(target_pid);
}

result inject_preload(const config& cfg) {
  auto log = redlog::get_logger("w1nj3ct.linux");

  log.info(
      "linux preload injection starting", redlog::field("binary_path", cfg.binary_path ? *cfg.binary_path : "null"),
      redlog::field("library_path", cfg.library_path)
  );

  if (!cfg.binary_path) {
    log.error("binary_path required for preload injection");
    return make_error_result(error_code::configuration_invalid, "binary_path required for preload injection");
  }

  // validate binary exists and is executable
  if (access(cfg.binary_path->c_str(), F_OK) != 0) {
    log.error("target binary not found", redlog::field("binary_path", *cfg.binary_path), redlog::field("errno", errno));
    return make_error_result(error_code::target_not_found, "binary not found: " + *cfg.binary_path);
  }

  if (access(cfg.binary_path->c_str(), X_OK) != 0) {
    log.error(
        "target binary not executable", redlog::field("binary_path", *cfg.binary_path), redlog::field("errno", errno)
    );
    return make_error_result(error_code::target_access_denied, "binary not executable: " + *cfg.binary_path);
  }

  log.debug("target binary validated", redlog::field("binary_path", *cfg.binary_path));

  // set up environment with LD_PRELOAD
  log.debug("setting up injection environment");

  // start with current environment - use same approach as Darwin version
  std::map<std::string, std::string> env;
  size_t base_env_count = 0;

  for (char** env_var = environ; *env_var != nullptr; env_var++) {
    std::string env_str(*env_var);
    std::string::size_type eq_pos = env_str.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = env_str.substr(0, eq_pos);
      std::string value = env_str.substr(eq_pos + 1);
      env[key] = value;
      base_env_count++;
    }
  }

  log.trace("inherited environment variables", redlog::field("count", base_env_count));

  // add/override with cfg.env_vars
  for (const auto& [key, value] : cfg.env_vars) {
    env[key] = value;
    log.verbose("adding environment variable", redlog::field("key", key), redlog::field("value", value));
  }

  // add LD_PRELOAD
  env["LD_PRELOAD"] = cfg.library_path;
  log.info("configured LD_PRELOAD", redlog::field("library_path", cfg.library_path));

  // build command line
  std::vector<const char*> argv;
  argv.push_back(cfg.binary_path->c_str());
  for (const auto& arg : cfg.args) {
    argv.push_back(arg.c_str());
    log.trace("adding command argument", redlog::field("arg", arg));
  }
  argv.push_back(nullptr);

  log.debug("command line prepared", redlog::field("argc", argv.size() - 1));

  // build environment
  std::vector<std::string> env_strings;
  std::vector<const char*> envp;
  for (const auto& [key, value] : env) {
    env_strings.push_back(key + "=" + value);
    envp.push_back(env_strings.back().c_str());
  }
  envp.push_back(nullptr);

  log.debug("environment prepared", redlog::field("env_count", env.size()));

  // fork and exec with modified environment
  log.debug("launching target process");
  auto launch_start = std::chrono::steady_clock::now();

  pid_t child_pid = fork();
  if (child_pid == 0) {
    // child process
    log.trace("child process starting execve", redlog::field("binary_path", *cfg.binary_path));
    execve(cfg.binary_path->c_str(), const_cast<char**>(argv.data()), const_cast<char**>(envp.data()));
    // execve only returns on error
    _exit(1);
  } else if (child_pid > 0) {
    // parent process - conditionally wait for child to complete
    if (cfg.wait_for_completion) {
      log.debug("waiting for child process", redlog::field("child_pid", child_pid));

      int status;
      pid_t wait_result = waitpid(child_pid, &status, 0);

      auto launch_duration = std::chrono::steady_clock::now() - launch_start;
      auto launch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(launch_duration).count();

      if (wait_result == -1) {
        log.error("waitpid failed", redlog::field("child_pid", child_pid), redlog::field("errno", errno));
        return make_error_result(error_code::launch_failed, "waitpid failed", errno);
      }

      if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        log.info(
            "child process exited", redlog::field("child_pid", child_pid), redlog::field("exit_code", exit_code),
            redlog::field("execution_time_ms", launch_ms)
        );

        if (exit_code == 0) {
          return make_success_result(child_pid);
        } else {
          return make_error_result(
              error_code::launch_failed, "child process failed with exit code " + std::to_string(exit_code)
          );
        }
      } else if (WIFSIGNALED(status)) {
        int signal = WTERMSIG(status);
        log.error(
            "child process terminated by signal", redlog::field("child_pid", child_pid),
            redlog::field("signal", signal), redlog::field("execution_time_ms", launch_ms)
        );
        return make_error_result(
            error_code::launch_failed, "child process terminated by signal " + std::to_string(signal)
        );
      } else {
        log.error(
            "child process exited with unknown status", redlog::field("child_pid", child_pid),
            redlog::field("status", status)
        );
        return make_error_result(error_code::launch_failed, "child process exited with unknown status");
      }
    } else {
      log.info(
          "preload injection started successfully - not waiting for completion", redlog::field("child_pid", child_pid)
      );
      return make_success_result(child_pid);
    }
  } else {
    // fork failed
    log.error("fork failed", redlog::field("errno", errno));
    return make_error_result(error_code::launch_failed, "fork failed", errno);
  }
}

std::vector<process_info> list_processes() {
  std::vector<process_info> processes;

  DIR* proc_dir = opendir("/proc");
  if (!proc_dir) {
    return processes;
  }

  struct dirent* entry;
  while ((entry = readdir(proc_dir)) != nullptr) {
    // check if directory name is a number (pid)
    char* endptr;
    int pid = strtol(entry->d_name, &endptr, 10);
    if (*endptr != '\0' || pid <= 0) {
      continue;
    }

    process_info info;
    info.pid = pid;

    // read process name from /proc/pid/comm
    std::string comm_path = "/proc/" + std::string(entry->d_name) + "/comm";
    std::ifstream comm_file(comm_path);
    if (comm_file.is_open()) {
      std::getline(comm_file, info.name);
      // remove trailing newline if present
      if (!info.name.empty() && info.name.back() == '\n') {
        info.name.pop_back();
      }
    }

    // read command line from /proc/pid/cmdline
    std::string cmdline_path = "/proc/" + std::string(entry->d_name) + "/cmdline";
    std::ifstream cmdline_file(cmdline_path, std::ios::binary);
    if (cmdline_file.is_open()) {
      std::string cmdline;
      std::getline(cmdline_file, cmdline, '\0'); // first argument is the executable
      if (!cmdline.empty()) {
        info.full_path = cmdline;

        // rebuild full command line with spaces
        std::string full_cmdline;
        cmdline_file.seekg(0);
        char c;
        while (cmdline_file.get(c)) {
          if (c == '\0') {
            full_cmdline += ' ';
          } else {
            full_cmdline += c;
          }
        }
        if (!full_cmdline.empty() && full_cmdline.back() == ' ') {
          full_cmdline.pop_back();
        }
        info.command_line = full_cmdline;
      }
    }

    processes.push_back(info);
  }

  closedir(proc_dir);
  return processes;
}

std::vector<process_info> find_processes_by_name(const std::string& name) {
  std::vector<process_info> matches;
  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    // match by process name (comm)
    if (proc.name == name) {
      matches.push_back(proc);
      continue;
    }

    // also try matching by executable path basename
    if (!proc.full_path.empty()) {
      size_t last_slash = proc.full_path.find_last_of('/');
      std::string basename = (last_slash != std::string::npos) ? proc.full_path.substr(last_slash + 1) : proc.full_path;
      if (basename == name) {
        matches.push_back(proc);
      }
    }
  }

  return matches;
}

std::optional<process_info> get_process_info(int pid) {
  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    if (proc.pid == pid) {
      return proc;
    }
  }

  return std::nullopt;
}

bool check_injection_capabilities() {
  // use the kubo injector's capability check if available
  // for now, do a basic ptrace capability test
  pid_t child_pid = fork();
  if (child_pid == 0) {
    // child process - sleep briefly then exit
    usleep(100000); // 100ms
    _exit(0);
  } else if (child_pid > 0) {
    // parent process - try to attach to child using kubo injector
    usleep(10000); // 10ms - give child time to start

    injector_t* injector = nullptr;
    int attach_result = injector_attach(&injector, child_pid);
    if (attach_result == INJERR_SUCCESS) {
      injector_detach(injector);

      // wait for child to exit
      int status;
      waitpid(child_pid, &status, 0);
      return true;
    }

    // wait for child to exit even if attach failed
    int status;
    waitpid(child_pid, &status, 0);
    return false;
  } else {
    // fork failed
    return false;
  }
}

} // namespace w1::inject::linux_impl