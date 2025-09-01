#include "darwin_injector.hpp"
#include "error.hpp"
#include <chrono>
#include <redlog.hpp>

// include the darwin injection backend
extern "C" {
#include "impl/injector.h"
}

#include <crt_externs.h>
#include <cstdlib>
#include <iostream>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x100
#endif

namespace w1::inject::darwin {

result inject_runtime(const config& cfg) {
  auto log = redlog::get_logger("w1nj3ct.darwin");

  log.info("darwin runtime injection starting", redlog::field("library_path", cfg.library_path));

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
      for (const auto& proc : processes) {
        log.verbose(
            "found process", redlog::field("pid", proc.pid), redlog::field("name", proc.name),
            redlog::field("path", proc.full_path)
        );
      }
      return make_error_result(error_code::multiple_targets_found, *cfg.process_name);
    }
    target_pid = processes[0].pid;
    log.info(
        "resolved process name to pid", redlog::field("name", *cfg.process_name), redlog::field("pid", target_pid),
        redlog::field("path", processes[0].full_path)
    );
  } else {
    target_pid = *cfg.pid;
    log.debug("using specified pid", redlog::field("pid", target_pid));

    // validate target process exists
    auto proc_info = get_process_info(target_pid);
    if (proc_info) {
      log.verbose(
          "target process validated", redlog::field("pid", target_pid), redlog::field("name", proc_info->name),
          redlog::field("path", proc_info->full_path)
      );
    } else {
      log.warn("target process info not available", redlog::field("pid", target_pid));
    }
  }

  // use existing injector backend
  auto attach_start = std::chrono::steady_clock::now();
  log.debug("attaching to target process", redlog::field("pid", target_pid));

  injector_t* injector = nullptr;
  int err = injector_attach(&injector, target_pid);
  if (err != INJERR_SUCCESS) {
    error_code mapped_error;
    std::string error_detail = injector_error();

    switch (err) {
    case INJERR_NO_PROCESS:
      mapped_error = error_code::target_not_found;
      log.error(
          "target process not found during attach", redlog::field("pid", target_pid),
          redlog::field("injector_error", error_detail), redlog::field("error_code", err)
      );
      break;
    case INJERR_PERMISSION:
      mapped_error = error_code::target_access_denied;
      log.error(
          "permission denied attaching to target process", redlog::field("pid", target_pid),
          redlog::field("injector_error", error_detail), redlog::field("error_code", err),
          redlog::field("uid", getuid()), redlog::field("euid", geteuid())
      );
      break;
    case INJERR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      log.error(
          "out of memory during process attach", redlog::field("pid", target_pid),
          redlog::field("injector_error", error_detail), redlog::field("error_code", err)
      );
      break;
    default:
      mapped_error = error_code::injection_failed;
      log.error(
          "unknown error during process attach", redlog::field("pid", target_pid),
          redlog::field("injector_error", error_detail), redlog::field("error_code", err)
      );
      break;
    }
    return make_error_result(mapped_error, error_detail, err);
  }

  auto attach_duration = std::chrono::steady_clock::now() - attach_start;
  auto attach_ms = std::chrono::duration_cast<std::chrono::milliseconds>(attach_duration).count();

  log.info(
      "successfully attached to target process", redlog::field("pid", target_pid),
      redlog::field("attach_time_ms", attach_ms)
  );

  // inject the library
  auto inject_start = std::chrono::steady_clock::now();
  log.debug(
      "injecting library into target process", redlog::field("pid", target_pid),
      redlog::field("library_path", cfg.library_path)
  );

  void* handle = nullptr;
  err = injector_inject(injector, cfg.library_path.c_str(), &handle);

  // cleanup injector regardless of result
  injector_detach(injector);
  log.trace("detached from target process", redlog::field("pid", target_pid));

  if (err != INJERR_SUCCESS) {
    error_code mapped_error;
    std::string error_detail = injector_error();

    switch (err) {
    case INJERR_FILE_NOT_FOUND:
      mapped_error = error_code::library_not_found;
      log.error(
          "library file not found during injection", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    case INJERR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      log.error(
          "out of memory during library injection", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    case INJERR_ERROR_IN_TARGET:
      mapped_error = error_code::injection_failed;
      log.error(
          "error in target process during injection", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    case INJERR_PERMISSION:
      mapped_error = error_code::target_access_denied;
      log.error(
          "permission denied during library injection", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    case INJERR_UNSUPPORTED_TARGET:
      mapped_error = error_code::target_invalid_architecture;
      log.error(
          "unsupported target architecture", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    default:
      mapped_error = error_code::injection_failed;
      log.error(
          "unknown error during library injection", redlog::field("pid", target_pid),
          redlog::field("library_path", cfg.library_path), redlog::field("injector_error", error_detail),
          redlog::field("error_code", err)
      );
      break;
    }
    return make_error_result(mapped_error, error_detail, err);
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
  auto log = redlog::get_logger("w1nj3ct.darwin");

  log.info(
      "darwin preload injection starting", redlog::field("binary_path", cfg.binary_path ? *cfg.binary_path : "null"),
      redlog::field("library_path", cfg.library_path), redlog::field("disable_aslr", cfg.disable_aslr)
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

  // set up environment with DYLD_INSERT_LIBRARIES
  log.debug("setting up injection environment");

  // start with current environment
  std::map<std::string, std::string> env;
  char*** environ_ptr = _NSGetEnviron();
  size_t base_env_count = 0;

  if (environ_ptr && *environ_ptr) {
    for (char** ep = *environ_ptr; *ep; ep++) {
      std::string env_var(*ep);
      size_t eq_pos = env_var.find('=');
      if (eq_pos != std::string::npos) {
        std::string key = env_var.substr(0, eq_pos);
        std::string value = env_var.substr(eq_pos + 1);
        env[key] = value;
        base_env_count++;
      }
    }
  }

  log.trace("inherited environment variables", redlog::field("count", base_env_count));

  // add/override with cfg.env_vars
  for (const auto& [key, value] : cfg.env_vars) {
    env[key] = value;
    log.verbose("adding environment variable", redlog::field("key", key), redlog::field("value", value));
  }

  // add DYLD_INSERT_LIBRARIES
  env["DYLD_INSERT_LIBRARIES"] = cfg.library_path;
  log.info("configured DYLD_INSERT_LIBRARIES", redlog::field("library_path", cfg.library_path));

  // warn about potential SIP issues
  if (cfg.binary_path->find("/System/") == 0 || cfg.binary_path->find("/usr/bin/") == 0 ||
      cfg.binary_path->find("/bin/") == 0) {
    log.warn("injecting into system binary may fail due to SIP", redlog::field("binary_path", *cfg.binary_path));
  }

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

  // first pass: populate all strings to avoid reallocation
  env_strings.reserve(env.size());
  for (const auto& [key, value] : env) {
    env_strings.push_back(key + "=" + value);
  }

  // second pass: collect pointers after all strings are in place
  envp.reserve(env.size() + 1);
  for (const auto& env_str : env_strings) {
    envp.push_back(env_str.c_str());
  }
  envp.push_back(nullptr);

  log.debug("environment prepared", redlog::field("vars", env.size()), redlog::field("total_vars", envp.size() - 1));

  pid_t child_pid = -1;

  if (cfg.disable_aslr) {
    // use posix_spawn with ASLR disabled
    log.debug("launching child process with ASLR disabled using posix_spawn");

    posix_spawnattr_t attrs;
    int ret = posix_spawnattr_init(&attrs);
    if (ret != 0) {
      log.error("posix_spawnattr_init failed", redlog::field("error", strerror(ret)));
      return make_error_result(error_code::launch_failed, "posix_spawnattr_init failed", ret);
    }

    short ps_flags = 0;
    ps_flags |= POSIX_SPAWN_SETEXEC;
    ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
    ret = posix_spawnattr_setflags(&attrs, ps_flags);
    if (ret != 0) {
      posix_spawnattr_destroy(&attrs);
      log.error("posix_spawnattr_setflags failed", redlog::field("error", strerror(ret)));
      return make_error_result(error_code::launch_failed, "posix_spawnattr_setflags failed", ret);
    }

    // fork first, then use posix_spawn with SETEXEC in child
    child_pid = fork();
    if (child_pid == 0) {
      // child process, suspend if requested
      if (cfg.suspended) {
        fprintf(stderr, "[w1nj3ct.darwin] child: suspending with SIGSTOP\n");
        fflush(stderr);
        raise(SIGSTOP);
        fprintf(stderr, "[w1nj3ct.darwin] child: resumed after SIGSTOP\n");
        fflush(stderr);
      }

      // child process, use posix_spawn with SETEXEC
      log.trace(
          "child process executing target binary with ASLR disabled", redlog::field("binary_path", *cfg.binary_path)
      );

      ret = posix_spawnp(
          NULL, cfg.binary_path->c_str(), NULL, &attrs, const_cast<char**>(argv.data()), const_cast<char**>(envp.data())
      );

      // posix_spawnp with SETEXEC only returns on error
      int spawn_errno = errno;
      fprintf(stderr, "[w1nj3ct.darwin] posix_spawnp failed: %s (errno=%d)\n", strerror(spawn_errno), spawn_errno);
      _exit(1);
    }

    posix_spawnattr_destroy(&attrs);
  } else {
    // use traditional fork/exec
    log.debug("forking child process for preload injection");
    child_pid = fork();
    if (child_pid == 0) {
      // child process, suspend if requested
      if (cfg.suspended) {
        fprintf(stderr, "[w1nj3ct.darwin] child: suspending with SIGSTOP\n");
        fflush(stderr);
        raise(SIGSTOP);
        fprintf(stderr, "[w1nj3ct.darwin] child: resumed after SIGSTOP\n");
        fflush(stderr);
      }

      // child process
      log.trace("child process executing target binary", redlog::field("binary_path", *cfg.binary_path));

      execve(cfg.binary_path->c_str(), const_cast<char**>(argv.data()), const_cast<char**>(envp.data()));

      // execve only returns on error
      int exec_errno = errno;
      fprintf(stderr, "[w1nj3ct.darwin] execve failed: %s (errno=%d)\n", strerror(exec_errno), exec_errno);
      _exit(1);
    }
  }

  if (child_pid > 0) {
    // parent process: wait for child to complete
    log.info(
        "preload injection started successfully", redlog::field("pid", child_pid),
        redlog::field("binary_path", *cfg.binary_path), redlog::field("library_path", cfg.library_path)
    );

    // handle suspended launch
    if (cfg.suspended) {
      log.info("waiting for child process to suspend itself", redlog::field("pid", child_pid));

      // wait for child to stop itself with SIGSTOP
      int status;
      pid_t wait_result = waitpid(child_pid, &status, WUNTRACED);

      if (wait_result == -1) {
        int wait_errno = errno;
        log.error(
            "failed to wait for child process suspension", redlog::field("pid", child_pid),
            redlog::field("errno", wait_errno), redlog::field("error", strerror(wait_errno))
        );
        kill(child_pid, SIGKILL);
        return make_error_result(error_code::launch_failed, "waitpid failed during suspension", wait_errno);
      }

      if (WIFSTOPPED(status)) {
        log.info("child process suspended successfully", redlog::field("pid", child_pid));

        // output to console for user interaction
        std::cout << "Process created and suspended (PID: " << child_pid << ")" << std::endl;
        std::cout << "Binary: " << *cfg.binary_path << std::endl;
        std::cout << "Library: " << cfg.library_path << std::endl;
        std::cout << "Attach debugger and press Enter to resume process..." << std::endl;
        std::cin.get();

        // resume child process
        log.info("resuming child process", redlog::field("pid", child_pid));
        if (kill(child_pid, SIGCONT) == -1) {
          int kill_errno = errno;
          log.error(
              "failed to resume child process", redlog::field("pid", child_pid), redlog::field("errno", kill_errno),
              redlog::field("error", strerror(kill_errno))
          );
        }
      } else {
        log.warn("child process did not stop as expected", redlog::field("pid", child_pid));
      }
    }

    if (cfg.wait_for_completion) {
      log.debug("waiting for child process to complete", redlog::field("pid", child_pid));

      int status;
      pid_t wait_result = waitpid(child_pid, &status, 0);

      if (wait_result == -1) {
        int wait_errno = errno;
        log.error(
            "failed to wait for child process", redlog::field("pid", child_pid), redlog::field("errno", wait_errno),
            redlog::field("error", strerror(wait_errno))
        );
        return make_error_result(error_code::launch_failed, "waitpid failed", wait_errno);
      }

      if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        log.info(
            "preload injection completed, child process exited", redlog::field("pid", child_pid),
            redlog::field("exit_code", exit_code)
        );

        // injection was successful regardless of target exit code
        auto result = make_success_result(child_pid);
        result.target_exit_code = exit_code;
        return result;
      } else if (WIFSIGNALED(status)) {
        int signal = WTERMSIG(status);
        log.error(
            "child process terminated by signal", redlog::field("pid", child_pid), redlog::field("signal", signal),
            redlog::field("signal_name", strsignal(signal))
        );
        return make_error_result(
            error_code::launch_failed, "child process terminated by signal " + std::to_string(signal)
        );
      } else {
        log.error(
            "child process exited with unknown status", redlog::field("pid", child_pid), redlog::field("status", status)
        );
        return make_error_result(error_code::launch_failed, "child process exited with unknown status");
      }
    } else {
      log.info("preload injection started successfully, not waiting for completion", redlog::field("pid", child_pid));
      return make_success_result(child_pid);
    }
  } else {
    // fork failed
    int fork_errno = errno;
    log.error(
        "fork failed during preload injection", redlog::field("binary_path", *cfg.binary_path),
        redlog::field("errno", fork_errno), redlog::field("error", strerror(fork_errno))
    );

    return make_error_result(error_code::launch_failed, "fork failed", fork_errno);
  }
}

std::vector<process_info> list_processes() {
  auto log = redlog::get_logger("w1nj3ct.darwin");
  std::vector<process_info> processes;

  log.trace("listing all processes");

  // get process count
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t size = 0;
  if (sysctl(mib, 4, nullptr, &size, nullptr, 0) != 0) {
    log.error("failed to get process list size", redlog::field("errno", errno));
    return processes;
  }

  // get process list
  size_t count = size / sizeof(struct kinfo_proc);
  log.debug("retrieving process list", redlog::field("estimated", count));

  std::vector<struct kinfo_proc> procs(count);
  if (sysctl(mib, 4, procs.data(), &size, nullptr, 0) != 0) {
    log.error("failed to retrieve process list", redlog::field("errno", errno));
    return processes;
  }

  // convert to our format
  size_t path_failures = 0;
  for (const auto& proc : procs) {
    process_info info;
    info.pid = proc.kp_proc.p_pid;
    info.name = proc.kp_proc.p_comm;

    // get full path using libproc
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(info.pid, pathbuf, sizeof(pathbuf)) > 0) {
      info.full_path = pathbuf;
    } else {
      path_failures++;
    }

    processes.push_back(info);
  }

  log.debug(
      "process list retrieved", redlog::field("total_processes", processes.size()),
      redlog::field("path_lookup_failures", path_failures)
  );

  return processes;
}

std::vector<process_info> find_processes_by_name(const std::string& name) {
  auto log = redlog::get_logger("w1nj3ct.darwin");

  log.debug("searching for processes by name", redlog::field("target_name", name));

  std::vector<process_info> matches;
  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    if (proc.name == name) {
      matches.push_back(proc);
      log.verbose(
          "found matching process", redlog::field("pid", proc.pid), redlog::field("name", proc.name),
          redlog::field("path", proc.full_path)
      );
    }
  }

  log.debug(
      "process search completed", redlog::field("target_name", name), redlog::field("matches_found", matches.size()),
      redlog::field("total_searched", all_processes.size())
  );

  return matches;
}

std::optional<process_info> get_process_info(int pid) {
  auto log = redlog::get_logger("w1nj3ct.darwin");

  log.trace("looking up process info", redlog::field("pid", pid));

  auto all_processes = list_processes();

  for (const auto& proc : all_processes) {
    if (proc.pid == pid) {
      log.trace(
          "found process info", redlog::field("pid", proc.pid), redlog::field("name", proc.name),
          redlog::field("path", proc.full_path)
      );
      return proc;
    }
  }

  log.debug("process not found", redlog::field("pid", pid), redlog::field("searched", all_processes.size()));

  return std::nullopt;
}

bool check_injection_capabilities() {
  auto log = redlog::get_logger("w1nj3ct.darwin");

  log.debug("checking darwin injection capabilities");

  // try to create a test injector to check permissions
  injector_t* injector = nullptr;
  int current_pid = getpid();

  log.trace("attempting self-injection test", redlog::field("pid", current_pid));

  int err = injector_attach(&injector, current_pid);

  if (err == INJERR_SUCCESS) {
    injector_detach(injector);
    log.debug("injection capabilities verified, self-attach successful");
    return true;
  } else {
    log.warn(
        "injection capabilities limited, self-attach failed", redlog::field("error_code", err),
        redlog::field("injector_error", injector_error()), redlog::field("uid", getuid()),
        redlog::field("euid", geteuid())
    );
    return false;
  }
}

} // namespace w1::inject::darwin