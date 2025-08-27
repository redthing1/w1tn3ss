#include "darwin_internal.hpp"
#include <spawn.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cstring>

extern char** environ;

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x100
#endif

namespace w1::debugger::darwin {

std::unique_ptr<session> session_attach(pid target_pid, const config& cfg, result& out_result) {
  (void) cfg;

  // get task port for target process
  mach_port_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), target_pid.native, &task);

  if (kr != KERN_SUCCESS) {
    // analyze the error more carefully
    if (kr == KERN_FAILURE) {
      // could be multiple reasons, try to figure out what went wrong

      // check if we have the debugger entitlement
      if (!check_has_debugger_entitlement()) {
        // we don't have the entitlement!
        out_result = make_error_result(
            error_code::debugger_entitlement_missing, "missing com.apple.security.cs.debugger entitlement", kr
        );
      } else {
        // generic failure
        out_result = make_error_result(error_code::target_access_denied, "task_for_pid failed", kr);
      }
    } else if (kr == KERN_INVALID_ARGUMENT) {
      out_result = make_error_result(error_code::target_not_found, "invalid pid", kr);
    } else {
      out_result = make_error_result(error_code::operation_failed, "task_for_pid failed", kr);
    }
    return nullptr;
  }

  // create darwin_session with task port - we'll need to forward declare this
  auto impl = std::make_unique<darwin_session>(target_pid, task);
  out_result = make_success_result();
  return session::create_from_impl(std::move(impl));
}

std::unique_ptr<session> session_launch(const std::string& path, const config& cfg, result& out_result) {
  posix_spawnattr_t attr;
  posix_spawn_file_actions_t file_actions;

  // initialize spawn attributes
  if (posix_spawnattr_init(&attr) != 0) {
    out_result = make_error_result(error_code::system_error, "failed to init spawn attributes", errno);
    return nullptr;
  }

  // initialize file actions
  if (posix_spawn_file_actions_init(&file_actions) != 0) {
    posix_spawnattr_destroy(&attr);
    out_result = make_error_result(error_code::system_error, "failed to init file actions", errno);
    return nullptr;
  }

  // set flags - start suspended if requested
  short flags = 0;
  if (cfg.start_suspended) {
    flags |= POSIX_SPAWN_START_SUSPENDED;
  }
  if (cfg.disable_aslr) {
    flags |= _POSIX_SPAWN_DISABLE_ASLR;
  }

  if (posix_spawnattr_setflags(&attr, flags) != 0) {
    posix_spawn_file_actions_destroy(&file_actions);
    posix_spawnattr_destroy(&attr);
    out_result = make_error_result(error_code::system_error, "failed to set spawn flags", errno);
    return nullptr;
  }

  // prepare arguments
  std::vector<char*> argv;
  argv.push_back(const_cast<char*>(path.c_str()));
  for (const auto& arg : cfg.args) {
    argv.push_back(const_cast<char*>(arg.c_str()));
  }
  argv.push_back(nullptr);

  // prepare environment - use current if not specified
  std::vector<char*> envp;
  if (!cfg.env_vars.empty()) {
    for (const auto& [key, value] : cfg.env_vars) {
      std::string env_str = key + "=" + value;
      char* env_copy = strdup(env_str.c_str());
      envp.push_back(env_copy);
    }
    envp.push_back(nullptr);
  }

  // spawn the process
  pid_t child_pid;
  int spawn_result = posix_spawn(
      &child_pid, path.c_str(), &file_actions, &attr, argv.data(), cfg.env_vars.empty() ? environ : envp.data()
  );

  // cleanup environment strings if we allocated them
  for (char* env_str : envp) {
    if (env_str) {
      free(env_str);
    }
  }

  // cleanup spawn attributes
  posix_spawn_file_actions_destroy(&file_actions);
  posix_spawnattr_destroy(&attr);

  if (spawn_result != 0) {
    out_result = make_error_result(error_code::operation_failed, "failed to spawn process", spawn_result);
    return nullptr;
  }

  // now attach to the spawned process
  return session_attach(pid{child_pid}, cfg, out_result);
}

std::vector<process_info> list_processes() {
  std::vector<process_info> procs;

  // use sysctl to get process list
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t size;

  if (sysctl(mib, 4, nullptr, &size, nullptr, 0) < 0) {
    return procs;
  }

  std::vector<uint8_t> buffer(size);
  if (sysctl(mib, 4, buffer.data(), &size, nullptr, 0) < 0) {
    return procs;
  }

  // parse the results
  struct kinfo_proc* proc_list = (struct kinfo_proc*) buffer.data();
  size_t proc_count = size / sizeof(struct kinfo_proc);

  for (size_t i = 0; i < proc_count; i++) {
    process_info info;
    info.process_id = pid{proc_list[i].kp_proc.p_pid};
    info.name = proc_list[i].kp_proc.p_comm;
    // full path would require proc_pidpath
    procs.push_back(info);
  }

  return procs;
}

bool check_debugger_capability() {
  // check if we have the necessary entitlements
  return check_has_debugger_entitlement();
}

} // namespace w1::debugger::darwin
