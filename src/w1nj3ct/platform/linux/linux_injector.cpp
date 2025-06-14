#include "linux_injector.hpp"
#include "../../error.hpp"

// include the new linux injection backend
extern "C" {
#include "../../backend/linux/linux_elf.h"
#include "../../backend/linux/linux_ptrace.h"
#include "../../backend/linux/linux_shellcode.h"
}

#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace w1::inject::linux_impl {

result inject_runtime(const config& cfg) {
  // validate we have a target
  if (!cfg.pid && !cfg.process_name) {
    return make_error_result(error_code::configuration_invalid, "no target specified");
  }

  int target_pid = -1;

  // resolve process name to pid if needed
  if (cfg.process_name) {
    auto processes = find_processes_by_name(*cfg.process_name);
    if (processes.empty()) {
      return make_error_result(error_code::target_not_found, *cfg.process_name);
    }
    if (processes.size() > 1) {
      return make_error_result(error_code::multiple_targets_found, *cfg.process_name);
    }
    target_pid = processes[0].pid;
  } else {
    target_pid = *cfg.pid;
  }

  // step 1: attach to target process using ptrace
  int attach_result = linux_ptrace_attach(target_pid);
  if (attach_result != LINUX_PTRACE_SUCCESS) {
    error_code mapped_error;
    switch (attach_result) {
    case LINUX_PTRACE_NO_PROCESS:
      mapped_error = error_code::target_not_found;
      break;
    case LINUX_PTRACE_PERMISSION:
      mapped_error = error_code::target_access_denied;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }
    return make_error_result(
        mapped_error, std::string("ptrace attach failed: ") + linux_ptrace_strerror(attach_result), attach_result
    );
  }

  // cleanup function to ensure detach
  auto cleanup = [target_pid]() { linux_ptrace_detach(target_pid); };

  // step 2: find dlopen symbol in the target process
  void* dlopen_addr = nullptr;
  int symbol_result = linux_find_symbol(target_pid, "libdl.so", "dlopen", &dlopen_addr);
  if (symbol_result != LINUX_ELF_SUCCESS) {
    // try alternative library names
    symbol_result = linux_find_symbol(target_pid, "libc.so", "dlopen", &dlopen_addr);
    if (symbol_result != LINUX_ELF_SUCCESS) {
      symbol_result = linux_find_symbol(target_pid, "libc.so.6", "dlopen", &dlopen_addr);
    }
    if (symbol_result != LINUX_ELF_SUCCESS) {
      // Try comprehensive list of ld.so names for all architectures
      const char* ld_names[] = {
          "ld-linux-x86-64.so.2",  // x86_64
          "ld-linux-x86-64.so",    // x86_64 without version
          "ld-linux-aarch64.so.1", // ARM64
          "ld-linux-aarch64.so",   // ARM64 without version
          "ld-linux-armhf.so.3",   // ARM32 hard-float
          "ld-linux-armhf.so",     // ARM32 hard-float without version
          "ld-linux.so.3",         // ARM32 soft-float
          "ld-linux.so.2",         // i386
          "ld-linux.so",           // generic
          "ld.so.1",               // some distributions
          nullptr
      };

      for (int i = 0; ld_names[i] != nullptr && symbol_result != LINUX_ELF_SUCCESS; i++) {
        symbol_result = linux_find_symbol(target_pid, ld_names[i], "dlopen", &dlopen_addr);
      }
    }
  }

  if (symbol_result != LINUX_ELF_SUCCESS) {
    cleanup();
    error_code mapped_error;
    switch (symbol_result) {
    case LINUX_ELF_ERROR_SYMBOL_NOT_FOUND:
      mapped_error = error_code::injection_failed;
      break;
    case LINUX_ELF_ERROR_LIBRARY_NOT_FOUND:
      mapped_error = error_code::library_not_found;
      break;
    case LINUX_ELF_ERROR_PERMISSION_DENIED:
      mapped_error = error_code::target_access_denied;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }
    return make_error_result(
        mapped_error, std::string("dlopen symbol resolution failed: ") + linux_elf_error_string(symbol_result),
        symbol_result
    );
  }

  // step 3: detect target process architecture
  linux_arch_t arch = linux_detect_process_architecture(target_pid);
  if (arch == ARCH_UNKNOWN) {
    cleanup();
    return make_error_result(error_code::target_invalid_architecture, "unsupported target architecture");
  }

  // step 4: generate dlopen shellcode
  void* shellcode = nullptr;
  size_t shellcode_size = 0;
  int shellcode_result = linux_generate_dlopen_shellcode(cfg.library_path.c_str(), arch, &shellcode, &shellcode_size);
  if (shellcode_result != LINUX_SHELLCODE_SUCCESS) {
    cleanup();
    error_code mapped_error;
    switch (shellcode_result) {
    case LINUX_SHELLCODE_ERROR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      break;
    case LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH:
      mapped_error = error_code::target_invalid_architecture;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }
    return make_error_result(
        mapped_error, std::string("shellcode generation failed: ") + linux_shellcode_error_string(shellcode_result),
        shellcode_result
    );
  }

  // cleanup function for shellcode
  auto shellcode_cleanup = [shellcode]() {
    if (shellcode) {
      linux_free_shellcode(shellcode);
    }
  };

  // step 5: inject and execute shellcode
  void* injection_result = nullptr;
  int exec_result = linux_inject_and_execute_shellcode(target_pid, shellcode, shellcode_size, &injection_result);

  // cleanup shellcode regardless of result
  shellcode_cleanup();

  if (exec_result != LINUX_SHELLCODE_SUCCESS) {
    cleanup();
    error_code mapped_error;
    switch (exec_result) {
    case LINUX_SHELLCODE_ERROR_NO_MEMORY:
      mapped_error = error_code::out_of_memory;
      break;
    case LINUX_SHELLCODE_ERROR_PERMISSION:
      mapped_error = error_code::target_access_denied;
      break;
    case LINUX_SHELLCODE_ERROR_PTRACE_FAILED:
      mapped_error = error_code::injection_failed;
      break;
    default:
      mapped_error = error_code::injection_failed;
      break;
    }
    return make_error_result(
        mapped_error, std::string("shellcode execution failed: ") + linux_shellcode_error_string(exec_result),
        exec_result
    );
  }

  // step 6: detach from process
  cleanup();

  // check if dlopen returned null (injection failed)
  if (injection_result == nullptr) {
    return make_error_result(error_code::injection_failed, "dlopen returned null - library injection failed");
  }

  return make_success_result(target_pid);
}

result inject_preload(const config& cfg) {
  if (!cfg.binary_path) {
    return make_error_result(error_code::configuration_invalid, "binary_path required for preload injection");
  }

  // set up environment with LD_PRELOAD
  std::map<std::string, std::string> env = cfg.env_vars;
  env["LD_PRELOAD"] = cfg.library_path;

  // build command line
  std::vector<const char*> argv;
  argv.push_back(cfg.binary_path->c_str());
  for (const auto& arg : cfg.args) {
    argv.push_back(arg.c_str());
  }
  argv.push_back(nullptr);

  // build environment
  std::vector<std::string> env_strings;
  std::vector<const char*> envp;
  for (const auto& [key, value] : env) {
    env_strings.push_back(key + "=" + value);
    envp.push_back(env_strings.back().c_str());
  }
  envp.push_back(nullptr);

  // fork and exec with modified environment
  pid_t child_pid = fork();
  if (child_pid == 0) {
    // child process
    execve(cfg.binary_path->c_str(), const_cast<char**>(argv.data()), const_cast<char**>(envp.data()));
    // execve only returns on error
    _exit(1);
  } else if (child_pid > 0) {
    // parent process - injection successful
    return make_success_result(child_pid);
  } else {
    // fork failed
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

    // read process status for additional info
    std::string stat_path = "/proc/" + std::string(entry->d_name) + "/stat";
    std::ifstream stat_file(stat_path);
    if (stat_file.is_open()) {
      std::string stat_line;
      std::getline(stat_file, stat_line);
      // parse basic info from stat file if needed
      // format: pid (comm) state ppid pgrp session tty_nr ...
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
  // check if we can perform ptrace operations
  // try attaching to ourselves as a basic capability test
  pid_t self_pid = getpid();

  // fork a child process to test ptrace on
  pid_t child_pid = fork();
  if (child_pid == 0) {
    // child process - sleep briefly then exit
    usleep(100000); // 100ms
    _exit(0);
  } else if (child_pid > 0) {
    // parent process - try to attach to child
    usleep(10000); // 10ms - give child time to start

    int attach_result = linux_ptrace_attach(child_pid);
    if (attach_result == LINUX_PTRACE_SUCCESS) {
      linux_ptrace_detach(child_pid);

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