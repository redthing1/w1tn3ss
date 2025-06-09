#include "darwin_injector.hpp"
#include "../../error.hpp"

// include the darwin injection backend
extern "C" {
#include "darwin/injector.h"
}

#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <libproc.h>

namespace w1::inject::darwin {

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
    
    // use existing injector backend
    injector_t* injector = nullptr;
    int err = injector_attach(&injector, target_pid);
    if (err != INJERR_SUCCESS) {
        error_code mapped_error;
        switch (err) {
            case INJERR_NO_PROCESS:
                mapped_error = error_code::target_not_found;
                break;
            case INJERR_PERMISSION:
                mapped_error = error_code::target_access_denied;
                break;
            case INJERR_NO_MEMORY:
                mapped_error = error_code::out_of_memory;
                break;
            default:
                mapped_error = error_code::injection_failed;
                break;
        }
        return make_error_result(mapped_error, injector_error(), err);
    }
    
    // inject the library
    void* handle = nullptr;
    err = injector_inject(injector, cfg.library_path.c_str(), &handle);
    
    // cleanup injector regardless of result
    injector_detach(injector);
    
    if (err != INJERR_SUCCESS) {
        error_code mapped_error;
        switch (err) {
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
        return make_error_result(mapped_error, injector_error(), err);
    }
    
    return make_success_result(target_pid);
}

result inject_preload(const config& cfg) {
    if (!cfg.binary_path) {
        return make_error_result(error_code::configuration_invalid, "binary_path required for preload injection");
    }
    
    // set up environment with DYLD_INSERT_LIBRARIES
    std::map<std::string, std::string> env = cfg.env_vars;
    env["DYLD_INSERT_LIBRARIES"] = cfg.library_path;
    
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
    
    // get process count
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, nullptr, &size, nullptr, 0) != 0) {
        return processes;
    }
    
    // get process list
    size_t count = size / sizeof(struct kinfo_proc);
    std::vector<struct kinfo_proc> procs(count);
    if (sysctl(mib, 4, procs.data(), &size, nullptr, 0) != 0) {
        return processes;
    }
    
    // convert to our format
    for (const auto& proc : procs) {
        process_info info;
        info.pid = proc.kp_proc.p_pid;
        info.name = proc.kp_proc.p_comm;
        
        // get full path using libproc
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(info.pid, pathbuf, sizeof(pathbuf)) > 0) {
            info.full_path = pathbuf;
        }
        
        processes.push_back(info);
    }
    
    return processes;
}

std::vector<process_info> find_processes_by_name(const std::string& name) {
    std::vector<process_info> matches;
    auto all_processes = list_processes();
    
    for (const auto& proc : all_processes) {
        if (proc.name == name) {
            matches.push_back(proc);
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
    // try to create a test injector to check permissions
    injector_t* injector = nullptr;
    int err = injector_attach(&injector, getpid()); // attach to self
    
    if (err == INJERR_SUCCESS) {
        injector_detach(injector);
        return true;
    }
    
    return false;
}

}