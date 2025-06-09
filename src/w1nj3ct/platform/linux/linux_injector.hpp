#pragma once

#include "../../w1nj3ct.hpp"

namespace w1::inject::linux_impl {
    // wrapper for linux injection (using kubo/injector backend when available)
    result inject_runtime(const config& cfg);
    result inject_preload(const config& cfg);
    
    // process discovery 
    std::vector<process_info> list_processes();
    std::vector<process_info> find_processes_by_name(const std::string& name);
    std::optional<process_info> get_process_info(int pid);
    
    // capabilities check
    bool check_injection_capabilities();
}