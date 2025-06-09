#include "w1nj3ct.hpp"
#include "error.hpp"
#include <redlog/redlog.hpp>

// platform-specific includes
#ifdef __APPLE__
#include "platform/darwin/darwin_injector.hpp"
#elif defined(__linux__)
#include "platform/linux/linux_injector.hpp"
#elif defined(_WIN32)
#include "platform/windows/windows_injector.hpp"
#endif

#include <filesystem>

namespace w1::inject {

// validate configuration before injection
error_code validate_config(const config& cfg) {
    // check exactly one target specified
    int target_count = 0;
    if (cfg.pid) target_count++;
    if (cfg.process_name) target_count++;
    if (cfg.binary_path) target_count++;
    
    if (target_count != 1) {
        return error_code::configuration_invalid;
    }
    
    // validate library path exists
    if (!std::filesystem::exists(cfg.library_path)) {
        return error_code::library_not_found;
    }
    
    // check method compatibility with target type
    if (cfg.injection_method == method::launch && !cfg.binary_path) {
        return error_code::configuration_invalid;
    }
    
    if (cfg.injection_method == method::runtime && cfg.binary_path) {
        return error_code::configuration_invalid;
    }
    
    // platform-specific validation
#ifdef _WIN32
    if (cfg.injection_method == method::launch) {
        return error_code::technique_not_supported;
    }
#endif
    
    return error_code::success;
}

result inject(const config& cfg) {
    auto log = redlog::get_logger("w1nj3ct");
    
    log.debug("injection request received",
              redlog::field("method", cfg.injection_method == method::runtime ? "runtime" : "preload"),
              redlog::field("library", cfg.library_path));
    
    // 1. validate configuration
    error_code validation_result = validate_config(cfg);
    if (validation_result != error_code::success) {
        log.error("configuration validation failed", redlog::field("error", error_code_to_string(validation_result)));
        return make_error_result(validation_result, "configuration validation failed");
    }
    
    log.trace("configuration validated successfully");
    
    // 2. platform detection and dispatch
#ifdef __APPLE__
    if (cfg.injection_method == method::runtime) {
        return darwin::inject_runtime(cfg);
    } else {
        return darwin::inject_preload(cfg);
    }
#elif defined(__linux__)
    if (cfg.injection_method == method::runtime) {
        return linux_impl::inject_runtime(cfg);
    } else {
        return linux_impl::inject_preload(cfg);
    }
#elif defined(_WIN32)
    if (cfg.injection_method == method::runtime) {
        return windows::inject_runtime(cfg);
    } else {
        return windows::inject_preload(cfg);
    }
#else
    return make_error_result(error_code::platform_not_supported, "unsupported platform");
#endif
}

std::vector<process_info> list_processes() {
#ifdef __APPLE__
    return darwin::list_processes();
#elif defined(__linux__)
    return linux_impl::list_processes();
#elif defined(_WIN32)
    return windows::list_processes();
#else
    return {};
#endif
}

std::vector<process_info> find_processes(const std::string& name) {
#ifdef __APPLE__
    return darwin::find_processes_by_name(name);
#elif defined(__linux__)
    return linux_impl::find_processes_by_name(name);
#elif defined(_WIN32)
    return windows::find_processes_by_name(name);
#else
    return {};
#endif
}

std::optional<process_info> get_process_info(int pid) {
#ifdef __APPLE__
    return darwin::get_process_info(pid);
#elif defined(__linux__)
    return linux_impl::get_process_info(pid);
#elif defined(_WIN32)
    return windows::get_process_info(pid);
#else
    return std::nullopt;
#endif
}

bool check_injection_capabilities() {
#ifdef __APPLE__
    return darwin::check_injection_capabilities();
#elif defined(__linux__)
    return linux_impl::check_injection_capabilities();
#elif defined(_WIN32)
    return windows::check_injection_capabilities();
#else
    return false;
#endif
}

std::vector<std::string> get_supported_platforms() {
    std::vector<std::string> platforms;
#ifdef __APPLE__
    platforms.push_back("macOS");
#endif
#ifdef __linux__
    platforms.push_back("Linux");
#endif
#ifdef _WIN32
    platforms.push_back("Windows");
#endif
    return platforms;
}

bool is_library_compatible(const std::string& library_path, int pid) {
    // basic check - library exists
    if (!std::filesystem::exists(library_path)) {
        return false;
    }
    
    // TODO: implement architecture compatibility checking
    // for now, assume compatible
    return true;
}

}