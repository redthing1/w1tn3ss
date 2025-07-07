#include "env_enumerator.hpp"

#ifndef _WIN32
// On Unix systems, environ needs to be explicitly declared
// Some systems define it in unistd.h, others don't
extern "C" {
    extern char** environ;
}
#endif

namespace w1::util {

std::unordered_map<std::string, std::string> env_enumerator::get_vars_with_prefix(const std::string& prefix) {
    std::unordered_map<std::string, std::string> result;
    
#ifdef _WIN32
    // windows: use GetEnvironmentStrings
    LPCH env_strings = GetEnvironmentStrings();
    if (env_strings) {
        LPCH current = env_strings;
        while (*current) {
            std::string env_var(current);
            if (env_var.find(prefix) == 0) {
                size_t eq_pos = env_var.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = env_var.substr(prefix.length(), eq_pos - prefix.length());
                    std::string value = env_var.substr(eq_pos + 1);
                    result[key] = value;
                }
            }
            current += env_var.length() + 1;
        }
        FreeEnvironmentStrings(env_strings);
    }
#else
    // unix: use environ
    if (char** env_ptr = environ) {
        for (char** env = env_ptr; *env != nullptr; env++) {
            std::string env_var(*env);
            if (env_var.find(prefix) == 0) {
                size_t eq_pos = env_var.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = env_var.substr(prefix.length(), eq_pos - prefix.length());
                    std::string value = env_var.substr(eq_pos + 1);
                    result[key] = value;
                }
            }
        }
    }
#endif
    
    return result;
}

} // namespace w1::util