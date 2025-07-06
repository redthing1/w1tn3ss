#include "calling_convention_detector.hpp"
#include "calling_convention_factory.hpp"
#include <redlog.hpp>
#include <algorithm>
#include <cctype>

namespace w1::abi {

calling_convention_detector::calling_convention_detector() {
    initialize_default_rules();
}

void calling_convention_detector::initialize_default_rules() {
    #ifdef _WIN32
        // windows system dlls typically use stdcall on x86
        add_rule({
            std::regex("(kernel32|user32|ntdll|advapi32|gdi32)\\.dll", std::regex_constants::icase),
            std::regex(".*"),
            #ifdef _WIN64
                calling_convention_id::X86_64_MICROSOFT,
            #else
                calling_convention_id::X86_STDCALL,
            #endif
            100
        });
        
        // msvcrt uses cdecl
        add_rule({
            std::regex("msvcrt.*\\.dll", std::regex_constants::icase),
            std::regex(".*"),
            #ifdef _WIN64
                calling_convention_id::X86_64_MICROSOFT,
            #else
                calling_convention_id::X86_CDECL,
            #endif
            90
        });
    #endif
}

calling_convention_ptr calling_convention_detector::detect(
    const std::string& binary_path,
    const std::string& symbol_name) const {
    
    // extract module name from path
    size_t last_slash = binary_path.find_last_of("/\\");
    std::string module_name = (last_slash != std::string::npos) 
        ? binary_path.substr(last_slash + 1) 
        : binary_path;
    
    // check custom rules first
    for (const auto& rule : rules_) {
        if (std::regex_match(module_name, rule.module_pattern) &&
            std::regex_match(symbol_name, rule.symbol_pattern)) {
            return calling_convention_factory::instance().create(rule.convention);
        }
    }
    
    // try symbol-based detection
    return detect_from_symbol(symbol_name);
}

calling_convention_ptr calling_convention_detector::detect_from_module(
    const util::module_info& module,
    const std::string& symbol_name) const {
    
    return detect(module.path, symbol_name);
}

calling_convention_ptr calling_convention_detector::detect_from_symbol(
    const std::string& symbol_name) const {
    
    #ifdef _WIN32
        #ifdef _WIN64
            // windows x64 always uses microsoft convention
            return calling_convention_factory::instance().create(
                calling_convention_id::X86_64_MICROSOFT);
        #else
            // windows x86 - parse decorated names
            auto decorated = parse_decorated_name(symbol_name);
            if (decorated) {
                return calling_convention_factory::instance().create(
                    decorated->convention);
            }
            // default to cdecl if no decoration
            return calling_convention_factory::instance().create(
                calling_convention_id::X86_CDECL);
        #endif
    #else
        // unix platforms
        return get_platform_default();
    #endif
}

calling_convention_ptr calling_convention_detector::get_platform_default() const {
    return calling_convention_factory::instance().create_default();
}

void calling_convention_detector::add_rule(const detection_rule& rule) {
    // insert sorted by priority (highest first)
    auto it = std::lower_bound(rules_.begin(), rules_.end(), rule,
        [](const detection_rule& a, const detection_rule& b) {
            return a.priority > b.priority;
        });
    rules_.insert(it, rule);
}

void calling_convention_detector::clear_rules() {
    rules_.clear();
}

std::optional<calling_convention_detector::decorated_info> 
calling_convention_detector::parse_decorated_name(
    const std::string& decorated_name) const {
    
    if (decorated_name.empty()) {
        return std::nullopt;
    }
    
    decorated_info info;
    
    // c++ member functions often start with ?
    if (decorated_name[0] == '?') {
        // simplified c++ name parsing
        info.convention = calling_convention_id::X86_THISCALL;
        info.has_this_pointer = true;
        info.undecorated_name = decorated_name; // would need full undecoration
        return info;
    }
    
    // stdcall: _func@12 (underscore prefix, @bytes suffix)
    if (decorated_name[0] == '_') {
        size_t at_pos = decorated_name.find('@');
        if (at_pos != std::string::npos && at_pos > 1) {
            // extract stack bytes
            std::string bytes_str = decorated_name.substr(at_pos + 1);
            if (std::all_of(bytes_str.begin(), bytes_str.end(), ::isdigit)) {
                info.convention = calling_convention_id::X86_STDCALL;
                info.stack_cleanup = std::stoul(bytes_str);
                info.undecorated_name = decorated_name.substr(1, at_pos - 1);
                return info;
            }
        }
    }
    
    // fastcall: @func@12 (@ prefix, @bytes suffix)
    if (decorated_name[0] == '@') {
        size_t at_pos = decorated_name.find('@', 1);
        if (at_pos != std::string::npos) {
            // extract stack bytes
            std::string bytes_str = decorated_name.substr(at_pos + 1);
            if (std::all_of(bytes_str.begin(), bytes_str.end(), ::isdigit)) {
                info.convention = calling_convention_id::X86_FASTCALL;
                info.stack_cleanup = std::stoul(bytes_str);
                info.undecorated_name = decorated_name.substr(1, at_pos - 1);
                return info;
            }
        }
    }
    
    // vectorcall: func@@12 (double @ before bytes)
    size_t double_at = decorated_name.find("@@");
    if (double_at != std::string::npos) {
        std::string bytes_str = decorated_name.substr(double_at + 2);
        if (!bytes_str.empty() && std::all_of(bytes_str.begin(), bytes_str.end(), ::isdigit)) {
            info.convention = calling_convention_id::X86_VECTORCALL;
            info.stack_cleanup = std::stoul(bytes_str);
            info.undecorated_name = decorated_name.substr(0, double_at);
            return info;
        }
    }
    
    // no decoration = cdecl
    info.convention = calling_convention_id::X86_CDECL;
    info.stack_cleanup = 0; // caller cleans stack
    info.undecorated_name = decorated_name;
    return info;
}

calling_convention_id calling_convention_detector::detect_windows_x86(
    const std::string& symbol_name) const {
    
    auto decorated = parse_decorated_name(symbol_name);
    if (decorated) {
        return decorated->convention;
    }
    return calling_convention_id::X86_CDECL;
}

calling_convention_id calling_convention_detector::detect_windows_x64(
    const std::string& module_name) const {
    
    // windows x64 only has one calling convention
    return calling_convention_id::X86_64_MICROSOFT;
}

calling_convention_id calling_convention_detector::detect_unix_convention() const {
    #if defined(__x86_64__)
        return calling_convention_id::X86_64_SYSTEM_V;
    #elif defined(__aarch64__)
        return calling_convention_id::AARCH64_AAPCS;
    #elif defined(__arm__)
        return calling_convention_id::ARM32_AAPCS;
    #elif defined(__i386__)
        return calling_convention_id::X86_CDECL;
    #else
        return calling_convention_id::UNKNOWN;
    #endif
}

calling_convention_id calling_convention_detector::detect_arm_convention() const {
    #ifdef _WIN32
        #ifdef __aarch64__
            return calling_convention_id::AARCH64_WINDOWS;
        #else
            return calling_convention_id::ARM32_AAPCS; // simplified
        #endif
    #else
        #ifdef __aarch64__
            return calling_convention_id::AARCH64_AAPCS;
        #else
            return calling_convention_id::ARM32_AAPCS;
        #endif
    #endif
}

} // namespace w1::abi