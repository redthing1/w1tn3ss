#include "api_knowledge_db.hpp"
#include <redlog.hpp>
#include <unordered_set>
#include <algorithm>
#include <fstream>
#include <common/ext/jsonstruct.hpp>

// Platform-specific API definitions
#ifdef __APPLE__
#include "detail/macos_apis.hpp"
#elif defined(__linux__)
#include "detail/linux_apis.hpp"
#elif defined(_WIN32)
#include "detail/windows_apis.hpp"
#endif

namespace w1::abi {

// populate with common apis from various platforms
namespace builtin_apis {

// common libc file apis
static const std::vector<api_info> libc_file_apis = {
    {
        .name = "open",
        .module = "libc.so.6",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) | 
                 static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "pathname", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "mode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN, .is_optional = true}
        },
        .return_value = {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR},
        .description = "open and possibly create a file",
        .cleanup_api = "close",
        .headers = {"fcntl.h"}
    },
    {
        .name = "close",
        .module = "libc.so.6", 
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "close a file descriptor",
        .headers = {"unistd.h"}
    },
    {
        .name = "read",
        .module = "libc.so.6",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT, .size_param_index = 2},
            {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytes_read", .param_type = param_info::type::SIZE},
        .description = "read from a file descriptor",
        .headers = {"unistd.h"}
    },
    {
        .name = "write", 
        .module = "libc.so.6",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN, .size_param_index = 2},
            {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytes_written", .param_type = param_info::type::SIZE},
        .description = "write to a file descriptor",
        .headers = {"unistd.h"}
    }
};

// common libc memory apis
static const std::vector<api_info> libc_memory_apis = {
    {
        .name = "malloc",
        .module = "libc.so.6",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
        .description = "allocate memory",
        .cleanup_api = "free",
        .headers = {"stdlib.h"}
    },
    {
        .name = "free",
        .module = "libc.so.6",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::UNKNOWN},
        .description = "free allocated memory",
        .headers = {"stdlib.h"}
    },
    {
        .name = "mmap",
        .module = "libc.so.6",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "addr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN, .is_optional = true},
            {.name = "length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "prot", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN},
            {.name = "offset", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "addr", .param_type = param_info::type::POINTER},
        .description = "map files or devices into memory",
        .cleanup_api = "munmap",
        .headers = {"sys/mman.h"}
    }
};

// common windows kernel32 apis
static const std::vector<api_info> kernel32_apis = {
    {
        .name = "CreateFileW",
        .module = "kernel32.dll",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "lpFileName", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "dwDesiredAccess", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwShareMode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpSecurityAttributes", .param_type = param_info::type::STRUCT, .param_direction = param_info::direction::IN, .is_optional = true},
            {.name = "dwCreationDisposition", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "dwFlagsAndAttributes", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "hTemplateFile", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN, .is_optional = true}
        },
        .return_value = {.name = "hFile", .param_type = param_info::type::HANDLE},
        .description = "creates or opens a file or i/o device",
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "fileapi.h"}
    },
    {
        .name = "VirtualAlloc",
        .module = "kernel32.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "lpAddress", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN, .is_optional = true},
            {.name = "dwSize", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flAllocationType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "flProtect", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "lpAddress", .param_type = param_info::type::POINTER},
        .description = "reserves, commits, or changes the state of a region of pages in the virtual address space",
        .cleanup_api = "VirtualFree",
        .headers = {"windows.h", "memoryapi.h"}
    }
};

// macos-specific apis
static const std::vector<api_info> macos_apis = {
    {
        .name = "mach_vm_allocate",
        .module = "libsystem_kernel.dylib",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "target", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "address", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "kern_return", .param_type = param_info::type::ERROR_CODE},
        .description = "allocate a region of virtual memory",
        .cleanup_api = "mach_vm_deallocate",
        .headers = {"mach/mach_vm.h"}
    }
};

} // namespace builtin_apis

// implementation class
class api_knowledge_db::impl {
public:
    impl() : log_("w1::abi::api_knowledge_db") {
        log_.debug("initializing api knowledge database");
        load_builtin_apis();
        log_.info("loaded builtin apis", redlog::field("count", apis_.size()));
    }
    
    std::optional<api_info> lookup(const std::string& api_name) const {
        log_.debug("looking up api", redlog::field("name", api_name));
        
        // Try exact match first
        auto it = apis_.find(api_name);
        if (it != apis_.end()) {
            log_.debug("found api info", redlog::field("name", api_name), 
                      redlog::field("module", it->second.module),
                      redlog::field("category", static_cast<int>(it->second.api_category)),
                      redlog::field("param_count", it->second.parameters.size()));
            return it->second;
        }
        
        // Try without underscore prefix (for macOS symbols)
        if (!api_name.empty() && api_name[0] == '_') {
            std::string without_underscore = api_name.substr(1);
            it = apis_.find(without_underscore);
            if (it != apis_.end()) {
                log_.debug("found api info without underscore", 
                          redlog::field("original", api_name),
                          redlog::field("matched", without_underscore), 
                          redlog::field("module", it->second.module),
                          redlog::field("param_count", it->second.parameters.size()));
                return it->second;
            }
        }
        
        // Try with underscore prefix (for macOS symbols)
        std::string with_underscore = "_" + api_name;
        it = apis_.find(with_underscore);
        if (it != apis_.end()) {
            log_.debug("found api info with underscore", 
                      redlog::field("original", api_name),
                      redlog::field("matched", with_underscore), 
                      redlog::field("module", it->second.module),
                      redlog::field("param_count", it->second.parameters.size()));
            return it->second;
        }
        
        log_.debug("api not found", redlog::field("name", api_name));
        return std::nullopt;
    }
    
    std::optional<api_info> lookup(const std::string& module, const std::string& api_name) const {
        log_.debug("looking up api with module", 
                  redlog::field("module", module), 
                  redlog::field("name", api_name));
        
        // try exact match first
        auto it = apis_.find(api_name);
        if (it != apis_.end() && it->second.module == module) {
            log_.debug("found exact match", redlog::field("name", api_name));
            return it->second;
        }
        
        // try module prefix match (e.g., "libc.so.6" matches "libc.so")
        if (it != apis_.end()) {
            if (it->second.module.find(module) != std::string::npos ||
                module.find(it->second.module) != std::string::npos) {
                log_.debug("found partial module match", 
                          redlog::field("name", api_name),
                          redlog::field("actual_module", it->second.module));
                return it->second;
            }
        }
        
        log_.debug("api not found for module", 
                  redlog::field("module", module), 
                  redlog::field("name", api_name));
        return std::nullopt;
    }
    
    std::vector<std::string> get_apis_by_category(api_info::category category) const {
        log_.debug("getting apis by category", redlog::field("category", static_cast<int>(category)));
        
        std::vector<std::string> result;
        for (const auto& [name, info] : apis_) {
            if (info.api_category == category) {
                result.push_back(name);
            }
        }
        
        log_.debug("found apis in category", 
                  redlog::field("category", static_cast<int>(category)),
                  redlog::field("count", result.size()));
        return result;
    }
    
    std::vector<std::string> get_apis_with_flags(uint32_t flags) const {
        log_.debug("getting apis with flags", redlog::field("flags", flags));
        
        std::vector<std::string> result;
        for (const auto& [name, info] : apis_) {
            if ((info.flags & flags) == flags) {
                result.push_back(name);
            }
        }
        
        log_.debug("found apis with flags", 
                  redlog::field("flags", flags),
                  redlog::field("count", result.size()));
        return result;
    }
    
    bool is_known_api(const std::string& api_name) const {
        bool known = apis_.find(api_name) != apis_.end();
        log_.debug("checking if api is known", 
                  redlog::field("name", api_name),
                  redlog::field("known", known));
        return known;
    }
    
    std::vector<std::string> get_module_apis(const std::string& module) const {
        log_.debug("getting apis for module", redlog::field("module", module));
        
        std::vector<std::string> result;
        for (const auto& [name, info] : apis_) {
            if (info.module == module) {
                result.push_back(name);
            }
        }
        
        log_.debug("found module apis", 
                  redlog::field("module", module),
                  redlog::field("count", result.size()));
        return result;
    }
    
    void add_api(const api_info& info) {
        log_.info("adding api to knowledge database", 
                 redlog::field("name", info.name),
                 redlog::field("module", info.module),
                 redlog::field("category", static_cast<int>(info.api_category)));
        
        apis_[info.name] = info;
        modules_.insert(info.module);
    }
    
    bool load_from_file(const std::string& path) {
        log_.info("loading api definitions from file", redlog::field("path", path));
        
        try {
            std::ifstream file(path);
            if (!file.is_open()) {
                log_.err("failed to open file", redlog::field("path", path));
                return false;
            }
            
            // Read entire file into string
            std::string json_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            
            // TODO: Parse using jsonstruct - need to define proper structs with JS_OBJECT macros
            // For now, just log that we need to implement this
            log_.warn("JSON parsing using jsonstruct not yet implemented - need to define JS_OBJECT structs");
            return false;
            
        } catch (const std::exception& e) {
            log_.err("failed to read api definitions file", 
                    redlog::field("path", path),
                    redlog::field("error", e.what()));
            return false;
        }
    }
    
    size_t get_api_count() const { return apis_.size(); }
    size_t get_module_count() const { return modules_.size(); }
    
private:
    redlog::logger log_;
    std::unordered_map<std::string, api_info> apis_;
    std::unordered_set<std::string> modules_;
    
    void load_builtin_apis() {
        log_.debug("loading builtin apis for platform");
        
        // Load platform-specific APIs
#ifdef __APPLE__
        load_api_set(detail::macos_system_apis, "macos system apis");
#elif defined(__linux__)
        load_api_set(detail::linux_system_apis, "linux system apis");
#elif defined(_WIN32)
        load_api_set(builtin_apis::kernel32_apis, "windows kernel32 apis");
#endif
        
        // Keep the cross-platform APIs for now - but they'll be shadowed by platform-specific ones
        load_api_set(builtin_apis::libc_file_apis, "libc file apis");
        load_api_set(builtin_apis::libc_memory_apis, "libc memory apis");
    }
    
    void load_api_set(const std::vector<api_info>& api_set, const std::string& set_name) {
        log_.debug("loading api set", redlog::field("name", set_name));
        
        for (const auto& api : api_set) {
            add_api(api);
        }
        
        log_.debug("loaded api set", 
                  redlog::field("name", set_name),
                  redlog::field("count", api_set.size()));
    }
    
    // string conversion helpers
    api_info::category string_to_category(const std::string& s) {
        static const std::unordered_map<std::string, api_info::category> map = {
            {"FILE_IO", api_info::category::FILE_IO},
            {"FILE_MANAGEMENT", api_info::category::FILE_MANAGEMENT},
            {"PROCESS_CONTROL", api_info::category::PROCESS_CONTROL},
            {"MEMORY_MANAGEMENT", api_info::category::MEMORY_MANAGEMENT},
            {"HEAP_MANAGEMENT", api_info::category::HEAP_MANAGEMENT},
            {"NETWORK_SOCKET", api_info::category::NETWORK_SOCKET}
            // add more as needed
        };
        
        auto it = map.find(s);
        return it != map.end() ? it->second : api_info::category::UNKNOWN;
    }
    
    uint32_t string_to_flag(const std::string& s) {
        static const std::unordered_map<std::string, api_info::behavior_flags> map = {
            {"ALLOCATES_MEMORY", api_info::behavior_flags::ALLOCATES_MEMORY},
            {"FREES_MEMORY", api_info::behavior_flags::FREES_MEMORY},
            {"OPENS_HANDLE", api_info::behavior_flags::OPENS_HANDLE},
            {"CLOSES_HANDLE", api_info::behavior_flags::CLOSES_HANDLE},
            {"BLOCKING", api_info::behavior_flags::BLOCKING},
            {"FILE_IO", api_info::behavior_flags::FILE_IO}
            // add more as needed
        };
        
        auto it = map.find(s);
        return it != map.end() ? static_cast<uint32_t>(it->second) : 0;
    }
    
    param_info::type string_to_param_type(const std::string& s) {
        static const std::unordered_map<std::string, param_info::type> map = {
            {"INTEGER", param_info::type::INTEGER},
            {"POINTER", param_info::type::POINTER},
            {"SIZE", param_info::type::SIZE},
            {"FLAGS", param_info::type::FLAGS},
            {"HANDLE", param_info::type::HANDLE},
            {"FILE_DESCRIPTOR", param_info::type::FILE_DESCRIPTOR},
            {"STRING", param_info::type::STRING},
            {"BUFFER", param_info::type::BUFFER},
            {"PATH", param_info::type::PATH}
            // add more as needed
        };
        
        auto it = map.find(s);
        return it != map.end() ? it->second : param_info::type::UNKNOWN;
    }
    
    param_info::direction string_to_direction(const std::string& s) {
        if (s == "OUT") return param_info::direction::OUT;
        if (s == "IN_OUT") return param_info::direction::IN_OUT;
        return param_info::direction::IN;
    }
};

// api_knowledge_db implementation
api_knowledge_db::api_knowledge_db() : pimpl(std::make_unique<impl>()) {}
api_knowledge_db::~api_knowledge_db() = default;

std::optional<api_info> api_knowledge_db::lookup(const std::string& api_name) const {
    return pimpl->lookup(api_name);
}

std::optional<api_info> api_knowledge_db::lookup(const std::string& module, const std::string& api_name) const {
    return pimpl->lookup(module, api_name);
}

std::vector<std::string> api_knowledge_db::get_apis_by_category(api_info::category category) const {
    return pimpl->get_apis_by_category(category);
}

std::vector<std::string> api_knowledge_db::get_apis_with_flags(uint32_t flags) const {
    return pimpl->get_apis_with_flags(flags);
}

bool api_knowledge_db::is_known_api(const std::string& api_name) const {
    return pimpl->is_known_api(api_name);
}

std::vector<std::string> api_knowledge_db::get_module_apis(const std::string& module) const {
    return pimpl->get_module_apis(module);
}

void api_knowledge_db::add_api(const api_info& info) {
    pimpl->add_api(info);
}

bool api_knowledge_db::load_from_file(const std::string& path) {
    return pimpl->load_from_file(path);
}

size_t api_knowledge_db::get_api_count() const {
    return pimpl->get_api_count();
}

size_t api_knowledge_db::get_module_count() const {
    return pimpl->get_module_count();
}

// helper functions
param_info::type infer_param_type(const std::string& param_name, const std::string& type_name) {
    // infer based on common naming patterns
    std::string lower_name = param_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    if (lower_name.find("path") != std::string::npos || 
        lower_name.find("file") != std::string::npos) {
        return param_info::type::PATH;
    }
    
    if (lower_name.find("size") != std::string::npos ||
        lower_name.find("len") != std::string::npos ||
        lower_name.find("count") != std::string::npos) {
        return param_info::type::SIZE;
    }
    
    if (lower_name.find("flags") != std::string::npos ||
        lower_name.find("mode") != std::string::npos) {
        return param_info::type::FLAGS;
    }
    
    if (lower_name.find("handle") != std::string::npos ||
        lower_name == "h" || lower_name.find("hwnd") != std::string::npos) {
        return param_info::type::HANDLE;
    }
    
    if (lower_name == "fd" || lower_name.find("descriptor") != std::string::npos) {
        return param_info::type::FILE_DESCRIPTOR;
    }
    
    if (lower_name.find("buffer") != std::string::npos ||
        lower_name.find("buf") != std::string::npos ||
        lower_name.find("data") != std::string::npos) {
        return param_info::type::BUFFER;
    }
    
    if (lower_name.find("str") != std::string::npos ||
        lower_name.find("name") != std::string::npos ||
        lower_name.find("text") != std::string::npos) {
        return param_info::type::STRING;
    }
    
    // check type name hints
    std::string lower_type = type_name;
    std::transform(lower_type.begin(), lower_type.end(), lower_type.begin(), ::tolower);
    
    if (lower_type.find("char*") != std::string::npos ||
        lower_type.find("wchar*") != std::string::npos) {
        return param_info::type::STRING;
    }
    
    if (lower_type.find("void*") != std::string::npos ||
        lower_type.find("ptr") != std::string::npos) {
        return param_info::type::POINTER;
    }
    
    if (lower_type.find("int") != std::string::npos ||
        lower_type.find("long") != std::string::npos ||
        lower_type.find("dword") != std::string::npos) {
        return param_info::type::INTEGER;
    }
    
    return param_info::type::UNKNOWN;
}

std::string format_api_signature(const api_info& info) {
    std::string sig = info.return_value.name + " " + info.name + "(";
    
    for (size_t i = 0; i < info.parameters.size(); ++i) {
        if (i > 0) sig += ", ";
        
        const auto& param = info.parameters[i];
        sig += param.name;
        
        if (param.param_direction == param_info::direction::OUT) {
            sig += " [out]";
        } else if (param.param_direction == param_info::direction::IN_OUT) {
            sig += " [in,out]";
        }
        
        if (param.is_optional) {
            sig += " [opt]";
        }
    }
    
    sig += ")";
    return sig;
}

} // namespace w1::abi