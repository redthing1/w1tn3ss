#pragma once

#include "calling_convention_base.hpp"
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <memory>

namespace w1::abi {

// represents semantic information about an api parameter
struct param_info {
    enum class type {
        UNKNOWN,
        // numeric types
        INTEGER,
        UNSIGNED,
        POINTER,
        SIZE,
        COUNT,
        FLAGS,
        BOOLEAN,
        FLOAT,
        DOUBLE,
        // special types
        HANDLE,
        FILE_DESCRIPTOR,
        STRING,
        WSTRING,    // wide string (windows)
        BUFFER,
        STRUCT,
        CALLBACK,
        VOID,       // for return values
        // semantic types
        PATH,
        URL,
        REGISTRY_KEY,
        PROCESS_ID,
        THREAD_ID,
        ERROR_CODE
    };
    
    enum class direction {
        IN,      // input parameter
        OUT,     // output parameter
        IN_OUT   // both input and output
    };
    
    std::string name;
    type param_type = type::UNKNOWN;
    direction param_direction = direction::IN;
    size_t size_hint = 0;  // for buffers/structs
    bool is_optional = false;
    std::string description;
    std::string type_description;  // human-readable type description
    
    // relationships to other parameters
    int size_param_index = -1;  // if this is a buffer, which param contains its size
    int count_param_index = -1; // if this is an array, which param contains count
    size_t buffer_size = 0;     // known buffer size
    
    // for flags parameters
    std::unordered_map<uint32_t, std::string> flag_values;  // flag -> name mapping
};

// represents semantic information about an api function
struct api_info {
    enum class category {
        UNKNOWN,
        // file operations
        FILE_IO,
        FILE_MANAGEMENT,
        STDIO,              // standard I/O (printf, puts, etc)
        // process/thread
        PROCESS_CONTROL,
        THREAD_CONTROL,
        THREADING,          // thread creation and management
        // memory
        MEMORY_MANAGEMENT,
        HEAP_MANAGEMENT,
        // synchronization
        SYNCHRONIZATION,
        MUTEX,
        EVENT,
        SEMAPHORE,
        // network
        NETWORK_SOCKET,
        NETWORK_DNS,
        NETWORK_HTTP,
        // registry (windows)
        REGISTRY,
        // security
        SECURITY,
        CRYPTO,
        // system
        SYSTEM_INFO,
        TIME,
        // string/locale
        STRING_MANIPULATION,
        LOCALE,
        // dll/library
        LIBRARY_LOADING,
        // ipc
        IPC,
        PIPE,
        SHARED_MEMORY,
        // ui (if needed)
        UI,
        WINDOW,
        // other
        MISC
    };
    
    enum class behavior_flags : uint32_t {
        NONE = 0,
        ALLOCATES_MEMORY = 1 << 0,      // function allocates memory
        FREES_MEMORY = 1 << 1,          // function frees memory
        OPENS_HANDLE = 1 << 2,          // creates a handle/fd
        CLOSES_HANDLE = 1 << 3,         // closes a handle/fd
        BLOCKING = 1 << 4,              // may block
        ASYNC = 1 << 5,                 // asynchronous operation
        MODIFIES_GLOBAL_STATE = 1 << 6, // changes process-wide state
        THREAD_SAFE = 1 << 7,           // documented as thread-safe
        DEPRECATED = 1 << 8,            // deprecated api
        SECURITY_SENSITIVE = 1 << 9,    // security-relevant
        NETWORK_IO = 1 << 10,           // performs network i/o
        FILE_IO = 1 << 11,              // performs file i/o
        REGISTRY_ACCESS = 1 << 12,      // accesses registry (windows)
        PRIVILEGED = 1 << 13            // requires elevated privileges
    };
    
    std::string name;
    std::string module;  // e.g., "kernel32.dll", "libc.so.6"
    category api_category = category::UNKNOWN;
    uint32_t flags = 0;
    
    // calling convention
    calling_convention_id convention = calling_convention_id::UNKNOWN;
    // platform-specific overrides (e.g., "win32" -> X86_STDCALL)
    std::unordered_map<std::string, calling_convention_id> platform_conventions;
    
    // parameters
    std::vector<param_info> parameters;
    param_info return_value;
    
    // semantic information
    std::string description;
    std::vector<std::string> common_errors;  // common error conditions
    std::vector<std::string> security_notes; // security considerations
    
    // relationships
    std::vector<std::string> related_apis;   // similar or companion apis
    std::string cleanup_api;                 // api to call for cleanup (e.g., free for malloc)
    
    // platform info
    std::string min_version;  // minimum os version
    std::vector<std::string> headers;  // header files that declare this
};

// knowledge database for api semantics
class api_knowledge_db {
public:
    api_knowledge_db();
    ~api_knowledge_db();
    
    // lookup api information
    std::optional<api_info> lookup(const std::string& api_name) const;
    std::optional<api_info> lookup(const std::string& module, const std::string& api_name) const;
    
    // query apis by category
    std::vector<std::string> get_apis_by_category(api_info::category category) const;
    
    // query apis by behavior
    std::vector<std::string> get_apis_with_flags(uint32_t flags) const;
    
    // check if api is known
    bool is_known_api(const std::string& api_name) const;
    
    // get all apis in a module
    std::vector<std::string> get_module_apis(const std::string& module) const;
    
    // add custom api info (for extending the database)
    void add_api(const api_info& info);
    
    // load additional definitions from file
    bool load_from_file(const std::string& path);
    
    // get statistics
    size_t get_api_count() const;
    size_t get_module_count() const;

private:
    class impl;
    std::unique_ptr<impl> pimpl;
};

// helper functions for working with api info
inline bool has_flag(const api_info& info, api_info::behavior_flags flag) {
    return (info.flags & static_cast<uint32_t>(flag)) != 0;
}

inline void set_flag(api_info& info, api_info::behavior_flags flag) {
    info.flags |= static_cast<uint32_t>(flag);
}

// common parameter type detection
param_info::type infer_param_type(const std::string& param_name, const std::string& type_name);

// format api signature for display
std::string format_api_signature(const api_info& info);

} // namespace w1::abi