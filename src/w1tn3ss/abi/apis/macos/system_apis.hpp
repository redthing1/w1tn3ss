#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::macos {

// macOS system library APIs with correct library names and signatures
static const std::vector<api_info> macos_system_apis = {
    // stdio APIs from libsystem_c.dylib
    {
        .name = "_puts",
        .module = "libsystem_c.dylib",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "s", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "write string to stdout",
        .headers = {"stdio.h"}
    },
    {
        .name = "_printf",
        .module = "libsystem_c.dylib",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "format", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
            // Note: variadic args not handled yet
        },
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "formatted output to stdout",
        .headers = {"stdio.h"}
    },
    {
        .name = "_fprintf",
        .module = "libsystem_c.dylib",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "stream", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "format", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "formatted output to stream",
        .headers = {"stdio.h"}
    },
    
    // malloc APIs from libsystem_malloc.dylib
    {
        .name = "_malloc",
        .module = "libsystem_malloc.dylib",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
        .description = "allocate memory",
        .cleanup_api = "_free",
        .headers = {"stdlib.h"}
    },
    {
        .name = "_free",
        .module = "libsystem_malloc.dylib",
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
        .name = "_calloc",
        .module = "libsystem_malloc.dylib",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "nmemb", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
        .description = "allocate and zero memory",
        .cleanup_api = "_free",
        .headers = {"stdlib.h"}
    },
    {
        .name = "_realloc",
        .module = "libsystem_malloc.dylib",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY) |
                 static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "new_ptr", .param_type = param_info::type::POINTER},
        .description = "resize allocated memory",
        .headers = {"stdlib.h"}
    },
    
    // file I/O from libsystem_kernel.dylib
    {
        .name = "_open",
        .module = "libsystem_kernel.dylib",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) | 
                 static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .parameters = {
            {.name = "pathname", .param_type = param_info::type::PATH, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "mode", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN, .is_optional = true}
        },
        .return_value = {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR},
        .description = "open file",
        .cleanup_api = "_close",
        .headers = {"fcntl.h"}
    },
    {
        .name = "_close",
        .module = "libsystem_kernel.dylib",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "close file descriptor",
        .headers = {"unistd.h"}
    },
    {
        .name = "_read",
        .module = "libsystem_kernel.dylib",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT, .size_param_index = 2},
            {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytes_read", .param_type = param_info::type::SIZE},
        .description = "read from file descriptor",
        .headers = {"unistd.h"}
    },
    {
        .name = "_write",
        .module = "libsystem_kernel.dylib",
        .api_category = api_info::category::FILE_IO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "fd", .param_type = param_info::type::FILE_DESCRIPTOR, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN, .size_param_index = 2},
            {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytes_written", .param_type = param_info::type::SIZE},
        .description = "write to file descriptor",
        .headers = {"unistd.h"}
    },
    
    // mach VM APIs
    {
        .name = "_mach_vm_allocate",
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
        .description = "allocate virtual memory",
        .cleanup_api = "_mach_vm_deallocate",
        .headers = {"mach/mach_vm.h"}
    },
    
    // pthread APIs from libsystem_pthread.dylib
    {
        .name = "_pthread_create",
        .module = "libsystem_pthread.dylib",
        .api_category = api_info::category::THREADING,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "thread", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "attr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN, .is_optional = true},
            {.name = "start_routine", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "arg", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "create new thread",
        .headers = {"pthread.h"}
    }
};

} // namespace w1::abi::apis::macos