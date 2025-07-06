#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::linux {

// Linux system library APIs
static const std::vector<api_info> linux_system_apis = {
    // stdio APIs from libc
    {
        .name = "puts",
        .module = "libc.so.6",
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
        .name = "printf",
        .module = "libc.so.6",
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
        .name = "fprintf",
        .module = "libc.so.6",
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
    
    // malloc APIs from libc
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
        .name = "calloc",
        .module = "libc.so.6",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .parameters = {
            {.name = "nmemb", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
            {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "ptr", .param_type = param_info::type::POINTER},
        .description = "allocate and zero memory",
        .cleanup_api = "free",
        .headers = {"stdlib.h"}
    },
    {
        .name = "realloc",
        .module = "libc.so.6",
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
    
    // file I/O
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
        .description = "open file",
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
        .description = "close file descriptor",
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
        .description = "read from file descriptor",
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
        .description = "write to file descriptor",
        .headers = {"unistd.h"}
    },
    
    // memory management
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
    },
    {
        .name = "munmap",
        .module = "libc.so.6",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "addr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "length", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "unmap memory region",
        .headers = {"sys/mman.h"}
    },
    
    // pthread APIs
    {
        .name = "pthread_create",
        .module = "libpthread.so.0",
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
    },
    
    // network APIs
    {
        .name = "socket",
        .module = "libc.so.6",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "domain", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "type", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "protocol", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "sockfd", .param_type = param_info::type::FILE_DESCRIPTOR},
        .description = "create network socket",
        .cleanup_api = "close",
        .headers = {"sys/socket.h"}
    }
};

} // namespace w1::abi::apis::linux