#pragma once

#include "abi/api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

// determine windows calling convention based on architecture
#if defined(_M_X64) || defined(__x86_64__)
#define WINDOWS_API_CONVENTION calling_convention_id::X86_64_MICROSOFT
#elif defined(_M_IX86) || defined(__i386__)
#define WINDOWS_API_CONVENTION calling_convention_id::X86_STDCALL
#else
#define WINDOWS_API_CONVENTION calling_convention_id::UNKNOWN
#endif

/**
 * @brief universal c runtime (ucrtbase.dll) api definitions
 *
 * covers modern windows c runtime apis:
 * - string manipulation functions
 * - memory management functions
 * - i/o and formatting functions
 * - character classification and conversion
 * - mathematical functions
 * - program lifecycle functions
 */

static const std::vector<api_info> windows_ucrtbase_apis = {
    // string manipulation functions
    api_info{
        .name = "strdup",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "strSource",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "duplicate", .param_type = param_info::type::STRING},
        .description = "duplicate string by allocating memory copy",
        .security_notes = {"allocates memory that must be freed", "returns null on allocation failure"},
        .cleanup_api = "free",
        .headers = {"string.h"}
    },

    api_info{
        .name = "_strdup",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "strSource",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "duplicate", .param_type = param_info::type::STRING},
        .description = "microsoft-specific duplicate string function",
        .related_apis = {"strdup"},
        .cleanup_api = "free",
        .headers = {"string.h"}
    },

    api_info{
        .name = "strcpy",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "strDestination",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::OUT},
             {.name = "strSource",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "destination", .param_type = param_info::type::STRING},
        .description = "copy string to destination buffer",
        .security_notes = {"buffer overflow risk", "destination must be large enough", "use strcpy_s instead"},
        .related_apis = {"strcpy_s", "strncpy"},
        .headers = {"string.h"}
    },

    api_info{
        .name = "strlen",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "str", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "length", .param_type = param_info::type::SIZE},
        .description = "get length of null-terminated string",
        .headers = {"string.h"}
    },

    api_info{
        .name = "strcmp",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "string1", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "string2", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "compare two strings lexicographically",
        .headers = {"string.h"}
    },

    // memory management functions
    api_info{
        .name = "malloc",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "pointer", .param_type = param_info::type::POINTER},
        .description = "allocate memory block on heap",
        .related_apis = {"calloc", "realloc", "free"},
        .cleanup_api = "free",
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "free",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ptr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "free previously allocated memory block",
        .security_notes = {"double-free vulnerability", "use-after-free vulnerability"},
        .related_apis = {"malloc", "calloc", "realloc"},
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "calloc",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::HEAP_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::ALLOCATES_MEMORY),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "num", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
             {.name = "size", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "pointer", .param_type = param_info::type::POINTER},
        .description = "allocate and zero-initialize array of elements",
        .related_apis = {"malloc", "realloc", "free"},
        .cleanup_api = "free",
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "memcpy",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "dest", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
             {.name = "src", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
             {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
        .description = "copy bytes between buffers",
        .security_notes = {"buffer overflow risk", "overlapping buffers undefined", "use memcpy_s instead"},
        .related_apis = {"memmove", "memset", "memcpy_s"},
        .headers = {"string.h"}
    },

    api_info{
        .name = "memset",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MEMORY_MANAGEMENT,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "dest", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
             {.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
             {.name = "count", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "dest", .param_type = param_info::type::POINTER},
        .description = "set bytes in buffer to specified value",
        .headers = {"string.h"}
    },

    // i/o and formatting functions
    api_info{
        .name = "_stdio_common_vfprintf_s",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "options", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
             {.name = "stream", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "format", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "locale", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "arglist",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "secure formatted output to stream with locale",
        .related_apis = {"printf", "fprintf", "sprintf"},
        .headers = {"stdio.h"}
    },

    api_info{
        .name = "printf",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {
                {.name = "format", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
                // note: variadic parameters not fully supported yet
            },
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "formatted output to stdout",
        .related_apis = {"fprintf", "sprintf", "_stdio_common_vfprintf_s"},
        .headers = {"stdio.h"}
    },

    api_info{
        .name = "fprintf",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STDIO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FILE_IO),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "stream", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
             {.name = "format", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "chars_written", .param_type = param_info::type::INTEGER},
        .description = "formatted output to stream",
        .related_apis = {"printf", "sprintf", "_stdio_common_vfprintf_s"},
        .headers = {"stdio.h"}
    },

    // character classification and conversion
    api_info{
        .name = "towlower",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "lowercase", .param_type = param_info::type::INTEGER},
        .description = "convert wide character to lowercase",
        .related_apis = {"towupper", "tolower"},
        .headers = {"wctype.h"}
    },

    api_info{
        .name = "towupper",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "uppercase", .param_type = param_info::type::INTEGER},
        .description = "convert wide character to uppercase",
        .related_apis = {"towlower", "toupper"},
        .headers = {"wctype.h"}
    },

    api_info{
        .name = "isalpha",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
        .description = "check if character is alphabetic",
        .related_apis = {"isdigit", "isalnum", "isspace"},
        .headers = {"ctype.h"}
    },

    api_info{
        .name = "isdigit",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::STRING_MANIPULATION,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "c", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::BOOLEAN},
        .description = "check if character is decimal digit",
        .related_apis = {"isalpha", "isalnum", "isxdigit"},
        .headers = {"ctype.h"}
    },

    // mathematical functions
    api_info{
        .name = "fdexp",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MISC, // we need to add MATH category
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN},
             {.name = "exp", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
        .description = "multiply floating-point number by power of 2",
        .related_apis = {"ldexp", "frexp", "modf"},
        .headers = {"math.h"}
    },

    api_info{
        .name = "sin",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MISC, // MATH category needed
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
        .description = "calculate sine of angle in radians",
        .related_apis = {"cos", "tan", "asin"},
        .headers = {"math.h"}
    },

    api_info{
        .name = "cos",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MISC,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
        .description = "calculate cosine of angle in radians",
        .related_apis = {"sin", "tan", "acos"},
        .headers = {"math.h"}
    },

    api_info{
        .name = "sqrt",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::MISC,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "x", .param_type = param_info::type::DOUBLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::DOUBLE},
        .description = "calculate square root",
        .related_apis = {"pow", "cbrt"},
        .headers = {"math.h"}
    },

    // program lifecycle functions
    api_info{
        .name = "register_onexit_function",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::PROCESS_CONTROL, // could be RUNTIME_CONTROL
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "table",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT},
             {.name = "function",
              .param_type = param_info::type::CALLBACK,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "register function to be called at program termination",
        .related_apis = {"atexit", "_onexit", "exit"},
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "atexit",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "function",
              .param_type = param_info::type::CALLBACK,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "register function to be called at normal program termination",
        .related_apis = {"_onexit", "register_onexit_function", "exit"},
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "exit",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "status", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "terminate program normally with cleanup",
        .related_apis = {"abort", "_exit", "atexit"},
        .headers = {"stdlib.h"}
    },

    api_info{
        .name = "abort",
        .module = "ucrtbase.dll",
        .api_category = api_info::category::PROCESS_CONTROL,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "terminate program abnormally without cleanup",
        .related_apis = {"exit", "_exit", "terminate"},
        .headers = {"stdlib.h"}
    }
};

#undef WINDOWS_API_CONVENTION

} // namespace w1::abi::apis::windows