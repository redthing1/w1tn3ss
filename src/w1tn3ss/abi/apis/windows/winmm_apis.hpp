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
 * @brief winmm.dll api definitions
 *
 * covers windows multimedia apis commonly used for anti-analysis:
 * - high-precision timing functions
 * - multimedia timer services
 * - audio system detection
 * - system capability detection
 */

static const std::vector<api_info> windows_winmm_apis = {
    // === TIMING FUNCTIONS FOR EVASION ===

    api_info{
        .name = "timeGetTime",
        .module = "winmm.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "milliseconds", .param_type = param_info::type::INTEGER},
        .description = "retrieve system time in milliseconds",
        .security_notes = {"high-resolution timing for sandbox detection", "alternative to gettickcount"},
        .related_apis = {"GetTickCount", "QueryPerformanceCounter", "timeBeginPeriod"},
        .headers = {"windows.h", "timeapi.h", "mmsystem.h"}
    },

    api_info{
        .name = "timeBeginPeriod",
        .module = "winmm.dll",
        .api_category = api_info::category::TIME,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "uPeriod",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "request minimum timer resolution",
        .security_notes = {"improve timing precision for evasion", "system-wide timer modification"},
        .related_apis = {"timeEndPeriod", "timeGetTime", "timeGetDevCaps"},
        .headers = {"windows.h", "timeapi.h", "mmsystem.h"}
    },

    api_info{
        .name = "timeEndPeriod",
        .module = "winmm.dll",
        .api_category = api_info::category::TIME,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "uPeriod",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "clear timer resolution request",
        .related_apis = {"timeBeginPeriod", "timeGetTime"},
        .headers = {"windows.h", "timeapi.h", "mmsystem.h"}
    },

    api_info{
        .name = "timeGetDevCaps",
        .module = "winmm.dll",
        .api_category = api_info::category::TIME,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ptc", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
             {.name = "cbtc", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "query timer device capabilities",
        .security_notes = {"timer hardware analysis", "system capability fingerprinting"},
        .related_apis = {"timeGetTime", "timeBeginPeriod"},
        .headers = {"windows.h", "timeapi.h", "mmsystem.h"}
    },

    // multimedia system detection for vm analysis
    api_info{
        .name = "waveOutGetNumDevs",
        .module = "winmm.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "deviceCount", .param_type = param_info::type::INTEGER},
        .description = "retrieve number of audio output devices",
        .security_notes = {"audio device enumeration for vm detection", "hardware fingerprinting"},
        .related_apis = {"waveInGetNumDevs", "waveOutGetDevCaps", "midiOutGetNumDevs"},
        .headers = {"windows.h", "mmsystem.h"}
    },

    api_info{
        .name = "waveInGetNumDevs",
        .module = "winmm.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "deviceCount", .param_type = param_info::type::INTEGER},
        .description = "retrieve number of audio input devices",
        .security_notes = {"microphone detection for vm analysis", "audio hardware enumeration"},
        .related_apis = {"waveOutGetNumDevs", "waveInGetDevCaps"},
        .headers = {"windows.h", "mmsystem.h"}
    },

    api_info{
        .name = "midiOutGetNumDevs",
        .module = "winmm.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "deviceCount", .param_type = param_info::type::INTEGER},
        .description = "retrieve number of midi output devices",
        .security_notes = {"midi device detection for vm analysis", "multimedia hardware fingerprinting"},
        .related_apis = {"midiInGetNumDevs", "midiOutGetDevCaps"},
        .headers = {"windows.h", "mmsystem.h"}
    },

    api_info{
        .name = "joyGetNumDevs",
        .module = "winmm.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "deviceCount", .param_type = param_info::type::INTEGER},
        .description = "retrieve number of joystick devices",
        .security_notes = {"gaming device detection for vm analysis", "peripheral enumeration"},
        .related_apis = {"joyGetDevCaps", "joyGetPos"},
        .headers = {"windows.h", "mmsystem.h"}
    }
};

#undef WINDOWS_API_CONVENTION

} // namespace w1::abi::apis::windows