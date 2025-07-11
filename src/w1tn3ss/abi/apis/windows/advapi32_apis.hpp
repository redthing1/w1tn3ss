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
 * @brief advapi32.dll api definitions
 *
 * covers windows security and administration apis:
 * - token and privilege manipulation
 * - access control and security descriptors
 * - service control and management
 * - registry security and operations
 * - cryptographic providers
 * - event logging and auditing
 * - local security authority (lsa) functions
 */

static const std::vector<api_info> windows_advapi32_apis = {
    // === TOKEN AND PRIVILEGE MANIPULATION ===

    api_info{
        .name = "OpenProcessToken",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ProcessHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "TokenHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "open access token associated with process",
        .security_notes = {"privilege escalation vector", "token manipulation capability"},
        .related_apis = {"OpenThreadToken", "AdjustTokenPrivileges", "GetTokenInformation"},
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "processthreadsapi.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "OpenThreadToken",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "ThreadHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "DesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "OpenAsSelf",
              .param_type = param_info::type::BOOLEAN,
              .param_direction = param_info::direction::IN},
             {.name = "TokenHandle",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "open access token associated with thread",
        .related_apis = {"OpenProcessToken", "SetThreadToken", "ImpersonateLoggedOnUser"},
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "processthreadsapi.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "AdjustTokenPrivileges",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "TokenHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "DisableAllPrivileges",
              .param_type = param_info::type::BOOLEAN,
              .param_direction = param_info::direction::IN},
             {.name = "NewState",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "BufferLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "PreviousState",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "ReturnLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "enable or disable privileges in access token",
        .security_notes = {"privilege escalation mechanism", "requires se_privilege to adjust"},
        .related_apis = {"LookupPrivilegeValue", "GetTokenInformation", "OpenProcessToken"},
        .headers = {"windows.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "LookupPrivilegeValueW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "lpSystemName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "lpLuid",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve luid for privilege name",
        .related_apis = {"AdjustTokenPrivileges", "LookupPrivilegeName"},
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "GetTokenInformation",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "TokenHandle",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "TokenInformationClass",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "TokenInformation",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "TokenInformationLength",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "ReturnLength",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve information about access token",
        .related_apis = {"OpenProcessToken", "SetTokenInformation"},
        .headers = {"windows.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "DuplicateTokenEx",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hExistingToken",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "dwDesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "lpTokenAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "ImpersonationLevel",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "TokenType",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "phNewToken",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "create new access token that duplicates existing token",
        .security_notes = {"token duplication for impersonation", "privilege escalation vector"},
        .related_apis = {"OpenProcessToken", "ImpersonateLoggedOnUser"},
        .cleanup_api = "CloseHandle",
        .headers = {"windows.h", "securitybaseapi.h"}
    },

    // === IMPERSONATION ===

    api_info{
        .name = "ImpersonateLoggedOnUser",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hToken", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "impersonate security context of logged-on user",
        .security_notes = {"impersonation capability", "privilege escalation vector"},
        .related_apis = {"RevertToSelf", "DuplicateTokenEx", "LogonUser"},
        .headers = {"windows.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "RevertToSelf",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters = {},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "terminate impersonation of client",
        .related_apis = {"ImpersonateLoggedOnUser", "ImpersonateNamedPipeClient"},
        .headers = {"windows.h", "securitybaseapi.h"}
    },

    api_info{
        .name = "ImpersonateNamedPipeClient",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hNamedPipe",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "impersonate security context of named pipe client",
        .security_notes = {"named pipe impersonation", "privilege escalation via ipc"},
        .related_apis = {"RevertToSelf", "CreateNamedPipeW", "ConnectNamedPipe"},
        .headers = {"windows.h", "namedpipeapi.h"}
    },

    // === SERVICE CONTROL ===

    api_info{
        .name = "OpenSCManagerW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "lpMachineName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpDatabaseName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "dwDesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "scHandle", .param_type = param_info::type::HANDLE},
        .description = "establish connection to service control manager",
        .security_notes = {"service manipulation capability", "persistence mechanism"},
        .related_apis = {"CreateServiceW", "OpenServiceW", "CloseServiceHandle"},
        .cleanup_api = "CloseServiceHandle",
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "CreateServiceW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hSCManager",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "lpServiceName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpDisplayName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "dwDesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "dwServiceType",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "dwStartType",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "dwErrorControl",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "lpBinaryPathName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpLoadOrderGroup",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpdwTagId",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "lpDependencies",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpServiceStartName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpPassword",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "serviceHandle", .param_type = param_info::type::HANDLE},
        .description = "create service object and add to scm database",
        .security_notes = {"service creation for persistence", "requires administrative privileges"},
        .related_apis = {"OpenSCManagerW", "StartServiceW", "DeleteService"},
        .cleanup_api = "CloseServiceHandle",
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "OpenServiceW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hSCManager",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "lpServiceName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "dwDesiredAccess",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "serviceHandle", .param_type = param_info::type::HANDLE},
        .description = "open existing service for specified access",
        .related_apis = {"OpenSCManagerW", "QueryServiceStatus", "ControlService"},
        .cleanup_api = "CloseServiceHandle",
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "StartServiceW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hService", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "dwNumServiceArgs",
              .param_type = param_info::type::COUNT,
              .param_direction = param_info::direction::IN},
             {.name = "lpServiceArgVectors",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "start service",
        .security_notes = {"service execution capability", "potential privilege escalation"},
        .related_apis = {"OpenServiceW", "ControlService", "CreateServiceW"},
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "ControlService",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hService", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "dwControl", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
             {.name = "lpServiceStatus",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "send control code to service",
        .security_notes = {"service control capability", "can stop/pause/continue services"},
        .related_apis = {"StartServiceW", "QueryServiceStatus", "OpenServiceW"},
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "DeleteService",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hService",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "mark service for deletion",
        .security_notes = {"service deletion capability", "anti-forensics technique"},
        .related_apis = {"CreateServiceW", "OpenServiceW"},
        .headers = {"windows.h", "winsvc.h"}
    },

    api_info{
        .name = "CloseServiceHandle",
        .module = "advapi32.dll",
        .api_category = api_info::category::SECURITY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hSCObject",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "close handle to service control manager or service",
        .related_apis = {"OpenSCManagerW", "OpenServiceW", "CreateServiceW"},
        .headers = {"windows.h", "winsvc.h"}
    },

    // === REGISTRY OPERATIONS ===

    api_info{
        .name = "RegOpenKeyExW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpSubKey", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "ulOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
             {.name = "samDesired",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "phkResult",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "open specified registry key",
        .security_notes = {"registry access for persistence", "configuration modification"},
        .related_apis = {"RegCreateKeyExW", "RegSetValueExW", "RegQueryValueExW"},
        .cleanup_api = "RegCloseKey",
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegCreateKeyExW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpSubKey", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "Reserved",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "lpClass", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
             {.name = "dwOptions", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
             {.name = "samDesired",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "lpSecurityAttributes",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "phkResult",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "lpdwDisposition",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "create registry key or open existing one",
        .security_notes = {"registry key creation for persistence", "system configuration modification"},
        .related_apis = {"RegOpenKeyExW", "RegSetValueExW", "RegDeleteKeyW"},
        .cleanup_api = "RegCloseKey",
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegSetValueExW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpValueName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "Reserved",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "dwType", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
             {.name = "lpData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
             {.name = "cbData", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "set data for specified registry value",
        .security_notes = {"registry modification for persistence", "configuration tampering"},
        .related_apis = {"RegQueryValueExW", "RegDeleteValueW", "RegCreateKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegQueryValueExW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpValueName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpReserved",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN},
             {.name = "lpType", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
             {.name = "lpData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
             {.name = "lpcbData",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::IN_OUT}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "retrieve data for specified registry value",
        .related_apis = {"RegSetValueExW", "RegEnumValueW", "RegOpenKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegDeleteValueW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpValueName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "delete named value from specified registry key",
        .security_notes = {"registry cleanup", "anti-forensics technique"},
        .related_apis = {"RegSetValueExW", "RegDeleteKeyW", "RegQueryValueExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegDeleteKeyW",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::REGISTRY_ACCESS) |
                 static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "lpSubKey",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "delete subkey and all its values",
        .security_notes = {"registry key deletion", "anti-forensics technique"},
        .related_apis = {"RegCreateKeyExW", "RegDeleteValueW", "RegDeleteTreeW"},
        .headers = {"windows.h", "winreg.h"}
    },

    api_info{
        .name = "RegCloseKey",
        .module = "advapi32.dll",
        .api_category = api_info::category::REGISTRY,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "close handle to specified registry key",
        .related_apis = {"RegOpenKeyExW", "RegCreateKeyExW"},
        .headers = {"windows.h", "winreg.h"}
    },

    // === CRYPTOGRAPHIC PROVIDERS ===

    api_info{
        .name = "CryptAcquireContextW",
        .module = "advapi32.dll",
        .api_category = api_info::category::CRYPTO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "phProv", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
             {.name = "szContainer",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "szProvider",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "dwProvType",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "acquire handle to cryptographic service provider",
        .related_apis = {"CryptGenRandom", "CryptCreateHash", "CryptReleaseContext"},
        .cleanup_api = "CryptReleaseContext",
        .headers = {"windows.h", "wincrypt.h"}
    },

    api_info{
        .name = "CryptGenRandom",
        .module = "advapi32.dll",
        .api_category = api_info::category::CRYPTO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProv", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "dwLen", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "pbBuffer",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "generate cryptographically random data",
        .related_apis = {"CryptAcquireContextW", "CryptCreateHash"},
        .headers = {"windows.h", "wincrypt.h"}
    },

    api_info{
        .name = "CryptCreateHash",
        .module = "advapi32.dll",
        .api_category = api_info::category::CRYPTO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hProv", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "Algid", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
             {.name = "hKey", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
             {.name = "phHash",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "create empty hash object",
        .related_apis = {"CryptHashData", "CryptGetHashParam", "CryptDestroyHash"},
        .cleanup_api = "CryptDestroyHash",
        .headers = {"windows.h", "wincrypt.h"}
    },

    api_info{
        .name = "CryptHashData",
        .module = "advapi32.dll",
        .api_category = api_info::category::CRYPTO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hHash", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
             {.name = "pbData", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
             {.name = "dwDataLen", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
             {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "add data to specified hash object",
        .related_apis = {"CryptCreateHash", "CryptGetHashParam"},
        .headers = {"windows.h", "wincrypt.h"}
    },

    // === EVENT LOGGING ===

    api_info{
        .name = "OpenEventLogW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "lpUNCServerName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN},
             {.name = "lpSourceName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "eventLogHandle", .param_type = param_info::type::HANDLE},
        .description = "open handle to event log",
        .related_apis = {"ReadEventLogW", "WriteEventLogW", "CloseEventLog"},
        .cleanup_api = "CloseEventLog",
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "ReadEventLogW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hEventLog",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "dwReadFlags",
              .param_type = param_info::type::FLAGS,
              .param_direction = param_info::direction::IN},
             {.name = "dwRecordOffset",
              .param_type = param_info::type::INTEGER,
              .param_direction = param_info::direction::IN},
             {.name = "lpBuffer",
              .param_type = param_info::type::BUFFER,
              .param_direction = param_info::direction::OUT},
             {.name = "nNumberOfBytesToRead",
              .param_type = param_info::type::SIZE,
              .param_direction = param_info::direction::IN},
             {.name = "pnBytesRead",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT},
             {.name = "pnMinNumberOfBytesNeeded",
              .param_type = param_info::type::POINTER,
              .param_direction = param_info::direction::OUT}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "read entries from event log",
        .related_apis = {"OpenEventLogW", "GetOldestEventLogRecord"},
        .headers = {"windows.h", "winbase.h"}
    },

    api_info{
        .name = "ClearEventLogW",
        .module = "advapi32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE) |
                 static_cast<uint32_t>(api_info::behavior_flags::SECURITY_SENSITIVE),
        .convention = WINDOWS_API_CONVENTION,
        .parameters =
            {{.name = "hEventLog",
              .param_type = param_info::type::HANDLE,
              .param_direction = param_info::direction::IN},
             {.name = "lpBackupFileName",
              .param_type = param_info::type::STRING,
              .param_direction = param_info::direction::IN}},
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "clear event log",
        .security_notes = {"log clearing for anti-forensics", "evidence destruction"},
        .related_apis = {"OpenEventLogW", "ReadEventLogW"},
        .headers = {"windows.h", "winbase.h"}
    }
};

#undef WINDOWS_API_CONVENTION

} // namespace w1::abi::apis::windows