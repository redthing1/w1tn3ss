#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

/**
 * @brief ws2_32.dll api definitions
 *
 * covers windows socket api 2.0 functions:
 * - socket creation and management
 * - network connection establishment
 * - data transmission and reception
 * - address resolution and dns
 * - async socket operations
 * - socket options and configuration
 * - raw socket support
 */

static const std::vector<api_info> windows_ws2_32_apis = {
    // === SOCKET INITIALIZATION ===
    
    api_info{
        .name = "WSAStartup",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {
            {.name = "wVersionRequested", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpWSAData", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "initialize winsock dll usage",
        .cleanup_api = "WSACleanup",
        .related_apis = {"WSACleanup", "socket", "WSAGetLastError"},
        .headers = {"winsock2.h", "ws2tcpip.h"}
    },

    api_info{
        .name = "WSACleanup",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::MODIFIES_GLOBAL_STATE),
        .parameters = {},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "terminate use of winsock dll",
        .related_apis = {"WSAStartup"},
        .headers = {"winsock2.h"}
    },

    // === SOCKET CREATION AND MANAGEMENT ===

    api_info{
        .name = "socket",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "af", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "type", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "protocol", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "socketHandle", .param_type = param_info::type::HANDLE},
        .description = "create socket for network communication",
        .cleanup_api = "closesocket",
        .security_notes = {"network communication capability", "c2 communication vector"},
        .related_apis = {"bind", "connect", "listen", "closesocket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "WSASocket",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "af", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "type", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "protocol", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "lpProtocolInfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "g", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "socketHandle", .param_type = param_info::type::HANDLE},
        .description = "create socket with extended attributes",
        .cleanup_api = "closesocket",
        .security_notes = {"raw socket capability", "advanced network operations"},
        .related_apis = {"socket", "WSADuplicateSocket", "closesocket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "closesocket",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "close existing socket",
        .related_apis = {"socket", "shutdown"},
        .headers = {"winsock2.h"}
    },

    // === CONNECTION ESTABLISHMENT ===

    api_info{
        .name = "bind",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "name", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "namelen", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "associate local address with socket",
        .related_apis = {"socket", "listen", "accept"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "connect",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "name", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "namelen", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "establish connection to remote socket",
        .security_notes = {"outbound connection capability", "c2 server communication"},
        .related_apis = {"socket", "send", "recv", "WSAConnect"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "listen",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "backlog", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "place socket in listening state",
        .security_notes = {"server socket capability", "backdoor listener"},
        .related_apis = {"bind", "accept", "socket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "accept",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE) |
                 static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "addr", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "addrlen", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "clientSocket", .param_type = param_info::type::HANDLE},
        .description = "accept incoming connection request",
        .cleanup_api = "closesocket",
        .security_notes = {"accept inbound connections", "backdoor communication"},
        .related_apis = {"listen", "send", "recv", "WSAAccept"},
        .headers = {"winsock2.h"}
    },

    // === DATA TRANSMISSION ===

    api_info{
        .name = "send",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytesSent", .param_type = param_info::type::INTEGER},
        .description = "send data on connected socket",
        .security_notes = {"data exfiltration capability", "c2 communication"},
        .related_apis = {"recv", "sendto", "WSASend"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "recv",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytesReceived", .param_type = param_info::type::INTEGER},
        .description = "receive data from connected socket",
        .security_notes = {"command reception capability", "c2 communication"},
        .related_apis = {"send", "recvfrom", "WSARecv"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "sendto",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "to", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "tolen", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "bytesSent", .param_type = param_info::type::INTEGER},
        .description = "send data to specific destination",
        .security_notes = {"udp communication", "broadcasting capability"},
        .related_apis = {"recvfrom", "send", "socket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "recvfrom",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "buf", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "len", .param_type = param_info::type::SIZE, .param_direction = param_info::direction::IN},
            {.name = "flags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "from", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "fromlen", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "bytesReceived", .param_type = param_info::type::INTEGER},
        .description = "receive data and source address",
        .related_apis = {"sendto", "recv", "socket"},
        .headers = {"winsock2.h"}
    },

    // === ASYNC OPERATIONS ===

    api_info{
        .name = "WSASend",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffers", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "dwBufferCount", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesSent", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "dwFlags", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpCompletionRoutine", .param_type = param_info::type::CALLBACK, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "send data with scatter-gather and overlapped i/o",
        .related_apis = {"WSARecv", "send", "WSASendTo"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "WSARecv",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::ASYNC),
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpBuffers", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "dwBufferCount", .param_type = param_info::type::COUNT, .param_direction = param_info::direction::IN},
            {.name = "lpNumberOfBytesRecvd", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "lpFlags", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpOverlapped", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "lpCompletionRoutine", .param_type = param_info::type::CALLBACK, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "receive data with scatter-gather and overlapped i/o",
        .related_apis = {"WSASend", "recv", "WSARecvFrom"},
        .headers = {"winsock2.h"}
    },

    // === ADDRESS RESOLUTION ===

    api_info{
        .name = "getaddrinfo",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_DNS,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "pNodeName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "pServiceName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "pHints", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "ppResult", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "resolve hostname to network addresses",
        .cleanup_api = "freeaddrinfo",
        .security_notes = {"dns resolution capability", "c2 domain resolution"},
        .related_apis = {"freeaddrinfo", "getnameinfo", "gethostbyname"},
        .headers = {"winsock2.h", "ws2tcpip.h"}
    },

    api_info{
        .name = "freeaddrinfo",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_DNS,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::FREES_MEMORY),
        .parameters = {
            {.name = "pAddrInfo", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "free address information structure",
        .related_apis = {"getaddrinfo", "getnameinfo"},
        .headers = {"winsock2.h", "ws2tcpip.h"}
    },

    api_info{
        .name = "gethostbyname",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_DNS,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::NETWORK_IO) |
                 static_cast<uint32_t>(api_info::behavior_flags::BLOCKING) |
                 static_cast<uint32_t>(api_info::behavior_flags::DEPRECATED),
        .parameters = {
            {.name = "name", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "hostent", .param_type = param_info::type::POINTER},
        .description = "resolve hostname to ip address (deprecated)",
        .security_notes = {"legacy dns resolution", "c2 domain resolution"},
        .related_apis = {"getaddrinfo", "gethostbyaddr", "inet_addr"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "gethostname",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_DNS,
        .flags = 0,
        .parameters = {
            {.name = "name", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "namelen", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "retrieve local hostname",
        .related_apis = {"getaddrinfo", "gethostbyname"},
        .headers = {"winsock2.h"}
    },

    // === SOCKET OPTIONS ===

    api_info{
        .name = "setsockopt",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = 0,
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "level", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "optname", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "optval", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::IN},
            {.name = "optlen", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "set socket option",
        .related_apis = {"getsockopt", "socket", "ioctlsocket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "getsockopt",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = 0,
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "level", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "optname", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "optval", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "optlen", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "retrieve socket option",
        .related_apis = {"setsockopt", "socket"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "ioctlsocket",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = 0,
        .parameters = {
            {.name = "s", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "cmd", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "argp", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT}
        },
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "control i/o mode of socket",
        .related_apis = {"setsockopt", "select", "WSAEventSelect"},
        .headers = {"winsock2.h"}
    },

    // === SOCKET SELECTION ===

    api_info{
        .name = "select",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "nfds", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "readfds", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "writefds", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "exceptfds", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN_OUT},
            {.name = "timeout", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "readySockets", .param_type = param_info::type::INTEGER},
        .description = "determine status of one or more sockets",
        .related_apis = {"WSAEventSelect", "WSAWaitForMultipleEvents", "ioctlsocket"},
        .headers = {"winsock2.h"}
    },

    // === ERROR HANDLING ===

    api_info{
        .name = "WSAGetLastError",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "error", .param_type = param_info::type::ERROR_CODE},
        .description = "retrieve error code for last winsock operation",
        .related_apis = {"WSASetLastError", "GetLastError"},
        .headers = {"winsock2.h"}
    },

    api_info{
        .name = "WSASetLastError",
        .module = "ws2_32.dll",
        .api_category = api_info::category::NETWORK_SOCKET,
        .flags = 0,
        .parameters = {
            {.name = "iError", .param_type = param_info::type::ERROR_CODE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "void", .param_type = param_info::type::VOID},
        .description = "set error code for winsock operations",
        .related_apis = {"WSAGetLastError", "SetLastError"},
        .headers = {"winsock2.h"}
    }
};

} // namespace w1::abi::apis::windows