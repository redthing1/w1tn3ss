#pragma once

#include "../../api_knowledge_db.hpp"
#include <vector>

namespace w1::abi::apis::windows {

/**
 * @brief user32.dll api definitions
 *
 * covers windows ui and windowing apis:
 * - window creation and management
 * - message handling and processing
 * - input handling (keyboard, mouse)
 * - drawing and painting
 * - dialog and menu management
 * - system metrics and configuration
 */

static const std::vector<api_info> windows_user32_apis = {
    // window creation and management
    api_info{
        .name = "CreateWindowExW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "dwExStyle", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "lpClassName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpWindowName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "dwStyle", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN},
            {.name = "X", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "Y", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "nWidth", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "nHeight", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "hWndParent", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hMenu", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hInstance", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lpParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "hwnd", .param_type = param_info::type::HANDLE},
        .description = "create window with extended styles",
        .cleanup_api = "DestroyWindow",
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "DestroyWindow",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "destroy specified window",
        .related_apis = {"CreateWindowExW", "CloseWindow"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "FindWindowW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "lpClassName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpWindowName", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "hwnd", .param_type = param_info::type::HANDLE},
        .description = "find window by class name and/or window name",
        .related_apis = {"FindWindowExW", "EnumWindows"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "ShowWindow",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "nCmdShow", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "was_visible", .param_type = param_info::type::BOOLEAN},
        .description = "set window show state",
        .related_apis = {"SetWindowPos", "IsWindowVisible"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "GetWindowTextW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpString", .param_type = param_info::type::BUFFER, .param_direction = param_info::direction::OUT},
            {.name = "nMaxCount", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "length", .param_type = param_info::type::INTEGER},
        .description = "copy window title to buffer",
        .related_apis = {"SetWindowTextW", "GetWindowTextLengthW"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "SetWindowTextW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpString", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "change window title",
        .related_apis = {"GetWindowTextW", "GetWindowTextLengthW"},
        .headers = {"windows.h", "winuser.h"}
    },

    // message handling
    api_info{
        .name = "GetMessageW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "lpMsg", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "wMsgFilterMin", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "wMsgFilterMax", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "retrieve message from calling thread's message queue",
        .related_apis = {"PeekMessage", "PostMessage", "DispatchMessage"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "PeekMessageW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "lpMsg", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT},
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "wMsgFilterMin", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "wMsgFilterMax", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "wRemoveMsg", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "message_available", .param_type = param_info::type::BOOLEAN},
        .description = "check for message without blocking",
        .related_apis = {"GetMessage", "PostMessage", "DispatchMessage"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "DispatchMessageW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "lpMsg", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "dispatch message to window procedure",
        .related_apis = {"GetMessage", "PeekMessage", "TranslateMessage"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "SendMessageW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "Msg", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "wParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "send message to window (synchronous)",
        .related_apis = {"PostMessage", "SendMessageTimeout"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "PostMessageW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "Msg", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "wParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN},
            {.name = "lParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "post message to window (asynchronous)",
        .related_apis = {"SendMessage", "PostThreadMessage"},
        .headers = {"windows.h", "winuser.h"}
    },

    // message boxes and dialogs
    api_info{
        .name = "MessageBoxW",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::BLOCKING),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "lpText", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "lpCaption", .param_type = param_info::type::STRING, .param_direction = param_info::direction::IN},
            {.name = "uType", .param_type = param_info::type::FLAGS, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "result", .param_type = param_info::type::INTEGER},
        .description = "display message box",
        .headers = {"windows.h", "winuser.h"}
    },

    // input handling
    api_info{
        .name = "GetKeyState",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "nVirtKey", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "state", .param_type = param_info::type::INTEGER},
        .description = "retrieve state of virtual key",
        .related_apis = {"GetAsyncKeyState", "GetKeyboardState"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "GetCursorPos",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "lpPoint", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::OUT}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "retrieve cursor position in screen coordinates",
        .related_apis = {"SetCursorPos", "ClientToScreen"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "SetCursorPos",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "X", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN},
            {.name = "Y", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "move cursor to specified screen coordinates",
        .related_apis = {"GetCursorPos", "ScreenToClient"},
        .headers = {"windows.h", "winuser.h"}
    },

    // drawing and device context
    api_info{
        .name = "GetDC",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::OPENS_HANDLE),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "hdc", .param_type = param_info::type::HANDLE},
        .description = "retrieve device context for window",
        .cleanup_api = "ReleaseDC",
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "ReleaseDC",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = static_cast<uint32_t>(api_info::behavior_flags::CLOSES_HANDLE),
        .parameters = {
            {.name = "hWnd", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN},
            {.name = "hDC", .param_type = param_info::type::HANDLE, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::INTEGER},
        .description = "release device context",
        .related_apis = {"GetDC", "GetWindowDC"},
        .headers = {"windows.h", "winuser.h"}
    },

    // system metrics and information
    api_info{
        .name = "GetSystemMetrics",
        .module = "user32.dll",
        .api_category = api_info::category::SYSTEM_INFO,
        .flags = 0,
        .parameters = {
            {.name = "nIndex", .param_type = param_info::type::INTEGER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "value", .param_type = param_info::type::INTEGER},
        .description = "retrieve system metrics and configuration",
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "GetDesktopWindow",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "hwnd", .param_type = param_info::type::HANDLE},
        .description = "retrieve handle to desktop window",
        .related_apis = {"GetForegroundWindow", "GetActiveWindow"},
        .headers = {"windows.h", "winuser.h"}
    },

    api_info{
        .name = "GetForegroundWindow",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {},
        .return_value = {.name = "hwnd", .param_type = param_info::type::HANDLE},
        .description = "retrieve handle to foreground window",
        .related_apis = {"SetForegroundWindow", "GetActiveWindow"},
        .headers = {"windows.h", "winuser.h"}
    },

    // window enumeration
    api_info{
        .name = "EnumWindows",
        .module = "user32.dll",
        .api_category = api_info::category::UI,
        .flags = 0,
        .parameters = {
            {.name = "lpEnumFunc", .param_type = param_info::type::CALLBACK, .param_direction = param_info::direction::IN},
            {.name = "lParam", .param_type = param_info::type::POINTER, .param_direction = param_info::direction::IN}
        },
        .return_value = {.name = "success", .param_type = param_info::type::BOOLEAN},
        .description = "enumerate all top-level windows",
        .related_apis = {"EnumChildWindows", "FindWindow"},
        .headers = {"windows.h", "winuser.h"}
    }
};

} // namespace w1::abi::apis::windows