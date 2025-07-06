#pragma once

/**
 * @brief Clean Windows headers without macro pollution
 * 
 * This header provides access to Windows APIs while preventing
 * the numerous macro definitions that pollute the global namespace
 * and conflict with modern C++ code.
 * 
 * Usage: Include this instead of <windows.h> directly.
 */

#ifdef _WIN32

// Prevent Windows from defining min/max macros and other pollution
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// Prevent common macro conflicts
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

// Include Windows headers
#include <windows.h>

// Additional Windows headers that might be needed
#ifdef NEED_PSAPI
#include <psapi.h>
#endif

#ifdef NEED_TLHELP32
#include <tlhelp32.h>
#endif

// Undefine the most problematic macros that conflict with modern C++
#ifdef IN
#undef IN
#endif

#ifdef OUT
#undef OUT
#endif

#ifdef VOID
#undef VOID
#endif

#ifdef ERROR
#undef ERROR
#endif

#ifdef DELETE
#undef DELETE
#endif

#ifdef OPTIONAL
#undef OPTIONAL
#endif

#ifdef CONST
#undef CONST
#endif

#ifdef CALLBACK
#undef CALLBACK
#endif

#ifdef STRICT
#undef STRICT
#endif

// Common function name conflicts
#ifdef CreateWindow
#undef CreateWindow
#endif

#ifdef CreateFile
#undef CreateFile
#endif

#ifdef LoadLibrary
#undef LoadLibrary
#endif

#ifdef GetMessage
#undef GetMessage
#endif

#ifdef SendMessage
#undef SendMessage
#endif

#ifdef MessageBox
#undef MessageBox
#endif

#ifdef CreateProcess
#undef CreateProcess
#endif

#ifdef CreateMutex
#undef CreateMutex
#endif

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

// If specific Windows types or functions are needed, they should be
// explicitly declared here with proper C++ naming conventions

#endif // _WIN32