#pragma once

/**
 * @brief clean windows headers for p1ll
 */

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN
#endif

#include <windows.h>

#ifdef NEED_PSAPI
#include <psapi.h>
#endif

// undefine problematic macros
#ifdef ERROR
#undef ERROR
#endif

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#endif // _WIN32