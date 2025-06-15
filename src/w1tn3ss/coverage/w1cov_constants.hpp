/**
 * @file w1cov_constants.hpp
 * @brief Centralized constants for w1cov coverage collection
 *
 * This header consolidates all hardcoded values used throughout the w1cov
 * coverage system to improve maintainability and consistency.
 */

#pragma once

#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace w1::cov {

// =============================================================================
// Environment Variables
// =============================================================================

/// Enable/disable coverage collection
constexpr const char* ENV_W1COV_ENABLED = "W1COV_ENABLED";

/// Coverage data output file path
constexpr const char* ENV_W1COV_OUTPUT_FILE = "W1COV_OUTPUT_FILE";

/// Enable verbose debug output
constexpr const char* ENV_W1COV_DEBUG = "W1COV_DEBUG";

/// Exclude system libraries from instrumentation
constexpr const char* ENV_W1COV_EXCLUDE_SYSTEM = "W1COV_EXCLUDE_SYSTEM";

/// Store full module paths vs basenames only
constexpr const char* ENV_W1COV_TRACK_FULL_PATHS = "W1COV_TRACK_FULL_PATHS";

/// Output format: "drcov" or "text"
constexpr const char* ENV_W1COV_FORMAT = "W1COV_FORMAT";

/// Target module patterns (comma-separated)
constexpr const char* ENV_W1COV_TARGET_MODULES = "W1COV_TARGET_MODULES";

// =============================================================================
// Default Values
// =============================================================================

/// Default output filename
constexpr const char* DEFAULT_OUTPUT_FILENAME = "w1cov.drcov";

/// Default output format
constexpr const char* DEFAULT_OUTPUT_FORMAT = "drcov";

/// Default temporary module name for standalone coverage
constexpr const char* DEFAULT_TEMP_MODULE_NAME = "instrumented_code";

/// Value indicating "enabled" for environment variables
constexpr const char* ENABLED_VALUE = "1";

// =============================================================================
// Performance and Memory Constants
// =============================================================================

/// Default QBDI virtual stack size (1MB)
constexpr size_t DEFAULT_STACK_SIZE = 0x100000;

/// Page alignment mask for memory operations
constexpr size_t PAGE_ALIGNMENT_MASK = 0xFFF;

/// Fake return address for QBDI run() operations
constexpr uint64_t FAKE_RETURN_ADDRESS = 0x40000;

/// Default instruction size assumption (ARM64/x86_64)
constexpr uint16_t DEFAULT_INSTRUCTION_SIZE = 4;

/// Interval for progress reporting in basic block callbacks
constexpr uint64_t PROGRESS_REPORT_INTERVAL = 1000;

/// Interval for performance logging in instruction callbacks
constexpr uint64_t PERFORMANCE_LOG_INTERVAL = 10000;

// =============================================================================
// Logging and Output
// =============================================================================

/// Standard logging prefix for w1cov messages
constexpr const char* LOG_PREFIX = "[w1cov]";

/// Log level names for structured output
constexpr const char* LOG_LEVEL_ERROR = "error";
constexpr const char* LOG_LEVEL_WARN = "warn";
constexpr const char* LOG_LEVEL_INFO = "info";
constexpr const char* LOG_LEVEL_DEBUG = "debug";
constexpr const char* LOG_LEVEL_TRACE = "trace";

// =============================================================================
// DrCov Export Constants
// =============================================================================

/// DrCov file format version
constexpr uint32_t DRCOV_VERSION = 2;

/// DrCov flavor for standard coverage
constexpr const char* DRCOV_FLAVOR_STANDARD = "drcov";

/// DrCov flavor for coverage with hitcounts
constexpr const char* DRCOV_FLAVOR_HITS = "drcov-hits";

/// DrCov module table version
constexpr uint32_t DRCOV_MODULE_VERSION = 2;

// =============================================================================
// System Library Detection Patterns
// =============================================================================

/// Number of system library patterns per platform
constexpr size_t MAX_SYSTEM_PATTERNS = 10;

/// macOS system library path patterns
constexpr const char* MACOS_SYSTEM_PATTERNS[] = {
    "/System/Library/", "/usr/lib/system/", "/usr/lib/libc++", "/usr/lib/libSystem", "libsystem_",
    "libc++",           "libdyld",          "/System/",        "/usr/lib/",          "/usr/local/lib/"
};

/// Linux system library path patterns
constexpr const char* LINUX_SYSTEM_PATTERNS[] = {
    "/lib/x86_64-linux-gnu/",
    "/lib64/",
    "/usr/lib/x86_64-linux-gnu/",
    "ld-linux",
    "libc.so",
    "libpthread.so",
    "libm.so",
    "libdl.so",
    "/lib/",
    "/usr/lib/"
};

/// Windows system library path patterns
constexpr const char* WINDOWS_SYSTEM_PATTERNS[] = {
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "msvcrt.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "ole32.dll"
};

// =============================================================================
// Utility Functions
// =============================================================================

/// Simple logging function for w1cov
inline void log(const char* format, ...) {
  printf("[w1cov] ");
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
  printf("\n");
}

} // namespace w1::cov