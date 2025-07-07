#pragma once

#include <cstring>

#ifdef _WIN32
#include "../../common/windows_clean.hpp"
#else
#include <unistd.h>
#endif

namespace w1::util {

/**
 * @brief Platform-agnostic function to write to stderr
 *
 * This function is signal-safe and can be used in signal handlers
 * or exception catch blocks where regular I/O might not be safe.
 *
 * @param message The message to write to stderr
 */
inline void stderr_write(const char* message) {
  if (!message) {
    return;
  }

#ifdef _WIN32
  HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);
  if (hStderr != INVALID_HANDLE_VALUE) {
    DWORD written;
    WriteFile(hStderr, message, static_cast<DWORD>(strlen(message)), &written, NULL);
  }
#else
  write(STDERR_FILENO, message, strlen(message));
#endif
}

/**
 * @brief Platform-agnostic function to write to stderr with size
 *
 * @param message The message to write to stderr
 * @param size The size of the message
 */
inline void stderr_write(const char* message, size_t size) {
  if (!message || size == 0) {
    return;
  }

#ifdef _WIN32
  HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);
  if (hStderr != INVALID_HANDLE_VALUE) {
    DWORD written;
    WriteFile(hStderr, message, static_cast<DWORD>(size), &written, NULL);
  }
#else
  write(STDERR_FILENO, message, size);
#endif
}

} // namespace w1::util