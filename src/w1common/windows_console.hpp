#pragma once

#if defined(_WIN32) || defined(WIN32)

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <cstdio>

namespace w1::common {

/**
 * @brief allocate and configure a windows console for gui applications
 *
 * this function:
 * - allocates a new console window
 * - redirects stdout/stderr to the console
 * - enables ansi escape code support for colors
 * - sets streams to unbuffered for immediate output
 *
 * @return true if console was successfully allocated and configured
 */
inline bool allocate_windows_console() {
  if (!AllocConsole()) {
    return false;
  }

  // redirect stdout and stderr to console
  FILE* pCout;
  FILE* pCerr;
  freopen_s(&pCout, "CONOUT$", "w", stdout);
  freopen_s(&pCerr, "CONOUT$", "w", stderr);

  // ensure streams are unbuffered for immediate output
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // enable ansi escape codes for color output
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);

  if (hOut != INVALID_HANDLE_VALUE) {
    DWORD dwMode = 0;
    if (GetConsoleMode(hOut, &dwMode)) {
      dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      SetConsoleMode(hOut, dwMode);
    }
  }

  if (hErr != INVALID_HANDLE_VALUE) {
    DWORD dwMode = 0;
    if (GetConsoleMode(hErr, &dwMode)) {
      dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
      SetConsoleMode(hErr, dwMode);
    }
  }

  return true;
}

} // namespace w1::common

#endif // _WIN32 || WIN32