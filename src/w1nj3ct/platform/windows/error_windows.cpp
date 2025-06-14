#include "../../error.hpp"
#include <string>
#include <windows.h>

std::string translate_platform_error(DWORD error_code) {
  LPSTR messageBuffer = nullptr;
  size_t size = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error_code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &messageBuffer, 0, NULL
  );

  std::string message(messageBuffer, size);
  LocalFree(messageBuffer);
  return message;
}