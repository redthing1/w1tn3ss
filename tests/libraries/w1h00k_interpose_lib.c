#if defined(_WIN32)
#include <windows.h>

#define W1H00K_EXPORT __declspec(dllexport)

W1H00K_EXPORT HMODULE w1h00k_interpose_get_module_handle(void) {
  return GetModuleHandleA(NULL);
}
#else
#include <unistd.h>

#define W1H00K_EXPORT __attribute__((visibility("default")))

W1H00K_EXPORT pid_t w1h00k_interpose_getpid(void) {
  return getpid();
}
#endif
