#if defined(_WIN32)
#include <stdint.h>
#include <windows.h>

#define W1H00K_EXPORT __declspec(dllexport)

W1H00K_EXPORT HMODULE w1h00k_interpose_get_module_handle(void) { return GetModuleHandleA(NULL); }

// Keep a non-trivial prologue so inline hooks have enough bytes to patch.
static volatile uintptr_t g_inline_sink = 0;

__declspec(noinline) W1H00K_EXPORT HMODULE w1h00k_interpose_get_module_handle_inline(void) {
  HMODULE handle = GetModuleHandleA(NULL);
  volatile uintptr_t sink = (uintptr_t) handle;
  sink ^= 0x1234u;
  sink += 0x10u;
  g_inline_sink = sink;
  return handle;
}
#else
#include <stdint.h>
#include <unistd.h>

#define W1H00K_EXPORT __attribute__((visibility("default")))

W1H00K_EXPORT pid_t w1h00k_interpose_getpid(void) { return getpid(); }

// Keep a non-trivial prologue so inline hooks have enough bytes to patch.
static volatile uintptr_t g_inline_sink = 0;

__attribute__((noinline)) W1H00K_EXPORT pid_t w1h00k_interpose_getpid_inline(void) {
  pid_t pid = getpid();
  volatile uintptr_t sink = (uintptr_t) pid;
  sink ^= 0x1234u;
  sink += 0x10u;
  g_inline_sink = sink;
  return pid;
}
#endif
