#include "thread_hook_internal.hpp"

#if defined(_WIN32)

#include <redlog.hpp>

#include <errno.h>
#include <funchook.h>
#include <memory>
#include <process.h>

namespace threadtest::hooking {

namespace {

using create_thread_fn = HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using beginthreadex_start_fn = unsigned(__stdcall*)(void*);
using beginthreadex_fn = uintptr_t(__stdcall*)(void*, unsigned, beginthreadex_start_fn, void*, unsigned, unsigned*);

create_thread_fn g_real_create_thread = nullptr;
beginthreadex_fn g_real_beginthreadex = nullptr;
funchook_t* g_funchook = nullptr;

struct interceptor_context {
  thread_start_interceptor interceptor;
  thread_start_fn start_routine;
  void* arg;
};

thread_result_t execute_interceptor(interceptor_context* raw_ctx) {
  std::unique_ptr<interceptor_context> ctx(raw_ctx);
  if (!ctx) {
    return thread_result_t{};
  }

  if (!ctx->start_routine) {
    return thread_result_t{};
  }

  if (!ctx->interceptor) {
    return ctx->start_routine(ctx->arg);
  }

  return ctx->interceptor(ctx->start_routine, ctx->arg);
}

DWORD WINAPI create_thread_trampoline(LPVOID raw_ctx) {
  return static_cast<DWORD>(execute_interceptor(static_cast<interceptor_context*>(raw_ctx)));
}

unsigned __stdcall beginthreadex_trampoline(void* raw_ctx) {
  return static_cast<unsigned>(execute_interceptor(static_cast<interceptor_context*>(raw_ctx)));
}

HANDLE WINAPI create_thread_hook(
    LPSECURITY_ATTRIBUTES security, SIZE_T stack_size, LPTHREAD_START_ROUTINE start_routine, LPVOID param, DWORD flags,
    LPDWORD thread_id
) {
  auto log = redlog::get_logger("threadtest.interpose");

  if (!g_real_create_thread) {
    log.err("CreateThread hook invoked without original pointer");
    ::SetLastError(ERROR_INVALID_FUNCTION);
    return nullptr;
  }

  if (!g_interceptor || !start_routine) {
    return g_real_create_thread(security, stack_size, start_routine, param, flags, thread_id);
  }

  auto* ctx = new interceptor_context{g_interceptor, start_routine, param};
  HANDLE handle = g_real_create_thread(security, stack_size, create_thread_trampoline, ctx, flags, thread_id);
  if (!handle) {
    DWORD error = ::GetLastError();
    log.err("CreateThread failed", redlog::field("error", error));
    delete ctx;
  } else {
    uint64_t handle_value = reinterpret_cast<uint64_t>(handle);
    log.dbg(
        "CreateThread intercepted", redlog::field("handle", handle_value),
        redlog::field("flags", static_cast<uint64_t>(flags)),
        redlog::field("thread_id", thread_id ? static_cast<uint64_t>(*thread_id) : 0ULL)
    );
  }
  return handle;
}

uintptr_t __stdcall beginthreadex_hook(
    void* security, unsigned stack_size, beginthreadex_start_fn start_routine, void* arglist, unsigned initflag,
    unsigned* thrdaddr
) {
  auto log = redlog::get_logger("threadtest.interpose");

  if (!g_real_beginthreadex || !start_routine) {
    return g_real_beginthreadex ? g_real_beginthreadex(security, stack_size, start_routine, arglist, initflag, thrdaddr) : 0;
  }

  if (!g_interceptor) {
    return g_real_beginthreadex(security, stack_size, start_routine, arglist, initflag, thrdaddr);
  }

  auto* ctx = new interceptor_context{g_interceptor, reinterpret_cast<thread_start_fn>(start_routine), arglist};
  uintptr_t handle = g_real_beginthreadex(security, stack_size, beginthreadex_trampoline, ctx, initflag, thrdaddr);
  if (handle == 0) {
    int error = errno;
    log.err("_beginthreadex failed", redlog::field("errno", error));
    delete ctx;
  } else {
    log.dbg(
        "_beginthreadex intercepted", redlog::field("handle", static_cast<uint64_t>(handle)),
        redlog::field("flags", static_cast<uint64_t>(initflag)),
        redlog::field("thread_id", thrdaddr ? static_cast<uint64_t>(*thrdaddr) : 0ULL)
    );
  }
  return handle;
}

beginthreadex_fn resolve_beginthreadex() {
  static const wchar_t* module_candidates[] = {
      L"ucrtbase.dll", L"msvcrt.dll", L"msvcr120.dll", L"msvcr110.dll", L"msvcr100.dll"};

  for (auto module_name : module_candidates) {
    HMODULE module = ::GetModuleHandleW(module_name);
    if (!module) {
      continue;
    }

    auto* proc = reinterpret_cast<beginthreadex_fn>(::GetProcAddress(module, "_beginthreadex"));
    if (proc) {
      return proc;
    }
  }

  return nullptr;
}

const char* funchook_error_string(funchook_t* handle) {
  const char* message = funchook_error_message(handle);
  return message ? message : "unknown";
}

} // namespace

bool install_platform_hooks() {
  auto log = redlog::get_logger("threadtest.interpose");

  HMODULE kernel32 = ::GetModuleHandleW(L"KERNEL32.DLL");
  if (!kernel32) {
    log.err("failed to resolve kernel32");
    return false;
  }

  g_real_create_thread = reinterpret_cast<create_thread_fn>(::GetProcAddress(kernel32, "CreateThread"));
  if (!g_real_create_thread) {
    log.err("failed to resolve CreateThread");
    return false;
  }

  if (!g_funchook) {
    g_funchook = funchook_create();
    if (!g_funchook) {
      log.err("funchook_create failed");
      g_real_create_thread = nullptr;
      return false;
    }
  }

  int status = funchook_prepare(
      g_funchook, reinterpret_cast<void**>(&g_real_create_thread), reinterpret_cast<void*>(create_thread_hook)
  );
  if (status != FUNCHOOK_OK) {
    log.err(
        "funchook_prepare CreateThread failed", redlog::field("status", status),
        redlog::field("error", funchook_error_string(g_funchook))
    );
    funchook_destroy(g_funchook);
    g_funchook = nullptr;
    g_real_create_thread = nullptr;
    return false;
  }

  beginthreadex_fn candidate = resolve_beginthreadex();
  if (candidate) {
    g_real_beginthreadex = candidate;
    status = funchook_prepare(
        g_funchook, reinterpret_cast<void**>(&g_real_beginthreadex), reinterpret_cast<void*>(beginthreadex_hook)
    );
    if (status != FUNCHOOK_OK) {
      log.wrn(
          "funchook_prepare _beginthreadex failed", redlog::field("status", status),
          redlog::field("error", funchook_error_string(g_funchook))
      );
      g_real_beginthreadex = nullptr;
    }
  }

  status = funchook_install(g_funchook, 0);
  if (status != FUNCHOOK_OK) {
    log.err(
        "funchook_install failed", redlog::field("status", status),
        redlog::field("error", funchook_error_string(g_funchook))
    );
    funchook_destroy(g_funchook);
    g_funchook = nullptr;
    g_real_create_thread = nullptr;
    g_real_beginthreadex = nullptr;
    return false;
  }

  log.inf(
      "CreateThread hook installed",
      redlog::field("beginthreadex_hooked", static_cast<bool>(g_real_beginthreadex))
  );
  return true;
}

void uninstall_platform_hooks() {
  if (!g_funchook) {
    g_real_create_thread = nullptr;
    g_real_beginthreadex = nullptr;
    return;
  }

  int status = funchook_uninstall(g_funchook, 0);
  if (status != FUNCHOOK_OK) {
    auto log = redlog::get_logger("threadtest.interpose");
    log.wrn(
        "funchook_uninstall failed", redlog::field("status", status),
        redlog::field("error", funchook_error_string(g_funchook))
    );
  }

  funchook_destroy(g_funchook);
  g_funchook = nullptr;
  g_real_create_thread = nullptr;
  g_real_beginthreadex = nullptr;
}

} // namespace threadtest::hooking

#endif // defined(_WIN32)
