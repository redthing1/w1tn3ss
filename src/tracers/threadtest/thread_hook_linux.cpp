#include "thread_hook_internal.hpp"

#if defined(__linux__)

#include <redlog.hpp>

#include <dlfcn.h>
#include <errno.h>
#include <memory>
#include <pthread.h>
#include <plthook.h>

namespace threadtest::hooking {

namespace detail {

using pthread_create_fn = int (*)(pthread_t*, const pthread_attr_t*, thread_start_fn, void*);

pthread_create_fn g_original_pthread_create = nullptr;

struct interceptor_context {
  thread_start_interceptor interceptor;
  thread_start_fn start_routine;
  void* arg;
};

int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg);

void* trampoline_dispatch(void* raw_ctx) {
  std::unique_ptr<interceptor_context> ctx(static_cast<interceptor_context*>(raw_ctx));
  if (!ctx || !ctx->start_routine) {
    return nullptr;
  }

  if (!ctx->interceptor) {
    return ctx->start_routine(ctx->arg);
  }

  return ctx->interceptor(ctx->start_routine, ctx->arg);
}

pthread_create_fn resolve_original_pthread_create() {
  void* handle = dlopen("libpthread.so.0", RTLD_LAZY | RTLD_NOLOAD);
  if (!handle) {
    handle = dlopen("libpthread.so.0", RTLD_LAZY);
  }

  pthread_create_fn fn = nullptr;
  if (handle) {
    fn = reinterpret_cast<pthread_create_fn>(dlsym(handle, "pthread_create"));
  }
  if (!fn) {
    fn = reinterpret_cast<pthread_create_fn>(dlsym(RTLD_NEXT, "pthread_create"));
  }
  return fn;
}

int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg) {
  auto log = redlog::get_logger("threadtest.interpose");

  if (!g_original_pthread_create) {
    log.err("pthread_create hook invoked without original pointer");
    return EAGAIN;
  }

  if (!g_interceptor || !start_routine) {
    return g_original_pthread_create(thread, attr, start_routine, arg);
  }

  auto* ctx = new interceptor_context{g_interceptor, start_routine, arg};
  int result = g_original_pthread_create(thread, attr, trampoline_dispatch, ctx);
  if (result != 0) {
    log.err("pthread_create failed", redlog::field("result", result));
    delete ctx;
  } else {
    log.dbg("pthread_create intercepted", redlog::field("thread", thread));
  }
  return result;
}

bool install_thread_hooks() {
  auto log = redlog::get_logger("threadtest.interpose");

  pthread_create_fn original = resolve_original_pthread_create();
  if (!original) {
    log.err("failed to resolve original pthread_create");
    return false;
  }

  if (!g_original_pthread_create) {
    g_original_pthread_create = original;
  }

  plthook_t* hook = nullptr;
  if (plthook_open_by_address(&hook, reinterpret_cast<void*>(original)) != 0) {
    log.wrn("plthook_open_by_address failed", redlog::field("error", plthook_error()));
    return false;
  }

  void* old_func = nullptr;
  int status = plthook_replace(hook, "pthread_create", reinterpret_cast<void*>(pthread_create_hook), &old_func);
  if (status != 0) {
    log.wrn("plthook_replace failed", redlog::field("status", status), redlog::field("error", plthook_error()));
    plthook_close(hook);
    return false;
  }

  if (old_func && !g_original_pthread_create) {
    g_original_pthread_create = reinterpret_cast<pthread_create_fn>(old_func);
  }

  plthook_close(hook);
  log.inf("pthread_create hook installed");
  return true;
}

void uninstall_thread_hooks() {
  if (!g_original_pthread_create) {
    return;
  }

  plthook_t* hook = nullptr;
  if (plthook_open_by_address(&hook, reinterpret_cast<void*>(pthread_create_hook)) != 0) {
    g_original_pthread_create = nullptr;
    return;
  }

  plthook_replace(hook, "pthread_create", reinterpret_cast<void*>(g_original_pthread_create), nullptr);
  plthook_close(hook);
  g_original_pthread_create = nullptr;
}

bool install_syscall_hooks() { return false; }

void uninstall_syscall_hooks() {}

} // namespace detail

bool install_platform_hooks() {
  bool thread_ok = detail::install_thread_hooks();
  bool syscall_ok = detail::install_syscall_hooks();
  return thread_ok || syscall_ok;
}

void uninstall_platform_hooks() {
  detail::uninstall_thread_hooks();
  detail::uninstall_syscall_hooks();
}

} // namespace threadtest::hooking

#endif // defined(__linux__)
