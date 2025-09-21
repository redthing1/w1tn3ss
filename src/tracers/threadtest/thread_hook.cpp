#include "thread_hook.hpp"

#include <pthread.h>

#include <redlog.hpp>

#if defined(__APPLE__) || defined(__linux__)
#include <plthook.h>
#include <dlfcn.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <cstring>
#endif

namespace threadtest::hooking {

namespace {

using pthread_create_fn = int (*)(pthread_t*, const pthread_attr_t*, thread_start_fn, void*);

thread_start_interceptor g_interceptor = nullptr;
pthread_create_fn g_original_pthread_create = nullptr;
bool g_installed = false;

#if defined(__APPLE__)
bool g_add_image_callback_registered = false;
#endif

struct interceptor_context {
  thread_start_interceptor interceptor;
  thread_start_fn start_routine;
  void* arg;
};

void* trampoline_dispatch(void* raw_ctx) {
  interceptor_context ctx = *static_cast<interceptor_context*>(raw_ctx);
  delete static_cast<interceptor_context*>(raw_ctx);

  if (!ctx.interceptor || !ctx.start_routine) {
    return ctx.start_routine ? ctx.start_routine(ctx.arg) : nullptr;
  }

  return ctx.interceptor(ctx.start_routine, ctx.arg);
}

pthread_create_fn resolve_original_pthread_create() {
#if defined(__APPLE__)
  void* handle = dlopen("/usr/lib/system/libsystem_pthread.dylib", RTLD_LAZY | RTLD_NOLOAD);
  if (!handle) {
    handle = dlopen("/usr/lib/system/libsystem_pthread.dylib", RTLD_LAZY);
  }
  pthread_create_fn fn = nullptr;
  if (handle) {
    fn = reinterpret_cast<pthread_create_fn>(dlsym(handle, "pthread_create"));
  }
  if (!fn) {
    fn = reinterpret_cast<pthread_create_fn>(dlsym(RTLD_DEFAULT, "pthread_create"));
  }
  if (!fn) {
    fn = reinterpret_cast<pthread_create_fn>(dlsym(RTLD_NEXT, "pthread_create"));
  }
  return fn;
#elif defined(__linux__)
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
#else
  return nullptr;
#endif
}

int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg) {
  auto log = redlog::get_logger("threadtest.interpose");

  if (!g_original_pthread_create) {
    log.err("pthread_create hook invoked without original pointer");
    return EAGAIN;
  }

  interceptor_context* ctx = new interceptor_context{g_interceptor, start_routine, arg};
  int result = g_original_pthread_create(thread, attr, trampoline_dispatch, ctx);
  if (result != 0) {
    log.err("pthread_create failed", redlog::field("result", result));
    delete ctx;
  } else {
    log.dbg("pthread_create intercepted", redlog::field("thread", thread));
  }
  return result;
}

#if defined(__APPLE__)

bool is_system_image(const char* image_name) {
  if (!image_name) {
    return true;
  }
  return std::strncmp(image_name, "/usr/lib/", 9) == 0 || std::strstr(image_name, "/System/") != nullptr;
}

bool replace_symbol_in_image(const char* image_name, void* new_func, void** old_func) {
  if (!image_name || is_system_image(image_name)) {
    return false;
  }

  plthook_t* hook = nullptr;
  int open_status = plthook_open(&hook, image_name);
  if (open_status != 0) {
    auto log = redlog::get_logger("threadtest.interpose");
    log.trc(
        "plthook_open failed", redlog::field("status", open_status), redlog::field("image", image_name),
        redlog::field("error", plthook_error())
    );
    return false;
  }

  auto try_replace = [&](const char* symbol) {
    void* previous = nullptr;
    int replace_status = plthook_replace(hook, symbol, new_func, &previous);
    if (replace_status == 0) {
      if (previous == new_func) {
        return true;
      }
      if (old_func && previous && !*old_func) {
        *old_func = previous;
      }
      auto log = redlog::get_logger("threadtest.interpose");
      log.dbg("patched symbol", redlog::field("symbol", symbol), redlog::field("image", image_name));
      return true;
    }
    return false;
  };

  bool replaced = try_replace("pthread_create");
  if (!replaced) {
    replaced = try_replace("_pthread_create");
  }

  plthook_close(hook);
  return replaced;
}

void image_added_callback(const struct mach_header* header, intptr_t) {
  const char* image_name = nullptr;
  uint32_t image_count = _dyld_image_count();
  for (uint32_t i = 0; i < image_count; ++i) {
    if (_dyld_get_image_header(i) == header) {
      image_name = _dyld_get_image_name(i);
      break;
    }
  }

  if (!image_name) {
    return;
  }

  replace_symbol_in_image(image_name, reinterpret_cast<void*>(pthread_create_hook), nullptr);
}

bool install_platform_hooks() {
  auto log = redlog::get_logger("threadtest.interpose");

  pthread_create_fn original = resolve_original_pthread_create();
  if (!original) {
    log.err("failed to resolve original pthread_create");
    return false;
  }

  if (!g_original_pthread_create) {
    g_original_pthread_create = original;
  }

  uint32_t image_count = _dyld_image_count();
  size_t patched_images = 0;
  for (uint32_t i = 0; i < image_count; ++i) {
    const char* image_name = _dyld_get_image_name(i);
    if (replace_symbol_in_image(image_name, reinterpret_cast<void*>(pthread_create_hook), nullptr)) {
      ++patched_images;
    }
  }

  if (!g_add_image_callback_registered) {
    _dyld_register_func_for_add_image(image_added_callback);
    g_add_image_callback_registered = true;
  }

  log.inf("pthread_create hook installed", redlog::field("patched_images", static_cast<uint64_t>(patched_images)));
  return patched_images > 0;
}

void uninstall_platform_hooks() {
  if (!g_original_pthread_create) {
    return;
  }

  uint32_t image_count = _dyld_image_count();
  for (uint32_t i = 0; i < image_count; ++i) {
    const char* image_name = _dyld_get_image_name(i);
    if (!image_name || is_system_image(image_name)) {
      continue;
    }

    plthook_t* hook = nullptr;
    if (plthook_open(&hook, image_name) != 0) {
      continue;
    }

    auto restore = [&](const char* symbol) {
      plthook_replace(hook, symbol, reinterpret_cast<void*>(g_original_pthread_create), nullptr);
    };

    restore("pthread_create");
    restore("_pthread_create");
    plthook_close(hook);
  }
}

#elif defined(__linux__)

bool install_platform_hooks() {
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

void uninstall_platform_hooks() {
  if (!g_original_pthread_create) {
    return;
  }

  plthook_t* hook = nullptr;
  if (plthook_open_by_address(&hook, reinterpret_cast<void*>(pthread_create_hook)) != 0) {
    return;
  }

  plthook_replace(hook, "pthread_create", reinterpret_cast<void*>(g_original_pthread_create), nullptr);
  plthook_close(hook);
}

#else

bool install_platform_hooks() {
  auto log = redlog::get_logger("threadtest.interpose");
  log.wrn("pthread interception not implemented on this platform");
  return false;
}

void uninstall_platform_hooks() {}

#endif

} // namespace

bool install(thread_start_interceptor interceptor) {
  if (g_installed) {
    return true;
  }

  g_interceptor = interceptor;

  if (!install_platform_hooks()) {
    g_interceptor = nullptr;
    return false;
  }

  g_installed = true;
  return true;
}

void uninstall() {
  if (!g_installed) {
    return;
  }

  uninstall_platform_hooks();
  g_original_pthread_create = nullptr;
  g_interceptor = nullptr;
  g_installed = false;
#if defined(__APPLE__)
  g_add_image_callback_registered = false;
#endif
}

bool installed() { return g_installed; }

} // namespace threadtest::hooking
