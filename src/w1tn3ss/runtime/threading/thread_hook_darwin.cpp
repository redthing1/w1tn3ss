#include "thread_hook_internal.hpp"

#if defined(__APPLE__)

#include <redlog.hpp>

#include <array>
#include <cstring>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/dyld.h>
#include <memory>
#include <pthread.h>
#if __has_include(<pthread/pthread_spis.h>)
#include <pthread/pthread_spis.h>
#endif
#include <plthook.h>

namespace w1::runtime::threading::hooking {

namespace detail {

using pthread_create_fn = int (*)(pthread_t*, const pthread_attr_t*, thread_start_fn, void*);
using bsdthread_create_fn = int (*)(void*, void*, void*, void*, uint32_t);

int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg);
int pthread_create_suspended_np_hook(
    pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg
);
int pthread_create_from_mach_thread_hook(
    pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg
);
int bsdthread_create_hook(void* func, void* func_arg, void* stack, void* pthread, uint32_t flags);

struct interceptor_context {
  thread_start_interceptor interceptor;
  thread_start_fn start_routine;
  void* arg;
};

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

pthread_create_fn g_original_pthread_create = nullptr;
pthread_create_fn g_original_pthread_create_suspended_np = nullptr;
pthread_create_fn g_original_pthread_create_from_mach_thread = nullptr;
bsdthread_create_fn g_original_bsdthread_create = nullptr;
bool g_add_image_callback_registered = false;

enum class symbol_library { none, pthread, kernel };

struct hook_spec {
  const char* tag;
  void** original_slot;
  void* replacement;
  symbol_library library;
  std::array<const char*, 3> symbols;
};

static const std::array<hook_spec, 4> kHookSpecs = {{
    {"pthread_create",
     reinterpret_cast<void**>(&g_original_pthread_create),
     reinterpret_cast<void*>(pthread_create_hook),
     symbol_library::pthread,
     {"pthread_create", "_pthread_create", nullptr}},
    {"pthread_create_suspended_np",
     reinterpret_cast<void**>(&g_original_pthread_create_suspended_np),
     reinterpret_cast<void*>(pthread_create_suspended_np_hook),
     symbol_library::pthread,
     {"pthread_create_suspended_np", "_pthread_create_suspended_np", nullptr}},
    {"pthread_create_from_mach_thread",
     reinterpret_cast<void**>(&g_original_pthread_create_from_mach_thread),
     reinterpret_cast<void*>(pthread_create_from_mach_thread_hook),
     symbol_library::pthread,
     {"pthread_create_from_mach_thread", nullptr, nullptr}},
    {"___bsdthread_create",
     reinterpret_cast<void**>(&g_original_bsdthread_create),
     reinterpret_cast<void*>(bsdthread_create_hook),
     symbol_library::kernel,
     {"___bsdthread_create", "__bsdthread_create", nullptr}},
}};

void* resolve_symbol(symbol_library library, const char* symbol) {
  if (!symbol) {
    return nullptr;
  }

  const char* image_path = nullptr;
  switch (library) {
  case symbol_library::pthread:
    image_path = "/usr/lib/system/libsystem_pthread.dylib";
    break;
  case symbol_library::kernel:
    image_path = "/usr/lib/system/libsystem_kernel.dylib";
    break;
  case symbol_library::none:
  default:
    break;
  }

  auto try_lookup = [&](void* handle) -> void* {
    if (!handle) {
      return nullptr;
    }
    return dlsym(handle, symbol);
  };

  if (image_path) {
    void* handle = dlopen(image_path, RTLD_LAZY | RTLD_NOLOAD);
    if (!handle) {
      handle = dlopen(image_path, RTLD_LAZY);
    }
    if (void* sym = try_lookup(handle)) {
      return sym;
    }
  }

  if (void* sym = try_lookup(RTLD_DEFAULT)) {
    return sym;
  }
  if (void* sym = try_lookup(RTLD_NEXT)) {
    return sym;
  }
  return nullptr;
}

void ensure_original_symbol(size_t index) {
  if (index >= kHookSpecs.size()) {
    return;
  }

  const hook_spec& spec = kHookSpecs[index];
  if (!spec.original_slot || *spec.original_slot) {
    return;
  }

  for (const char* symbol : spec.symbols) {
    if (!symbol) {
      continue;
    }
    void* resolved = resolve_symbol(spec.library, symbol);
    if (resolved) {
      *spec.original_slot = resolved;
      return;
    }
  }
}

void ensure_original_symbols() {
  for (size_t i = 0; i < kHookSpecs.size(); ++i) {
    ensure_original_symbol(i);
  }
}

bool is_system_image(const char* image_name) {
  if (!image_name) {
    return true;
  }
  return std::strncmp(image_name, "/usr/lib/", 9) == 0 || std::strstr(image_name, "/System/") != nullptr;
}

bool patch_image(const char* image_name) {
  if (!image_name || is_system_image(image_name)) {
    return false;
  }

  plthook_t* hook = nullptr;
  int open_status = plthook_open(&hook, image_name);
  if (open_status != 0) {
    auto log = redlog::get_logger("w1.threading.interpose");
    log.trc(
        "plthook_open failed", redlog::field("status", open_status), redlog::field("image", image_name),
        redlog::field("error", plthook_error())
    );
    return false;
  }

  bool patched = false;
  auto log = redlog::get_logger("w1.threading.interpose");

  for (const auto& spec : kHookSpecs) {
    if (!spec.replacement) {
      continue;
    }

    for (const char* symbol : spec.symbols) {
      if (!symbol) {
        continue;
      }

      void* previous = nullptr;
      int replace_status = plthook_replace(hook, symbol, spec.replacement, &previous);
      if (replace_status != 0) {
        continue;
      }
      if (previous == spec.replacement) {
        continue;
      }

      if (spec.original_slot && previous && !*spec.original_slot) {
        *spec.original_slot = previous;
      }

      log.dbg("patched symbol", redlog::field("symbol", symbol), redlog::field("image", image_name));
      patched = true;
      break;
    }
  }

  plthook_close(hook);
  return patched;
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

  patch_image(image_name);
}

pthread_create_fn ensure_pthread_original(pthread_create_fn current, const char* symbol) {
  if (current) {
    return current;
  }
  return reinterpret_cast<pthread_create_fn>(resolve_symbol(symbol_library::pthread, symbol));
}

bsdthread_create_fn ensure_bsdthread_original(bsdthread_create_fn current) {
  if (current) {
    return current;
  }
  return reinterpret_cast<bsdthread_create_fn>(resolve_symbol(symbol_library::kernel, "___bsdthread_create"));
}

int intercept_pthread_create(
    const char* tag, pthread_create_fn& original, const char* symbol, pthread_t* thread, const pthread_attr_t* attr,
    thread_start_fn start_routine, void* arg
) {
  auto log = redlog::get_logger("w1.threading.interpose");

  if (!original) {
    original = ensure_pthread_original(original, symbol);
  }

  if (!original) {
    log.err("missing original pthread entry", redlog::field("symbol", symbol));
    return EAGAIN;
  }

  if (!g_interceptor || !start_routine) {
    return original(thread, attr, start_routine, arg);
  }

  auto* ctx = new interceptor_context{g_interceptor, start_routine, arg};
  int result = original(thread, attr, trampoline_dispatch, ctx);
  if (result != 0) {
    log.err("pthread variant failed", redlog::field("tag", tag), redlog::field("result", result));
    delete ctx;
  } else {
    log.dbg("pthread variant intercepted", redlog::field("tag", tag));
  }
  return result;
}

int pthread_create_hook(pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg) {
  return intercept_pthread_create(
      "pthread_create", g_original_pthread_create, "pthread_create", thread, attr, start_routine, arg
  );
}

int pthread_create_suspended_np_hook(
    pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg
) {
  return intercept_pthread_create(
      "pthread_create_suspended_np", g_original_pthread_create_suspended_np, "pthread_create_suspended_np", thread,
      attr, start_routine, arg
  );
}

int pthread_create_from_mach_thread_hook(
    pthread_t* thread, const pthread_attr_t* attr, thread_start_fn start_routine, void* arg
) {
  return intercept_pthread_create(
      "pthread_create_from_mach_thread", g_original_pthread_create_from_mach_thread, "pthread_create_from_mach_thread",
      thread, attr, start_routine, arg
  );
}

int bsdthread_create_hook(void* func, void* func_arg, void* stack, void* pthread, uint32_t flags) {
  auto log = redlog::get_logger("w1.threading.interpose");

  if (!g_original_bsdthread_create) {
    g_original_bsdthread_create = ensure_bsdthread_original(g_original_bsdthread_create);
  }

  if (!g_original_bsdthread_create || !func || !g_interceptor) {
    return g_original_bsdthread_create ? g_original_bsdthread_create(func, func_arg, stack, pthread, flags) : EINVAL;
  }

  auto* ctx = new interceptor_context{g_interceptor, reinterpret_cast<thread_start_fn>(func), func_arg};
  int result = g_original_bsdthread_create(reinterpret_cast<void*>(trampoline_dispatch), ctx, stack, pthread, flags);
  if (result != 0) {
    log.err("bsdthread_create failed", redlog::field("result", result));
    delete ctx;
  } else {
    log.dbg("bsdthread_create intercepted", redlog::field("flags", static_cast<uint64_t>(flags)));
  }
  return result;
}

bool install_thread_hooks() {
  ensure_original_symbols();

  uint32_t image_count = _dyld_image_count();
  size_t patched_images = 0;
  for (uint32_t i = 0; i < image_count; ++i) {
    const char* image_name = _dyld_get_image_name(i);
    if (patch_image(image_name)) {
      ++patched_images;
    }
  }

  if (!g_add_image_callback_registered) {
    _dyld_register_func_for_add_image(image_added_callback);
    g_add_image_callback_registered = true;
  }

  auto log = redlog::get_logger("w1.threading.interpose");
  log.inf("darwin thread hooks installed", redlog::field("patched_images", static_cast<uint64_t>(patched_images)));
  return patched_images > 0;
}

void uninstall_thread_hooks() {
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

    for (const auto& spec : kHookSpecs) {
      if (!spec.original_slot || !*spec.original_slot) {
        continue;
      }
      for (const char* symbol : spec.symbols) {
        if (!symbol) {
          continue;
        }
        plthook_replace(hook, symbol, *spec.original_slot, nullptr);
      }
    }

    plthook_close(hook);
  }

  g_original_pthread_create = nullptr;
  g_original_pthread_create_suspended_np = nullptr;
  g_original_pthread_create_from_mach_thread = nullptr;
  g_original_bsdthread_create = nullptr;
  g_add_image_callback_registered = false;
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

} // namespace w1::runtime::threading::hooking

#endif // defined(__APPLE__)
