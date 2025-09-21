#include "thread_runtime.hpp"

#include <thread>
#include <vector>

#if defined(__APPLE__)
#include <pthread.h>
#elif defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

namespace w1::runtime::threading {
namespace {

thread_local thread_context* t_tls_context = nullptr;

uint64_t current_native_thread_id() {
#if defined(__APPLE__)
  uint64_t tid = 0;
  if (pthread_threadid_np(nullptr, &tid) == 0) {
    return tid;
  }
  return 0;
#elif defined(__linux__)
  return static_cast<uint64_t>(::syscall(SYS_gettid));
#elif defined(_WIN32)
  return static_cast<uint64_t>(::GetCurrentThreadId());
#else
  return 0;
#endif
}

thread_result_t thread_start_dispatch(thread_start_fn start_routine, void* arg) {
  return thread_service::instance().handle_thread_start(start_routine, arg);
}

} // namespace

thread_service& thread_service::instance() {
  static thread_service service;
  return service;
}

void thread_service::configure(thread_runtime_options options, std::shared_ptr<thread_session_factory> factory) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    options_ = std::move(options);
    factory_ = std::move(factory);
    configured_ = static_cast<bool>(factory_);
  }

  if (options_.enable_thread_hooks && configured_) {
    if (!hooking::install(thread_start_dispatch)) {
      log_.wrn("failed to install thread hooks; worker threads will not be instrumented");
    }
  } else {
    hooking::uninstall();
  }
}

thread_context* thread_service::register_main_thread(QBDI::VMInstanceRef vm, std::string_view name) {
  if (!configured_) {
    log_.err("thread runtime not configured");
    return nullptr;
  }

  uint64_t native_id = current_native_thread_id();
  thread_context* context_ptr = nullptr;

  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!configured_ || !factory_) {
      log_.err("thread runtime factory unavailable");
      return nullptr;
    }

    if (native_id != 0) {
      auto mapping = thread_id_by_native_.find(native_id);
      if (mapping != thread_id_by_native_.end()) {
        auto ctx_it = contexts_.find(mapping->second);
        if (ctx_it != contexts_.end()) {
          t_tls_context = ctx_it->second.get();
          return ctx_it->second.get();
        }
      }
    }

    uint64_t thread_id = allocate_thread_id();
    auto context = std::make_unique<thread_context>();
    context->thread_id = thread_id;
    context->native_id = native_id;
    context->is_main = true;
    context->name = name.empty() ? std::string("main") : std::string(name);
    context->log = redlog::get_logger(make_logger_name(thread_id));
    context->session = factory_->create_for_main_thread(thread_id, context->name, context->log);

    if (!context->session) {
      log_.err("failed to create main thread session", redlog::field("thread_id", thread_id));
      return nullptr;
    }

    context_ptr = context.get();
    contexts_[thread_id] = std::move(context);

    if (native_id != 0) {
      thread_id_by_native_[native_id] = thread_id;
    }

    t_tls_context = context_ptr;
  }

  if (!context_ptr->session->initialize_main(vm)) {
    log_.err("main thread session initialization failed", redlog::field("thread_id", context_ptr->thread_id));
    remove_context(context_ptr->thread_id, native_id);
    return nullptr;
  }

  context_ptr->log.inf(
      "registered main thread", redlog::field("thread_id", context_ptr->thread_id),
      redlog::field("native_id", native_id)
  );

  return context_ptr;
}

void thread_service::unregister_all() {
  std::vector<std::unique_ptr<thread_context>> contexts;

  {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& entry : contexts_) {
      contexts.push_back(std::move(entry.second));
    }
    contexts_.clear();
    thread_id_by_native_.clear();
    t_tls_context = nullptr;
  }

  for (auto& context : contexts) {
    if (context && context->session) {
      context->session->shutdown();
    }
  }

  if (hooking::installed()) {
    hooking::uninstall();
  }
}

thread_result_t thread_service::handle_thread_start(thread_start_fn start_routine, void* arg) {
  if (!start_routine) {
    return thread_result_t{};
  }

  if (!configured_) {
    return start_routine(arg);
  }

  uint64_t native_id = current_native_thread_id();
  thread_context* context = attach_worker_thread(native_id, "worker");
  if (!context || !context->session) {
    return start_routine(arg);
  }

  thread_result_t result{};
  auto* session = context->session.get();

  result = session->run_worker(start_routine, arg);
  session->shutdown();
  remove_context(context->thread_id, native_id);

  return result;
}

thread_context* thread_service::tls_context() const { return t_tls_context; }

void thread_service::set_tls_context(thread_context* context) const { t_tls_context = context; }

std::optional<uint64_t> thread_service::get_current_thread_id() const {
  uint64_t native_id = current_native_thread_id();
  if (native_id == 0) {
    return std::nullopt;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  auto it = thread_id_by_native_.find(native_id);
  if (it == thread_id_by_native_.end()) {
    return std::nullopt;
  }
  return it->second;
}

thread_context* thread_service::attach_worker_thread(uint64_t native_id, std::string_view name) {
  if (!configured_ || !factory_) {
    return nullptr;
  }

  std::string thread_name = name.empty() ? std::string("worker") : std::string(name);
  thread_context* context_ptr = nullptr;

  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!configured_ || !factory_) {
      return nullptr;
    }

    if (native_id != 0) {
      auto mapping = thread_id_by_native_.find(native_id);
      if (mapping != thread_id_by_native_.end()) {
        auto ctx_it = contexts_.find(mapping->second);
        if (ctx_it != contexts_.end()) {
          context_ptr = ctx_it->second.get();
          t_tls_context = context_ptr;
          return context_ptr;
        }
      }
    }

    uint64_t thread_id = allocate_thread_id();
    auto context = std::make_unique<thread_context>();
    context->thread_id = thread_id;
    context->native_id = native_id;
    context->is_main = false;
    context->name = std::move(thread_name);
    context->log = redlog::get_logger(make_logger_name(thread_id));
    context->session = factory_->create_for_worker_thread(thread_id, context->name, context->log);

    if (!context->session) {
      log_.err("failed to create worker thread session", redlog::field("thread_id", thread_id));
      return nullptr;
    }

    context_ptr = context.get();
    contexts_[thread_id] = std::move(context);

    if (native_id != 0) {
      thread_id_by_native_[native_id] = thread_id;
    }

    t_tls_context = context_ptr;
  }

  if (!context_ptr->session->initialize_worker()) {
    log_.err("worker thread session initialization failed", redlog::field("thread_id", context_ptr->thread_id));
    remove_context(context_ptr->thread_id, native_id);
    return nullptr;
  }

  context_ptr->log.dbg(
      "attached thread", redlog::field("thread_id", context_ptr->thread_id), redlog::field("native_id", native_id)
  );

  return context_ptr;
}

std::unique_ptr<thread_context> thread_service::remove_context(uint64_t thread_id, uint64_t native_id) {
  std::unique_ptr<thread_context> removed;

  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (native_id != 0) {
      thread_id_by_native_.erase(native_id);
    }

    auto ctx_it = contexts_.find(thread_id);
    if (ctx_it != contexts_.end()) {
      removed = std::move(ctx_it->second);
      contexts_.erase(ctx_it);
    }

    if (removed && t_tls_context == removed.get()) {
      t_tls_context = nullptr;
    }
  }

  return removed;
}

std::string thread_service::make_logger_name(uint64_t thread_id) const {
  if (options_.logger_prefix.empty()) {
    return std::string{"w1.thread."} + std::to_string(thread_id);
  }
  return options_.logger_prefix + "." + std::to_string(thread_id);
}

uint64_t thread_service::allocate_thread_id() { return next_thread_id_++; }

} // namespace w1::runtime::threading
