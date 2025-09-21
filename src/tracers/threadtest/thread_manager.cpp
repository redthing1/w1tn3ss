#include "thread_manager.hpp"

#include <thread>

#include <w1tn3ss/util/stderr_write.hpp>

#include "threadtest_tracer.hpp"

#if defined(__APPLE__) || defined(__linux__)
#include <pthread.h>
#endif

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

namespace threadtest {
namespace {

thread_local thread_context* t_current_context = nullptr;

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

} // namespace

thread_manager& thread_manager::instance() {
  static thread_manager instance;
  return instance;
}

void thread_manager::configure(const threadtest_config& config) {
  std::lock_guard<std::mutex> lock(mutex_);
  config_ = config;
  configured_ = true;
  log_.inf(
      "thread manager configured", redlog::field("verbose", config_.verbose),
      redlog::field("thread_hooks", config_.enable_thread_hooks)
  );
}

thread_context* thread_manager::register_main_thread(QBDI::VMInstanceRef vm) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (!configured_) {
    log_.err("manager not configured");
    return nullptr;
  }

  uint64_t native_id = current_native_thread_id();
  if (native_id != 0) {
    auto existing = thread_id_by_native_.find(native_id);
    if (existing != thread_id_by_native_.end()) {
      auto ctx_it = contexts_.find(existing->second);
      if (ctx_it != contexts_.end()) {
        t_current_context = ctx_it->second.get();
        return ctx_it->second.get();
      }
    }
  }
  uint64_t assigned_id = allocate_thread_id();

  auto context = std::make_unique<thread_context>();
  context->thread_id = assigned_id;
  context->thread_name = "main";
  context->log = redlog::get_logger("threadtest.thread." + std::to_string(assigned_id));

  context->tracer = std::make_unique<threadtest_tracer>(config_, *context);
  context->engine = std::make_unique<w1::tracer_engine<threadtest_tracer>>(vm, *context->tracer, config_);

  auto* context_ptr = context.get();
  contexts_[assigned_id] = std::move(context);

  if (native_id != 0) {
    thread_id_by_native_[native_id] = assigned_id;
  }

  t_current_context = context_ptr;

  log_.inf("registered main thread", redlog::field("thread_id", assigned_id), redlog::field("native_id", native_id));

  return context_ptr;
}

thread_context* thread_manager::attach_thread(uint64_t native_id, const std::string& name) {
  if (!configured_) {
    log_.err("manager not configured");
    return nullptr;
  }

  std::lock_guard<std::mutex> lock(mutex_);

  if (native_id == 0) {
    native_id = current_native_thread_id();
  }

  if (native_id != 0) {
    if (auto existing = thread_id_by_native_.find(native_id); existing != thread_id_by_native_.end()) {
      if (auto ctx_it = contexts_.find(existing->second); ctx_it != contexts_.end()) {
        t_current_context = ctx_it->second.get();
        return ctx_it->second.get();
      }
    }
  }

  uint64_t assigned_id = allocate_thread_id();
  auto context = std::make_unique<thread_context>();
  context->thread_id = assigned_id;
  context->thread_name = name;
  context->log = redlog::get_logger("threadtest.thread." + std::to_string(assigned_id));

  context->tracer = std::make_unique<threadtest_tracer>(config_, *context);
  context->engine = std::make_unique<w1::tracer_engine<threadtest_tracer>>(*context->tracer, config_);

  auto* context_ptr = context.get();
  contexts_[assigned_id] = std::move(context);

  if (native_id != 0) {
    thread_id_by_native_[native_id] = assigned_id;
  }

  t_current_context = context_ptr;

  log_.dbg(
      "attached thread", redlog::field("thread_id", assigned_id), redlog::field("native_id", native_id),
      redlog::field("name", name)
  );

  return context_ptr;
}

void thread_manager::detach_thread(uint64_t native_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (native_id == 0) {
    native_id = current_native_thread_id();
  }

  if (native_id == 0) {
    return;
  }

  auto mapping = thread_id_by_native_.find(native_id);
  if (mapping == thread_id_by_native_.end()) {
    return;
  }

  uint64_t thread_id = mapping->second;
  thread_id_by_native_.erase(mapping);

  if (auto ctx_it = contexts_.find(thread_id); ctx_it != contexts_.end()) {
    log_.dbg("detached thread", redlog::field("thread_id", thread_id), redlog::field("native_id", native_id));
    contexts_.erase(ctx_it);
  }

  if (t_current_context && t_current_context->thread_id == thread_id) {
    t_current_context = nullptr;
  }
}

thread_context* thread_manager::tls_context() const { return t_current_context; }

void thread_manager::set_tls_context(thread_context* context) const { t_current_context = context; }

std::optional<uint64_t> thread_manager::get_current_thread_id() const {
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

uint64_t thread_manager::allocate_thread_id() { return next_thread_id_++; }

} // namespace threadtest
