#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <QBDI.h>
#include <redlog.hpp>

#include <w1tn3ss/runtime/threading/thread_hook.hpp>

namespace w1::runtime::threading {

struct thread_runtime_options {
  int verbose = 0;
  bool enable_thread_hooks = true;
  std::string logger_prefix = "w1.thread";
};

class thread_tracer_session {
public:
  virtual ~thread_tracer_session() = default;

  virtual bool initialize_main(QBDI::VMInstanceRef vm) = 0;
  virtual bool initialize_worker() = 0;
  virtual thread_result_t run_worker(thread_start_fn start_routine, void* arg) = 0;
  virtual void shutdown() = 0;
  virtual const char* tracer_name() const = 0;
};

class thread_session_factory {
public:
  virtual ~thread_session_factory() = default;

  virtual std::unique_ptr<thread_tracer_session> create_for_main_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) = 0;

  virtual std::unique_ptr<thread_tracer_session> create_for_worker_thread(
      uint64_t thread_id, std::string_view thread_name, redlog::logger log
  ) = 0;
};

struct thread_context {
  uint64_t thread_id = 0;
  uint64_t native_id = 0;
  std::string name;
  std::unique_ptr<thread_tracer_session> session;
  redlog::logger log = redlog::get_logger("w1.thread");
  bool is_main = false;
};

class thread_service {
public:
  static thread_service& instance();

  void configure(thread_runtime_options options, std::shared_ptr<thread_session_factory> factory);

  thread_context* register_main_thread(QBDI::VMInstanceRef vm, std::string_view name = "main");

  void unregister_all();

  thread_result_t handle_thread_start(thread_start_fn start_routine, void* arg);

  thread_context* tls_context() const;
  void set_tls_context(thread_context* context) const;

  std::optional<uint64_t> get_current_thread_id() const;

  const thread_runtime_options& options() const { return options_; }

private:
  thread_service() = default;

  thread_context* attach_worker_thread(uint64_t native_id, std::string_view name);
  std::unique_ptr<thread_context> remove_context(uint64_t thread_id, uint64_t native_id);
  std::string make_logger_name(uint64_t thread_id) const;
  uint64_t allocate_thread_id();

  thread_runtime_options options_;
  std::shared_ptr<thread_session_factory> factory_;
  bool configured_ = false;

  mutable std::mutex mutex_;
  std::unordered_map<uint64_t, std::unique_ptr<thread_context>> contexts_;
  std::unordered_map<uint64_t, uint64_t> thread_id_by_native_;
  uint64_t next_thread_id_ = 1;

  redlog::logger log_ = redlog::get_logger("w1.threading.service");
};

} // namespace w1::runtime::threading
