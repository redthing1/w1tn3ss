#pragma once

#include <cstdint>
#include <functional>
#include <string>

namespace w1::monitor {

struct thread_event {
  enum class kind { started, stopped, renamed };
  kind type = kind::started;
  uint64_t tid = 0;
  std::string name{};
};

enum class thread_entry_kind { posix, win32 };

struct thread_entry_context {
  thread_entry_kind kind = thread_entry_kind::posix;
  uint64_t tid = 0;
  void* start_routine = nullptr;
  void* arg = nullptr;
};

using thread_entry_callback = std::function<bool(const thread_entry_context&, uint64_t& result_out)>;

class thread_monitor {
public:
  virtual ~thread_monitor() = default;
  virtual void start() = 0;
  virtual void stop() = 0;
  virtual bool poll(thread_event& out) = 0;
  virtual void set_entry_callback(thread_entry_callback callback) { (void)callback; }
};

} // namespace w1::monitor
