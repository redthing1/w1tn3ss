#pragma once

#include <cstdint>
#include <string>

namespace w1::monitor {

struct thread_event {
  enum class kind { started, stopped, renamed };
  kind type = kind::started;
  uint64_t tid = 0;
  std::string name{};
};

class thread_monitor {
public:
  virtual ~thread_monitor() = default;
  virtual void start() = 0;
  virtual void stop() = 0;
  virtual bool poll(thread_event& out) = 0;
};

} // namespace w1::monitor
