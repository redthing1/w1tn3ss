#pragma once

#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"

namespace w1::runtime {

struct process_event {
  enum class kind { module_loaded, module_unloaded, thread_started, thread_stopped, thread_renamed };
  kind type = kind::module_loaded;
  w1::monitor::module_event module{};
  w1::monitor::thread_event thread{};
};

} // namespace w1::runtime
