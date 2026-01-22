#include "w1monitor/monitor_factory.hpp"

#include "w1monitor/backend/null/null_module_monitor.hpp"
#include "w1monitor/backend/null/null_thread_monitor.hpp"

namespace w1::monitor {

std::unique_ptr<module_monitor> make_module_monitor() {
  return backend::null_backend::make_module_monitor();
}

std::unique_ptr<thread_monitor> make_thread_monitor() {
  return backend::null_backend::make_thread_monitor();
}

} // namespace w1::monitor
