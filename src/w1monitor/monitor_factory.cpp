#include "w1monitor/monitor_factory.hpp"

#if defined(__APPLE__)
#include "w1monitor/backend/darwin/darwin_module_monitor.hpp"
#include "w1monitor/backend/darwin/darwin_thread_monitor.hpp"
#else
#include "w1monitor/backend/null/null_module_monitor.hpp"
#include "w1monitor/backend/null/null_thread_monitor.hpp"
#endif

namespace w1::monitor {

std::unique_ptr<module_monitor> make_module_monitor() {
#if defined(__APPLE__)
  return backend::darwin::make_module_monitor();
#else
  return backend::null_backend::make_module_monitor();
#endif
}

std::unique_ptr<thread_monitor> make_thread_monitor() {
#if defined(__APPLE__)
  return backend::darwin::make_thread_monitor();
#else
  return backend::null_backend::make_thread_monitor();
#endif
}

} // namespace w1::monitor
