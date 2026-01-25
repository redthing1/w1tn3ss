#pragma once

#include <memory>

#include "w1monitor/module_monitor.hpp"
#include "w1monitor/thread_monitor.hpp"

namespace w1::monitor {

std::unique_ptr<module_monitor> make_module_monitor();
std::unique_ptr<thread_monitor> make_thread_monitor();

} // namespace w1::monitor
