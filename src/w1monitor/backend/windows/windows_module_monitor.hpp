#pragma once

#include <memory>

#include "w1monitor/module_monitor.hpp"

namespace w1::monitor::backend::windows {

std::unique_ptr<module_monitor> make_module_monitor();

} // namespace w1::monitor::backend::windows
