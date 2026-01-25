#pragma once

#include <memory>

#include "w1monitor/module_monitor.hpp"

namespace w1::monitor::backend::null_backend {

std::unique_ptr<module_monitor> make_module_monitor();

} // namespace w1::monitor::backend::null_backend
