#pragma once

#include <memory>

#include "w1monitor/thread_monitor.hpp"

namespace w1::monitor::backend::darwin {

std::unique_ptr<thread_monitor> make_thread_monitor();

} // namespace w1::monitor::backend::darwin
