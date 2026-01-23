#pragma once

#include <utility>

#include "config/script_config.hpp"
#include "runtime/script_runtime.hpp"

namespace w1::tracers::script {

// Public helpers for standalone usage.
template <typename Fn> decltype(auto) with_thread_runtime(script_config config, Fn&& fn) {
  auto runtime = make_script_runtime(std::move(config));
  return fn(runtime);
}

} // namespace w1::tracers::script
