#pragma once

#include <utility>

#include "config/coverage_config.hpp"
#include "runtime/coverage_runtime.hpp"

namespace w1cov {

// Public helpers for standalone usage.
template <typename Fn>
decltype(auto) with_process_runtime(coverage_config config, Fn&& fn) {
  auto runtime = make_process_runtime(std::move(config));
  return with_runtime(runtime, std::forward<Fn>(fn));
}

template <typename Fn>
decltype(auto) with_thread_runtime(coverage_config config, Fn&& fn) {
  auto runtime = make_thread_runtime(std::move(config));
  return with_runtime(runtime, std::forward<Fn>(fn));
}

} // namespace w1cov
