#pragma once

#include <utility>

#include "config/transfer_config.hpp"
#include "runtime/transfer_runtime.hpp"

namespace w1xfer {

// public helpers for standalone usage
template <typename Fn> decltype(auto) with_runtime(transfer_config config, Fn&& fn) {
  auto runtime = make_transfer_runtime(std::move(config));
  return fn(runtime);
}

} // namespace w1xfer
