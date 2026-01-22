#pragma once

#include <memory>
#include <optional>

#include <QBDI.h>

namespace w1::instrument {

template <typename Policy>
struct preload_state {
  using config_type = typename Policy::config_type;
  using runtime_type = typename Policy::runtime_type;

  std::optional<config_type> config{};
  std::unique_ptr<runtime_type> runtime{};
};

template <typename Policy>
bool preload_run(
    preload_state<Policy>& state, const void* self_anchor, QBDI::VMInstanceRef vm, QBDI::rword start, QBDI::rword stop
) {
  state.config = Policy::load_config();
  Policy::configure_logging(*state.config);
  if (Policy::should_exclude_self(*state.config)) {
    Policy::apply_self_excludes(*state.config, self_anchor);
  }

  state.runtime = Policy::create_runtime(*state.config, vm);
  if (!state.runtime) {
    return false;
  }

  return Policy::run(*state.runtime, vm, start, stop);
}

template <typename Policy>
void preload_shutdown(preload_state<Policy>& state, int status) {
  if (state.runtime && state.config) {
    Policy::shutdown(*state.runtime, status, *state.config);
  }
  state.runtime.reset();
  state.config.reset();
}

} // namespace w1::instrument
