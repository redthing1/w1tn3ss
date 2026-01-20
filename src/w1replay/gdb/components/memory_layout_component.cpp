#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/memory_map.hpp"

namespace w1replay::gdb {

memory_layout_component::memory_layout_component(adapter_state& state) : state_(state) {}

std::vector<gdbstub::memory_region> memory_layout_component::memory_map() const {
  const auto* replay_state = (state_.session && state_.track_memory) ? state_.session->state() : nullptr;
  return build_memory_map(state_.context.modules, state_.context.memory_map, replay_state);
}

} // namespace w1replay::gdb
