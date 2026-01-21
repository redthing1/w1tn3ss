#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/memory_map.hpp"

namespace w1replay::gdb {

memory_layout_component::memory_layout_component(const adapter_services& services) : services_(services) {}

std::vector<gdbstub::memory_region> memory_layout_component::memory_map() const {
  if (!services_.context) {
    return {};
  }
  const auto* replay_state = (services_.session && services_.track_memory) ? services_.session->state() : nullptr;
  return build_memory_map(
      services_.context->modules, services_.context->memory_map, replay_state, services_.module_resolver
  );
}

} // namespace w1replay::gdb
