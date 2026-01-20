#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

offsets_component::offsets_component(adapter_state& state) : state_(state) {}

std::optional<gdbstub::offsets_info> offsets_component::get_offsets_info() const {
  auto pc = state_.current_pc();
  if (!pc.has_value()) {
    return std::nullopt;
  }

  uint64_t module_offset = 0;
  auto* module = state_.context.find_module_for_address(*pc, 1, module_offset);
  if (!module) {
    return std::nullopt;
  }

  std::string error;
  const auto* layout = state_.module_source_state.get_module_layout(*module, error);
  if (!layout) {
    return std::nullopt;
  }

  if (module->base < layout->link_base) {
    return std::nullopt;
  }
  uint64_t slide = module->base - layout->link_base;
  return gdbstub::offsets_info::section(slide, slide, slide);
}

} // namespace w1replay::gdb
