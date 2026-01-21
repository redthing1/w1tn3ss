#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

offsets_component::offsets_component(const adapter_services& services) : services_(services) {}

std::optional<gdbstub::offsets_info> offsets_component::get_offsets_info() const {
  if (!services_.session || !services_.context || !services_.module_index) {
    return std::nullopt;
  }

  uint64_t pc = services_.session->current_step().address;
  auto match = services_.module_index->find(pc, 1);
  if (!match.has_value() || !match->module) {
    return std::nullopt;
  }
  const auto& module = *match->module;
  if ((module.flags & w1::rewind::module_record_flag_link_base_valid) == 0) {
    return std::nullopt;
  }
  if (module.base < module.link_base) {
    return std::nullopt;
  }
  uint64_t slide = module.base - module.link_base;
  return gdbstub::offsets_info::section(slide, slide, slide);
}

} // namespace w1replay::gdb
