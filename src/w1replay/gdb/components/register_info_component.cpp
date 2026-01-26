#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

register_info_component::register_info_component(const adapter_services& services) : services_(services) {}

std::optional<gdbstub::register_info> register_info_component::get_register_info(int regno) const {
  if (!services_.layout) {
    return std::nullopt;
  }
  if (regno < 0 || static_cast<size_t>(regno) >= services_.layout->registers.size()) {
    return std::nullopt;
  }
  const auto& reg = services_.layout->registers[static_cast<size_t>(regno)];
  gdbstub::register_info info{};
  info.name = reg.name;
  info.bitsize = static_cast<int>(reg.bits);
  info.encoding = "uint";
  info.format = "hex";
  info.set = "general";
  if (reg.is_pc) {
    info.generic = "pc";
  } else if (reg.is_sp) {
    info.generic = "sp";
  } else if (reg.is_flags) {
    info.generic = "flags";
  }
  if (reg.dwarf_regnum.has_value()) {
    info.dwarf_regnum = *reg.dwarf_regnum;
  }
  if (reg.gcc_regnum.has_value()) {
    info.gcc_regnum = *reg.gcc_regnum;
  }
  return info;
}

} // namespace w1replay::gdb
