#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

namespace {
bool is_frame_pointer_name(const std::string& name) {
  return name == "fp" || name == "x29" || name == "rbp" || name == "ebp" || name == "r11" || name == "r7";
}
} // namespace

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
  switch (reg.reg_class) {
  case w1::rewind::register_class::fpr:
    info.encoding = "ieee754";
    info.format = "float";
    info.set = "float";
    break;
  case w1::rewind::register_class::simd:
    info.encoding = "vector";
    info.format = "vector-uint8";
    info.set = "vector";
    break;
  case w1::rewind::register_class::gpr:
  case w1::rewind::register_class::flags:
  case w1::rewind::register_class::system:
  case w1::rewind::register_class::unknown:
  default:
    info.encoding = "uint";
    info.format = "hex";
    info.set = "general";
    break;
  }
  if (reg.is_pc) {
    info.generic = "pc";
  } else if (reg.is_sp) {
    info.generic = "sp";
  } else if (reg.is_flags) {
    info.generic = "flags";
  } else if (is_frame_pointer_name(reg.name)) {
    info.generic = "fp";
  }
  if (reg.dwarf_regnum) {
    info.dwarf_regnum = *reg.dwarf_regnum;
  }
  if (reg.ehframe_regnum) {
    info.gcc_regnum = *reg.ehframe_regnum;
  }
  return info;
}

} // namespace w1replay::gdb
