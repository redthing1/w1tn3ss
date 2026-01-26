#include "target_xml.hpp"

#include <sstream>

namespace w1replay::gdb {

namespace {

const char* type_for_reg(const register_desc& reg) {
  if (reg.is_pc) {
    return "code_ptr";
  }
  if (reg.is_sp) {
    return "data_ptr";
  }
  return "int";
}

const char* generic_for_reg(const register_desc& reg) {
  if (reg.is_pc) {
    return "pc";
  }
  if (reg.is_sp) {
    return "sp";
  }
  if (reg.is_flags) {
    return "flags";
  }
  if (reg.is_fp) {
    return "fp";
  }
  return nullptr;
}

} // namespace

std::string build_target_xml(const register_layout& layout) {
  if (layout.architecture.empty() || layout.registers.empty()) {
    return {};
  }

  std::ostringstream xml;
  xml << "<?xml version=\"1.0\"?>\n";
  xml << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
  xml << "<target version=\"1.0\">\n";
  xml << "  <architecture>" << layout.architecture << "</architecture>\n";
  xml << "  <feature name=\"" << layout.feature_name << "\">\n";
  for (size_t i = 0; i < layout.registers.size(); ++i) {
    const auto& reg = layout.registers[i];
    xml << "    <reg name=\"" << reg.name << "\" bitsize=\"" << reg.bits << "\" regnum=\"" << i << "\"";
    xml << " type=\"" << type_for_reg(reg) << "\"";
    if (reg.dwarf_regnum.has_value()) {
      xml << " dwarf_regnum=\"" << *reg.dwarf_regnum << "\"";
    }
    if (reg.gcc_regnum.has_value()) {
      xml << " gcc_regnum=\"" << *reg.gcc_regnum << "\"";
    }
    if (const char* generic = generic_for_reg(reg)) {
      xml << " generic=\"" << generic << "\"";
    }
    xml << " group=\"general\"";
    xml << "/>\n";
  }
  xml << "  </feature>\n";
  xml << "</target>\n";
  return xml.str();
}

} // namespace w1replay::gdb
