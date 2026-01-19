#include "target_xml.hpp"

#include <sstream>

namespace w1replay::gdb {

namespace {

const char* group_for_class(w1::rewind::register_class cls) {
  switch (cls) {
  case w1::rewind::register_class::fpr:
    return "float";
  case w1::rewind::register_class::simd:
    return "vector";
  case w1::rewind::register_class::gpr:
  case w1::rewind::register_class::flags:
  case w1::rewind::register_class::system:
  case w1::rewind::register_class::unknown:
  default:
    return "general";
  }
}

const char* type_for_reg(const register_desc& reg) {
  if (reg.is_pc) {
    return "code_ptr";
  }
  if (reg.is_sp) {
    return "data_ptr";
  }
  if (reg.reg_class == w1::rewind::register_class::fpr) {
    return "float";
  }
  return "int";
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
    xml << " group=\"" << group_for_class(reg.reg_class) << "\"";
    xml << "/>\n";
  }
  xml << "  </feature>\n";
  xml << "</target>\n";
  return xml.str();
}

} // namespace w1replay::gdb
