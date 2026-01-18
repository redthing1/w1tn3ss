#include "target_xml.hpp"

#include <sstream>

namespace w1replay::gdb {

std::string build_target_xml(const register_layout& layout) {
  if (layout.architecture.empty() || layout.registers.empty()) {
    return {};
  }

  std::ostringstream xml;
  xml << "<?xml version=\"1.0\"?>\n";
  xml << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
  xml << "<target>\n";
  xml << "  <architecture>" << layout.architecture << "</architecture>\n";
  xml << "  <feature name=\"" << layout.feature_name << "\">\n";
  for (size_t i = 0; i < layout.registers.size(); ++i) {
    const auto& reg = layout.registers[i];
    xml << "    <reg name=\"" << reg.name << "\" bitsize=\"" << reg.bits << "\" regnum=\"" << i << "\"";
    if (reg.is_pc) {
      xml << " type=\"code_ptr\"";
    } else if (reg.is_sp) {
      xml << " type=\"data_ptr\"";
    } else {
      xml << " type=\"int\"";
    }
    xml << "/>\n";
  }
  xml << "  </feature>\n";
  xml << "</target>\n";
  return xml.str();
}

} // namespace w1replay::gdb
