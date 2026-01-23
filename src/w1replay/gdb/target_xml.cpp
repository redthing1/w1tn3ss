#include "target_xml.hpp"

#include <algorithm>
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

  struct xml_reg_entry {
    const register_desc* reg = nullptr;
    size_t remote_regnum = 0;
    std::optional<int> dwarf_regnum;
    std::optional<int> ehframe_regnum;
  };

  std::vector<xml_reg_entry> entries;
  entries.reserve(layout.registers.size());
  for (size_t i = 0; i < layout.registers.size(); ++i) {
    const auto& reg = layout.registers[i];
    xml_reg_entry entry{};
    entry.reg = &reg;
    entry.remote_regnum = i;
    entry.dwarf_regnum = reg.dwarf_regnum;
    entry.ehframe_regnum = reg.ehframe_regnum;
    entries.push_back(entry);
  }

  std::stable_sort(entries.begin(), entries.end(), [](const xml_reg_entry& lhs, const xml_reg_entry& rhs) {
    if (lhs.dwarf_regnum && rhs.dwarf_regnum) {
      return *lhs.dwarf_regnum < *rhs.dwarf_regnum;
    }
    if (lhs.dwarf_regnum) {
      return true;
    }
    if (rhs.dwarf_regnum) {
      return false;
    }
    return lhs.remote_regnum < rhs.remote_regnum;
  });

  std::ostringstream xml;
  xml << "<?xml version=\"1.0\"?>\n";
  xml << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n";
  xml << "<target version=\"1.0\">\n";
  xml << "  <architecture>" << layout.architecture << "</architecture>\n";
  xml << "  <feature name=\"" << layout.feature_name << "\">\n";
  for (const auto& entry : entries) {
    const auto& reg = *entry.reg;
    xml << "    <reg name=\"" << reg.name << "\" bitsize=\"" << reg.bits << "\" regnum=\"" << entry.remote_regnum
        << "\"";
    if (entry.dwarf_regnum) {
      xml << " dwarf_regnum=\"" << *entry.dwarf_regnum << "\"";
    }
    if (entry.ehframe_regnum) {
      xml << " gcc_regnum=\"" << *entry.ehframe_regnum << "\"";
    }
    xml << " type=\"" << type_for_reg(reg) << "\"";
    if (const char* generic = generic_for_reg(reg)) {
      xml << " generic=\"" << generic << "\"";
    }
    xml << " group=\"" << group_for_class(reg.reg_class) << "\"";
    xml << "/>\n";
  }
  xml << "  </feature>\n";
  xml << "</target>\n";
  return xml.str();
}

} // namespace w1replay::gdb
