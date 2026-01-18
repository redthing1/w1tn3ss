#include <string>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/layout.hpp"
#include "w1replay/gdb/target_xml.hpp"

namespace {

bool xml_has_reg(const std::string& xml, const std::string& name, size_t regnum) {
  std::string needle = "name=\"" + name + "\"";
  std::string regnum_text = "regnum=\"" + std::to_string(regnum) + "\"";
  auto pos = xml.find(needle);
  if (pos == std::string::npos) {
    return false;
  }
  return xml.find(regnum_text, pos) != std::string::npos;
}

} // namespace

TEST_CASE("gdb target xml encodes architecture and regnums") {
  auto layout = w1replay::gdb::build_register_layout(
      w1::rewind::trace_arch::aarch64,
      8,
      {"x0", "x1", "lr", "sp", "pc", "nzcv"}
  );

  auto xml = w1replay::gdb::build_target_xml(layout);
  CHECK(xml.find("<architecture>aarch64</architecture>") != std::string::npos);
  CHECK(xml_has_reg(xml, "x0", 0));
  CHECK(xml_has_reg(xml, "x30", 30));
  CHECK(xml_has_reg(xml, "sp", 31));
  CHECK(xml_has_reg(xml, "pc", 32));
  CHECK(xml_has_reg(xml, "cpsr", 33));
}
