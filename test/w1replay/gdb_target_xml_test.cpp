#include <string>

#include "doctest/doctest.hpp"

#include "w1replay/gdb/layout.hpp"
#include "w1replay/gdb/target_xml.hpp"
#include "w1rewind/rewind_test_helpers.hpp"

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
  std::vector<std::string> regs = {"x0", "x1", "lr", "sp", "pc", "nzcv"};
  auto arch = w1::rewind::test_helpers::parse_arch_or_fail("arm64");
  auto specs = w1::rewind::test_helpers::make_register_specs(regs, arch);
  auto layout = w1replay::gdb::build_register_layout(arch, specs);

  auto xml = w1replay::gdb::build_target_xml(layout);
  CHECK(xml.find("<architecture>aarch64</architecture>") != std::string::npos);
  CHECK(xml_has_reg(xml, "x0", 0));
  CHECK(xml_has_reg(xml, "lr", 2));
  CHECK(xml_has_reg(xml, "sp", 3));
  CHECK(xml_has_reg(xml, "pc", 4));
  CHECK(xml_has_reg(xml, "cpsr", 5));
}
