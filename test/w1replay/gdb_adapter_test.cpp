#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"

#include "w1rewind/rewind_test_helpers.hpp"

namespace {

std::filesystem::path write_trace(
    const char* name, std::string_view arch_id, const w1::arch::arch_spec& arch,
    std::vector<std::string> registers, uint64_t image_offset, uint64_t image_base = 0x1000
) {
  using namespace w1::rewind::test_helpers;

  std::filesystem::path trace_path = temp_path(name);

  auto header = make_header(0, 64);
  auto handle = open_trace(trace_path, header, redlog::get_logger("test.w1replay.gdb"));

  write_basic_metadata(handle.builder, arch_id, arch, registers);
  write_image_mapping(handle.builder, 1, image_base, 0x1000);
  write_thread_start(handle.builder, 1, "thread1");
  write_instruction(handle.builder, 1, 0, image_base + image_offset);
  write_thread_end(handle.builder, 1);

  handle.builder.flush();
  handle.writer->flush();
  handle.writer->close();
  return trace_path;
}

bool has_reg_bitsize(const std::string& xml, const std::string& name, uint32_t bitsize) {
  std::string needle = "name=\"" + name + "\" bitsize=\"" + std::to_string(bitsize) + "\"";
  return xml.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("w1replay gdb adapter builds x86_64 target xml and pc") {
  auto trace_path = write_trace(
      "w1replay_gdb_x86_64.trace", "x86_64", w1::rewind::test_helpers::parse_arch_or_fail("x86_64"),
      {"rax", "rflags", "fs", "gs", "rip", "rsp"}, 0x1234
  );

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  CHECK(adapter.session().current_step().address == 0x2234);

  const auto& arch = adapter.arch_spec();
  CHECK(arch.address_bits.has_value());
  CHECK(*arch.address_bits == 64);
  CHECK(arch.target_xml.find("<architecture>i386:x86-64</architecture>") != std::string::npos);
  CHECK(has_reg_bitsize(arch.target_xml, "eflags", 32));
  CHECK(has_reg_bitsize(arch.target_xml, "fs", 16));
  CHECK(has_reg_bitsize(arch.target_xml, "gs", 16));
}

TEST_CASE("w1replay gdb adapter encodes arm64 register sizes") {
  auto trace_path = write_trace(
      "w1replay_gdb_arm64.trace", "arm64", w1::rewind::test_helpers::parse_arch_or_fail("arm64"),
      {"x0", "sp", "pc", "nzcv"},
      0x2000
  );

  w1replay::gdb::adapter::config config;
  config.trace_path = trace_path.string();

  w1replay::gdb::adapter adapter(std::move(config));
  REQUIRE(adapter.open());

  const auto& arch = adapter.arch_spec();
  CHECK(arch.address_bits.has_value());
  CHECK(*arch.address_bits == 64);
  CHECK(arch.target_xml.find("<architecture>aarch64</architecture>") != std::string::npos);
  CHECK(has_reg_bitsize(arch.target_xml, "x0", 64));
  CHECK(has_reg_bitsize(arch.target_xml, "cpsr", 32));
}
