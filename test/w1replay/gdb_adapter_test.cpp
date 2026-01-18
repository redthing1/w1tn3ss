#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include <redlog.hpp>

#include "w1replay/gdb/adapter.hpp"
#include "w1rewind/record/trace_writer.hpp"

#include "w1rewind/rewind_test_helpers.hpp"

namespace {

std::filesystem::path write_trace(
    const char* name,
    w1::rewind::trace_arch arch,
    uint32_t pointer_size,
    std::vector<std::string> registers,
    uint64_t module_offset,
    uint64_t module_base = 0x1000
) {
  using namespace w1::rewind::test_helpers;

  std::filesystem::path trace_path = temp_path(name);

  w1::rewind::trace_writer_config writer_config;
  writer_config.path = trace_path.string();
  writer_config.log = redlog::get_logger("test.w1replay.gdb");
  writer_config.chunk_size = 64;

  auto writer = w1::rewind::make_trace_writer(writer_config);
  REQUIRE(writer);
  REQUIRE(writer->open());

  w1::rewind::trace_header header{};
  header.architecture = arch;
  header.pointer_size = pointer_size;
  header.flags = w1::rewind::trace_flag_instructions;
  REQUIRE(writer->write_header(header));

  write_target_info(*writer, arch, pointer_size);
  write_register_specs(*writer, registers, arch, pointer_size);
  write_module_table(*writer, 1, module_base);
  write_thread_start(*writer, 1, "thread1");
  write_instruction(*writer, 1, 0, module_base + module_offset);
  write_thread_end(*writer, 1);

  writer->flush();
  writer->close();
  return trace_path;
}

bool has_reg_bitsize(const std::string& xml, const std::string& name, uint32_t bitsize) {
  std::string needle = "name=\"" + name + "\" bitsize=\"" + std::to_string(bitsize) + "\"";
  return xml.find(needle) != std::string::npos;
}

} // namespace

TEST_CASE("w1replay gdb adapter builds x86_64 target xml and pc") {
  auto trace_path = write_trace(
      "w1replay_gdb_x86_64.trace",
      w1::rewind::trace_arch::x86_64,
      8,
      {"rax", "rflags", "fs", "gs", "rip", "rsp"},
      0x1234
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
      "w1replay_gdb_arm64.trace",
      w1::rewind::trace_arch::aarch64,
      8,
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
