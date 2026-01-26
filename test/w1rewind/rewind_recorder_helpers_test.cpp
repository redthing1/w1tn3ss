#include <algorithm>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/thread/memory_access_builder.hpp"
#include "tracers/w1rewind/thread/register_delta_builder.hpp"
#include "tracers/w1rewind/engine/register_schema.hpp"
#include "tracers/w1rewind/engine/qbdi_register_schema_provider.hpp"
#include "tracers/w1rewind/config/rewind_config.hpp"
#include "tracers/w1rewind/thread/snapshot_builder.hpp"
#include "w1base/arch_spec.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/memory_reader.hpp"
#include "w1runtime/module_catalog.hpp"
#include "w1runtime/register_capture.hpp"

namespace {

const char* set_test_register(QBDI::GPRState& gpr, uint64_t value) {
#if defined(QBDI_ARCH_X86_64)
  gpr.rax = value;
  return "rax";
#elif defined(QBDI_ARCH_X86)
  gpr.eax = static_cast<uint32_t>(value);
  return "eax";
#elif defined(QBDI_ARCH_AARCH64)
  gpr.x0 = value;
  return "x0";
#elif defined(QBDI_ARCH_ARM)
  gpr.r0 = static_cast<uint32_t>(value);
  return "r0";
#else
  (void) gpr;
  (void) value;
  return "";
#endif
}

struct register_capture_result {
  std::string name;
  w1::util::register_state regs;
};

register_capture_result capture_test_state(uint64_t value) {
  QBDI::GPRState gpr{};
  const char* name = set_test_register(gpr, value);
  return {name, w1::util::register_capturer::capture(&gpr)};
}

w1::rewind::endian to_endian(w1::arch::byte_order order) {
  switch (order) {
  case w1::arch::byte_order::little:
    return w1::rewind::endian::little;
  case w1::arch::byte_order::big:
    return w1::rewind::endian::big;
  default:
    break;
  }
  return w1::rewind::endian::unknown;
}

std::string arch_mode_name(w1::arch::mode mode) {
  switch (mode) {
  case w1::arch::mode::x86_64:
    return "x86_64";
  case w1::arch::mode::x86_32:
    return "x86_32";
  case w1::arch::mode::arm:
    return "arm";
  case w1::arch::mode::thumb:
    return "thumb";
  case w1::arch::mode::aarch64:
    return "aarch64";
  case w1::arch::mode::riscv32:
    return "riscv32";
  case w1::arch::mode::riscv64:
    return "riscv64";
  case w1::arch::mode::mips32:
    return "mips32";
  case w1::arch::mode::mips64:
    return "mips64";
  case w1::arch::mode::ppc32:
    return "ppc32";
  case w1::arch::mode::ppc64:
    return "ppc64";
  case w1::arch::mode::sparc32:
    return "sparc32";
  case w1::arch::mode::sparc64:
    return "sparc64";
  case w1::arch::mode::systemz:
    return "systemz";
  case w1::arch::mode::wasm32:
    return "wasm32";
  case w1::arch::mode::wasm64:
    return "wasm64";
  default:
    break;
  }
  return "unknown";
}

w1::rewind::arch_descriptor_record build_arch_descriptor_from_spec(const w1::arch::arch_spec& arch) {
  w1::rewind::arch_descriptor_record record{};
  record.arch_id = arch_mode_name(arch.arch_mode);
  record.byte_order = to_endian(arch.arch_byte_order);
  record.pointer_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.address_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.gdb_arch = std::string(w1::arch::gdb_arch_name(arch));
  record.gdb_feature = std::string(w1::arch::gdb_feature_name(arch));
  if (arch.arch_family == w1::arch::family::arm && arch.arch_mode != w1::arch::mode::aarch64) {
    record.modes.push_back({0, "arm"});
    record.modes.push_back({1, "thumb"});
  } else {
    record.modes.push_back({0, record.arch_id});
  }
  return record;
}

} // namespace

TEST_CASE("register schema and delta builder track changes") {
  auto capture1 = capture_test_state(0x1111);
  auto capture2 = capture_test_state(0x2222);

  REQUIRE(!capture1.name.empty());
  REQUIRE(capture1.name == capture2.name);

  auto arch = w1::arch::detect_host_arch_spec();
  auto arch_desc = build_arch_descriptor_from_spec(arch);
  w1rewind::register_schema schema;
  w1rewind::qbdi_register_schema_provider provider;
  std::vector<w1::rewind::register_spec> specs;
  std::string error;
  REQUIRE(provider.build_register_schema(arch_desc, specs, error));
  schema.set_specs(std::move(specs));
  REQUIRE(schema.covers_registers(capture1.regs, error));

  const auto* spec = schema.find_spec(capture1.name);
  REQUIRE(spec != nullptr);
  uint32_t reg_id = spec->reg_id;

  std::optional<w1::util::register_state> last;
  auto deltas1 = w1rewind::capture_register_deltas(schema, capture1.regs, arch_desc.byte_order, last);
  auto it1 = std::find_if(deltas1.begin(), deltas1.end(), [reg_id](const auto& delta) {
    return delta.reg_id == reg_id;
  });
  REQUIRE(it1 != deltas1.end());
  REQUIRE(it1->value.size() >= 2);
  CHECK(it1->value[0] == 0x11);
  CHECK(it1->value[1] == 0x11);

  auto deltas2 = w1rewind::capture_register_deltas(schema, capture2.regs, arch_desc.byte_order, last);
  CHECK(deltas2.size() == 1);
  CHECK(deltas2[0].reg_id == reg_id);
  REQUIRE(deltas2[0].value.size() >= 2);
  CHECK(deltas2[0].value[0] == 0x22);
  CHECK(deltas2[0].value[1] == 0x22);
}

TEST_CASE("snapshot builder emits register snapshots on interval") {
  auto capture = capture_test_state(0xABCD);
  REQUIRE(!capture.name.empty());

  auto arch = w1::arch::detect_host_arch_spec();
  auto arch_desc = build_arch_descriptor_from_spec(arch);
  w1rewind::register_schema schema;
  w1rewind::qbdi_register_schema_provider provider;
  std::vector<w1::rewind::register_spec> specs;
  std::string error;
  REQUIRE(provider.build_register_schema(arch_desc, specs, error));
  schema.set_specs(std::move(specs));
  REQUIRE(schema.covers_registers(capture.regs, error));

  w1rewind::rewind_config config;
  config.registers.snapshot_interval = 2;
  config.stack_snapshots.interval = 0;
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::window_mode::none;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader reader(nullptr, modules);
  w1::trace_context ctx(1, nullptr, &modules, &reader);

  w1rewind::snapshot_state state{};
  auto first = w1rewind::maybe_capture_snapshot(
      ctx, capture.regs, schema, config, state, redlog::get_logger("test"), arch_desc.byte_order
  );
  CHECK(!first.has_value());

  auto second = w1rewind::maybe_capture_snapshot(
      ctx, capture.regs, schema, config, state, redlog::get_logger("test"), arch_desc.byte_order
  );
  REQUIRE(second.has_value());
  CHECK(second->snapshot_id == 0);
  CHECK(state.snapshot_count == 1);

  const auto* spec = schema.find_spec(capture.name);
  REQUIRE(spec != nullptr);
  uint32_t reg_id = spec->reg_id;
  auto it = std::find_if(second->registers.begin(), second->registers.end(), [reg_id](const auto& delta) {
    return delta.reg_id == reg_id;
  });
  REQUIRE(it != second->registers.end());
  REQUIRE(it->value.size() >= 2);
  CHECK(it->value[0] == 0xCD);
  CHECK(it->value[1] == 0xAB);
}

TEST_CASE("memory access builder captures inline values and truncation") {
  w1rewind::rewind_config config;
  config.memory.values = true;
  config.memory.max_value_bytes = 4;

  w1::runtime::module_catalog modules;
  w1::util::memory_reader reader(nullptr, modules);
  w1::trace_context ctx(1, nullptr, &modules, &reader);

  w1::memory_event event{};
  event.address = 0x1000;
  event.size = 8;
  event.value_valid = true;
  event.value = 0x1122334455667788ULL;
  event.is_read = true;
  event.is_write = false;

  std::vector<w1::address_range> segments = {
      {0x0FFF, 0x1000},
      {0x1000, 0x1008},
  };

  std::vector<w1rewind::pending_memory_access> out;
  uint64_t memory_events = 0;
  w1rewind::append_memory_access(
      config, ctx, event, w1::rewind::mem_access_op::read, segments, out, memory_events
  );

  REQUIRE(out.size() == 1);
  const auto& record = out.front();
  CHECK(record.address == 0x1000);
  CHECK(record.size == 8);
  CHECK((record.flags & w1::rewind::mem_access_value_known) != 0);
  CHECK((record.flags & w1::rewind::mem_access_value_truncated) != 0);
  CHECK(record.data.size() == 4);
  CHECK(record.data[0] == 0x88);
  CHECK(record.data[1] == 0x77);
  CHECK(record.data[2] == 0x66);
  CHECK(record.data[3] == 0x55);
  CHECK(memory_events == 1);
}
