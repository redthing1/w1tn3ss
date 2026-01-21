#include <algorithm>
#include <string>
#include <vector>

#include "doctest/doctest.hpp"

#include "tracers/w1rewind/memory_access_builder.hpp"
#include "tracers/w1rewind/register_delta_builder.hpp"
#include "tracers/w1rewind/register_schema.hpp"
#include "tracers/w1rewind/rewind_config.hpp"
#include "tracers/w1rewind/snapshot_builder.hpp"
#include "w1base/arch_spec.hpp"
#include "w1instrument/tracer/trace_context.hpp"
#include "w1runtime/memory_reader.hpp"
#include "w1runtime/module_registry.hpp"
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

size_t find_register_index(const std::vector<std::string>& names, const std::string& target) {
  auto it = std::find(names.begin(), names.end(), target);
  if (it == names.end()) {
    return names.size();
  }
  return static_cast<size_t>(std::distance(names.begin(), it));
}

} // namespace

TEST_CASE("register schema and delta builder track changes") {
  auto capture1 = capture_test_state(0x1111);
  auto capture2 = capture_test_state(0x2222);

  REQUIRE(!capture1.name.empty());
  REQUIRE(capture1.name == capture2.name);

  auto arch = w1::arch::detect_host_arch_spec();
  w1rewind::register_schema schema;
  schema.update(capture1.regs, arch);

  size_t reg_index = find_register_index(schema.names(), capture1.name);
  REQUIRE(reg_index < schema.names().size());

  std::optional<w1::util::register_state> last;
  auto deltas1 = w1rewind::capture_register_deltas(schema, capture1.regs, last);
  auto it1 = std::find_if(deltas1.begin(), deltas1.end(), [reg_index](const auto& delta) {
    return delta.reg_id == reg_index;
  });
  REQUIRE(it1 != deltas1.end());
  CHECK(it1->value == 0x1111);

  auto deltas2 = w1rewind::capture_register_deltas(schema, capture2.regs, last);
  CHECK(deltas2.size() == 1);
  CHECK(deltas2[0].reg_id == reg_index);
  CHECK(deltas2[0].value == 0x2222);
}

TEST_CASE("snapshot builder emits register snapshots on interval") {
  auto capture = capture_test_state(0xABCD);
  REQUIRE(!capture.name.empty());

  auto arch = w1::arch::detect_host_arch_spec();
  w1rewind::register_schema schema;
  schema.update(capture.regs, arch);

  w1rewind::rewind_config config;
  config.registers.snapshot_interval = 2;
  config.stack_snapshots.interval = 0;
  config.stack_window.mode = w1rewind::rewind_config::stack_window_options::mode::none;

  w1::runtime::module_registry modules;
  w1::util::memory_reader reader(nullptr, modules);
  w1::trace_context ctx(1, nullptr, &modules, &reader);

  w1rewind::snapshot_state state{};
  auto first = w1rewind::maybe_capture_snapshot(ctx, capture.regs, schema, config, state, redlog::get_logger("test"));
  CHECK(!first.has_value());

  auto second = w1rewind::maybe_capture_snapshot(ctx, capture.regs, schema, config, state, redlog::get_logger("test"));
  REQUIRE(second.has_value());
  CHECK(second->snapshot_id == 0);
  CHECK(state.snapshot_count == 1);

  size_t reg_index = find_register_index(schema.names(), capture.name);
  REQUIRE(reg_index < schema.names().size());
  auto it = std::find_if(second->registers.begin(), second->registers.end(), [reg_index](const auto& delta) {
    return delta.reg_id == reg_index;
  });
  REQUIRE(it != second->registers.end());
  CHECK(it->value == 0xABCD);
}

TEST_CASE("memory access builder captures inline values and truncation") {
  w1rewind::rewind_config config;
  config.memory.values = true;
  config.memory.max_value_bytes = 4;

  w1::runtime::module_registry modules;
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
      config, ctx, event, w1::rewind::memory_access_kind::read, segments, out, memory_events
  );

  REQUIRE(out.size() == 1);
  const auto& record = out.front();
  CHECK(record.address == 0x1000);
  CHECK(record.size == 8);
  CHECK(record.value_known);
  CHECK(record.value_truncated);
  CHECK(record.data.size() == 4);
  CHECK(record.data[0] == 0x88);
  CHECK(record.data[1] == 0x77);
  CHECK(record.data[2] == 0x66);
  CHECK(record.data[3] == 0x55);
  CHECK(memory_events == 1);
}
