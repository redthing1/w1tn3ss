#include <cstdint>
#include <string>
#include <vector>

#include <QBDI.h>
#include "doctest/doctest.hpp"

#include "tracers/w1rewind/engine/qbdi_register_schema_provider.hpp"
#include "tracers/w1rewind/engine/register_schema.hpp"
#include "tracers/w1rewind/engine/target_environment_provider.hpp"
#include "tracers/w1rewind/thread/stack_window_policy.hpp"
#include "w1base/arch_spec.hpp"
#include "w1runtime/register_capture.hpp"

namespace {

w1rewind::register_schema build_host_schema() {
  const auto host_arch = w1::arch::detect_host_arch_spec();
  const auto arch_desc = w1rewind::build_arch_descriptor(host_arch);
  w1rewind::qbdi_register_schema_provider provider{};
  std::vector<w1::rewind::register_spec> specs;
  std::string error;
  REQUIRE(provider.build_register_schema(arch_desc, specs, error));

  w1rewind::register_schema schema;
  schema.set_specs(std::move(specs));
  return schema;
}

} // namespace

TEST_CASE("stack window policy clamps fixed window size") {
  QBDI::GPRState gpr{};
#if defined(QBDI_ARCH_X86_64)
  gpr.rsp = 0x2000;
#elif defined(QBDI_ARCH_AARCH64)
  gpr.sp = 0x2000;
#elif defined(QBDI_ARCH_ARM)
  gpr.sp = 0x2000;
#elif defined(QBDI_ARCH_X86)
  gpr.esp = 0x2000;
#else
  return;
#endif

  auto regs = w1::util::register_capturer::capture(&gpr);
  w1rewind::rewind_config::stack_window_options options{};
  options.mode = w1rewind::rewind_config::stack_window_options::window_mode::fixed;
  options.above_bytes = 16;
  options.below_bytes = 32;
  options.max_total_bytes = 40;

  const auto schema = build_host_schema();
  auto result = w1rewind::compute_stack_window_segments(regs, schema, options);
  REQUIRE(result.segments.size() == 1);
  CHECK(result.segments[0].base == 0x2000 - 32);
  CHECK(result.segments[0].size == 40);
}

TEST_CASE("stack window policy emits frame window segment") {
  QBDI::GPRState gpr{};
  uint64_t sp = 0x2000;
  uint64_t fp = 0x2100;
  uint64_t expected_fp_base = 0;
  uint64_t expected_fp_size = 0;

#if defined(QBDI_ARCH_X86_64)
  gpr.rsp = sp;
  gpr.rbp = fp;
  expected_fp_base = fp;
  expected_fp_size = 16;
#elif defined(QBDI_ARCH_AARCH64)
  gpr.sp = sp;
  gpr.x29 = fp;
  expected_fp_base = fp;
  expected_fp_size = 16;
#elif defined(QBDI_ARCH_ARM)
  gpr.sp = sp;
  gpr.r11 = fp;
  expected_fp_base = fp;
  expected_fp_size = 8;
#elif defined(QBDI_ARCH_X86)
  gpr.esp = sp;
  gpr.ebp = fp;
  expected_fp_base = fp;
  expected_fp_size = 8;
#else
  return;
#endif

  auto regs = w1::util::register_capturer::capture(&gpr);
  w1rewind::rewind_config::stack_window_options options{};
  options.mode = w1rewind::rewind_config::stack_window_options::window_mode::frame;
  options.above_bytes = 16;
  options.below_bytes = 32;
  options.max_total_bytes = 128;

  const auto schema = build_host_schema();
  auto result = w1rewind::compute_stack_window_segments(regs, schema, options);
  REQUIRE(result.segments.size() == 2);

  bool saw_fp = false;
  for (const auto& segment : result.segments) {
    if (segment.base == expected_fp_base && segment.size == expected_fp_size) {
      saw_fp = true;
    }
  }
  CHECK(saw_fp);
  CHECK(!result.frame_window_missing);
}
