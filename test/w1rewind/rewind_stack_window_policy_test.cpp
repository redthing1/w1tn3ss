#include <cstdint>

#include <QBDI.h>
#include "doctest/doctest.hpp"

#include "tracers/w1rewind/thread/stack_window_policy.hpp"
#include "w1runtime/register_capture.hpp"

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

  auto result = w1rewind::compute_stack_window_segments(regs, options);
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

  auto result = w1rewind::compute_stack_window_segments(regs, options);
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
