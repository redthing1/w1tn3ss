#include "doctest/doctest.hpp"

#include <array>

#include "w1analysis/abi_dispatcher.hpp"
#include "w1runtime/module_registry.hpp"
#include "w1runtime/memory_reader.hpp"

TEST_CASE("abi_dispatcher extracts register arguments") {
  w1::runtime::module_registry modules;
  w1::util::memory_reader memory(nullptr, modules);
  w1::analysis::abi_dispatcher dispatcher;

  QBDI::GPRState gpr{};

#if defined(QBDI_ARCH_X86_64)
  gpr.rdi = 11;
  gpr.rsi = 22;
  gpr.rdx = 33;
  gpr.rcx = 44;
  gpr.r8 = 55;
  gpr.r9 = 66;

  auto args = dispatcher.extract_arguments(memory, &gpr, 3);
  REQUIRE(args.size() == 3);
  CHECK(args[0].raw_value == 11);
  CHECK(args[1].raw_value == 22);
  CHECK(args[2].raw_value == 33);
#elif defined(QBDI_ARCH_AARCH64)
  gpr.x0 = 11;
  gpr.x1 = 22;
  gpr.x2 = 33;
  gpr.x3 = 44;

  auto args = dispatcher.extract_arguments(memory, &gpr, 3);
  REQUIRE(args.size() == 3);
  CHECK(args[0].raw_value == 11);
  CHECK(args[1].raw_value == 22);
  CHECK(args[2].raw_value == 33);
#elif defined(QBDI_ARCH_X86)
  auto args = dispatcher.extract_arguments(memory, &gpr, 1);
  REQUIRE(args.size() == 1);
  CHECK(args[0].is_valid == false);
#else
  auto args = dispatcher.extract_arguments(memory, &gpr, 1);
  CHECK(args.empty() || args[0].is_valid == false);
#endif
}

TEST_CASE("abi_dispatcher extracts stack arguments") {
  w1::runtime::module_registry modules;
  w1::util::memory_reader memory(nullptr, modules);
  w1::analysis::abi_dispatcher dispatcher;

  QBDI::GPRState gpr{};

#if defined(QBDI_ARCH_X86_64) && !defined(_WIN32)
  std::array<uint64_t, 4> stack = {0xdead, 70, 80, 90};
  gpr.rsp = static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(stack.data()));

  auto args = dispatcher.extract_arguments(memory, &gpr, 7);
  REQUIRE(args.size() == 7);
  CHECK(args[6].raw_value == 70);
#elif defined(QBDI_ARCH_X86_64) && defined(_WIN32)
  std::array<uint64_t, 6> stack = {0xdead, 0, 0, 0, 0, 111};
  gpr.rsp = static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(stack.data()));

  auto args = dispatcher.extract_arguments(memory, &gpr, 5);
  REQUIRE(args.size() == 5);
  CHECK(args[4].raw_value == 111);
#elif defined(QBDI_ARCH_AARCH64)
  std::array<uint64_t, 2> stack = {99, 100};
  gpr.sp = static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(stack.data()));

  auto args = dispatcher.extract_arguments(memory, &gpr, 9);
  REQUIRE(args.size() == 9);
  CHECK(args[8].raw_value == 99);
#elif defined(QBDI_ARCH_X86)
  std::array<uint32_t, 2> stack = {123, 456};
  gpr.esp = static_cast<QBDI::rword>(reinterpret_cast<uintptr_t>(stack.data()));

  auto args = dispatcher.extract_arguments(memory, &gpr, 1);
  REQUIRE(args.size() == 1);
  CHECK(args[0].raw_value == 123);
#else
  auto args = dispatcher.extract_arguments(memory, &gpr, 1);
  CHECK(args.empty() || args[0].is_valid == false);
#endif
}
