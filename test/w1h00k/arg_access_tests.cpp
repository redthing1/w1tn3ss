#include "doctest/doctest.hpp"

#include <cstdint>

#include "w1h00k/core/hook_args.hpp"
#include "w1h00k/hook.hpp"

namespace {

uintptr_t addr(const void* ptr) { return reinterpret_cast<uintptr_t>(ptr); }

} // namespace

TEST_CASE("w1h00k arg accessors honor ABI layouts") {
  alignas(16) uint8_t int_regs[8 * sizeof(void*)] = {};
  alignas(16) uint8_t flt_regs[16 * 8] = {};
  alignas(16) uint8_t stack[128] = {};

  w1::h00k::hook_arg_handle args{};
  args.int_regs = int_regs;
  args.flt_regs = flt_regs;
  args.stack = stack;

  if constexpr (sizeof(void*) == 8) {
    args.abi = w1::h00k::hook_call_abi::sysv;
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 0)) == addr(int_regs));
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 5)) == addr(int_regs + 5 * 8));
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 6) == nullptr);
    CHECK(addr(w1::h00k::arg_get_flt_reg_addr(&args, 7)) == addr(flt_regs + 7 * 16));
    CHECK(w1::h00k::arg_get_flt_reg_addr(&args, 8) == nullptr);
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack + 8));

    args.abi = w1::h00k::hook_call_abi::win64;
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 3)) == addr(int_regs + 3 * 8));
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 4) == nullptr);
    CHECK(addr(w1::h00k::arg_get_flt_reg_addr(&args, 3)) == addr(flt_regs + 3 * 16));
    CHECK(w1::h00k::arg_get_flt_reg_addr(&args, 4) == nullptr);
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack + 40));

    args.abi = w1::h00k::hook_call_abi::win64_vectorcall;
    CHECK(addr(w1::h00k::arg_get_flt_reg_addr(&args, 5)) == addr(flt_regs + 5 * 16));
    CHECK(w1::h00k::arg_get_flt_reg_addr(&args, 6) == nullptr);

    args.abi = w1::h00k::hook_call_abi::aapcs64;
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 7)) == addr(int_regs + 7 * 8));
    CHECK(addr(w1::h00k::arg_get_flt_reg_addr(&args, 7)) == addr(flt_regs + 7 * 16));
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack));
  } else {
    args.abi = w1::h00k::hook_call_abi::sysv;
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 0) == nullptr);
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack + 4));

    args.abi = w1::h00k::hook_call_abi::win32_cdecl;
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 0) == nullptr);
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack + 4));

    args.abi = w1::h00k::hook_call_abi::win32_fastcall;
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 1)) == addr(int_regs + 1 * 4));
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 2) == nullptr);
    CHECK(addr(w1::h00k::arg_get_stack_addr(&args, 0)) == addr(stack + 4));

    args.abi = w1::h00k::hook_call_abi::win32_thiscall;
    CHECK(addr(w1::h00k::arg_get_int_reg_addr(&args, 0)) == addr(int_regs));
    CHECK(w1::h00k::arg_get_int_reg_addr(&args, 1) == nullptr);
  }
}
