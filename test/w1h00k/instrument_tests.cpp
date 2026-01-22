#include "doctest/doctest.hpp"

#include <cstdint>
#include <cstring>

#include "w1h00k/hook.hpp"

namespace {

#if defined(_MSC_VER)
#define W1_NO_INLINE __declspec(noinline)
#else
#define W1_NO_INLINE __attribute__((noinline))
#endif

volatile int g_int_sink = 0;
volatile double g_fp_sink = 0.0;

W1_NO_INLINE double mixed_args(int a0,
                               double f0,
                               int a1,
                               float f1,
                               int a2,
                               int a3,
                               int a4,
                               int a5,
                               int a6,
                               int a7,
                               int a8) {
  int sum = a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8;
  double fsum = f0 + static_cast<double>(f1);
  g_int_sink = sum;
  g_fp_sink = fsum;
  return static_cast<double>(sum) + fsum;
}

struct capture_state {
  bool called = false;
  bool has_int0 = false;
  bool has_int1 = false;
  bool has_f0 = false;
  bool has_f1 = false;
  bool has_stack0 = false;
  int int0 = 0;
  int int1 = 0;
  int stack0 = 0;
  double f0 = 0.0;
  float f1 = 0.0f;
};

capture_state g_capture{};

int read_int_arg(const void* addr) {
  if (!addr) {
    return 0;
  }
  if constexpr (sizeof(void*) == 4) {
    int32_t value = 0;
    std::memcpy(&value, addr, sizeof(value));
    return static_cast<int>(value);
  }
  int64_t value = 0;
  std::memcpy(&value, addr, sizeof(value));
  return static_cast<int>(value);
}

double read_double_arg(const void* addr) {
  double value = 0.0;
  if (addr) {
    std::memcpy(&value, addr, sizeof(value));
  }
  return value;
}

float read_float_arg(const void* addr) {
  float value = 0.0f;
  if (addr) {
    std::memcpy(&value, addr, sizeof(value));
  }
  return value;
}

void prehook(w1::h00k::hook_info* info) {
  g_capture = {};
  g_capture.called = true;

  if (auto* ptr = w1::h00k::arg_get_int_reg_addr(info->args, 0)) {
    g_capture.int0 = read_int_arg(ptr);
    g_capture.has_int0 = true;
  }

  int int1_index = 1;
  int f0_index = 0;
  int f1_index = 1;

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
  int1_index = 2;
  f0_index = 1;
  f1_index = 3;
#endif

  if (auto* ptr = w1::h00k::arg_get_int_reg_addr(info->args, int1_index)) {
    g_capture.int1 = read_int_arg(ptr);
    g_capture.has_int1 = true;
  }

  if (auto* ptr = w1::h00k::arg_get_flt_reg_addr(info->args, f0_index)) {
    g_capture.f0 = read_double_arg(ptr);
    g_capture.has_f0 = true;
  }
  if (auto* ptr = w1::h00k::arg_get_flt_reg_addr(info->args, f1_index)) {
    g_capture.f1 = read_float_arg(ptr);
    g_capture.has_f1 = true;
  }

  if (auto* ptr = w1::h00k::arg_get_stack_addr(info->args, 0)) {
    g_capture.stack0 = read_int_arg(ptr);
    g_capture.has_stack0 = true;
  }
}

} // namespace

TEST_CASE("w1h00k instrumentation prehook captures arguments") {
  constexpr int a0 = 1;
  constexpr double f0 = 2.5;
  constexpr int a1 = 3;
  constexpr float f1 = 4.25f;
  constexpr int a2 = 5;
  constexpr int a3 = 6;
  constexpr int a4 = 7;
  constexpr int a5 = 8;
  constexpr int a6 = 9;
  constexpr int a7 = 10;
  constexpr int a8 = 11;

  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::address;
  request.target.address = reinterpret_cast<void*>(&mixed_args);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.kind = w1::h00k::hook_kind::instrument;
  request.prehook = &prehook;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());
  REQUIRE(original != nullptr);

  const double expected = static_cast<double>(a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8) +
                          f0 + static_cast<double>(f1);

  g_capture = {};
  double out = mixed_args(a0, f0, a1, f1, a2, a3, a4, a5, a6, a7, a8);
  CHECK(doctest::Approx(out) == expected);

  CHECK(g_capture.called);
#if defined(__aarch64__) || defined(_M_ARM64)
  const int expected_stack0 = a8;
#elif defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
  const int expected_stack0 = a2;
#elif defined(__x86_64__) || defined(_M_X64)
  const int expected_stack0 = a6;
#else
  const int expected_stack0 = a0;
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
  CHECK(g_capture.has_int0);
  CHECK(g_capture.int0 == a0);
  CHECK(g_capture.has_int1);
  CHECK(g_capture.int1 == a1);
  CHECK(g_capture.has_f0);
  CHECK(doctest::Approx(g_capture.f0) == f0);
  CHECK(g_capture.has_f1);
  CHECK(doctest::Approx(static_cast<double>(g_capture.f1)) == static_cast<double>(f1));
#else
  CHECK(!g_capture.has_int0);
  CHECK(!g_capture.has_int1);
  CHECK(!g_capture.has_f0);
  CHECK(!g_capture.has_f1);
#endif

  CHECK(g_capture.has_stack0);
  CHECK(g_capture.stack0 == expected_stack0);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);

  g_capture = {};
  out = mixed_args(a0, f0, a1, f1, a2, a3, a4, a5, a6, a7, a8);
  CHECK(doctest::Approx(out) == expected);
  CHECK(!g_capture.called);
}

#if defined(_WIN32) && defined(_M_IX86)
W1_NO_INLINE int __fastcall fastcall_add(int a, int b, int c) {
  int result = a + b + c;
  g_int_sink = result;
  return result;
}

struct fastcall_state {
  bool called = false;
  int a = 0;
  int b = 0;
};

fastcall_state g_fastcall{};

void prehook_fastcall(w1::h00k::hook_info* info) {
  g_fastcall = {};
  g_fastcall.called = true;
  if (auto* ptr = w1::h00k::arg_get_int_reg_addr(info->args, 0)) {
    g_fastcall.a = read_int_arg(ptr);
  }
  if (auto* ptr = w1::h00k::arg_get_int_reg_addr(info->args, 1)) {
    g_fastcall.b = read_int_arg(ptr);
  }
}

TEST_CASE("w1h00k instrumentation supports win32 fastcall") {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::address;
  request.target.address = reinterpret_cast<void*>(&fastcall_add);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.kind = w1::h00k::hook_kind::instrument;
  request.call_abi = w1::h00k::hook_call_abi::win32_fastcall;
  request.prehook = &prehook_fastcall;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());

  g_fastcall = {};
  CHECK(fastcall_add(1, 2, 3) == 6);
  CHECK(g_fastcall.called);
  CHECK(g_fastcall.a == 1);
  CHECK(g_fastcall.b == 2);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}
#endif

#if defined(_WIN32) && defined(_M_X64) && defined(_MSC_VER)
W1_NO_INLINE double __vectorcall vectorcall_sum(double a, double b, double c, double d, double e, double f) {
  double result = a + b + c + d + e + f;
  g_fp_sink = result;
  return result;
}

struct vectorcall_state {
  bool called = false;
  double e = 0.0;
  double f = 0.0;
};

vectorcall_state g_vectorcall{};

void prehook_vectorcall(w1::h00k::hook_info* info) {
  g_vectorcall = {};
  g_vectorcall.called = true;
  if (auto* ptr = w1::h00k::arg_get_flt_reg_addr(info->args, 4)) {
    g_vectorcall.e = read_double_arg(ptr);
  }
  if (auto* ptr = w1::h00k::arg_get_flt_reg_addr(info->args, 5)) {
    g_vectorcall.f = read_double_arg(ptr);
  }
}

TEST_CASE("w1h00k instrumentation supports win64 vectorcall registers") {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::address;
  request.target.address = reinterpret_cast<void*>(&vectorcall_sum);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.kind = w1::h00k::hook_kind::instrument;
  request.call_abi = w1::h00k::hook_call_abi::win64_vectorcall;
  request.prehook = &prehook_vectorcall;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());

  g_vectorcall = {};
  CHECK(doctest::Approx(vectorcall_sum(1.0, 2.0, 3.0, 4.0, 5.0, 6.0)) == 21.0);
  CHECK(g_vectorcall.called);
  CHECK(doctest::Approx(g_vectorcall.e) == 5.0);
  CHECK(doctest::Approx(g_vectorcall.f) == 6.0);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}
#endif
