#include "doctest/doctest.hpp"

#include <cstdint>

#include "w1h00k/hook.hpp"

namespace {

#if defined(_MSC_VER)
#define W1_NO_INLINE __declspec(noinline)
#else
#define W1_NO_INLINE __attribute__((noinline))
#endif

volatile int g_sink = 0;

W1_NO_INLINE int add_one(int value) {
  int result = value + 1;
  g_sink = result;
  return result;
}

W1_NO_INLINE int add_ten(int value) {
  int result = value + 10;
  g_sink = result;
  return result;
}

W1_NO_INLINE int mul_two(int value) {
  int result = value * 2;
  g_sink = result;
  return result;
}

W1_NO_INLINE int mul_three(int value) {
  int result = value * 3;
  g_sink = result;
  return result;
}

} // namespace

TEST_CASE("w1h00k inline hook replaces and detaches") {
  using fn_t = int (*)(int);
  fn_t target = &add_one;
  fn_t replacement = &add_ten;

  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(target);
  request.replacement = reinterpret_cast<void*>(replacement);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error == w1::h00k::hook_error::ok);
  REQUIRE(original != nullptr);

  CHECK(target(1) == 11);
  auto orig_fn = reinterpret_cast<fn_t>(original);
  CHECK(orig_fn(1) == 2);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
  CHECK(target(1) == 2);
}

TEST_CASE("w1h00k inline hook rejects invalid target") {
  w1::h00k::hook_request request{};
  request.replacement = reinterpret_cast<void*>(&add_ten);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  CHECK(result.error == w1::h00k::hook_error::invalid_target);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook respects allowed mask") {
  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(&add_one);
  request.replacement = reinterpret_cast<void*>(&add_ten);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  CHECK(result.error == w1::h00k::hook_error::unsupported);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook rejects duplicate attach") {
  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(&add_one);
  request.replacement = reinterpret_cast<void*>(&add_ten);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error == w1::h00k::hook_error::ok);

  auto duplicate = w1::h00k::attach(request, nullptr);
  CHECK(duplicate.error == w1::h00k::hook_error::already_hooked);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}

TEST_CASE("w1h00k inline hook detach handles missing handle") {
  w1::h00k::hook_handle handle{};
  handle.id = 9999;
  CHECK(w1::h00k::detach(handle) == w1::h00k::hook_error::not_found);
}

TEST_CASE("w1h00k inline hook transaction attach") {
  using fn_t = int (*)(int);
  fn_t target = &mul_two;
  fn_t replacement = &mul_three;

  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(target);
  request.replacement = reinterpret_cast<void*>(replacement);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  w1::h00k::hook_transaction txn;
  void* original = nullptr;
  auto result = txn.attach(request, &original);
  REQUIRE(result.error == w1::h00k::hook_error::ok);
  REQUIRE(original != nullptr);
  REQUIRE(result.handle.id != 0);

  CHECK(txn.commit() == w1::h00k::hook_error::ok);
  CHECK(target(3) == 9);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
  CHECK(target(3) == 6);
}

TEST_CASE("w1h00k inline transaction abort leaves target untouched") {
  using fn_t = int (*)(int);
  fn_t target = &add_one;
  fn_t replacement = &add_ten;

  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(target);
  request.replacement = reinterpret_cast<void*>(replacement);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  w1::h00k::hook_handle handle{};
  {
    w1::h00k::hook_transaction txn;
    auto result = txn.attach(request, nullptr);
    REQUIRE(result.error == w1::h00k::hook_error::ok);
    handle = result.handle;
  }

  CHECK(target(1) == 2);
  CHECK(w1::h00k::detach(handle) == w1::h00k::hook_error::not_found);
}

TEST_CASE("w1h00k inline hook stress") {
  using fn_t = int (*)(int);
  fn_t target = &add_one;
  fn_t replacement = &add_ten;

  w1::h00k::hook_request request{};
  request.target.address = reinterpret_cast<void*>(target);
  request.replacement = reinterpret_cast<void*>(replacement);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error == w1::h00k::hook_error::ok);

  int sum = 0;
  for (int i = 0; i < 10000; ++i) {
    sum += target(i);
  }
  CHECK(sum > 0);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}
