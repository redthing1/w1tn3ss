#include "doctest/doctest.hpp"

#include <cstdint>
#include <string>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

#include "w1h00k/hook.hpp"
#include "test_paths.hpp"

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

#if defined(_WIN32)
using interpose_lib_fn = HMODULE (*)();
static HMODULE g_expected_handle = nullptr;

static HMODULE WINAPI replacement_interpose() {
  return g_expected_handle;
}
#else
using interpose_lib_fn = pid_t (*)();
static pid_t g_expected_pid = 0;

static pid_t replacement_interpose() {
  return g_expected_pid;
}
#endif

struct interpose_library {
#if defined(_WIN32)
  HMODULE handle = nullptr;
#else
  void* handle = nullptr;
#endif

  explicit interpose_library(const std::string& path) {
#if defined(_WIN32)
    handle = LoadLibraryA(path.c_str());
#else
    handle = dlopen(path.c_str(), RTLD_NOW);
#endif
  }

  ~interpose_library() {
#if defined(_WIN32)
    if (handle) {
      FreeLibrary(handle);
    }
#else
    if (handle) {
      dlclose(handle);
    }
#endif
  }

  interpose_library(const interpose_library&) = delete;
  interpose_library& operator=(const interpose_library&) = delete;
};

interpose_lib_fn load_interpose_symbol(
#if defined(_WIN32)
    HMODULE handle
#else
    void* handle
#endif
) {
  if (!handle) {
    return nullptr;
  }
#if defined(_WIN32)
  return reinterpret_cast<interpose_lib_fn>(GetProcAddress(handle, "w1h00k_interpose_get_module_handle"));
#else
  return reinterpret_cast<interpose_lib_fn>(dlsym(handle, "w1h00k_interpose_getpid"));
#endif
}

w1::h00k::hook_request make_inline_request(void* target, void* replacement) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::address;
  request.target.address = target;
  request.replacement = replacement;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  return request;
}

} // namespace

TEST_CASE("w1h00k inline hook replaces and detaches") {
  using fn_t = int (*)(int);
  fn_t target = &add_one;
  fn_t replacement = &add_ten;

  auto request = make_inline_request(reinterpret_cast<void*>(target), reinterpret_cast<void*>(replacement));

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());
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
  CHECK(result.error.code == w1::h00k::hook_error::invalid_target);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook respects allowed mask") {
  auto request = make_inline_request(reinterpret_cast<void*>(&add_one), reinterpret_cast<void*>(&add_ten));
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  CHECK(result.error.code == w1::h00k::hook_error::unsupported);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook rejects missing preferred backend") {
  auto request = make_inline_request(reinterpret_cast<void*>(&add_one), reinterpret_cast<void*>(&add_ten));
  request.preferred = w1::h00k::hook_technique::interpose;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose) |
                    w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  CHECK(result.error.code == w1::h00k::hook_error::unsupported);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook falls back when allowed") {
  auto request = make_inline_request(reinterpret_cast<void*>(&add_one), reinterpret_cast<void*>(&add_ten));
  request.preferred = w1::h00k::hook_technique::interpose;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose) |
                    w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.selection = w1::h00k::hook_selection::allow_fallback;

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());
  CHECK(original != nullptr);
  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}

TEST_CASE("w1h00k inline hook reports unresolved symbol") {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = "w1h00k_missing_symbol";
  request.replacement = reinterpret_cast<void*>(&add_ten);
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  CHECK(result.error.code == w1::h00k::hook_error::not_found);
  CHECK(original == nullptr);
}

TEST_CASE("w1h00k inline hook rejects duplicate attach") {
  auto request = make_inline_request(reinterpret_cast<void*>(&add_one), reinterpret_cast<void*>(&add_ten));

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());

  auto duplicate = w1::h00k::attach(request, nullptr);
  CHECK(duplicate.error.code == w1::h00k::hook_error::already_hooked);

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

  auto request = make_inline_request(reinterpret_cast<void*>(target), reinterpret_cast<void*>(replacement));

  w1::h00k::hook_transaction txn;
  void* original = nullptr;
  auto result = txn.attach(request, &original);
  REQUIRE(result.error.ok());
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

  auto request = make_inline_request(reinterpret_cast<void*>(target), reinterpret_cast<void*>(replacement));

  w1::h00k::hook_handle handle{};
  {
    w1::h00k::hook_transaction txn;
    auto result = txn.attach(request, nullptr);
    REQUIRE(result.error.ok());
    handle = result.handle;
  }

  CHECK(target(1) == 2);
  CHECK(w1::h00k::detach(handle) == w1::h00k::hook_error::not_found);
}

TEST_CASE("w1h00k inline hook stress") {
  using fn_t = int (*)(int);
  fn_t target = &add_one;
  fn_t replacement = &add_ten;

  auto request = make_inline_request(reinterpret_cast<void*>(target), reinterpret_cast<void*>(replacement));

  void* original = nullptr;
  auto result = w1::h00k::attach(request, &original);
  REQUIRE(result.error.ok());

  int sum = 0;
  for (int i = 0; i < 10000; ++i) {
    sum += target(i);
  }
  CHECK(sum > 0);

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
}

TEST_CASE("w1h00k inline hook resolves symbols in loaded modules") {
  const auto lib_path = w1::test_paths::interpose_library_path();
  interpose_library lib(lib_path);
  REQUIRE(lib.handle != nullptr);
  auto entry = load_interpose_symbol(lib.handle);
  REQUIRE(entry != nullptr);

#if defined(_WIN32)
  const HMODULE original = entry();
  g_expected_handle = reinterpret_cast<HMODULE>(0x12345678);
  REQUIRE(original != g_expected_handle);

  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = "w1h00k_interpose_get_module_handle";
  request.target.module = w1::test_paths::interpose_library_name();
  request.replacement = reinterpret_cast<void*>(&replacement_interpose);
  request.preferred = w1::h00k::hook_technique::inline_trampoline;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.selection = w1::h00k::hook_selection::strict;
#else
  const pid_t original = entry();
  g_expected_pid = original + 1;

  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = "w1h00k_interpose_getpid";
  request.target.module = w1::test_paths::interpose_library_name();
  request.replacement = reinterpret_cast<void*>(&replacement_interpose);
  request.preferred = w1::h00k::hook_technique::inline_trampoline;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::inline_trampoline);
  request.selection = w1::h00k::hook_selection::strict;
#endif

  void* original_ptr = nullptr;
  auto result = w1::h00k::attach(request, &original_ptr);
  REQUIRE(result.error.ok());
  REQUIRE(original_ptr != nullptr);

#if defined(_WIN32)
  CHECK(entry() == g_expected_handle);
  auto orig_fn = reinterpret_cast<interpose_lib_fn>(original_ptr);
  CHECK(orig_fn() == original);
#else
  CHECK(entry() == g_expected_pid);
  auto orig_fn = reinterpret_cast<interpose_lib_fn>(original_ptr);
  CHECK(orig_fn() == original);
#endif

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
  CHECK(entry() == original);
}
