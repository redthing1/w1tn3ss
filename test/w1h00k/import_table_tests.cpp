#include "doctest/doctest.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "w1h00k/hook.hpp"

namespace {

#if defined(_WIN32)
static HMODULE g_expected_handle = nullptr;
static HMODULE WINAPI replacement_get_module_handle(LPCSTR) {
  return g_expected_handle;
}
#else
static pid_t g_expected_pid = 0;
static pid_t replacement_getpid() {
  return g_expected_pid;
}
#endif

w1::h00k::hook_request make_import_request(const char* symbol, void* replacement) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::import_slot;
  request.target.symbol = symbol;
  request.replacement = replacement;
#if defined(_WIN32)
  request.preferred = w1::h00k::hook_technique::iat;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::iat);
#else
  request.preferred = w1::h00k::hook_technique::plt_got;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::plt_got);
#endif
  return request;
}

} // namespace

TEST_CASE("w1h00k import-table hook replaces slot") {
#if defined(_WIN32)
  const HMODULE original = GetModuleHandleA(nullptr);
  g_expected_handle = reinterpret_cast<HMODULE>(0x12345678);
  REQUIRE(original != g_expected_handle);

  auto request = make_import_request("GetModuleHandleA", reinterpret_cast<void*>(&replacement_get_module_handle));
  void* original_ptr = nullptr;
  auto result = w1::h00k::attach(request, &original_ptr);
  REQUIRE(result.error.ok());

  CHECK(GetModuleHandleA(nullptr) == g_expected_handle);
  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
  CHECK(GetModuleHandleA(nullptr) == original);
#else
  const pid_t original = getpid();
  g_expected_pid = original + 1;

  auto request = make_import_request("getpid", reinterpret_cast<void*>(&replacement_getpid));
  void* original_ptr = nullptr;
  auto result = w1::h00k::attach(request, &original_ptr);
  REQUIRE(result.error.ok());

  CHECK(getpid() == g_expected_pid);
  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);
  CHECK(getpid() == original);
#endif
}
