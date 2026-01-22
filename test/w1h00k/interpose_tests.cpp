#include "doctest/doctest.hpp"

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

#if defined(_WIN32)
constexpr const char* kInterposeLibName = "w1h00k_interpose_lib.dll";
using interpose_lib_fn = HMODULE (*)();
static HMODULE g_expected_handle = nullptr;

static HMODULE WINAPI replacement_get_module_handle(LPCSTR) {
  return g_expected_handle;
}
#else
#if defined(__APPLE__)
constexpr const char* kInterposeLibName = "w1h00k_interpose_lib.dylib";
#else
constexpr const char* kInterposeLibName = "w1h00k_interpose_lib.so";
#endif
using interpose_lib_fn = pid_t (*)();
static pid_t g_expected_pid = 0;

static pid_t replacement_getpid() {
  return g_expected_pid;
}
#endif

std::string interpose_library_path() {
  return w1::h00k::test_paths::test_library_path(kInterposeLibName);
}

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

interpose_lib_fn load_interpose_entry(
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

w1::h00k::hook_request make_interpose_request(const char* symbol, void* replacement) {
  w1::h00k::hook_request request{};
  request.target.kind = w1::h00k::hook_target_kind::symbol;
  request.target.symbol = symbol;
  request.replacement = replacement;
  request.preferred = w1::h00k::hook_technique::interpose;
  request.allowed = w1::h00k::technique_mask(w1::h00k::hook_technique::interpose);
  return request;
}

} // namespace

TEST_CASE("w1h00k interpose hooks loaded modules") {
  const auto lib_path = interpose_library_path();
  interpose_library lib(lib_path);
  REQUIRE(lib.handle != nullptr);
  auto entry = load_interpose_entry(lib.handle);
  REQUIRE(entry != nullptr);

#if defined(_WIN32)
  const HMODULE original_main = GetModuleHandleA(nullptr);
  const HMODULE original_lib = entry();
  g_expected_handle = reinterpret_cast<HMODULE>(0x12345678);
  REQUIRE(original_main != g_expected_handle);

  auto request = make_interpose_request("GetModuleHandleA",
                                        reinterpret_cast<void*>(&replacement_get_module_handle));
#else
  const pid_t original_main = getpid();
  const pid_t original_lib = entry();
  g_expected_pid = original_main + 1;

  auto request = make_interpose_request("getpid", reinterpret_cast<void*>(&replacement_getpid));
#endif

  void* original_ptr = nullptr;
  auto result = w1::h00k::attach(request, &original_ptr);
  REQUIRE(result.error.ok());

#if defined(_WIN32)
  CHECK(GetModuleHandleA(nullptr) == g_expected_handle);
  CHECK(entry() == g_expected_handle);
#else
  CHECK(getpid() == g_expected_pid);
  CHECK(entry() == g_expected_pid);
#endif

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);

#if defined(_WIN32)
  CHECK(GetModuleHandleA(nullptr) == original_main);
  CHECK(entry() == original_lib);
#else
  CHECK(getpid() == original_main);
  CHECK(entry() == original_lib);
#endif
}

TEST_CASE("w1h00k interpose respects module filter") {
  const auto lib_path = interpose_library_path();
  interpose_library lib(lib_path);
  REQUIRE(lib.handle != nullptr);
  auto entry = load_interpose_entry(lib.handle);
  REQUIRE(entry != nullptr);

#if defined(_WIN32)
  const HMODULE original_main = GetModuleHandleA(nullptr);
  const HMODULE original_lib = entry();
  g_expected_handle = reinterpret_cast<HMODULE>(0x76543210);
  REQUIRE(original_main != g_expected_handle);

  auto request = make_interpose_request("GetModuleHandleA",
                                        reinterpret_cast<void*>(&replacement_get_module_handle));
#else
  const pid_t original_main = getpid();
  const pid_t original_lib = entry();
  g_expected_pid = original_main + 2;

  auto request = make_interpose_request("getpid", reinterpret_cast<void*>(&replacement_getpid));
#endif

  request.target.module = kInterposeLibName;

  auto result = w1::h00k::attach(request, nullptr);
  REQUIRE(result.error.ok());

#if defined(_WIN32)
  CHECK(GetModuleHandleA(nullptr) == original_main);
  CHECK(entry() == g_expected_handle);
#else
  CHECK(getpid() == original_main);
  CHECK(entry() == g_expected_pid);
#endif

  CHECK(w1::h00k::detach(result.handle) == w1::h00k::hook_error::ok);

#if defined(_WIN32)
  CHECK(GetModuleHandleA(nullptr) == original_main);
  CHECK(entry() == original_lib);
#else
  CHECK(getpid() == original_main);
  CHECK(entry() == original_lib);
#endif
}
