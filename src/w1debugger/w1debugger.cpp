// neat, modernized debugger api - core stubs

#include "w1debugger.hpp"
#include "platform/stub_session.hpp"

#include <cstring>

namespace w1::debugger {

// error category for dbg_errc
namespace {
struct dbg_error_category : std::error_category {
  const char* name() const noexcept override { return "w1.debugger"; }
  std::string message(int c) const override {
    switch (static_cast<dbg_errc>(c)) {
    case dbg_errc::ok:
      return "ok";
    case dbg_errc::invalid_argument:
      return "invalid argument";
    case dbg_errc::not_supported:
      return "not supported";
    case dbg_errc::permission_denied:
      return "permission denied";
    case dbg_errc::no_such_process:
      return "no such process";
    case dbg_errc::no_such_thread:
      return "no such thread";
    case dbg_errc::timeout:
      return "timeout";
    case dbg_errc::unavailable:
      return "unavailable";
    case dbg_errc::interrupted:
      return "interrupted";
    case dbg_errc::already_exists:
      return "already exists";
    case dbg_errc::not_found:
      return "not found";
    case dbg_errc::backend_error:
      return "backend error";
    }
    return "unknown";
  }
};
const dbg_error_category& cat() {
  static dbg_error_category inst;
  return inst;
}
} // namespace

std::error_code make_error_code(dbg_errc e) noexcept { return {static_cast<int>(e), cat()}; }

// register_file helpers
std::expected<std::uint64_t, std::error_code> register_file::get_u64(std::size_t index) const {
  const std::size_t off = index * sizeof(std::uint64_t);
  if (off + sizeof(std::uint64_t) > data.size()) {
    return std::unexpected(make_error_code(dbg_errc::invalid_argument));
  }
  std::uint64_t v{};
  std::memcpy(&v, data.data() + off, sizeof(v));
  return v;
}

std::expected<void, std::error_code> register_file::set_u64(std::size_t index, std::uint64_t v) {
  const std::size_t off = index * sizeof(std::uint64_t);
  if (off + sizeof(std::uint64_t) > data.size()) {
    return std::unexpected(make_error_code(dbg_errc::invalid_argument));
  }
  std::memcpy(data.data() + off, &v, sizeof(v));
  return {};
}

// factories (stubs)
std::expected<std::unique_ptr<session>, std::error_code> session::launch(const launch_options&) {
  target_info ti{};
#if defined(__APPLE__)
  ti.os = os_kind::macos;
#elif defined(__linux__)
  ti.os = os_kind::linux;
#elif defined(_WIN32)
  ti.os = os_kind::windows;
#else
  ti.os = os_kind::linux;
#endif

#if defined(__aarch64__) || defined(__arm64__)
  ti.cpu = arch::arm64;
#else
  ti.cpu = arch::x86_64;
#endif
  ti.endian = endianness::little;
  ti.pid = 0;
  return std::unique_ptr<session>(new platform::stub_session(std::move(ti)));
}

std::expected<std::unique_ptr<session>, std::error_code> session::attach(const attach_options& opts) {
  target_info ti{};
#if defined(__APPLE__)
  ti.os = os_kind::macos;
#elif defined(__linux__)
  ti.os = os_kind::linux;
#elif defined(_WIN32)
  ti.os = os_kind::windows;
#else
  ti.os = os_kind::linux;
#endif

#if defined(__aarch64__) || defined(__arm64__)
  ti.cpu = arch::arm64;
#else
  ti.cpu = arch::x86_64;
#endif
  ti.endian = endianness::little;
  ti.pid = opts.pid;
  return std::unique_ptr<session>(new platform::stub_session(std::move(ti)));
}

// utilities (best-effort stubs)
std::expected<std::vector<process_info>, std::error_code> list_processes() {
  return std::unexpected(make_error_code(dbg_errc::not_supported));
}

std::expected<bool, std::error_code> can_debug() { return true; }

} // namespace w1::debugger
