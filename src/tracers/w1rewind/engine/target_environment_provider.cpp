#include "target_environment_provider.hpp"

#include <string_view>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/utsname.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace {

using w1::rewind::endian;

#if defined(__APPLE__)
std::string sysctl_string(const char* key) {
  size_t size = 0;
  if (sysctlbyname(key, nullptr, &size, nullptr, 0) != 0 || size == 0) {
    return {};
  }
  std::string out(size, '\0');
  if (sysctlbyname(key, out.data(), &size, nullptr, 0) != 0) {
    return {};
  }
  if (!out.empty() && out.back() == '\0') {
    out.pop_back();
  }
  return out;
}
#endif

std::string detect_host_name() {
#if defined(_WIN32)
  char buffer[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
  if (GetComputerNameA(buffer, &size)) {
    return std::string(buffer, size);
  }
#else
  char buffer[256] = {};
  if (gethostname(buffer, sizeof(buffer) - 1) == 0) {
    buffer[sizeof(buffer) - 1] = '\0';
    return buffer;
  }
#endif
  return {};
}

std::string detect_os_version() {
#if defined(__APPLE__)
  return sysctl_string("kern.osproductversion");
#elif !defined(_WIN32)
  struct utsname info{};
  if (uname(&info) == 0) {
    return info.release;
  }
#endif
  return {};
}

std::string detect_os_build() {
#if defined(__APPLE__)
  return sysctl_string("kern.osversion");
#elif !defined(_WIN32)
  struct utsname info{};
  if (uname(&info) == 0) {
    return info.version;
  }
#endif
  return {};
}

std::string detect_os_kernel() {
#if defined(__APPLE__)
  return sysctl_string("kern.osrelease");
#elif defined(_WIN32)
  return "windows";
#else
  struct utsname info{};
  if (uname(&info) == 0) {
    return info.sysname;
  }
#endif
  return {};
}

uint64_t detect_pid() {
#if defined(_WIN32)
  return static_cast<uint64_t>(GetCurrentProcessId());
#else
  return static_cast<uint64_t>(getpid());
#endif
}

endian to_endian(w1::arch::byte_order order) {
  switch (order) {
  case w1::arch::byte_order::little:
    return endian::little;
  case w1::arch::byte_order::big:
    return endian::big;
  default:
    return endian::unknown;
  }
}

std::string_view arch_mode_name(w1::arch::mode mode) {
  switch (mode) {
  case w1::arch::mode::x86_64:
    return "x86_64";
  case w1::arch::mode::x86_32:
    return "x86_32";
  case w1::arch::mode::arm:
    return "arm";
  case w1::arch::mode::thumb:
    return "thumb";
  case w1::arch::mode::aarch64:
    return "aarch64";
  case w1::arch::mode::riscv64:
    return "riscv64";
  case w1::arch::mode::riscv32:
    return "riscv32";
  case w1::arch::mode::mips64:
    return "mips64";
  case w1::arch::mode::mips32:
    return "mips32";
  case w1::arch::mode::ppc32:
    return "ppc32";
  case w1::arch::mode::ppc64:
    return "ppc64";
  case w1::arch::mode::sparc32:
    return "sparc32";
  case w1::arch::mode::sparc64:
    return "sparc64";
  case w1::arch::mode::systemz:
    return "systemz";
  case w1::arch::mode::wasm32:
    return "wasm32";
  case w1::arch::mode::wasm64:
    return "wasm64";
  case w1::arch::mode::unknown:
  default:
    return "unknown";
  }
}

} // namespace

namespace w1rewind {

std::string detect_host_os_id() {
#if defined(_WIN32)
  return "windows";
#elif defined(__APPLE__)
  return "macos";
#elif defined(__linux__)
  return "linux";
#else
  return {};
#endif
}

w1::rewind::arch_descriptor_record build_arch_descriptor(const w1::arch::arch_spec& arch) {
  w1::rewind::arch_descriptor_record record{};
  record.arch_id = std::string(arch_mode_name(arch.arch_mode));
  record.byte_order = to_endian(arch.arch_byte_order);
  record.pointer_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.address_bits = static_cast<uint16_t>(arch.pointer_bits);
  record.gdb_arch = std::string(w1::arch::gdb_arch_name(arch));
  record.gdb_feature = std::string(w1::arch::gdb_feature_name(arch));

  record.modes.clear();
  if (arch.arch_family == w1::arch::family::arm && arch.arch_mode != w1::arch::mode::aarch64) {
    record.modes.push_back({0, "arm"});
    record.modes.push_back({1, "thumb"});
  } else {
    record.modes.push_back({0, record.arch_id});
  }
  return record;
}

w1::rewind::environment_record build_host_environment_record(const w1::rewind::arch_descriptor_record& arch) {
  w1::rewind::environment_record env{};
  env.os_id = detect_host_os_id();
  if (env.os_id.empty()) {
    env.os_id = "unknown";
  }
  if (!arch.arch_id.empty()) {
    env.cpu = arch.arch_id;
  } else if (!arch.gdb_arch.empty()) {
    env.cpu = arch.gdb_arch;
  }
  if (env.cpu.empty()) {
    env.cpu = "unknown";
  }
  env.hostname = detect_host_name();
  if (env.hostname.empty()) {
    env.hostname = "w1rewind";
  }
  env.pid = detect_pid();

  const std::string os_version = detect_os_version();
  const std::string os_build = detect_os_build();
  const std::string os_kernel = detect_os_kernel();
  if (!os_version.empty()) {
    env.attrs.emplace_back("os_version", os_version);
  }
  if (!os_build.empty()) {
    env.attrs.emplace_back("os_build", os_build);
  }
  if (!os_kernel.empty()) {
    env.attrs.emplace_back("os_kernel", os_kernel);
  }

  return env;
}

} // namespace w1rewind
