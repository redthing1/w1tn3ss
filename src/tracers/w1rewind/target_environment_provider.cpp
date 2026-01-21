#include "target_environment_provider.hpp"

#include <algorithm>
#include <limits>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

namespace {
struct addressing_bits_info {
  uint32_t addressing_bits = 0;
  uint32_t low_mem_addressing_bits = 0;
  uint32_t high_mem_addressing_bits = 0;
};

uint32_t bit_length_u64(uint64_t value) {
  uint32_t bits = 0;
  while (value != 0) {
    value >>= 1;
    ++bits;
  }
  return bits;
}

addressing_bits_info compute_addressing_bits(
    const std::vector<w1::rewind::memory_region_record>& memory_map,
    const std::vector<w1::rewind::module_record>& modules, uint32_t pointer_bits
) {
  addressing_bits_info out{};
  uint32_t address_bits = pointer_bits == 0 ? 64u : pointer_bits;
  if (address_bits <= 32) {
    out.addressing_bits = address_bits;
    out.low_mem_addressing_bits = address_bits;
    out.high_mem_addressing_bits = address_bits;
    return out;
  }

  bool found = false;
  uint32_t low_bits = 0;
  uint32_t high_bits = 0;

  auto consider_end = [&](uint64_t end) {
    found = true;
    if ((end & (1ull << 63)) != 0) {
      uint32_t bits = bit_length_u64(~end) + 1;
      high_bits = std::max(high_bits, bits);
    } else {
      uint32_t bits = bit_length_u64(end) + 1;
      low_bits = std::max(low_bits, bits);
    }
  };

  auto consider_range = [&](uint64_t base, uint64_t size) {
    if (size == 0) {
      return;
    }
    uint64_t end = base + size - 1;
    if (end < base) {
      end = std::numeric_limits<uint64_t>::max();
    }
    consider_end(end);
  };

  if (!memory_map.empty()) {
    for (const auto& region : memory_map) {
      consider_range(region.base, region.size);
    }
  } else {
    for (const auto& module : modules) {
      consider_range(module.base, module.size);
    }
  }

  if (!found) {
    out.addressing_bits = address_bits;
    out.low_mem_addressing_bits = address_bits;
    out.high_mem_addressing_bits = address_bits;
    return out;
  }

  if (low_bits == 0) {
    low_bits = high_bits;
  }
  if (high_bits == 0) {
    high_bits = low_bits;
  }
  if (low_bits == 0) {
    low_bits = address_bits;
  }
  if (high_bits == 0) {
    high_bits = address_bits;
  }

  if (low_bits > address_bits) {
    low_bits = address_bits;
  }
  if (high_bits > address_bits) {
    high_bits = address_bits;
  }

  uint32_t max_bits = std::max(low_bits, high_bits);
  if (max_bits == 0 || max_bits > address_bits) {
    max_bits = address_bits;
  }

  out.addressing_bits = max_bits;
  out.low_mem_addressing_bits = low_bits;
  out.high_mem_addressing_bits = high_bits;
  return out;
}

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
  struct utsname info {};
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
  struct utsname info {};
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
  struct utsname info {};
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

} // namespace

namespace w1rewind {

std::string detect_os_id() {
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

w1::rewind::target_environment_record build_target_environment(
    const std::vector<w1::rewind::memory_region_record>& memory_map,
    const std::vector<w1::rewind::module_record>& modules, const w1::arch::arch_spec& arch
) {
  w1::rewind::target_environment_record env{};
  env.os_version = detect_os_version();
  env.os_build = detect_os_build();
  env.os_kernel = detect_os_kernel();
  env.hostname = detect_host_name();
  if (env.hostname.empty()) {
    env.hostname = "w1rewind";
  }
  env.pid = detect_pid();
  auto bits = compute_addressing_bits(memory_map, modules, arch.pointer_bits);
  env.addressing_bits = bits.addressing_bits;
  env.low_mem_addressing_bits = bits.low_mem_addressing_bits;
  env.high_mem_addressing_bits = bits.high_mem_addressing_bits;
  return env;
}

} // namespace w1rewind
