#include "platform.hpp"
#include <redlog/redlog.hpp>
#include <algorithm>

namespace p1ll::core {

platform_key get_current_platform() {
  auto log = redlog::get_logger("p1ll.platform");

  platform_key platform;

  // detect operating system
#ifdef __APPLE__
  platform.os = "darwin";
#elif __linux__
  platform.os = "linux";
#elif _WIN32
  platform.os = "windows";
#elif __FreeBSD__
  platform.os = "freebsd";
#elif __OpenBSD__
  platform.os = "openbsd";
#elif __NetBSD__
  platform.os = "netbsd";
#elif __DragonFly__
  platform.os = "dragonfly";
#elif __sun
  platform.os = "solaris";
#elif __CYGWIN__
  platform.os = "cygwin";
#elif __MINGW32__ || __MINGW64__
  platform.os = "mingw";
#else
  platform.os = "unknown";
  log.warn("unknown operating system detected - consider adding support");
#endif

  // detect architecture
#if defined(__x86_64__) || defined(_M_X64)
  platform.arch = "x64";
#elif defined(__aarch64__) || defined(_M_ARM64)
  platform.arch = "arm64";
#elif defined(__i386__) || defined(_M_IX86)
  platform.arch = "x86";
#elif defined(__arm__) || defined(_M_ARM)
  platform.arch = "arm";
#elif defined(__riscv) && (__riscv_xlen == 64)
  platform.arch = "riscv64";
#elif defined(__riscv) && (__riscv_xlen == 32)
  platform.arch = "riscv32";
#elif defined(__mips__) && defined(__mips64)
  platform.arch = "mips64";
#elif defined(__mips__)
  platform.arch = "mips";
#elif defined(__powerpc64__) || defined(__ppc64__)
  platform.arch = "ppc64";
#elif defined(__powerpc__) || defined(__ppc__)
  platform.arch = "ppc";
#elif defined(__s390x__)
  platform.arch = "s390x";
#elif defined(__s390__)
  platform.arch = "s390";
#else
  platform.arch = "unknown";
  log.warn("unknown architecture detected - consider adding support");
#endif

  log.dbg("detected platform", redlog::field("os", platform.os), redlog::field("arch", platform.arch));

  return platform;
}

platform_key parse_platform_key(const std::string& platform_str) {
  auto log = redlog::get_logger("p1ll.platform");

  platform_key platform;

  // input validation
  if (platform_str.empty()) {
    log.warn("empty platform string, using wildcard");
    platform.os = "*";
    platform.arch = "*";
    return platform;
  }

  // handle simple "*" wildcard as universal
  if (platform_str == "*") {
    platform.os = "*";
    platform.arch = "*";
  } else {
    size_t colon_pos = platform_str.find(':');
    if (colon_pos == std::string::npos) {
      // no colon found, treat as os with wildcard arch
      platform.os = platform_str;
      platform.arch = "*";
    } else if (colon_pos == 0) {
      // starts with colon, invalid format
      log.warn("invalid platform format (starts with colon), using wildcard", redlog::field("input", platform_str));
      platform.os = "*";
      platform.arch = "*";
    } else if (colon_pos >= platform_str.length() - 1) {
      // ends with colon, treat as os with wildcard arch
      platform.os = platform_str.substr(0, colon_pos);
      platform.arch = "*";
    } else {
      // normal "os:arch" format
      platform.os = platform_str.substr(0, colon_pos);
      platform.arch = platform_str.substr(colon_pos + 1);
    }
  }

  // trim whitespace from components
  if (!platform.os.empty() && platform.os != "*") {
    // simple whitespace trimming
    auto start = platform.os.find_first_not_of(" \t");
    auto end = platform.os.find_last_not_of(" \t");
    if (start != std::string::npos && end != std::string::npos) {
      platform.os = platform.os.substr(start, end - start + 1);
    }
  }

  if (!platform.arch.empty() && platform.arch != "*") {
    auto start = platform.arch.find_first_not_of(" \t");
    auto end = platform.arch.find_last_not_of(" \t");
    if (start != std::string::npos && end != std::string::npos) {
      platform.arch = platform.arch.substr(start, end - start + 1);
    }
  }

  log.dbg(
      "parsed platform key", redlog::field("input", platform_str), redlog::field("os", platform.os),
      redlog::field("arch", platform.arch)
  );

  return platform;
}

std::vector<std::string> get_platform_hierarchy(const platform_key& platform) {
  std::vector<std::string> hierarchy;

  // exact match first
  hierarchy.push_back(platform.to_string());

  // os wildcard if arch is not already wildcard
  if (platform.arch != "*") {
    hierarchy.push_back(platform.os + ":*");
  }

  // universal wildcards (both "*:*" and "*" are supported)
  if (platform.os != "*" || platform.arch != "*") {
    hierarchy.push_back("*:*");
    hierarchy.push_back("*"); // support simple "*" wildcard too
  }

  return hierarchy;
}

std::vector<std::string> get_current_platform_hierarchy() { return get_platform_hierarchy(get_current_platform()); }

bool platform_key::matches(const platform_key& other) const { return platform_matches(*this, other); }

bool platform_matches(const platform_key& key, const platform_key& target) {
  // wildcard matching
  bool os_match = (key.os == "*" || target.os == "*" || key.os == target.os);
  bool arch_match = (key.arch == "*" || target.arch == "*" || key.arch == target.arch);

  return os_match && arch_match;
}

std::vector<std::string> get_supported_operating_systems() {
  return {"darwin",    "linux",   "windows", "freebsd", "openbsd", "netbsd",
          "dragonfly", "solaris", "cygwin",  "mingw",   "unknown", "*"};
}

std::vector<std::string> get_supported_architectures() {
  return {"x64",  "arm64", "x86", "arm",   "riscv64", "riscv32", "mips64",
          "mips", "ppc64", "ppc", "s390x", "s390",    "unknown", "*"};
}

bool is_valid_platform_key(const platform_key& platform) {
  auto supported_os = get_supported_operating_systems();
  auto supported_arch = get_supported_architectures();

  // check if os is supported
  bool os_valid = std::find(supported_os.begin(), supported_os.end(), platform.os) != supported_os.end();

  // check if arch is supported
  bool arch_valid = std::find(supported_arch.begin(), supported_arch.end(), platform.arch) != supported_arch.end();

  return os_valid && arch_valid;
}

} // namespace p1ll::core