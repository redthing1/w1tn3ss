#include "platform.hpp"
#include "context.hpp"
#include <redlog.hpp>
#include <algorithm>

namespace p1ll {

std::string platform_detector::detect_operating_system() const {
#ifdef __APPLE__
  return "darwin";
#elif __linux__
  return "linux";
#elif _WIN32
  return "windows";
#elif __FreeBSD__
  return "freebsd";
#elif __OpenBSD__
  return "openbsd";
#elif __NetBSD__
  return "netbsd";
#elif __DragonFly__
  return "dragonfly";
#elif __sun
  return "solaris";
#elif __CYGWIN__
  return "cygwin";
#elif __MINGW32__ || __MINGW64__
  return "mingw";
#else
  return "unknown";
#endif
}

std::string platform_detector::detect_architecture() const {
#if defined(__x86_64__) || defined(_M_X64)
  return "x64";
#elif defined(__aarch64__) || defined(_M_ARM64)
  return "arm64";
#elif defined(__i386__) || defined(_M_IX86)
  return "x86";
#elif defined(__arm__) || defined(_M_ARM)
  return "arm";
#elif defined(__riscv) && (__riscv_xlen == 64)
  return "riscv64";
#elif defined(__riscv) && (__riscv_xlen == 32)
  return "riscv32";
#elif defined(__mips__) && defined(__mips64)
  return "mips64";
#elif defined(__mips__)
  return "mips";
#elif defined(__powerpc64__) || defined(__ppc64__)
  return "ppc64";
#elif defined(__powerpc__) || defined(__ppc__)
  return "ppc";
#elif defined(__s390x__)
  return "s390x";
#elif defined(__s390__)
  return "s390";
#else
  return "unknown";
#endif
}

platform_key platform_detector::get_detected_platform() const {
  auto log = redlog::get_logger("p1ll.platform");

  platform_key platform;
  platform.os = detect_operating_system();
  platform.arch = detect_architecture();

  if (platform.os == "unknown") {
    log.warn("unknown operating system detected - consider adding support");
  }
  if (platform.arch == "unknown") {
    log.warn("unknown architecture detected - consider adding support");
  }

  log.dbg("detected platform", redlog::field("os", platform.os), redlog::field("arch", platform.arch));

  return platform;
}

platform_key platform_detector::get_effective_platform(const context& ctx) const {
  return ctx.get_effective_platform();
}

std::vector<std::string> platform_detector::get_platform_hierarchy(const platform_key& platform) const {
  std::vector<std::string> hierarchy;

  // exact match first
  hierarchy.push_back(platform.to_string());

  // os wildcard if arch is not already wildcard
  if (platform.arch != "*") {
    hierarchy.push_back(platform.os + ":*");
  }

  // universal wildcards
  if (platform.os != "*" || platform.arch != "*") {
    hierarchy.push_back("*:*");
    hierarchy.push_back("*");
  }

  return hierarchy;
}

std::vector<std::string> platform_detector::get_platform_hierarchy_for_context(const context& ctx) const {
  return get_platform_hierarchy(get_effective_platform(ctx));
}

bool platform_detector::platform_matches(const platform_key& key, const platform_key& target) const {
  bool os_match = (key.os == "*" || target.os == "*" || key.os == target.os);
  bool arch_match = (key.arch == "*" || target.arch == "*" || key.arch == target.arch);
  return os_match && arch_match;
}

std::vector<std::string> platform_detector::get_supported_operating_systems() const {
  return {"darwin",    "linux",   "windows", "freebsd", "openbsd", "netbsd",
          "dragonfly", "solaris", "cygwin",  "mingw",   "unknown", "*"};
}

std::vector<std::string> platform_detector::get_supported_architectures() const {
  return {"x64",  "arm64", "x86", "arm",   "riscv64", "riscv32", "mips64",
          "mips", "ppc64", "ppc", "s390x", "s390",    "unknown", "*"};
}

bool platform_detector::is_valid_platform_key(const platform_key& platform) const {
  auto supported_os = get_supported_operating_systems();
  auto supported_arch = get_supported_architectures();

  bool os_valid = std::find(supported_os.begin(), supported_os.end(), platform.os) != supported_os.end();
  bool arch_valid = std::find(supported_arch.begin(), supported_arch.end(), platform.arch) != supported_arch.end();

  return os_valid && arch_valid;
}

platform_key platform_detector::parse_platform_key(const std::string& platform_str) const {
  auto log = redlog::get_logger("p1ll.platform");

  platform_key platform;

  if (platform_str.empty()) {
    log.warn("empty platform string, using wildcard");
    platform.os = "*";
    platform.arch = "*";
    return platform;
  }

  if (platform_str == "*") {
    platform.os = "*";
    platform.arch = "*";
  } else {
    size_t colon_pos = platform_str.find(':');
    if (colon_pos == std::string::npos) {
      platform.os = platform_str;
      platform.arch = "*";
    } else if (colon_pos == 0) {
      log.warn("invalid platform format (starts with colon), using wildcard", redlog::field("input", platform_str));
      platform.os = "*";
      platform.arch = "*";
    } else if (colon_pos >= platform_str.length() - 1) {
      platform.os = platform_str.substr(0, colon_pos);
      platform.arch = "*";
    } else {
      platform.os = platform_str.substr(0, colon_pos);
      platform.arch = platform_str.substr(colon_pos + 1);
    }
  }

  // trim whitespace
  auto trim = [](std::string& s) {
    if (s != "*") {
      auto start = s.find_first_not_of(" \t");
      auto end = s.find_last_not_of(" \t");
      if (start != std::string::npos && end != std::string::npos) {
        s = s.substr(start, end - start + 1);
      }
    }
  };

  trim(platform.os);
  trim(platform.arch);

  log.dbg(
      "parsed platform key", redlog::field("input", platform_str), redlog::field("os", platform.os),
      redlog::field("arch", platform.arch)
  );

  return platform;
}

platform_detector& get_platform_detector() {
  static platform_detector detector;
  return detector;
}

} // namespace p1ll