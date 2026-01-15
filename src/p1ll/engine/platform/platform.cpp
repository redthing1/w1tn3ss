#include "platform.hpp"
#include <redlog.hpp>
#include <algorithm>

namespace p1ll::engine::platform {

namespace {

std::string detect_operating_system() {
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

std::string detect_architecture() {
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

std::string trim(std::string_view input) {
  std::string value(input);
  auto start = value.find_first_not_of(" \t");
  auto end = value.find_last_not_of(" \t");
  if (start == std::string::npos || end == std::string::npos) {
    return "";
  }
  return value.substr(start, end - start + 1);
}

} // namespace

platform_key detect_platform() {
  platform_key key;
  key.os = detect_operating_system();
  key.arch = detect_architecture();
  auto log = redlog::get_logger("p1ll.platform");
  if (key.os == "unknown") {
    log.wrn("unknown operating system detected - consider adding support");
  }
  if (key.arch == "unknown") {
    log.wrn("unknown architecture detected - consider adding support");
  }
  log.dbg("detected platform", redlog::field("os", key.os), redlog::field("arch", key.arch));
  return key;
}

result<platform_key> parse_platform(std::string_view key) {
  auto log = redlog::get_logger("p1ll.platform");
  std::string text = trim(key);
  if (text.empty()) {
    log.wrn("empty platform selector, using wildcard");
    return ok_result(platform_key{"*", "*"});
  }
  if (text == "*") {
    return ok_result(platform_key{"*", "*"});
  }

  auto colon_pos = text.find(':');
  platform_key parsed;
  if (colon_pos == std::string::npos) {
    parsed.os = trim(text);
    parsed.arch = "*";
  } else {
    auto left = trim(text.substr(0, colon_pos));
    auto right = trim(text.substr(colon_pos + 1));
    parsed.os = left.empty() ? "*" : left;
    parsed.arch = right.empty() ? "*" : right;
  }

  if (parsed.os.empty() || parsed.arch.empty()) {
    log.err("invalid platform selector", redlog::field("input", std::string(key)));
    return error_result<platform_key>(error_code::invalid_argument, "invalid platform selector");
  }

  log.dbg(
      "parsed platform selector", redlog::field("input", text), redlog::field("os", parsed.os),
      redlog::field("arch", parsed.arch)
  );
  return ok_result(parsed);
}

bool platform_matches(const platform_key& selector, const platform_key& target) {
  bool os_match = selector.os == "*" || target.os == "*" || selector.os == target.os;
  bool arch_match = selector.arch == "*" || target.arch == "*" || selector.arch == target.arch;
  return os_match && arch_match;
}

bool platform_matches(std::string_view selector, const platform_key& target) {
  auto parsed = parse_platform(selector);
  if (!parsed.ok()) {
    return false;
  }
  return platform_matches(parsed.value, target);
}

bool any_platform_matches(const std::vector<std::string>& selectors, const platform_key& target) {
  if (selectors.empty()) {
    return true;
  }
  for (const auto& selector : selectors) {
    if (platform_matches(selector, target)) {
      return true;
    }
  }
  return false;
}

} // namespace p1ll::engine::platform
