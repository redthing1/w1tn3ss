#include "w1runtime/module_catalog.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <unordered_map>

#include <QBDI/Memory.hpp>
#include <mutex>

#if defined(_WIN32)
#include <w1base/windows_clean.hpp>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <cstring>
#elif defined(__linux__)
#include <limits.h>
#include <unistd.h>
#endif

namespace w1::runtime {
namespace {

struct module_span {
  std::string name;
  std::string path;
  uint64_t start = 0;
  uint64_t end = 0;
  uint32_t permissions = 0;
  bool is_system = false;
  std::vector<address_range> mapped_ranges;
  std::vector<address_range> exec_ranges;
};

std::string extract_basename(const std::string& path) {
  if (path.empty()) {
    return path;
  }

  size_t pos = path.find_last_of("/\\");
  if (pos != std::string::npos) {
    return path.substr(pos + 1);
  }

  return path;
}

std::string make_unnamed_name(uint64_t start) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "_unnamed_0x%llx", static_cast<unsigned long long>(start));
  return buffer;
}

#if defined(_WIN32)
std::string utf16_to_utf8(const wchar_t* value, size_t length) {
  if (!value || length == 0) {
    return {};
  }
  const int wchar_len = static_cast<int>(length);
  if (wchar_len <= 0) {
    return {};
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string out(static_cast<size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value, wchar_len, out.data(), required, nullptr, nullptr);
  return out;
}
#endif

std::optional<std::string> detect_main_executable_path() {
#if defined(_WIN32)
  std::wstring buffer;
  DWORD size = MAX_PATH;
  buffer.resize(size);
  DWORD length = GetModuleFileNameW(nullptr, buffer.data(), size);
  if (length == 0) {
    return std::nullopt;
  }
  while (length == size) {
    size *= 2;
    buffer.resize(size);
    length = GetModuleFileNameW(nullptr, buffer.data(), size);
    if (length == 0) {
      return std::nullopt;
    }
  }
  buffer.resize(length);
  return utf16_to_utf8(buffer.data(), buffer.size());
#elif defined(__APPLE__)
  uint32_t size = 0;
  if (_NSGetExecutablePath(nullptr, &size) != -1 || size == 0) {
    return std::nullopt;
  }
  std::string path(size, '\0');
  if (_NSGetExecutablePath(path.data(), &size) != 0) {
    return std::nullopt;
  }
  path.resize(std::strlen(path.c_str()));
  return path;
#elif defined(__linux__)
  char buffer[PATH_MAX];
  const ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
  if (len <= 0) {
    return std::nullopt;
  }
  buffer[len] = '\0';
  return std::string(buffer, static_cast<size_t>(len));
#else
  return std::nullopt;
#endif
}

std::string normalize_path(const std::string& path) {
  if (path.empty()) {
    return {};
  }
  std::error_code ec;
  auto canonical = std::filesystem::weakly_canonical(std::filesystem::path(path), ec);
  if (!ec) {
    return canonical.string();
  }
  return path;
}

bool path_equal(const std::string& left, const std::string& right) {
  if (left.empty() || right.empty()) {
    return false;
  }
#if defined(_WIN32)
  auto normalize_for_compare = [](std::string value) {
    std::replace(value.begin(), value.end(), '/', '\\');
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
      return static_cast<char>(std::tolower(ch));
    });
    return value;
  };
  return normalize_for_compare(left) == normalize_for_compare(right);
#else
  return left == right;
#endif
}

bool is_system_library(const std::string& path) {
  if (path.empty()) {
    return false;
  }

#ifdef __APPLE__
  if (path.rfind("/usr/lib/", 0) == 0 || path.rfind("/System/Library/", 0) == 0 || path.rfind("/Library/", 0) == 0) {
    return true;
  }
  if (path.rfind("libsystem", 0) == 0 || path.rfind("libc++", 0) == 0 || path.rfind("libobjc", 0) == 0 ||
      path.rfind("libdispatch", 0) == 0 || path.rfind("libxpc", 0) == 0 || path.rfind("libcorecrypto", 0) == 0 ||
      path.rfind("libcompiler_rt", 0) == 0 || path.rfind("libdyld", 0) == 0 || path.rfind("dyld", 0) == 0 ||
      path.rfind("libquarantine", 0) == 0 || path.rfind("libmacho", 0) == 0 || path.rfind("libcommonCrypto", 0) == 0 ||
      path.rfind("libunwind", 0) == 0 || path.rfind("libcopyfile", 0) == 0 || path.rfind("libremovefile", 0) == 0 ||
      path.rfind("libkeymgr", 0) == 0 || path.rfind("libcache", 0) == 0 || path.rfind("libSystem", 0) == 0 ||
      path.rfind("libRosetta", 0) == 0) {
    return true;
  }
  return false;
#elif defined(__linux__)
  return (
      path.rfind("/lib/", 0) == 0 || path.rfind("/usr/lib/", 0) == 0 || path.rfind("/lib64/", 0) == 0 ||
      path.rfind("/usr/lib64/", 0) == 0
  );
#elif defined(_WIN32)
  std::string lower_path = path;
  std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), [](unsigned char value) {
    return static_cast<char>(std::tolower(value));
  });
  return (
      lower_path.rfind("c:\\windows\\", 0) == 0 || lower_path.rfind("c:\\program files\\", 0) == 0 ||
      lower_path.rfind("c:\\program files (x86)\\", 0) == 0
  );
#else
  return false;
#endif
}

} // namespace

void module_catalog::refresh() {
  auto maps = QBDI::getCurrentProcessMaps(true);
  std::unordered_map<std::string, module_span> spans;
  spans.reserve(maps.size());

  for (const auto& map : maps) {
    uint64_t start = map.range.start();
    uint64_t end = map.range.end();
    if (end <= start) {
      continue;
    }

    std::string key = map.name;
    if (key.empty()) {
      key = make_unnamed_name(start);
    }

    auto [it, inserted] = spans.emplace(key, module_span{});
    module_span& span = it->second;

    if (inserted) {
      span.path = map.name;
      span.name = map.name.empty() ? key : extract_basename(map.name);
      span.start = start;
      span.end = end;
      span.permissions = static_cast<uint32_t>(map.permission);
      span.is_system = is_system_library(map.name);
    } else {
      span.start = std::min(span.start, start);
      span.end = std::max(span.end, end);
      span.permissions |= static_cast<uint32_t>(map.permission);
    }

    span.mapped_ranges.push_back(address_range{start, end});
    if (map.permission & QBDI::PF_EXEC) {
      span.exec_ranges.push_back(address_range{start, end});
    }
  }

  std::vector<module_info> modules;
  modules.reserve(spans.size());

  for (auto& [key, span] : spans) {
    if (span.end <= span.start) {
      continue;
    }

    std::sort(
        span.mapped_ranges.begin(), span.mapped_ranges.end(),
        [](const address_range& left, const address_range& right) { return left.start < right.start; }
    );
    std::sort(
        span.exec_ranges.begin(), span.exec_ranges.end(),
        [](const address_range& left, const address_range& right) { return left.start < right.start; }
    );

    module_info info{};
    info.name = span.name.empty() ? key : span.name;
    info.path = span.path.empty() ? info.name : span.path;
    info.base_address = span.start;
    info.size = span.end - span.start;
    info.permissions = span.permissions;
    info.is_system = span.is_system;
    info.full_range = address_range{span.start, span.end};
    info.mapped_ranges = std::move(span.mapped_ranges);
    info.exec_ranges = std::move(span.exec_ranges);

    modules.push_back(std::move(info));
  }

  std::sort(modules.begin(), modules.end(), [](const module_info& left, const module_info& right) {
    return left.full_range.start < right.full_range.start;
  });

  auto main_path = detect_main_executable_path();
  if (main_path && !main_path->empty()) {
    const std::string normalized_main = normalize_path(*main_path);
    const std::string main_basename = extract_basename(normalized_main.empty() ? *main_path : normalized_main);
    const std::string canonical_main = normalized_main.empty() ? *main_path : normalized_main;
    std::optional<size_t> main_index;
    for (size_t index = 0; index < modules.size(); ++index) {
      const auto& candidate = modules[index];
      if (path_equal(candidate.path, *main_path) ||
          (!normalized_main.empty() && path_equal(candidate.path, normalized_main))) {
        main_index = index;
        break;
      }
    }
    if (!main_index && !main_basename.empty()) {
      for (size_t index = 0; index < modules.size(); ++index) {
        if (extract_basename(modules[index].path) == main_basename) {
          main_index = index;
          break;
        }
      }
    }
    if (main_index) {
      auto& entry = modules[*main_index];
      entry.is_main = true;
      entry.path = canonical_main;
      if (entry.name.empty()) {
        entry.name = extract_basename(entry.path);
      }
    }
  }

  std::vector<range_index_entry> range_index;
  size_t total_ranges = 0;
  for (const auto& module : modules) {
    total_ranges += module.mapped_ranges.size();
  }
  range_index.reserve(total_ranges);

  for (size_t index = 0; index < modules.size(); ++index) {
    const auto& module = modules[index];
    for (const auto& range : module.mapped_ranges) {
      if (range.end <= range.start) {
        continue;
      }
      range_index.push_back(range_index_entry{range, index});
    }
  }

  std::sort(range_index.begin(), range_index.end(), [](const range_index_entry& left, const range_index_entry& right) {
    return left.range.start < right.range.start;
  });

  std::unique_lock lock(mutex_);
  modules_ = std::move(modules);
  range_index_ = std::move(range_index);
  version_.fetch_add(1, std::memory_order_release);
}

const module_info* module_catalog::find_containing(uint64_t address) const {
  std::shared_lock lock(mutex_);
  if (modules_.empty() || range_index_.empty()) {
    return nullptr;
  }

  auto it = std::upper_bound(
      range_index_.begin(), range_index_.end(), address,
      [](uint64_t value, const range_index_entry& entry) { return value < entry.range.start; }
  );

  if (it == range_index_.begin()) {
    return nullptr;
  }

  --it;
  if (address >= it->range.start && address < it->range.end) {
    return &modules_[it->module_index];
  }

  return nullptr;
}

std::vector<module_info> module_catalog::list_modules() const {
  std::shared_lock lock(mutex_);
  return modules_;
}

} // namespace w1::runtime
