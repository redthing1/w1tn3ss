#include "path_resolver.hpp"

#include <filesystem>

#include "w1rewind/format/trace_format.hpp"

namespace w1replay {

namespace {

std::string basename_for_path(std::string_view path) {
  if (path.empty()) {
    return {};
  }
  size_t end = path.find_last_not_of("/\\");
  if (end == std::string_view::npos) {
    return {};
  }
  size_t start = path.find_last_of("/\\", end);
  if (start == std::string_view::npos) {
    return std::string(path.substr(0, end + 1));
  }
  return std::string(path.substr(start + 1, end - start));
}

bool parse_mapping(const std::string& mapping, std::string& name, std::string& path) {
  auto eq_pos = mapping.find('=');
  if (eq_pos == std::string::npos || eq_pos == 0 || eq_pos + 1 >= mapping.size()) {
    return false;
  }
  name = mapping.substr(0, eq_pos);
  path = mapping.substr(eq_pos + 1);
  return !(name.empty() || path.empty());
}

} // namespace

default_module_path_resolver::default_module_path_resolver(
    std::vector<std::string> module_mappings, std::vector<std::string> module_dirs
)
    : module_dirs_(std::move(module_dirs)) {
  overrides_.reserve(module_mappings.size());
  for (const auto& mapping : module_mappings) {
    std::string name;
    std::string path;
    if (!parse_mapping(mapping, name, path)) {
      continue;
    }
    overrides_[name] = std::move(path);
  }
}

std::optional<std::string> default_module_path_resolver::resolve_module_path(
    const w1::rewind::module_record& module
) const {
  if (module.path.empty()) {
    return std::nullopt;
  }
  return resolve_name(module.path);
}

std::optional<std::string> default_module_path_resolver::resolve_region_name(std::string_view recorded_name) const {
  if (recorded_name.empty()) {
    return std::nullopt;
  }
  return resolve_name(recorded_name);
}

std::optional<std::string> default_module_path_resolver::resolve_name(std::string_view name) const {
  std::string module_name = basename_for_path(name);
  if (module_name.empty()) {
    return std::nullopt;
  }

  auto it = overrides_.find(module_name);
  if (it != overrides_.end()) {
    return it->second;
  }

  for (const auto& dir : module_dirs_) {
    if (dir.empty()) {
      continue;
    }
    std::filesystem::path candidate = std::filesystem::path(dir) / module_name;
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
      return candidate.string();
    }
  }

  return std::nullopt;
}

std::unique_ptr<module_path_resolver> make_module_path_resolver(
    std::vector<std::string> module_mappings, std::vector<std::string> module_dirs
) {
  return std::make_unique<default_module_path_resolver>(std::move(module_mappings), std::move(module_dirs));
}

} // namespace w1replay
