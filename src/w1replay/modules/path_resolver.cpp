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

default_image_path_resolver::default_image_path_resolver(
    std::vector<std::string> image_mappings, std::vector<std::string> image_dirs
)
    : image_dirs_(std::move(image_dirs)) {
  overrides_exact_.reserve(image_mappings.size());
  overrides_basename_.reserve(image_mappings.size());
  for (const auto& mapping : image_mappings) {
    std::string name;
    std::string path;
    if (!parse_mapping(mapping, name, path)) {
      continue;
    }
    overrides_exact_[name] = path;

    std::string base = basename_for_path(name);
    if (base.empty()) {
      continue;
    }
    if (ambiguous_basenames_.find(base) != ambiguous_basenames_.end()) {
      continue;
    }
    auto it = overrides_basename_.find(base);
    if (it == overrides_basename_.end()) {
      overrides_basename_[base] = default_image_path_resolver::basename_override{std::move(name), std::move(path)};
      continue;
    }
    if (it->second.key == name) {
      it->second.path = std::move(path);
      continue;
    }
    overrides_basename_.erase(it);
    ambiguous_basenames_.insert(std::move(base));
  }
}

std::optional<std::string> default_image_path_resolver::resolve_image_path(
    const w1::rewind::image_record& image
) const {
  if (!image.path.empty()) {
    if (auto resolved = resolve_name(image.path)) {
      return resolved;
    }
  }
  if (!image.identity.empty()) {
    if (auto resolved = resolve_override(image.identity)) {
      return resolved;
    }
  }
  if (!image.name.empty()) {
    if (auto resolved = resolve_override(image.name)) {
      return resolved;
    }
  }
  return std::nullopt;
}

std::optional<std::string> default_image_path_resolver::resolve_region_name(std::string_view recorded_name) const {
  if (recorded_name.empty()) {
    return std::nullopt;
  }
  return resolve_override(recorded_name);
}

std::optional<std::string> default_image_path_resolver::resolve_name(std::string_view name) const {
  auto override = resolve_override(name);
  if (override.has_value()) {
    return override;
  }

  std::string image_name = basename_for_path(name);
  if (image_name.empty()) {
    return std::nullopt;
  }

  for (const auto& dir : image_dirs_) {
    if (dir.empty()) {
      continue;
    }
    std::filesystem::path candidate = std::filesystem::path(dir) / image_name;
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
      return candidate.string();
    }
  }

  return std::nullopt;
}

std::optional<std::string> default_image_path_resolver::resolve_override(std::string_view name) const {
  if (name.empty()) {
    return std::nullopt;
  }

  auto exact_it = overrides_exact_.find(std::string(name));
  if (exact_it != overrides_exact_.end()) {
    return exact_it->second;
  }

  std::string image_name = basename_for_path(name);
  if (image_name.empty()) {
    return std::nullopt;
  }

  if (ambiguous_basenames_.find(image_name) != ambiguous_basenames_.end()) {
    return std::nullopt;
  }
  auto it = overrides_basename_.find(image_name);
  if (it != overrides_basename_.end()) {
    return it->second.path;
  }
  return std::nullopt;
}

std::unique_ptr<image_path_resolver> make_image_path_resolver(
    std::vector<std::string> image_mappings, std::vector<std::string> image_dirs
) {
  return std::make_unique<default_image_path_resolver>(std::move(image_mappings), std::move(image_dirs));
}

} // namespace w1replay
