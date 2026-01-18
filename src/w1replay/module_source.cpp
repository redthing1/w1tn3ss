#include "module_source.hpp"

#include "module_image_lief.hpp"

#include <algorithm>
#include <filesystem>
#include <unordered_map>

namespace w1replay {

namespace {

std::string basename_for_path(const std::string& path) {
  if (path.empty()) {
    return {};
  }
  return std::filesystem::path(path).filename().string();
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

void module_source::configure(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs) {
  module_mappings_ = std::move(module_mappings);
  module_dirs_ = std::move(module_dirs);
}

void module_source::set_address_reader(module_address_reader reader) {
  address_reader_ = std::move(reader);
}

void module_source::apply_to_context(w1::rewind::replay_context& context) {
  std::unordered_map<std::string, std::string> overrides;
  overrides.reserve(module_mappings_.size());
  for (const auto& mapping : module_mappings_) {
    std::string name;
    std::string path;
    if (!parse_mapping(mapping, name, path)) {
      continue;
    }
    overrides[name] = path;
  }

  for (auto& module : context.modules) {
    std::string module_name = basename_for_path(module.path);
    if (module_name.empty()) {
      continue;
    }

    auto it = overrides.find(module_name);
    if (it != overrides.end()) {
      module.path = it->second;
      continue;
    }

    for (const auto& dir : module_dirs_) {
      if (dir.empty()) {
        continue;
      }
      std::filesystem::path candidate = std::filesystem::path(dir) / module_name;
      std::error_code ec;
      if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
        module.path = candidate.string();
        break;
      }
    }
  }

  context.modules_by_id.clear();
  context.modules_by_id.reserve(context.modules.size());
  for (const auto& module : context.modules) {
    context.modules_by_id[module.id] = module;
  }
}

image_read_result module_source::read_module_image(
    const w1::rewind::module_record& module,
    uint64_t module_offset,
    size_t size
) {
  image_read_result result;

  if (size == 0) {
    result.error = "module read size is zero";
    return result;
  }

#if !defined(WITNESS_LIEF_ENABLED)
  (void)module;
  (void)module_offset;
  result.error = "module bytes unavailable (build with WITNESS_LIEF=ON)";
  return result;
#else
  std::string layout_error;
  const auto* layout = get_module_layout(module, layout_error);
  if (!layout) {
    result.error = layout_error.empty() ? "module layout unavailable" : layout_error;
    return result;
  }

  result = read_image_bytes(*layout, module_offset, size);
  if (!result.error.empty()) {
    result.error = "module image read failed: " + result.error;
  }
  return result;
#endif
}

image_read_result module_source::read_address_image(
    const w1::rewind::replay_context& context,
    uint64_t address,
    size_t size
) {
  image_read_result result;

  if (size == 0) {
    result.error = "empty read";
    return result;
  }

  if (address_reader_) {
    result.bytes.assign(size, std::byte{0});
    result.known.assign(size, 0);
    std::string reader_error;
    if (!address_reader_(address, result.bytes, reader_error)) {
      result.error = reader_error.empty() ? "address reader failed" : reader_error;
      return result;
    }
    std::fill(result.known.begin(), result.known.end(), 1);
    result.complete = true;
    return result;
  }

  uint64_t module_offset = 0;
  auto* matched = context.find_module_for_address(address, static_cast<uint64_t>(size), module_offset);
  if (!matched) {
    result.error = "address not in module";
    return result;
  }

  return read_module_image(*matched, module_offset, size);
}

const image_layout* module_source::get_module_layout(const w1::rewind::module_record& module, std::string& error) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void)module;
  error = "module bytes unavailable (build with WITNESS_LIEF=ON)";
  return nullptr;
#else
  if (module.path.empty()) {
    error = "module path missing";
    return nullptr;
  }

  auto& entry = modules_[module.path];
  if (!entry.binary) {
    auto binary = LIEF::Parser::parse(module.path);
    if (!binary) {
      error = "failed to parse module: " + module.path;
      return nullptr;
    }
    entry.binary = std::move(binary);
    if (!build_image_layout(*entry.binary, entry.layout, error)) {
      error = "failed to build module layout: " + error;
      entry.binary.reset();
      entry.layout = image_layout{};
      return nullptr;
    }
  }

  return &entry.layout;
#endif
}

} // namespace w1replay
