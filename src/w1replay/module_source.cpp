#include "module_source.hpp"

#include <algorithm>
#include <filesystem>
#include <limits>
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

bool add_overflows(uint64_t base, uint64_t addend) {
  return base > std::numeric_limits<uint64_t>::max() - addend;
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

bool module_source::read_module_bytes(
    const w1::rewind::module_record& module,
    uint64_t module_offset,
    uint32_t size,
    std::vector<std::byte>& out,
    std::string& error
) {
  out.clear();
  error.clear();

  if (size == 0) {
    error = "module read size is zero";
    return false;
  }

#if !defined(WITNESS_LIEF_ENABLED)
  (void)module;
  (void)module_offset;
  error = "module bytes unavailable (build with WITNESS_LIEF=ON)";
  return false;
#else
  if (module.path.empty()) {
    error = "module path missing";
    return false;
  }

  auto cache_it = modules_.find(module.path);
  if (cache_it == modules_.end() || !cache_it->second.binary || cache_it->second.path != module.path) {
    auto binary = LIEF::Parser::parse(module.path);
    if (!binary) {
      error = "failed to parse module: " + module.path;
      return false;
    }
    module_entry entry{};
    entry.path = module.path;
    entry.binary = std::move(binary);
    cache_it = modules_.insert_or_assign(module.path, std::move(entry)).first;
  }

  const auto& binary = *cache_it->second.binary;
  uint64_t address = module_offset;
  auto va_type = LIEF::Binary::VA_TYPES::RVA;
  switch (binary.format()) {
  case LIEF::Binary::FORMATS::MACHO: {
    uint64_t imagebase = binary.imagebase();
    if (add_overflows(imagebase, module_offset)) {
      error = "module imagebase + offset overflow";
      return false;
    }
    address = imagebase + module_offset;
    va_type = LIEF::Binary::VA_TYPES::VA;
    break;
  }
  case LIEF::Binary::FORMATS::ELF:
  case LIEF::Binary::FORMATS::PE:
    address = module_offset;
    va_type = LIEF::Binary::VA_TYPES::RVA;
    break;
  default:
    error = "unsupported binary format for module bytes";
    return false;
  }

  auto bytes = binary.get_content_from_virtual_address(address, size, va_type);
  if (bytes.empty() || bytes.size() < size) {
    error = "failed to read module bytes";
    return false;
  }

  out.resize(size);
  for (size_t i = 0; i < size; ++i) {
    out[i] = static_cast<std::byte>(bytes[i]);
  }
  return true;
#endif
}

bool module_source::read_address_bytes(
    const w1::rewind::replay_context& context,
    uint64_t address,
    std::span<std::byte> out,
    std::string& error
) {
  error.clear();
  if (address_reader_) {
    return address_reader_(address, out, error);
  }
  if (out.empty()) {
    error = "empty read";
    return false;
  }

  uint64_t module_offset = 0;
  auto* matched = context.find_module_for_address(address, static_cast<uint64_t>(out.size()), module_offset);
  if (!matched) {
    error = "address not in module";
    return false;
  }

  std::vector<std::byte> bytes;
  if (!read_module_bytes(*matched, module_offset, static_cast<uint32_t>(out.size()), bytes, error)) {
    return false;
  }

  std::copy(bytes.begin(), bytes.end(), out.begin());
  return true;
}

} // namespace w1replay
