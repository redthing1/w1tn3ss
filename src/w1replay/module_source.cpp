#include "module_source.hpp"

#include "module_image_lief.hpp"

#include <algorithm>
#include <array>
#include <filesystem>
#include <limits>
#include <unordered_map>

namespace w1replay {

namespace {

std::string basename_for_path(const std::string& path) {
  if (path.empty()) {
    return {};
  }
  // handle windows paths on non-windows hosts
  size_t end = path.find_last_not_of("/\\");
  if (end == std::string::npos) {
    return {};
  }
  size_t start = path.find_last_of("/\\", end);
  if (start == std::string::npos) {
    return path.substr(0, end + 1);
  }
  return path.substr(start + 1, end - start);
}

bool add_overflows(uint64_t base, uint64_t addend) {
  return base > std::numeric_limits<uint64_t>::max() - addend;
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

#if defined(WITNESS_LIEF_ENABLED)
std::string format_uuid(const std::array<uint8_t, 16>& bytes) {
  static const char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(36);
  auto append_byte = [&](uint8_t value) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  };
  size_t idx = 0;
  const size_t groups[] = {4, 2, 2, 2, 6};
  for (size_t group = 0; group < 5; ++group) {
    if (group > 0) {
      out.push_back('-');
    }
    for (size_t i = 0; i < groups[group]; ++i) {
      append_byte(bytes[idx++]);
    }
  }
  return out;
}

bool is_all_zero_uuid(const std::array<uint8_t, 16>& bytes) {
  for (uint8_t value : bytes) {
    if (value != 0) {
      return false;
    }
  }
  return true;
}
#endif

} // namespace

void module_source::configure(std::vector<std::string> module_mappings, std::vector<std::string> module_dirs) {
  module_mappings_ = std::move(module_mappings);
  module_dirs_ = std::move(module_dirs);
}

void module_source::set_address_reader(module_address_reader reader) { address_reader_ = std::move(reader); }

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

  auto apply_override = [&](std::string& path) {
    std::string module_name = basename_for_path(path);
    if (module_name.empty()) {
      return;
    }

    auto it = overrides.find(module_name);
    if (it != overrides.end()) {
      path = it->second;
      return;
    }

    for (const auto& dir : module_dirs_) {
      if (dir.empty()) {
        continue;
      }
      std::filesystem::path candidate = std::filesystem::path(dir) / module_name;
      std::error_code ec;
      if (std::filesystem::exists(candidate, ec) && std::filesystem::is_regular_file(candidate, ec)) {
        path = candidate.string();
        return;
      }
    }
  };

  for (auto& module : context.modules) {
    if (module.path.empty()) {
      continue;
    }
    apply_override(module.path);
  }

  for (auto& region : context.memory_map) {
    if (region.name.empty()) {
      continue;
    }
    apply_override(region.name);
  }

  context.modules_by_id.clear();
  context.modules_by_id.reserve(context.modules.size());
  for (const auto& module : context.modules) {
    context.modules_by_id[module.id] = module;
  }

  memory_map_entries_.clear();
  memory_map_context_ = nullptr;
}

image_read_result module_source::read_module_image(
    const w1::rewind::module_record& module, uint64_t module_offset, size_t size
) {
  image_read_result result;

  if (size == 0) {
    result.error = "module read size is zero";
    return result;
  }

#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  (void) module_offset;
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
    const w1::rewind::replay_context& context, uint64_t address, size_t size
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

  if (!context.memory_map.empty()) {
    ensure_memory_map_index(context);
    if (const auto* entry = find_memory_map_entry(address)) {
      if (entry->module_base <= address) {
        w1::rewind::module_record module{};
        module.base = entry->module_base;
        module.path = entry->name;
        uint64_t module_offset = address - entry->module_base;
        auto mapped = read_module_image(module, module_offset, size);
        if (mapped.error.empty()) {
          return mapped;
        }
      }
    }
  }

  uint64_t module_offset = 0;
  auto* matched = context.find_module_for_address(address, static_cast<uint64_t>(size), module_offset);
  if (!matched) {
    result.error = "address not in module";
    return result;
  }

  return read_module_image(*matched, module_offset, size);
}

void module_source::ensure_memory_map_index(const w1::rewind::replay_context& context) {
  if (memory_map_context_ == &context) {
    return;
  }

  memory_map_context_ = &context;
  memory_map_entries_.clear();
  if (context.memory_map.empty()) {
    return;
  }

  memory_map_entries_.reserve(context.memory_map.size());
  for (const auto& region : context.memory_map) {
    if (region.size == 0 || region.image_id == 0) {
      continue;
    }
    if (add_overflows(region.base, region.size)) {
      continue;
    }
    uint64_t end = region.base + region.size;
    if (end <= region.base) {
      continue;
    }
    auto it = context.modules_by_id.find(region.image_id);
    if (it == context.modules_by_id.end()) {
      continue;
    }
    const auto& module = it->second;
    memory_map_entry entry{};
    entry.start = region.base;
    entry.end = end;
    entry.module_base = module.base;
    entry.name = module.path.empty() ? region.name : module.path;
    memory_map_entries_.push_back(std::move(entry));
  }

  std::unordered_map<std::string, uint64_t> module_bases;
  module_bases.reserve(context.memory_map.size());
  for (const auto& region : context.memory_map) {
    if (region.image_id != 0 || region.name.empty() || region.size == 0) {
      continue;
    }
    if (add_overflows(region.base, region.size)) {
      continue;
    }
    auto it = module_bases.find(region.name);
    if (it == module_bases.end() || region.base < it->second) {
      module_bases[region.name] = region.base;
    }
  }

  for (const auto& region : context.memory_map) {
    if (region.image_id != 0 || region.name.empty() || region.size == 0) {
      continue;
    }
    if (add_overflows(region.base, region.size)) {
      continue;
    }
    uint64_t end = region.base + region.size;
    if (end <= region.base) {
      continue;
    }
    auto it = module_bases.find(region.name);
    if (it == module_bases.end()) {
      continue;
    }
    memory_map_entry entry{};
    entry.start = region.base;
    entry.end = end;
    entry.module_base = it->second;
    entry.name = region.name;
    memory_map_entries_.push_back(std::move(entry));
  }

  std::sort(memory_map_entries_.begin(), memory_map_entries_.end(), [](const auto& left, const auto& right) {
    return left.start < right.start;
  });
}

const module_source::memory_map_entry* module_source::find_memory_map_entry(uint64_t address) const {
  if (memory_map_entries_.empty()) {
    return nullptr;
  }

  auto it = std::upper_bound(
      memory_map_entries_.begin(), memory_map_entries_.end(), address,
      [](uint64_t value, const memory_map_entry& entry) { return value < entry.start; }
  );
  if (it == memory_map_entries_.begin()) {
    return nullptr;
  }
  --it;
  if (address >= it->start && address < it->end) {
    return &(*it);
  }
  return nullptr;
}

const image_layout* module_source::get_module_layout(const w1::rewind::module_record& module, std::string& error) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  error = "module bytes unavailable (build with WITNESS_LIEF=ON)";
  return nullptr;
#else
  auto* entry = get_or_load_entry(module, error);
  if (!entry) {
    return nullptr;
  }
  return &entry->layout;
#endif
}

std::optional<std::string> module_source::get_module_uuid(
    const w1::rewind::module_record& module, std::string& error
) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  error = "module uuid unavailable (build with WITNESS_LIEF=ON)";
  return std::nullopt;
#else
  auto* entry = get_or_load_entry(module, error);
  if (!entry || !entry->binary) {
    return std::nullopt;
  }
  if (entry->binary->format() != LIEF::Binary::FORMATS::MACHO) {
    error = "module is not Mach-O";
    return std::nullopt;
  }
  auto* macho = dynamic_cast<LIEF::MachO::Binary*>(entry->binary.get());
  if (!macho || !macho->has_uuid()) {
    error = "Mach-O UUID unavailable";
    return std::nullopt;
  }
  const auto* uuid_cmd = macho->uuid();
  if (!uuid_cmd) {
    error = "Mach-O UUID unavailable";
    return std::nullopt;
  }
  const auto& uuid_bytes = uuid_cmd->uuid();
  if (is_all_zero_uuid(uuid_bytes)) {
    error = "Mach-O UUID is zero";
    return std::nullopt;
  }
  return format_uuid(uuid_bytes);
#endif
}

std::optional<uint64_t> module_source::get_macho_section_va(
    const w1::rewind::module_record& module, std::string_view section_name, std::string& error
) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  (void) section_name;
  error = "module sections unavailable (build with WITNESS_LIEF=ON)";
  return std::nullopt;
#else
  if (section_name.empty()) {
    error = "section name missing";
    return std::nullopt;
  }
  auto* entry = get_or_load_entry(module, error);
  if (!entry || !entry->binary) {
    return std::nullopt;
  }
  if (entry->binary->format() != LIEF::Binary::FORMATS::MACHO) {
    error = "module is not Mach-O";
    return std::nullopt;
  }
  auto* macho = dynamic_cast<LIEF::MachO::Binary*>(entry->binary.get());
  if (!macho) {
    error = "invalid Mach-O binary";
    return std::nullopt;
  }
  const auto* section = macho->get_section(std::string(section_name));
  if (!section) {
    error = "Mach-O section not found: " + std::string(section_name);
    return std::nullopt;
  }
  return section->virtual_address();
#endif
}

std::optional<macho_header_info> module_source::get_macho_header_info(
    const w1::rewind::module_record& module, std::string& error
) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  error = "module header unavailable (build with WITNESS_LIEF=ON)";
  return std::nullopt;
#else
  auto* entry = get_or_load_entry(module, error);
  if (!entry || !entry->binary) {
    return std::nullopt;
  }
  if (entry->binary->format() != LIEF::Binary::FORMATS::MACHO) {
    error = "module is not Mach-O";
    return std::nullopt;
  }
  auto* macho = dynamic_cast<LIEF::MachO::Binary*>(entry->binary.get());
  if (!macho) {
    error = "invalid Mach-O binary";
    return std::nullopt;
  }
  const auto& header = macho->header();
  macho_header_info info{};
  info.magic = static_cast<uint32_t>(header.magic());
  info.cputype = static_cast<uint32_t>(header.cpu_type());
  info.cpusubtype = header.cpu_subtype();
  info.filetype = static_cast<uint32_t>(header.file_type());
  return info;
#endif
}

std::vector<macho_segment_info> module_source::get_macho_segments(
    const w1::rewind::module_record& module, std::string& error
) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  error = "module segments unavailable (build with WITNESS_LIEF=ON)";
  return {};
#else
  auto* entry = get_or_load_entry(module, error);
  if (!entry || !entry->binary) {
    return {};
  }
  if (entry->binary->format() != LIEF::Binary::FORMATS::MACHO) {
    error = "module is not Mach-O";
    return {};
  }
  auto* macho = dynamic_cast<LIEF::MachO::Binary*>(entry->binary.get());
  if (!macho) {
    error = "invalid Mach-O binary";
    return {};
  }

  std::vector<macho_segment_info> segments;
  segments.reserve(macho->segments().size());
  for (const auto& segment : macho->segments()) {
    macho_segment_info info{};
    info.name = segment.name();
    info.vmaddr = segment.virtual_address();
    info.vmsize = segment.virtual_size();
    info.fileoff = segment.file_offset();
    info.filesize = segment.file_size();
    info.maxprot = static_cast<uint32_t>(segment.max_protection());
    segments.push_back(std::move(info));
  }
  return segments;
#endif
}

bool module_source::read_by_address(
    const w1::rewind::replay_context& context, uint64_t address, std::span<std::byte> out, std::string& error
) {
  if (out.empty()) {
    return true;
  }

  auto result = read_address_image(context, address, out.size());
  if (!result.error.empty()) {
    error = result.error;
    return false;
  }
  if (!result.complete) {
    error = "module bytes incomplete";
    return false;
  }
  if (result.bytes.size() < out.size()) {
    error = "module bytes truncated";
    return false;
  }
  std::copy(result.bytes.begin(), result.bytes.begin() + static_cast<std::ptrdiff_t>(out.size()), out.begin());
  return true;
}

#if defined(WITNESS_LIEF_ENABLED)
module_source::module_entry* module_source::get_or_load_entry(
    const w1::rewind::module_record& module, std::string& error
) {
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
  return &entry;
}
#endif

} // namespace w1replay
