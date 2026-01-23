#include "lief_module_provider.hpp"

#include "module_image_lief.hpp"
#include "w1base/uuid_format.hpp"

#include <algorithm>
#include <unordered_map>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/replay/replay_context.hpp"

namespace w1replay {

lief_module_provider::lief_module_provider(lief_module_provider_config config)
    : resolver_(config.resolver), address_index_(config.address_index),
      address_reader_(std::move(config.address_reader)) {}

std::string lief_module_provider::resolved_module_path(const w1::rewind::module_record& module) const {
  if (resolver_) {
    if (auto resolved = resolver_->resolve_module_path(module)) {
      return *resolved;
    }
  }
  return module.path;
}

image_read_result lief_module_provider::read_module_bytes(
    const w1::rewind::module_record& module, uint64_t offset, size_t size
) {
  image_read_result result;

  if (size == 0) {
    result.error = "module read size is zero";
    return result;
  }

#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  (void) offset;
  result.error = "module bytes unavailable (build with WITNESS_LIEF=ON)";
  return result;
#else
  std::string layout_error;
  const auto* layout = module_layout(module, layout_error);
  if (!layout) {
    result.error = layout_error.empty() ? "module layout unavailable" : layout_error;
    return result;
  }

  result = read_image_bytes(*layout, offset, size);
  if (!result.error.empty()) {
    result.error = "module image read failed: " + result.error;
  }
  return result;
#endif
}

image_read_result lief_module_provider::read_address_bytes(
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

  std::optional<module_address_match> match;
  if (address_index_) {
    match = address_index_->find(address, static_cast<uint64_t>(size));
  } else {
    module_address_index fallback(context);
    match = fallback.find(address, static_cast<uint64_t>(size));
  }
  if (!match.has_value() || !match->module) {
    result.error = "address not in module";
    return result;
  }

  w1::rewind::module_record resolved = *match->module;
  std::string resolved_path = resolved_module_path(*match->module);
  if (!resolved_path.empty()) {
    resolved.path = std::move(resolved_path);
  }
  return read_module_bytes(resolved, match->module_offset, size);
}

const image_layout* lief_module_provider::module_layout(const w1::rewind::module_record& module, std::string& error) {
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

std::optional<std::string> lief_module_provider::module_uuid(
    const w1::rewind::module_record& module, std::string& error
) {
  error.clear();
  if (module.format == w1::rewind::module_format::macho && !module.identity.empty()) {
    return module.identity;
  }

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
  if (w1::util::is_all_zero_uuid(uuid_bytes)) {
    error = "Mach-O UUID is zero";
    return std::nullopt;
  }
  return w1::util::format_uuid(uuid_bytes);
#endif
}

std::optional<uint64_t> lief_module_provider::module_entry_point(
    const w1::rewind::module_record& module, std::string& error
) {
  error.clear();
#if !defined(WITNESS_LIEF_ENABLED)
  (void) module;
  error = "module entrypoint unavailable (build with WITNESS_LIEF=ON)";
  return std::nullopt;
#else
  auto* entry = get_or_load_entry(module, error);
  if (!entry || !entry->binary) {
    return std::nullopt;
  }
  return entry->binary->entrypoint();
#endif
}

std::optional<macho_header_info> lief_module_provider::macho_header(
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

std::vector<macho_segment_info> lief_module_provider::macho_segments(
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

#if defined(WITNESS_LIEF_ENABLED)
lief_module_provider::module_entry* lief_module_provider::get_or_load_entry(
    const w1::rewind::module_record& module, std::string& error
) {
  std::string path = resolved_module_path(module);
  if (path.empty()) {
    error = "module path missing";
    return nullptr;
  }

  auto& entry = modules_[path];
  if (!entry.binary) {
    auto binary = LIEF::Parser::parse(path);
    if (!binary) {
      error = "failed to parse module: " + path;
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
