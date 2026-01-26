#include "image_table_builder.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <limits>
#include <optional>
#include <string_view>

#include <QBDI.h>

#include "w1base/uuid_format.hpp"
#include "w1rewind/format/image_segment_utils.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#include <LIEF/ELF/Note.hpp>
#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <LIEF/MachO/Parser.hpp>
#include <LIEF/MachO/UUIDCommand.hpp>
#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/debug/CodeViewPDB.hpp>
#endif

namespace {

using w1rewind::image_metadata;

std::string lower_ascii(std::string_view value) {
  std::string out(value);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

w1::rewind::mapping_perm mapping_perm_from_qbdi(uint32_t perms) {
  w1::rewind::mapping_perm out = w1::rewind::mapping_perm::none;
  if (perms & QBDI::PF_READ) {
    out = out | w1::rewind::mapping_perm::read;
  }
  if (perms & QBDI::PF_WRITE) {
    out = out | w1::rewind::mapping_perm::write;
  }
  if (perms & QBDI::PF_EXEC) {
    out = out | w1::rewind::mapping_perm::exec;
  }
  return out;
}

bool path_exists(const std::string& path) {
  if (path.empty()) {
    return false;
  }
  std::error_code ec;
  return std::filesystem::exists(std::filesystem::path(path), ec);
}

std::string basename(const std::string& path) {
  auto pos = path.find_last_of("/\\");
  if (pos == std::string::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

#if defined(WITNESS_LIEF_ENABLED)
std::string hex_encode(LIEF::span<const uint8_t> bytes) {
  static const char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t value : bytes) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  }
  return out;
}

std::optional<uint64_t> elf_link_base(const LIEF::ELF::Binary& elf) {
  uint64_t link_base = std::numeric_limits<uint64_t>::max();
  for (const LIEF::ELF::Segment& segment : elf.segments()) {
    if (!segment.is_load() || segment.virtual_size() == 0) {
      continue;
    }
    link_base = std::min(link_base, segment.virtual_address());
  }
  if (link_base == std::numeric_limits<uint64_t>::max()) {
    return std::nullopt;
  }
  return link_base;
}

std::optional<uint64_t> macho_link_base(const LIEF::MachO::Binary& macho) {
  uint64_t link_base = std::numeric_limits<uint64_t>::max();
  for (const LIEF::MachO::SegmentCommand& segment : macho.segments()) {
    if (segment.name() == "__PAGEZERO" || segment.virtual_size() == 0) {
      continue;
    }
    link_base = std::min(link_base, segment.virtual_address());
  }
  if (link_base == std::numeric_limits<uint64_t>::max()) {
    return std::nullopt;
  }
  return link_base;
}

std::optional<uint64_t> pe_link_base(const LIEF::PE::Binary& pe) { return pe.imagebase(); }

LIEF::MachO::Header::CPU_TYPE macho_cpu_type_for_arch(const w1::rewind::arch_descriptor_record& arch) {
  using cpu_type = LIEF::MachO::Header::CPU_TYPE;
  std::string id = lower_ascii(arch.arch_id);
  std::string gdb_arch = lower_ascii(arch.gdb_arch);
  if (id == "x86_64" || id == "amd64" || gdb_arch == "i386:x86-64") {
    return cpu_type::X86_64;
  }
  if (id == "x86" || id == "i386" || id == "x86_32") {
    return cpu_type::X86;
  }
  if (id == "aarch64" || id == "arm64" || gdb_arch == "aarch64") {
    return cpu_type::ARM64;
  }
  if (id == "arm" || id == "thumb" || id == "armv7") {
    return cpu_type::ARM;
  }
  if (arch.pointer_bits == 64 && id.find("arm") != std::string::npos) {
    return cpu_type::ARM64;
  }
  if (arch.pointer_bits == 32 && id.find("arm") != std::string::npos) {
    return cpu_type::ARM;
  }
  return cpu_type::ANY;
}

std::optional<std::string> read_macho_uuid(const std::string& path, const w1::rewind::arch_descriptor_record& arch) {
  auto fat = LIEF::MachO::Parser::parse(path);
  if (!fat || fat->empty()) {
    return std::nullopt;
  }

  const auto target = macho_cpu_type_for_arch(arch);
  const LIEF::MachO::Binary* selected = nullptr;
  for (const auto& binary : *fat) {
    if (target == LIEF::MachO::Header::CPU_TYPE::ANY || binary.header().cpu_type() == target) {
      selected = &binary;
      break;
    }
  }
  if (!selected) {
    selected = fat->front();
  }
  if (!selected || !selected->has_uuid()) {
    return std::nullopt;
  }
  const auto* uuid_cmd = selected->uuid();
  if (!uuid_cmd) {
    return std::nullopt;
  }
  const auto& uuid_bytes = uuid_cmd->uuid();
  if (w1::util::is_all_zero_uuid(uuid_bytes)) {
    return std::nullopt;
  }
  return w1::util::format_uuid(uuid_bytes);
}

std::optional<uint64_t> read_macho_link_base(const std::string& path, const w1::rewind::arch_descriptor_record& arch) {
  auto fat = LIEF::MachO::Parser::parse(path);
  if (!fat || fat->empty()) {
    return std::nullopt;
  }

  const auto target = macho_cpu_type_for_arch(arch);
  const LIEF::MachO::Binary* selected = nullptr;
  for (const auto& binary : *fat) {
    if (target == LIEF::MachO::Header::CPU_TYPE::ANY || binary.header().cpu_type() == target) {
      selected = &binary;
      break;
    }
  }
  if (!selected) {
    selected = fat->front();
  }
  if (!selected) {
    return std::nullopt;
  }
  return macho_link_base(*selected);
}

image_metadata resolve_image_metadata(const std::string& path, const w1::rewind::arch_descriptor_record& arch) {
  image_metadata meta{};
  if (path.empty()) {
    return meta;
  }
  auto binary = LIEF::Parser::parse(path);
  if (!binary) {
    meta.file_backed = path_exists(path);
    return meta;
  }

  switch (binary->format()) {
  case LIEF::Binary::FORMATS::ELF: {
    meta.kind = "elf";
    auto* elf = dynamic_cast<LIEF::ELF::Binary*>(binary.get());
    if (!elf) {
      return meta;
    }
    meta.entry_point = elf->entrypoint();
    if (auto link_base = elf_link_base(*elf)) {
      meta.link_base = *link_base;
      meta.link_base_valid = true;
    }
    const auto* note = elf->get(LIEF::ELF::Note::TYPE::GNU_BUILD_ID);
    if (note) {
      auto desc = note->description();
      if (!desc.empty()) {
        meta.identity = hex_encode(desc);
      }
    }
    meta.segments.clear();
    meta.segments.reserve(elf->segments().size());
    for (const auto& segment : elf->segments()) {
      if (!segment.is_load()) {
        continue;
      }
      if (segment.virtual_size() == 0) {
        continue;
      }
      w1::rewind::image_segment_record seg{};
      seg.name = LIEF::ELF::to_string(segment.type());
      seg.vmaddr = segment.virtual_address();
      seg.vmsize = segment.virtual_size();
      seg.fileoff = segment.file_offset();
      seg.filesize = segment.physical_size();
      seg.maxprot = static_cast<uint32_t>(segment.flags());
      meta.segments.push_back(std::move(seg));
    }
    break;
  }
  case LIEF::Binary::FORMATS::MACHO: {
    meta.kind = "macho";
    auto uuid = read_macho_uuid(path, arch);
    if (uuid.has_value()) {
      meta.identity = *uuid;
    }
    if (auto link_base = read_macho_link_base(path, arch)) {
      meta.link_base = *link_base;
      meta.link_base_valid = true;
    }
    auto* macho = dynamic_cast<LIEF::MachO::Binary*>(binary.get());
    if (macho) {
      const auto& header = macho->header();
      meta.has_macho_header = true;
      meta.macho_header.magic = static_cast<uint32_t>(header.magic());
      meta.macho_header.cputype = static_cast<uint32_t>(header.cpu_type());
      meta.macho_header.cpusubtype = header.cpu_subtype();
      meta.macho_header.filetype = static_cast<uint32_t>(header.file_type());
      meta.segments.clear();
      meta.segments.reserve(macho->segments().size());
      for (const auto& segment : macho->segments()) {
        if (segment.virtual_size() == 0) {
          continue;
        }
        w1::rewind::image_segment_record seg{};
        seg.name = segment.name();
        seg.vmaddr = segment.virtual_address();
        seg.vmsize = segment.virtual_size();
        seg.fileoff = segment.file_offset();
        seg.filesize = segment.file_size();
        seg.maxprot = static_cast<uint32_t>(segment.max_protection());
        meta.segments.push_back(std::move(seg));
      }
      meta.entry_point = macho->entrypoint();
      if (!macho->has_uuid() && !meta.link_base_valid) {
        if (auto link_base = macho_link_base(*macho)) {
          meta.link_base = *link_base;
          meta.link_base_valid = true;
        }
      }
    }
    break;
  }
  case LIEF::Binary::FORMATS::PE: {
    meta.kind = "pe";
    auto* pe = dynamic_cast<LIEF::PE::Binary*>(binary.get());
    if (!pe) {
      return meta;
    }
    meta.entry_point = pe->entrypoint();
    if (auto link_base = pe_link_base(*pe)) {
      meta.link_base = *link_base;
      meta.link_base_valid = true;
    }
    if (const auto* pdb = pe->codeview_pdb()) {
      auto guid = pdb->guid();
      if (!guid.empty()) {
        meta.identity = std::move(guid);
        meta.identity_age = pdb->age();
      }
    }
    meta.segments.clear();
    meta.segments.reserve(pe->sections().size());
    for (const auto& section : pe->sections()) {
      uint64_t raw_size = section.sizeof_raw_data();
      uint64_t mem_size = w1::rewind::pe_section_mem_size(section.virtual_size(), raw_size);
      if (mem_size == 0) {
        continue;
      }
      w1::rewind::image_segment_record seg{};
      seg.name = section.name();
      seg.vmaddr = section.virtual_address();
      seg.vmsize = mem_size;
      seg.fileoff = section.pointerto_raw_data();
      seg.filesize = raw_size;
      seg.maxprot = static_cast<uint32_t>(section.characteristics());
      meta.segments.push_back(std::move(seg));
    }
    break;
  }
  default:
    break;
  }

  meta.file_backed = true;
  return meta;
}
#else
image_metadata resolve_image_metadata(const std::string& path, const w1::rewind::arch_descriptor_record&) {
  image_metadata meta{};
  meta.file_backed = path_exists(path);
  return meta;
}
#endif

} // namespace

namespace w1rewind {

image_metadata image_metadata_cache::lookup(const std::string& path) {
  if (path.empty()) {
    return image_metadata{};
  }
  auto it = cache_.find(path);
  if (it != cache_.end()) {
    return it->second;
  }
  image_metadata meta = resolve_image_metadata(path, arch_);
  cache_.emplace(path, meta);
  return meta;
}

w1::rewind::image_record build_image_record(
    const w1::runtime::module_info& module, uint64_t image_id, image_metadata_cache& cache, image_metadata* metadata_out
) {
  w1::rewind::image_record record{};
  record.image_id = image_id;
  record.name = module.name;
  if (record.name.empty()) {
    record.name = basename(module.path);
  }

  std::string path = module.path.empty() ? module.name : module.path;
  image_metadata meta = cache.lookup(path);
  if (metadata_out) {
    *metadata_out = meta;
  }

  record.kind = meta.kind.empty() ? "unknown" : meta.kind;
  record.identity = meta.identity;
  record.path = path;
  record.flags = w1::rewind::image_flag_none;
  if (module.is_main) {
    record.flags |= w1::rewind::image_flag_main;
  }
  if (meta.file_backed) {
    record.flags |= w1::rewind::image_flag_file_backed;
  }

  return record;
}

w1::rewind::image_metadata_record build_image_metadata_record(uint64_t image_id, const image_metadata& meta) {
  w1::rewind::image_metadata_record record{};
  record.image_id = image_id;
  record.format = meta.kind.empty() ? "unknown" : meta.kind;
  if (!meta.identity.empty() && record.format == "macho") {
    record.uuid = meta.identity;
    record.flags |= w1::rewind::image_meta_has_uuid;
  }
  if (meta.identity_age != 0) {
    record.identity_age = meta.identity_age;
    record.flags |= w1::rewind::image_meta_has_identity_age;
  }
  if (meta.entry_point.has_value()) {
    record.entry_point = *meta.entry_point;
    record.flags |= w1::rewind::image_meta_has_entry_point;
  }
  if (meta.link_base_valid) {
    record.link_base = meta.link_base;
    record.flags |= w1::rewind::image_meta_has_link_base;
  }
  if (meta.has_macho_header) {
    record.macho_header = meta.macho_header;
    record.flags |= w1::rewind::image_meta_has_macho_header;
  }
  if (!meta.segments.empty()) {
    record.segments = meta.segments;
    record.flags |= w1::rewind::image_meta_has_segments;
  }
  return record;
}

w1::rewind::mapping_record build_module_mapping(
    const w1::runtime::module_info& module, uint64_t image_id, uint32_t space_id
) {
  w1::rewind::mapping_record record{};
  record.kind = w1::rewind::mapping_event_kind::map;
  record.space_id = space_id;
  record.base = module.base_address;
  record.size = module.size;
  record.perms = mapping_perm_from_qbdi(module.permissions);
  record.image_id = image_id;
  record.name = module.path.empty() ? module.name : module.path;
  record.image_offset = 0;

  return record;
}

std::vector<w1::rewind::mapping_record> collect_process_mappings(
    std::span<const image_span> images, uint32_t space_id
) {
  std::vector<w1::rewind::mapping_record> regions;
  auto maps = QBDI::getCurrentProcessMaps(true);
  regions.reserve(maps.size());

  for (const auto& map : maps) {
    uint64_t start = map.range.start();
    uint64_t end = map.range.end();
    if (end <= start) {
      continue;
    }

    w1::rewind::mapping_record record{};
    record.kind = w1::rewind::mapping_event_kind::map;
    record.space_id = space_id;
    record.base = start;
    record.size = end - start;
    record.perms = mapping_perm_from_qbdi(map.permission);
    record.name = map.name;

    uint64_t best_overlap = 0;
    const image_span* best = nullptr;
    for (const auto& image : images) {
      if (image.size == 0) {
        continue;
      }
      uint64_t image_end = image.base + image.size;
      if (image_end <= image.base) {
        image_end = std::numeric_limits<uint64_t>::max();
      }
      uint64_t record_end = record.base + record.size;
      if (record_end <= record.base) {
        record_end = std::numeric_limits<uint64_t>::max();
      }
      if (image_end <= record.base || record.base >= image_end) {
        continue;
      }
      uint64_t overlap_start = std::max(record.base, image.base);
      uint64_t overlap_end = std::min(record_end, image_end);
      if (overlap_end <= overlap_start) {
        continue;
      }
      uint64_t overlap = overlap_end - overlap_start;
      if (overlap > best_overlap) {
        best_overlap = overlap;
        best = &image;
      }
    }

    if (best) {
      record.image_id = best->image_id;
      if (record.base >= best->base) {
        record.image_offset = record.base - best->base;
      }
    }

    regions.push_back(std::move(record));
  }

  std::sort(regions.begin(), regions.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
  return regions;
}

} // namespace w1rewind
