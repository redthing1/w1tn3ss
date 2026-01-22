#include "module_table_builder.hpp"

#include <algorithm>
#include <limits>
#include <optional>

#include <QBDI.h>

#include "w1base/uuid_format.hpp"
#include "w1rewind/record/memory_map_utils.hpp"

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
w1::rewind::module_perm module_perm_from_qbdi(uint32_t perms) {
  w1::rewind::module_perm out = w1::rewind::module_perm::none;
  if (perms & QBDI::PF_READ) {
    out = out | w1::rewind::module_perm::read;
  }
  if (perms & QBDI::PF_WRITE) {
    out = out | w1::rewind::module_perm::write;
  }
  if (perms & QBDI::PF_EXEC) {
    out = out | w1::rewind::module_perm::exec;
  }
  return out;
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
    if (!segment.is_load()) {
      continue;
    }
    if (segment.virtual_size() == 0) {
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
    if (segment.name() == "__PAGEZERO") {
      continue;
    }
    if (segment.virtual_size() == 0) {
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

LIEF::MachO::Header::CPU_TYPE macho_cpu_type_for_arch(const w1::arch::arch_spec& arch) {
  using cpu_type = LIEF::MachO::Header::CPU_TYPE;
  switch (arch.arch_mode) {
  case w1::arch::mode::x86_64:
    return cpu_type::X86_64;
  case w1::arch::mode::x86_32:
    return cpu_type::X86;
  case w1::arch::mode::aarch64:
    return cpu_type::ARM64;
  case w1::arch::mode::arm:
  case w1::arch::mode::thumb:
    return cpu_type::ARM;
  default:
    break;
  }
  return cpu_type::ANY;
}

std::optional<std::string> read_macho_uuid(const std::string& path, const w1::arch::arch_spec& arch) {
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

std::optional<uint64_t> read_macho_link_base(const std::string& path, const w1::arch::arch_spec& arch) {
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

void populate_module_identity(w1::rewind::module_record& record, const w1::arch::arch_spec& arch) {
  if (record.path.empty()) {
    return;
  }
  auto binary = LIEF::Parser::parse(record.path);
  if (!binary) {
    return;
  }

  switch (binary->format()) {
  case LIEF::Binary::FORMATS::ELF: {
    record.format = w1::rewind::module_format::elf;
    auto* elf = dynamic_cast<LIEF::ELF::Binary*>(binary.get());
    if (!elf) {
      return;
    }
    if (auto link_base = elf_link_base(*elf)) {
      record.link_base = *link_base;
      record.flags |= w1::rewind::module_record_flag_link_base_valid;
    }
    const auto* note = elf->get(LIEF::ELF::Note::TYPE::GNU_BUILD_ID);
    if (!note) {
      return;
    }
    auto desc = note->description();
    if (desc.empty()) {
      return;
    }
    record.identity = hex_encode(desc);
    return;
  }
  case LIEF::Binary::FORMATS::MACHO: {
    record.format = w1::rewind::module_format::macho;
    auto uuid = read_macho_uuid(record.path, arch);
    if (uuid.has_value()) {
      record.identity = *uuid;
    }
    if (auto link_base = read_macho_link_base(record.path, arch)) {
      record.link_base = *link_base;
      record.flags |= w1::rewind::module_record_flag_link_base_valid;
    }
    auto* macho = dynamic_cast<LIEF::MachO::Binary*>(binary.get());
    if (!macho) {
      return;
    }
    if (!macho->has_uuid()) {
      if ((record.flags & w1::rewind::module_record_flag_link_base_valid) == 0) {
        if (auto link_base = macho_link_base(*macho)) {
          record.link_base = *link_base;
          record.flags |= w1::rewind::module_record_flag_link_base_valid;
        }
      }
      return;
    }
    if ((record.flags & w1::rewind::module_record_flag_link_base_valid) == 0) {
      if (auto link_base = macho_link_base(*macho)) {
        record.link_base = *link_base;
        record.flags |= w1::rewind::module_record_flag_link_base_valid;
      }
    }
    const auto* uuid_cmd = macho->uuid();
    if (!uuid_cmd) {
      return;
    }
    const auto& uuid_bytes = uuid_cmd->uuid();
    if (w1::util::is_all_zero_uuid(uuid_bytes)) {
      return;
    }
    record.identity = w1::util::format_uuid(uuid_bytes);
    return;
  }
  case LIEF::Binary::FORMATS::PE: {
    record.format = w1::rewind::module_format::pe;
    auto* pe = dynamic_cast<LIEF::PE::Binary*>(binary.get());
    if (!pe) {
      return;
    }
    if (auto link_base = pe_link_base(*pe)) {
      record.link_base = *link_base;
      record.flags |= w1::rewind::module_record_flag_link_base_valid;
    }
    const auto* pdb = pe->codeview_pdb();
    if (!pdb) {
      return;
    }
    auto guid = pdb->guid();
    if (!guid.empty()) {
      record.identity = std::move(guid);
      record.identity_age = pdb->age();
    }
    return;
  }
  default:
    break;
  }
}
#else
void populate_module_identity(w1::rewind::module_record&, const w1::arch::arch_spec&) {}
#endif

} // namespace

namespace w1rewind {

std::vector<w1::rewind::memory_region_record> collect_memory_map(
    const std::vector<w1::rewind::module_record>& modules
) {
  std::vector<w1::rewind::memory_region_record> regions;
  auto maps = QBDI::getCurrentProcessMaps(true);
  regions.reserve(maps.size());
  for (const auto& map : maps) {
    uint64_t start = map.range.start();
    uint64_t end = map.range.end();
    if (end <= start) {
      continue;
    }
    w1::rewind::memory_region_record region{};
    region.base = start;
    region.size = end - start;
    region.permissions = module_perm_from_qbdi(map.permission);
    region.image_id = 0;
    region.name = map.name;
    regions.push_back(std::move(region));
  }
  w1::rewind::assign_memory_map_image_ids(regions, modules);
  std::sort(regions.begin(), regions.end(), [](const auto& left, const auto& right) { return left.base < right.base; });
  return regions;
}

std::vector<w1::rewind::module_record> build_module_table(
    const w1::runtime::module_catalog& modules, const w1::arch::arch_spec& arch
) {
  std::vector<w1::rewind::module_record> table;
  auto list = modules.list_modules();
  table.reserve(list.size());

  uint64_t next_id = 1;
  for (const auto& module : list) {
    w1::rewind::module_record record{};
    record.id = next_id++;
    record.base = module.base_address;
    record.size = module.size;
    record.permissions = module_perm_from_qbdi(module.permissions);
    record.path = module.path.empty() ? module.name : module.path;
    populate_module_identity(record, arch);
    table.push_back(std::move(record));
  }
  return table;
}

} // namespace w1rewind
