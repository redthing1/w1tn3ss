#include "lief_image_layout_provider.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include "file_image_reader.hpp"
#include "w1base/uuid_format.hpp"
#include "w1rewind/format/image_segment_utils.hpp"

#if defined(WITNESS_LIEF_ENABLED)
#include <LIEF/LIEF.hpp>
#endif

namespace w1replay {

#if defined(WITNESS_LIEF_ENABLED)

namespace {

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

std::string hex_encode(LIEF::span<const uint8_t> bytes) {
  static constexpr char k_hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t value : bytes) {
    out.push_back(k_hex[(value >> 4) & 0x0f]);
    out.push_back(k_hex[value & 0x0f]);
  }
  return out;
}

bool add_range(
    image_layout& layout, uint64_t va_start, uint64_t mem_size, uint64_t file_offset, uint64_t file_size,
    uint64_t file_limit, std::string& error
) {
  if (mem_size == 0) {
    return true;
  }
  if (file_size != 0) {
    if (add_overflows(file_offset, file_size) || file_offset + file_size > file_limit) {
      error = "segment file range out of bounds";
      return false;
    }
  }

  image_range range{};
  range.va_start = va_start;
  range.mem_size = mem_size;
  if (file_size != 0) {
    range.file_offset = file_offset;
    range.file_size = file_size;
  }
  layout.ranges.push_back(std::move(range));
  return true;
}

} // namespace

class lief_layout_provider final : public image_layout_provider {
public:
  bool build_layout(
      const w1::rewind::image_record& image, const w1::rewind::image_metadata_record* /*metadata*/,
      const std::string& path, image_layout& layout, image_layout_identity* identity, std::string& error
  ) override {
    error.clear();
    (void) image;
    if (path.empty()) {
      error = "image path missing";
      return false;
    }

    uint64_t file_size = 0;
    if (!read_file_size(path, file_size, error)) {
      return false;
    }

    auto binary = LIEF::Parser::parse(path);
    if (!binary) {
      error = "failed to parse image with LIEF";
      return false;
    }

    layout = image_layout{};
    layout.ranges.clear();
    if (identity) {
      identity->identity.clear();
      identity->age.reset();
    }

    uint64_t link_base = 0;
    bool saw_range = false;

    std::unique_ptr<LIEF::MachO::FatBinary> fat_binary;
    const LIEF::MachO::Binary* macho_binary = nullptr;

    switch (binary->format()) {
    case LIEF::Binary::FORMATS::ELF: {
      auto* elf = static_cast<LIEF::ELF::Binary*>(binary.get());
      for (const auto& segment : elf->segments()) {
        if (!segment.is_load()) {
          continue;
        }
        uint64_t mem_size = segment.virtual_size();
        if (mem_size == 0) {
          continue;
        }
        if (!add_range(
                layout, segment.virtual_address(), mem_size, segment.file_offset(), segment.physical_size(), file_size,
                error
            )) {
          return false;
        }
        if (!saw_range || segment.virtual_address() < link_base) {
          link_base = segment.virtual_address();
          saw_range = true;
        }
      }
      if (identity) {
        const auto* note = elf->get(LIEF::ELF::Note::TYPE::GNU_BUILD_ID);
        if (note) {
          auto desc = note->description();
          if (!desc.empty()) {
            identity->identity = hex_encode(desc);
          }
        }
      }
      break;
    }
    case LIEF::Binary::FORMATS::MACHO: {
      macho_binary = dynamic_cast<LIEF::MachO::Binary*>(binary.get());
      if (!macho_binary) {
        fat_binary = LIEF::MachO::Parser::parse(path);
        if (fat_binary && !fat_binary->empty()) {
          macho_binary = fat_binary->front();
        }
      }
      if (!macho_binary) {
        error = "failed to parse Mach-O image";
        return false;
      }
      for (const auto& segment : macho_binary->segments()) {
        if (segment.virtual_size() == 0) {
          continue;
        }
        if (segment.name() == "__PAGEZERO") {
          continue;
        }
        if (!add_range(
                layout, segment.virtual_address(), segment.virtual_size(), segment.file_offset(), segment.file_size(),
                file_size, error
            )) {
          return false;
        }
        if (!saw_range || segment.virtual_address() < link_base) {
          link_base = segment.virtual_address();
          saw_range = true;
        }
      }
      if (identity && macho_binary->has_uuid()) {
        const auto* uuid_cmd = macho_binary->uuid();
        if (uuid_cmd) {
          const auto& uuid_bytes = uuid_cmd->uuid();
          if (!w1::util::is_all_zero_uuid(uuid_bytes)) {
            identity->identity = w1::util::format_uuid(uuid_bytes);
          }
        }
      }
      break;
    }
    case LIEF::Binary::FORMATS::PE: {
      auto* pe = static_cast<LIEF::PE::Binary*>(binary.get());
      link_base = pe->imagebase();
      for (const auto& section : pe->sections()) {
        uint64_t raw_size = section.sizeof_raw_data();
        uint64_t mem_size = w1::rewind::pe_section_mem_size(section.virtual_size(), raw_size);
        if (mem_size == 0) {
          continue;
        }
        uint64_t va_start = link_base + section.virtual_address();
        if (!add_range(layout, va_start, mem_size, section.pointerto_raw_data(), raw_size, file_size, error)) {
          return false;
        }
      }
      if (!saw_range && !layout.ranges.empty()) {
        saw_range = true;
      }
      if (identity) {
        if (const auto* pdb = pe->codeview_pdb()) {
          auto guid = pdb->guid();
          if (!guid.empty()) {
            identity->identity = std::move(guid);
            identity->age = pdb->age();
          }
        }
      }
      break;
    }
    default:
      error = "unsupported binary format for LIEF layout";
      return false;
    }

    if (layout.ranges.empty()) {
      error = "image has no loadable ranges";
      return false;
    }

    if (!saw_range) {
      link_base = layout.ranges.front().va_start;
    }
    layout.link_base = link_base;
    layout.file_reader = std::make_shared<file_image_reader>(path, file_size);
    std::sort(layout.ranges.begin(), layout.ranges.end(), [](const image_range& a, const image_range& b) {
      return a.va_start < b.va_start;
    });
    return true;
  }
};

std::shared_ptr<image_layout_provider> make_lief_layout_provider(std::string& error) {
  error.clear();
  return std::make_shared<lief_layout_provider>();
}

#else

std::shared_ptr<image_layout_provider> make_lief_layout_provider(std::string& error) {
  error = "LIEF support disabled (build with WITNESS_LIEF=ON)";
  return {};
}

#endif

} // namespace w1replay
