#include "module_image_lief.hpp"

#if defined(WITNESS_LIEF_ENABLED)

#include <algorithm>
#include <limits>
#include <span>

namespace w1replay {

namespace {

std::span<const std::byte> as_byte_span(LIEF::span<const uint8_t> data) {
  return std::as_bytes(std::span<const uint8_t>(data.data(), data.size()));
}

bool build_elf_layout(const LIEF::ELF::Binary& elf, image_layout& layout, std::string& error) {
  uint64_t link_base = std::numeric_limits<uint64_t>::max();
  layout.ranges.clear();

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
    error = "no loadable segments";
    return false;
  }

  layout.link_base = link_base;
  for (const LIEF::ELF::Segment& segment : elf.segments()) {
    if (!segment.is_load()) {
      continue;
    }
    const uint64_t mem_size = segment.virtual_size();
    if (mem_size == 0) {
      continue;
    }
    image_range range{};
    range.va_start = segment.virtual_address();
    range.mem_size = mem_size;
    range.file_bytes = as_byte_span(segment.content());
    layout.ranges.push_back(range);
  }

  std::sort(layout.ranges.begin(), layout.ranges.end(), [](const image_range& a, const image_range& b) {
    return a.va_start < b.va_start;
  });
  return true;
}

bool build_macho_layout(const LIEF::MachO::Binary& macho, image_layout& layout, std::string& error) {
  uint64_t link_base = std::numeric_limits<uint64_t>::max();
  layout.ranges.clear();

  for (const LIEF::MachO::SegmentCommand& segment : macho.segments()) {
    if (segment.name() == "__PAGEZERO") {
      continue;
    }
    const uint64_t mem_size = segment.virtual_size();
    if (mem_size == 0) {
      continue;
    }
    link_base = std::min(link_base, segment.virtual_address());
  }

  if (link_base == std::numeric_limits<uint64_t>::max()) {
    error = "no loadable segments";
    return false;
  }

  layout.link_base = link_base;
  for (const LIEF::MachO::SegmentCommand& segment : macho.segments()) {
    if (segment.name() == "__PAGEZERO") {
      continue;
    }
    uint64_t mem_size = segment.virtual_size();
    if (mem_size == 0) {
      continue;
    }
    image_range range{};
    range.va_start = segment.virtual_address();
    range.mem_size = mem_size;
    range.file_bytes = as_byte_span(segment.content());
    layout.ranges.push_back(range);
  }

  std::sort(layout.ranges.begin(), layout.ranges.end(), [](const image_range& a, const image_range& b) {
    return a.va_start < b.va_start;
  });
  return true;
}

bool build_pe_layout(const LIEF::PE::Binary& pe, image_layout& layout, std::string& error) {
  layout.link_base = 0;
  layout.ranges.clear();

  for (const LIEF::PE::Section& section : pe.sections()) {
    auto content = section.content();
    uint64_t mem_size = std::max<uint64_t>(section.virtual_size(), content.size());
    if (mem_size == 0) {
      continue;
    }
    image_range range{};
    range.va_start = section.virtual_address();
    range.mem_size = mem_size;
    range.file_bytes = as_byte_span(content);
    layout.ranges.push_back(range);
  }

  if (layout.ranges.empty()) {
    error = "no sections";
    return false;
  }

  std::sort(layout.ranges.begin(), layout.ranges.end(), [](const image_range& a, const image_range& b) {
    return a.va_start < b.va_start;
  });
  return true;
}

} // namespace

bool build_image_layout(const LIEF::Binary& binary, image_layout& layout, std::string& error) {
  switch (binary.format()) {
  case LIEF::Binary::FORMATS::ELF: {
    auto* elf = dynamic_cast<const LIEF::ELF::Binary*>(&binary);
    if (!elf) {
      error = "invalid ELF binary";
      return false;
    }
    return build_elf_layout(*elf, layout, error);
  }
  case LIEF::Binary::FORMATS::MACHO: {
    auto* macho = dynamic_cast<const LIEF::MachO::Binary*>(&binary);
    if (!macho) {
      error = "invalid Mach-O binary";
      return false;
    }
    return build_macho_layout(*macho, layout, error);
  }
  case LIEF::Binary::FORMATS::PE: {
    auto* pe = dynamic_cast<const LIEF::PE::Binary*>(&binary);
    if (!pe) {
      error = "invalid PE binary";
      return false;
    }
    return build_pe_layout(*pe, layout, error);
  }
  default:
    error = "unsupported binary format";
    return false;
  }
}

} // namespace w1replay

#endif
