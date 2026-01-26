#include "image_layout_from_metadata.hpp"

#include <algorithm>
#include <limits>
#include <optional>

#include "file_image_reader.hpp"

namespace w1replay {

namespace {

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

std::optional<uint64_t> resolve_link_base(const w1::rewind::image_metadata_record& meta) {
  if ((meta.flags & w1::rewind::image_meta_has_link_base) != 0) {
    return meta.link_base;
  }

  uint64_t link_base = std::numeric_limits<uint64_t>::max();
  bool saw_segment = false;
  for (const auto& segment : meta.segments) {
    if (segment.vmsize == 0) {
      continue;
    }
    if (segment.name == "__PAGEZERO") {
      continue;
    }
    link_base = std::min(link_base, segment.vmaddr);
    saw_segment = true;
  }
  if (!saw_segment || link_base == std::numeric_limits<uint64_t>::max()) {
    return std::nullopt;
  }
  return link_base;
}

} // namespace

bool build_layout_from_metadata(
    const w1::rewind::image_metadata_record& meta, const std::string& path, image_layout& layout, std::string& error
) {
  if (meta.segments.empty()) {
    error = "image metadata missing segments";
    return false;
  }

  auto link_base = resolve_link_base(meta);
  if (!link_base.has_value()) {
    error = "image metadata missing link base";
    return false;
  }

  if (path.empty()) {
    error = "image path missing";
    return false;
  }

  uint64_t file_size = 0;
  if (!read_file_size(path, file_size, error)) {
    return false;
  }

  layout.link_base = *link_base;
  layout.ranges.clear();
  layout.ranges.reserve(meta.segments.size());

  for (const auto& segment : meta.segments) {
    if (segment.vmsize == 0) {
      continue;
    }

    image_range range{};
    range.va_start = segment.vmaddr;
    range.mem_size = segment.vmsize;

    if (segment.filesize != 0) {
      if (add_overflows(segment.fileoff, segment.filesize) || segment.fileoff + segment.filesize > file_size) {
        error = "segment file range out of bounds";
        return false;
      }
      range.file_offset = segment.fileoff;
      range.file_size = segment.filesize;
      range.file_bytes = {};
    }

    layout.ranges.push_back(std::move(range));
  }

  if (layout.ranges.empty()) {
    error = "image metadata missing loadable ranges";
    return false;
  }

  layout.file_reader = std::make_shared<file_image_reader>(path, file_size);
  std::sort(layout.ranges.begin(), layout.ranges.end(), [](const image_range& a, const image_range& b) {
    return a.va_start < b.va_start;
  });
  return true;
}

} // namespace w1replay
