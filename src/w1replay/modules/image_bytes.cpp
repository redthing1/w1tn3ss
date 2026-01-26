#include "image_bytes.hpp"

#include <algorithm>
#include <limits>

namespace w1replay {

namespace {

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

} // namespace

image_read_result make_empty_image_read(size_t size) {
  image_read_result result;
  if (size == 0) {
    return result;
  }
  result.bytes.assign(size, std::byte{0});
  result.known.assign(size, 0);
  return result;
}

bool any_known(const image_read_result& result) {
  return std::any_of(result.known.begin(), result.known.end(), [](uint8_t value) { return value != 0; });
}

bool all_known(const image_read_result& result) {
  if (result.known.empty()) {
    return false;
  }
  return std::all_of(result.known.begin(), result.known.end(), [](uint8_t value) { return value != 0; });
}

void merge_image_bytes(image_read_result& dest, const image_read_result& src) {
  if (src.bytes.empty() || src.known.empty()) {
    return;
  }

  if (dest.bytes.empty()) {
    dest.bytes.assign(src.bytes.size(), std::byte{0});
  }
  if (dest.known.size() != dest.bytes.size()) {
    dest.known.assign(dest.bytes.size(), 0);
  }

  const size_t limit = std::min({dest.bytes.size(), dest.known.size(), src.bytes.size(), src.known.size()});
  for (size_t i = 0; i < limit; ++i) {
    if (dest.known[i] == 0 && src.known[i]) {
      dest.bytes[i] = src.bytes[i];
      dest.known[i] = 1;
    }
  }
  dest.complete = all_known(dest);
}

void merge_image_bytes_at(image_read_result& dest, const image_read_result& src, size_t dest_offset) {
  if (src.bytes.empty() || src.known.empty()) {
    return;
  }

  if (dest.bytes.empty()) {
    dest.bytes.assign(dest_offset + src.bytes.size(), std::byte{0});
  }
  if (dest.known.size() != dest.bytes.size()) {
    dest.known.assign(dest.bytes.size(), 0);
  }
  if (dest_offset >= dest.bytes.size()) {
    return;
  }

  const size_t limit =
      std::min({src.bytes.size(), src.known.size(), dest.bytes.size() - dest_offset, dest.known.size() - dest_offset});
  for (size_t i = 0; i < limit; ++i) {
    if (dest.known[dest_offset + i] == 0 && src.known[i]) {
      dest.bytes[dest_offset + i] = src.bytes[i];
      dest.known[dest_offset + i] = 1;
    }
  }
  dest.complete = all_known(dest);
}

image_read_result read_image_bytes(const image_layout& layout, uint64_t image_offset, size_t size) {
  image_read_result result;

  if (size == 0) {
    result.error = "read size is zero";
    return result;
  }

  if (layout.ranges.empty()) {
    result.error = "no image ranges";
    return result;
  }

  if (add_overflows(layout.link_base, image_offset)) {
    result.error = "image offset overflows link base";
    return result;
  }
  const uint64_t start = layout.link_base + image_offset;
  if (add_overflows(start, size)) {
    result.error = "read size overflows address";
    return result;
  }
  const uint64_t end = start + size;

  result.bytes.assign(size, std::byte{0});
  result.known.assign(size, 0);

  for (const auto& range : layout.ranges) {
    if (range.mem_size == 0) {
      continue;
    }
    if (add_overflows(range.va_start, range.mem_size)) {
      result.error = "image range overflows address space";
      return result;
    }

    const uint64_t range_start = range.va_start;
    const uint64_t range_end = range.va_start + range.mem_size;
    if (range_end <= start || range_start >= end) {
      continue;
    }

    const uint64_t overlap_start = std::max(range_start, start);
    const uint64_t overlap_end = std::min(range_end, end);
    const uint64_t overlap_size64 = overlap_end - overlap_start;
    const uint64_t output_offset64 = overlap_start - start;
    const uint64_t range_offset64 = overlap_start - range_start;

    if (overlap_size64 == 0) {
      continue;
    }
    if (overlap_size64 > std::numeric_limits<size_t>::max() || output_offset64 > std::numeric_limits<size_t>::max() ||
        range_offset64 > std::numeric_limits<size_t>::max()) {
      result.error = "read size exceeds host limits";
      return result;
    }

    const size_t overlap_size = static_cast<size_t>(overlap_size64);
    const size_t output_offset = static_cast<size_t>(output_offset64);
    const size_t range_offset = static_cast<size_t>(range_offset64);

    const size_t stored_size = range.file_bytes.size();
    size_t file_available = 0;
    if (stored_size > 0) {
      if (range_offset < stored_size) {
        file_available = std::min(stored_size - range_offset, overlap_size);
      }
      if (file_available > 0) {
        const std::byte* src = range.file_bytes.data() + range_offset;
        std::byte* dest = result.bytes.data() + output_offset;
        std::copy(src, src + file_available, dest);
      }
    } else if (range.file_size > 0) {
      if (range_offset64 >= range.file_size) {
        file_available = 0;
      } else {
        uint64_t available64 = range.file_size - range_offset64;
        file_available = static_cast<size_t>(
            std::min<uint64_t>(available64, static_cast<uint64_t>(overlap_size))
        );
      }
      if (file_available > 0) {
        if (!layout.file_reader) {
          result.error = "image reader missing";
          return result;
        }
        if (add_overflows(range.file_offset, range_offset64)) {
          result.error = "image range overflows file offset";
          return result;
        }
        const uint64_t file_offset = range.file_offset + range_offset64;
        std::span<std::byte> dest(
            result.bytes.data() + output_offset,
            file_available
        );
        std::string error;
        if (!layout.file_reader->read(file_offset, dest, error)) {
          result.error = error.empty() ? "image read failed" : error;
          return result;
        }
      }
    }

    if (file_available > 0) {
      std::fill(
          result.known.begin() + static_cast<std::vector<uint8_t>::difference_type>(output_offset),
          result.known.begin() + static_cast<std::vector<uint8_t>::difference_type>(output_offset + file_available), 1
      );
    }

    const size_t bss_size = overlap_size - file_available;
    if (bss_size > 0) {
      const size_t bss_offset = output_offset + file_available;
      std::fill(
          result.known.begin() + static_cast<std::vector<uint8_t>::difference_type>(bss_offset),
          result.known.begin() + static_cast<std::vector<uint8_t>::difference_type>(bss_offset + bss_size), 1
      );
    }
  }

  result.complete = all_known(result);

  return result;
}

} // namespace w1replay
