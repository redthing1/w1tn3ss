#include "image_blob_reader.hpp"

#include <algorithm>
#include <limits>

namespace w1replay {

namespace {

bool add_overflows(uint64_t base, uint64_t addend) { return base > std::numeric_limits<uint64_t>::max() - addend; }

} // namespace

image_read_result read_image_blob_index(const w1::rewind::image_blob_index& index, uint64_t image_offset, size_t size) {
  image_read_result result = make_empty_image_read(size);
  if (size == 0) {
    result.error = "image read size is zero";
    return result;
  }
  if (index.spans.empty()) {
    return result;
  }
  if (add_overflows(image_offset, size)) {
    result.error = "image read overflows address space";
    return result;
  }
  const uint64_t end = image_offset + size;

  auto it = std::upper_bound(
      index.spans.begin(), index.spans.end(), image_offset,
      [](uint64_t value, const w1::rewind::image_blob_span& span) { return value < span.offset; }
  );
  if (it != index.spans.begin()) {
    --it;
  }

  for (; it != index.spans.end(); ++it) {
    const auto& span = *it;
    if (span.end <= image_offset) {
      continue;
    }
    if (span.offset >= end) {
      break;
    }

    const uint64_t overlap_start = std::max(span.offset, image_offset);
    const uint64_t overlap_end = std::min(span.end, end);
    const uint64_t overlap_size64 = overlap_end - overlap_start;
    const uint64_t blob_offset64 = overlap_start - span.offset;
    const uint64_t out_offset64 = overlap_start - image_offset;

    if (overlap_size64 == 0) {
      continue;
    }
    if (overlap_size64 > std::numeric_limits<size_t>::max() || blob_offset64 > std::numeric_limits<size_t>::max() ||
        out_offset64 > std::numeric_limits<size_t>::max()) {
      result.error = "image blob read exceeds host limits";
      return result;
    }

    const size_t overlap_size = static_cast<size_t>(overlap_size64);
    const size_t blob_offset = static_cast<size_t>(blob_offset64);
    const size_t out_offset = static_cast<size_t>(out_offset64);

    if (!span.data || span.size < blob_offset + overlap_size) {
      result.error = "image blob span out of bounds";
      return result;
    }

    const std::byte* src = reinterpret_cast<const std::byte*>(span.data + blob_offset);
    std::byte* dest = result.bytes.data() + out_offset;
    std::copy(src, src + overlap_size, dest);
    const auto known_offset = static_cast<std::ptrdiff_t>(out_offset);
    const auto known_end = known_offset + static_cast<std::ptrdiff_t>(overlap_size);
    std::fill(result.known.begin() + known_offset, result.known.begin() + known_end, 1);
  }

  result.complete = all_known(result);
  return result;
}

} // namespace w1replay
