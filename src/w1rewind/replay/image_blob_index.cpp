#include "image_blob_index.hpp"

#include <algorithm>
#include <limits>

namespace w1::rewind {

namespace {

uint64_t safe_end(uint64_t base, uint64_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + size;
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

} // namespace

bool build_image_blob_index(std::span<const image_blob_record> blobs, image_blob_index& out, std::string& error) {
  error.clear();
  out.spans.clear();
  out.spans.reserve(blobs.size());

  for (const auto& blob : blobs) {
    if (blob.data.empty()) {
      continue;
    }
    uint64_t end = safe_end(blob.offset, blob.data.size());
    if (end <= blob.offset) {
      error = "image blob range invalid";
      return false;
    }

    image_blob_span span{};
    span.offset = blob.offset;
    span.end = end;
    span.data = blob.data.data();
    span.size = blob.data.size();
    out.spans.push_back(span);
  }

  std::sort(out.spans.begin(), out.spans.end(), [](const image_blob_span& a, const image_blob_span& b) {
    return a.offset < b.offset;
  });
  for (size_t i = 1; i < out.spans.size(); ++i) {
    if (out.spans[i].offset < out.spans[i - 1].end) {
      error = "image blob ranges overlap";
      return false;
    }
  }

  return true;
}

} // namespace w1::rewind
