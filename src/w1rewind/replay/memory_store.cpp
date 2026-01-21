#include "memory_store.hpp"

#include <algorithm>
#include <limits>

namespace w1::rewind {

namespace {

uint64_t safe_end(uint64_t base, size_t size) {
  if (size == 0) {
    return base;
  }
  uint64_t end = base + static_cast<uint64_t>(size);
  if (end < base) {
    return std::numeric_limits<uint64_t>::max();
  }
  return end;
}

} // namespace

void memory_store::clear() { spans_.clear(); }

void memory_store::apply_bytes(uint64_t address, std::span<const uint8_t> bytes) {
  if (bytes.empty()) {
    return;
  }

  uint64_t start = address;
  uint64_t end = safe_end(address, bytes.size());
  if (end == std::numeric_limits<uint64_t>::max() && start != 0) {
    return;
  }

  std::vector<memory_span> merged;
  merged.reserve(spans_.size() + 1);

  size_t index = 0;
  while (index < spans_.size()) {
    const auto& span = spans_[index];
    uint64_t span_end = safe_end(span.base, span.bytes.size());
    if (span_end < start) {
      merged.push_back(span);
      ++index;
      continue;
    }
    break;
  }

  uint64_t merged_start = start;
  uint64_t merged_end = end;
  size_t merge_start = index;
  while (index < spans_.size()) {
    const auto& span = spans_[index];
    if (span.base > merged_end) {
      break;
    }
    uint64_t span_end = safe_end(span.base, span.bytes.size());
    if (span.base < merged_start) {
      merged_start = span.base;
    }
    if (span_end > merged_end) {
      merged_end = span_end;
    }
    ++index;
  }

  size_t merge_end = index;
  if (merge_start == merge_end) {
    memory_span span{};
    span.base = start;
    span.bytes.assign(bytes.begin(), bytes.end());
    merged.push_back(std::move(span));
  } else {
    size_t merged_size = static_cast<size_t>(merged_end - merged_start);
    std::vector<uint8_t> merged_bytes(merged_size, 0);

    for (size_t i = merge_start; i < merge_end; ++i) {
      const auto& span = spans_[i];
      size_t offset = static_cast<size_t>(span.base - merged_start);
      std::copy(span.bytes.begin(), span.bytes.end(), merged_bytes.begin() + static_cast<std::ptrdiff_t>(offset));
    }

    size_t incoming_offset = static_cast<size_t>(start - merged_start);
    std::copy(bytes.begin(), bytes.end(), merged_bytes.begin() + static_cast<std::ptrdiff_t>(incoming_offset));

    memory_span span{};
    span.base = merged_start;
    span.bytes = std::move(merged_bytes);
    merged.push_back(std::move(span));
  }

  merged.insert(merged.end(), spans_.begin() + static_cast<std::ptrdiff_t>(merge_end), spans_.end());
  spans_ = std::move(merged);
}

void memory_store::apply_segments(std::span<const memory_span> segments) {
  for (const auto& segment : segments) {
    apply_bytes(segment.base, segment.bytes);
  }
}

memory_read memory_store::read(uint64_t address, size_t size) const {
  memory_read out;
  out.bytes.assign(size, std::byte{0});
  out.known.assign(size, 0);

  if (size == 0 || spans_.empty()) {
    return out;
  }

  uint64_t start = address;
  uint64_t end = safe_end(address, size);
  if (end == std::numeric_limits<uint64_t>::max() && start != 0) {
    return out;
  }

  for (const auto& span : spans_) {
    uint64_t span_end = safe_end(span.base, span.bytes.size());
    if (span_end <= start) {
      continue;
    }
    if (span.base >= end) {
      break;
    }

    uint64_t overlap_start = std::max(start, span.base);
    uint64_t overlap_end = std::min(end, span_end);
    if (overlap_end <= overlap_start) {
      continue;
    }

    size_t out_offset = static_cast<size_t>(overlap_start - start);
    size_t span_offset = static_cast<size_t>(overlap_start - span.base);
    size_t overlap_size = static_cast<size_t>(overlap_end - overlap_start);

    for (size_t i = 0; i < overlap_size; ++i) {
      out.bytes[out_offset + i] = std::byte{span.bytes[span_offset + i]};
      out.known[out_offset + i] = 1;
    }
  }

  return out;
}

std::vector<memory_span> memory_store::spans() const { return spans_; }

} // namespace w1::rewind
