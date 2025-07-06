#include "safe_memory.hpp"
#include <algorithm>
#include <cstring>

namespace w1::util {

std::optional<std::string> safe_memory::read_string(QBDI::VMInstanceRef vm, uint64_t address, size_t max_length) {

  if (address == 0) {
    return std::nullopt;
  }

  std::string result;
  result.reserve(std::min(max_length, size_t(64)));

  // Read in chunks for efficiency
  constexpr size_t chunk_size = 16;

  for (size_t offset = 0; offset < max_length; offset += chunk_size) {
    size_t to_read = std::min(chunk_size, max_length - offset);

    // Check if this chunk is readable
    if (!memory_validator().check_access(address + offset, to_read, memory_range_index::READ)) {
      // Return what we got so far
      return result.empty() ? std::nullopt : std::optional(result);
    }

    const char* src = reinterpret_cast<const char*>(address + offset);

    for (size_t i = 0; i < to_read; ++i) {
      if (src[i] == 0) {
        return result;
      }
      result.push_back(src[i]);
    }
  }

  return result;
}

std::optional<std::wstring> safe_memory::read_wstring(QBDI::VMInstanceRef vm, uint64_t address, size_t max_length) {

  if (address == 0) {
    return std::nullopt;
  }

  std::wstring result;
  result.reserve(std::min(max_length, size_t(64)));

  // Check if we can read at least one wchar
  if (!memory_validator().check_access(address, sizeof(wchar_t), memory_range_index::READ)) {
    return std::nullopt;
  }

  const wchar_t* src = reinterpret_cast<const wchar_t*>(address);

  for (size_t i = 0; i < max_length; ++i) {
    // Check if next wchar is readable
    uint64_t wchar_addr = reinterpret_cast<uint64_t>(src + i);
    if (!memory_validator().check_access(wchar_addr, sizeof(wchar_t), memory_range_index::READ)) {
      return result.empty() ? std::nullopt : std::optional(result);
    }

    if (src[i] == 0) {
      return result;
    }
    result.push_back(src[i]);
  }

  return result;
}

std::optional<safe_memory::buffer_info> safe_memory::read_buffer(
    QBDI::VMInstanceRef vm, uint64_t address, size_t size, size_t max_size
) {

  if (address == 0 || size == 0) {
    return buffer_info{{}, true, 0};
  }

  size_t to_read = std::min(size, max_size);

  // Check if entire range is readable
  if (memory_validator().check_access(address, to_read, memory_range_index::READ)) {
    // Fast path: read entire buffer at once
    const uint8_t* src = reinterpret_cast<const uint8_t*>(address);
    std::vector<uint8_t> data(src, src + to_read);

    return buffer_info{std::move(data), to_read == size, to_read};
  }

  // Slow path: read page by page
  std::vector<uint8_t> data;
  data.reserve(to_read);

  const size_t page_size = 4096;
  size_t actually_read = 0;

  for (size_t offset = 0; offset < to_read; offset += page_size) {
    size_t chunk_size = std::min(page_size, to_read - offset);

    if (memory_validator().check_access(address + offset, chunk_size, memory_range_index::READ)) {
      const uint8_t* src = reinterpret_cast<const uint8_t*>(address + offset);
      data.insert(data.end(), src, src + chunk_size);
      actually_read += chunk_size;
    } else {
      // Stop at first unreadable chunk
      break;
    }
  }

  return buffer_info{std::move(data), to_read == size, actually_read};
}

std::vector<bool> safe_memory::read_batch(QBDI::VMInstanceRef vm, const std::vector<batch_read_request>& requests) {

  std::vector<bool> results(requests.size());

  for (size_t i = 0; i < requests.size(); ++i) {
    const auto& req = requests[i];

    if (memory_validator().check_access(req.address, req.size, memory_range_index::READ)) {
      const void* src = reinterpret_cast<const void*>(req.address);
      std::memcpy(req.buffer, src, req.size);
      results[i] = true;
    } else {
      results[i] = false;
    }
  }

  return results;
}

} // namespace w1::util