#pragma once

#include <QBDI.h>
#include "memory_range_index.hpp"
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace w1::util {

class safe_memory {
public:
  // Get thread-local memory validator
  static memory_range_index& memory_validator() {
    thread_local memory_range_index validator;
    return validator;
  }

  // Core read API - template for zero overhead
  template <typename T> static std::optional<T> read(QBDI::VMInstanceRef vm, uint64_t address) {
    static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");

    if (!memory_validator().check_access(address, sizeof(T), memory_range_index::READ)) {
      return std::nullopt;
    }

    const T* ptr = reinterpret_cast<const T*>(address);
    return *ptr;
  }

  // Read array of primitives
  template <typename T>
  static std::optional<std::vector<T>> read_array(QBDI::VMInstanceRef vm, uint64_t address, size_t count) {

    static_assert(std::is_trivially_copyable_v<T>);
    if (count == 0) {
      return std::vector<T>{};
    }

    size_t total_size = sizeof(T) * count;
    if (!memory_validator().check_access(address, total_size, memory_range_index::READ)) {
      return std::nullopt;
    }

    const T* ptr = reinterpret_cast<const T*>(address);
    return std::vector<T>(ptr, ptr + count);
  }

  // String reading with null termination detection
  static std::optional<std::string> read_string(QBDI::VMInstanceRef vm, uint64_t address, size_t max_length = 256);

  // Wide string reading (Windows)
  static std::optional<std::wstring> read_wstring(QBDI::VMInstanceRef vm, uint64_t address, size_t max_length = 256);

  // Buffer reading with metadata
  struct buffer_info {
    std::vector<uint8_t> data;
    bool complete; // false if truncated
    size_t bytes_read;
  };

  static std::optional<buffer_info> read_buffer(
      QBDI::VMInstanceRef vm, uint64_t address, size_t size, size_t max_size = 4096
  );

  // Structured read with automatic alignment
  template <typename T> static std::optional<T> read_struct(QBDI::VMInstanceRef vm, uint64_t address) {

    static_assert(std::is_standard_layout_v<T>, "T must have standard layout");

    if (!memory_validator().check_access(address, sizeof(T), memory_range_index::READ)) {
      return std::nullopt;
    }

    // Handle alignment requirements
    if (address % alignof(T) != 0) {
      // Read unaligned
      std::array<uint8_t, sizeof(T)> buffer;
      const uint8_t* src = reinterpret_cast<const uint8_t*>(address);
      std::memcpy(buffer.data(), src, sizeof(T));

      T result;
      std::memcpy(&result, buffer.data(), sizeof(T));
      return result;
    }

    return read<T>(vm, address);
  }

  // Batch read for performance
  struct batch_read_request {
    uint64_t address;
    size_t size;
    void* buffer; // Caller-provided buffer
  };

  static std::vector<bool> read_batch(QBDI::VMInstanceRef vm, const std::vector<batch_read_request>& requests);
};

// Wrapper class for safe memory reading with RAII
class safe_memory_reader {
public:
  explicit safe_memory_reader(QBDI::VMInstanceRef vm) : vm_(vm) {}

  template <typename T> std::optional<T> read(uint64_t address) const { return safe_memory::read<T>(vm_, address); }

  std::optional<std::string> read_string(uint64_t address, size_t max_length = 256) const {
    return safe_memory::read_string(vm_, address, max_length);
  }

  std::optional<safe_memory::buffer_info> read_buffer(uint64_t address, size_t size, size_t max_size = 4096) const {
    return safe_memory::read_buffer(vm_, address, size, max_size);
  }

private:
  QBDI::VMInstanceRef vm_;
};

} // namespace w1::util