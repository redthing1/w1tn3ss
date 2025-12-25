#pragma once

#include "engine/result.hpp"
#include "engine/types.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace p1ll::engine {

class address_space {
public:
  virtual ~address_space() = default;

  virtual result<std::vector<uint8_t>> read(uint64_t address, size_t size) const = 0;
  virtual status write(uint64_t address, std::span<const uint8_t> data) const = 0;
  virtual result<memory_region> region_info(uint64_t address) const = 0;
  virtual status set_protection(uint64_t address, size_t size, memory_protection protection) const = 0;
  virtual status flush_instruction_cache(uint64_t address, size_t size) const = 0;
  virtual result<std::vector<memory_region>> regions(const scan_filter& filter) const = 0;
  virtual result<size_t> page_size() const = 0;
  virtual result<void*> allocate(size_t size, memory_protection protection) const = 0;
  virtual status free(void* address, size_t size) const = 0;
};

class process_address_space final : public address_space {
public:
  process_address_space() = default;
  ~process_address_space() override = default;

  result<std::vector<uint8_t>> read(uint64_t address, size_t size) const override;
  status write(uint64_t address, std::span<const uint8_t> data) const override;
  result<memory_region> region_info(uint64_t address) const override;
  status set_protection(uint64_t address, size_t size, memory_protection protection) const override;
  status flush_instruction_cache(uint64_t address, size_t size) const override;
  result<std::vector<memory_region>> regions(const scan_filter& filter) const override;
  result<size_t> page_size() const override;
  result<void*> allocate(size_t size, memory_protection protection) const override;
  status free(void* address, size_t size) const override;
};

class buffer_address_space final : public address_space {
public:
  explicit buffer_address_space(std::span<uint8_t> buffer);
  ~buffer_address_space() override = default;

  result<std::vector<uint8_t>> read(uint64_t address, size_t size) const override;
  status write(uint64_t address, std::span<const uint8_t> data) const override;
  result<memory_region> region_info(uint64_t address) const override;
  status set_protection(uint64_t address, size_t size, memory_protection protection) const override;
  status flush_instruction_cache(uint64_t address, size_t size) const override;
  result<std::vector<memory_region>> regions(const scan_filter& filter) const override;
  result<size_t> page_size() const override;
  result<void*> allocate(size_t size, memory_protection protection) const override;
  status free(void* address, size_t size) const override;

private:
  std::span<uint8_t> buffer_;
};

} // namespace p1ll::engine
