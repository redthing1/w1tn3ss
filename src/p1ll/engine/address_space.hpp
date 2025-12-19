#pragma once

#include "core/types.hpp"
#include "memory_scanner.hpp"
#include "memory_types.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace p1ll::engine {

class address_space {
public:
  virtual ~address_space() = default;

  virtual std::optional<std::vector<uint8_t>> read(uint64_t address, size_t size) const = 0;
  virtual bool write(uint64_t address, const std::vector<uint8_t>& data) const = 0;
  virtual std::optional<memory_region> region_info(uint64_t address) const = 0;
  virtual bool set_protection(uint64_t address, size_t size, memory_protection protection) const = 0;
  virtual bool flush_instruction_cache(uint64_t address, size_t size) const = 0;
  virtual std::optional<std::vector<memory_region>> regions(const signature_query_filter& filter) const = 0;
  virtual std::optional<size_t> page_size() const = 0;
};

class process_address_space final : public address_space {
public:
  process_address_space();
  explicit process_address_space(memory_scanner& scanner);
  ~process_address_space() override = default;

  std::optional<std::vector<uint8_t>> read(uint64_t address, size_t size) const override;
  bool write(uint64_t address, const std::vector<uint8_t>& data) const override;
  std::optional<memory_region> region_info(uint64_t address) const override;
  bool set_protection(uint64_t address, size_t size, memory_protection protection) const override;
  bool flush_instruction_cache(uint64_t address, size_t size) const override;
  std::optional<std::vector<memory_region>> regions(const signature_query_filter& filter) const override;
  std::optional<size_t> page_size() const override;

private:
  memory_scanner* scanner_ = nullptr;
  std::unique_ptr<memory_scanner> owned_scanner_;
};

class buffer_address_space final : public address_space {
public:
  explicit buffer_address_space(std::vector<uint8_t>& buffer);
  ~buffer_address_space() override = default;

  std::optional<std::vector<uint8_t>> read(uint64_t address, size_t size) const override;
  bool write(uint64_t address, const std::vector<uint8_t>& data) const override;
  std::optional<memory_region> region_info(uint64_t address) const override;
  bool set_protection(uint64_t address, size_t size, memory_protection protection) const override;
  bool flush_instruction_cache(uint64_t address, size_t size) const override;
  std::optional<std::vector<memory_region>> regions(const signature_query_filter& filter) const override;
  std::optional<size_t> page_size() const override;

private:
  std::vector<uint8_t>& buffer_;
};

} // namespace p1ll::engine
