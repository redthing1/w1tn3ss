#include "address_space.hpp"
#include <algorithm>

namespace p1ll::engine {

process_address_space::process_address_space() : owned_scanner_(std::make_unique<memory_scanner>()) {
  scanner_ = owned_scanner_.get();
}

process_address_space::process_address_space(memory_scanner& scanner) : scanner_(&scanner) {}

std::optional<std::vector<uint8_t>> process_address_space::read(uint64_t address, size_t size) const {
  return scanner_ ? scanner_->read_memory(address, size) : std::nullopt;
}

bool process_address_space::write(uint64_t address, const std::vector<uint8_t>& data) const {
  return scanner_ ? scanner_->write_memory(address, data) : false;
}

std::optional<memory_region> process_address_space::region_info(uint64_t address) const {
  return scanner_ ? scanner_->get_region_info(address) : std::nullopt;
}

bool process_address_space::set_protection(uint64_t address, size_t size, memory_protection protection) const {
  return scanner_ ? scanner_->set_memory_protection(address, size, protection) : false;
}

bool process_address_space::flush_instruction_cache(uint64_t address, size_t size) const {
  return scanner_ ? scanner_->flush_instruction_cache(address, size) : false;
}

std::optional<std::vector<memory_region>> process_address_space::regions(const signature_query_filter& filter) const {
  return scanner_ ? scanner_->get_memory_regions(filter) : std::nullopt;
}

std::optional<size_t> process_address_space::page_size() const {
  return scanner_ ? scanner_->get_page_size() : std::nullopt;
}

buffer_address_space::buffer_address_space(std::vector<uint8_t>& buffer) : buffer_(buffer) {}

std::optional<std::vector<uint8_t>> buffer_address_space::read(uint64_t address, size_t size) const {
  if (size == 0) {
    return std::vector<uint8_t>{};
  }
  if (address > buffer_.size() || size > buffer_.size() - address) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(buffer_.begin() + address, buffer_.begin() + address + size);
}

bool buffer_address_space::write(uint64_t address, const std::vector<uint8_t>& data) const {
  if (data.empty()) {
    return true;
  }
  if (address > buffer_.size() || data.size() > buffer_.size() - address) {
    return false;
  }
  std::copy(data.begin(), data.end(), buffer_.begin() + address);
  return true;
}

std::optional<memory_region> buffer_address_space::region_info(uint64_t address) const {
  if (address >= buffer_.size()) {
    return std::nullopt;
  }
  memory_region region;
  region.base_address = 0;
  region.size = buffer_.size();
  region.protection = memory_protection::read_write;
  region.name = "buffer";
  region.is_executable = false;
  region.is_system = false;
  return region;
}

bool buffer_address_space::set_protection(uint64_t, size_t, memory_protection) const { return true; }

bool buffer_address_space::flush_instruction_cache(uint64_t, size_t) const { return true; }

std::optional<std::vector<memory_region>> buffer_address_space::regions(const signature_query_filter&) const {
  memory_region region;
  region.base_address = 0;
  region.size = buffer_.size();
  region.protection = memory_protection::read_write;
  region.name = "buffer";
  region.is_executable = false;
  region.is_system = false;
  return std::vector<memory_region>{region};
}

std::optional<size_t> buffer_address_space::page_size() const { return 1; }

} // namespace p1ll::engine
