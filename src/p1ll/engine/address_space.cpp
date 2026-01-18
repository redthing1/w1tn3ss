#include "address_space.hpp"
#include "engine/platform/process_memory.hpp"
#include <algorithm>
#include <filesystem>
#include <regex>

namespace p1ll::engine {

namespace {

bool filter_is_empty(const scan_filter& filter) {
  return filter.name_regex.empty() && !filter.only_executable && !filter.exclude_system && filter.min_size == 0 &&
         !filter.min_address.has_value() && !filter.max_address.has_value();
}

result<bool> matches_filter(const memory_region& region, const scan_filter& filter) {
  if (filter.only_executable && !region.is_executable) {
    return ok_result(false);
  }
  if (filter.exclude_system && region.is_system) {
    return ok_result(false);
  }
  if (filter.min_size > 0 && region.size < filter.min_size) {
    return ok_result(false);
  }

  if (filter.min_address.has_value()) {
    uint64_t region_end = region.base_address + region.size;
    if (region_end <= *filter.min_address) {
      return ok_result(false);
    }
  }
  if (filter.max_address.has_value()) {
    if (region.base_address >= *filter.max_address) {
      return ok_result(false);
    }
  }

  if (!filter.name_regex.empty()) {
    try {
      std::string region_name =
          region.name.empty() ? "[anonymous]" : std::filesystem::path(region.name).filename().string();
      if (!std::regex_search(region_name, std::regex(filter.name_regex))) {
        return ok_result(false);
      }
    } catch (const std::regex_error&) {
      return error_result<bool>(error_code::invalid_argument, "invalid regex in scan filter");
    }
  }

  return ok_result(true);
}

} // namespace

result<std::vector<uint8_t>> process_address_space::read(uint64_t address, size_t size) const {
  if (size == 0) {
    return ok_result(std::vector<uint8_t>{});
  }

  if (address > UINT64_MAX - size) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_argument, "address range overflow");
  }

  auto region = region_info(address);
  if (!region.ok()) {
    return error_result<std::vector<uint8_t>>(region.status_info.code, region.status_info.message);
  }
  if (!has_protection(region.value.protection, memory_protection::read)) {
    return error_result<std::vector<uint8_t>>(error_code::protection_error, "memory not readable");
  }
  if (address + size > region.value.base_address + region.value.size) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_argument, "read crosses region boundary");
  }

  return platform::read(address, size);
}

status process_address_space::write(uint64_t address, std::span<const uint8_t> data) const {
  if (data.empty()) {
    return ok_status();
  }

  if (address > UINT64_MAX - data.size()) {
    return make_status(error_code::invalid_argument, "address range overflow");
  }

  auto region = region_info(address);
  if (!region.ok()) {
    return region.status_info;
  }
  if (!has_protection(region.value.protection, memory_protection::write)) {
    return make_status(error_code::protection_error, "memory not writable");
  }
  if (address + data.size() > region.value.base_address + region.value.size) {
    return make_status(error_code::invalid_argument, "write crosses region boundary");
  }

  return platform::write(address, data);
}

result<memory_region> process_address_space::region_info(uint64_t address) const {
  return platform::region_info(address);
}

status process_address_space::set_protection(uint64_t address, size_t size, memory_protection protection) const {
  return platform::set_protection(address, size, protection);
}

status process_address_space::flush_instruction_cache(uint64_t address, size_t size) const {
  return platform::flush_instruction_cache(address, size);
}

result<std::vector<memory_region>> process_address_space::regions(const scan_filter& filter) const {
  auto regions = platform::enumerate_regions();
  if (!regions.ok()) {
    return error_result<std::vector<memory_region>>(regions.status_info.code, regions.status_info.message);
  }

  if (filter_is_empty(filter)) {
    return regions;
  }

  std::vector<memory_region> filtered;
  for (const auto& region : regions.value) {
    auto match = matches_filter(region, filter);
    if (!match.ok()) {
      return error_result<std::vector<memory_region>>(match.status_info.code, match.status_info.message);
    }
    if (match.value) {
      filtered.push_back(region);
    }
  }

  return ok_result(filtered);
}

result<size_t> process_address_space::page_size() const { return platform::page_size(); }

result<void*> process_address_space::allocate(size_t size, memory_protection protection) const {
  return platform::allocate(size, protection);
}

status process_address_space::free(void* address, size_t size) const { return platform::free(address, size); }

buffer_address_space::buffer_address_space(std::span<uint8_t> buffer) : buffer_(buffer) {}

result<std::vector<uint8_t>> buffer_address_space::read(uint64_t address, size_t size) const {
  if (size == 0) {
    return ok_result(std::vector<uint8_t>{});
  }
  if (address > buffer_.size() || size > buffer_.size() - address) {
    return error_result<std::vector<uint8_t>>(error_code::invalid_argument, "read out of buffer bounds");
  }
  return ok_result(std::vector<uint8_t>(buffer_.begin() + address, buffer_.begin() + address + size));
}

status buffer_address_space::write(uint64_t address, std::span<const uint8_t> data) const {
  if (data.empty()) {
    return ok_status();
  }
  if (address > buffer_.size() || data.size() > buffer_.size() - address) {
    return make_status(error_code::invalid_argument, "write out of buffer bounds");
  }
  std::copy(data.begin(), data.end(), buffer_.begin() + address);
  return ok_status();
}

result<memory_region> buffer_address_space::region_info(uint64_t address) const {
  if (address >= buffer_.size()) {
    return error_result<memory_region>(error_code::not_found, "address not found in buffer");
  }
  memory_region region;
  region.base_address = 0;
  region.size = buffer_.size();
  region.protection = memory_protection::read_write;
  region.name = "buffer";
  region.is_executable = false;
  region.is_system = false;
  return ok_result(region);
}

status buffer_address_space::set_protection(uint64_t, size_t, memory_protection) const { return ok_status(); }

status buffer_address_space::flush_instruction_cache(uint64_t, size_t) const { return ok_status(); }

result<std::vector<memory_region>> buffer_address_space::regions(const scan_filter& filter) const {
  memory_region region;
  region.base_address = 0;
  region.size = buffer_.size();
  region.protection = memory_protection::read_write;
  region.name = "buffer";
  region.is_executable = false;
  region.is_system = false;

  scan_filter effective_filter = filter;
  effective_filter.name_regex.clear();

  if (filter_is_empty(effective_filter)) {
    return ok_result(std::vector<memory_region>{region});
  }

  auto match = matches_filter(region, effective_filter);
  if (!match.ok()) {
    return error_result<std::vector<memory_region>>(match.status_info.code, match.status_info.message);
  }
  if (!match.value) {
    return ok_result(std::vector<memory_region>{});
  }
  return ok_result(std::vector<memory_region>{region});
}

result<size_t> buffer_address_space::page_size() const { return ok_result(static_cast<size_t>(1)); }

result<void*> buffer_address_space::allocate(size_t, memory_protection) const {
  return error_result<void*>(error_code::unsupported, "buffer address space does not allocate");
}

status buffer_address_space::free(void*, size_t) const {
  return make_status(error_code::unsupported, "buffer address space does not free");
}

} // namespace p1ll::engine
