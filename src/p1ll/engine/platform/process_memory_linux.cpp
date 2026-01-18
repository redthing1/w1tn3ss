#ifdef __linux__

#include "process_memory.hpp"
#include "process_memory_common.hpp"
#include "utils/memory_align.hpp"
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>

namespace p1ll::engine::platform {

namespace {

memory_protection platform_to_protection(int prot) {
  memory_protection result = memory_protection::none;
  if (prot & PROT_READ) {
    result = result | memory_protection::read;
  }
  if (prot & PROT_WRITE) {
    result = result | memory_protection::write;
  }
  if (prot & PROT_EXEC) {
    result = result | memory_protection::execute;
  }
  return result;
}

int protection_to_platform(memory_protection protection) {
  int result = PROT_NONE;
  if (has_protection(protection, memory_protection::read)) {
    result |= PROT_READ;
  }
  if (has_protection(protection, memory_protection::write)) {
    result |= PROT_WRITE;
  }
  if (has_protection(protection, memory_protection::execute)) {
    result |= PROT_EXEC;
  }
  return result;
}

} // namespace

result<std::vector<memory_region>> enumerate_regions() {
  std::ifstream maps("/proc/self/maps");
  if (!maps) {
    return error_result<std::vector<memory_region>>(error_code::io_error, "failed to open /proc/self/maps");
  }

  std::vector<memory_region> regions;
  std::string line;
  while (std::getline(maps, line)) {
    std::stringstream ss(line);
    uint64_t start = 0;
    uint64_t end = 0;
    std::string perms_str;
    std::string offset_str;
    std::string dev_str;
    std::string inode_str;
    std::string path_str;

    ss >> std::hex >> start;
    ss.ignore(1, '-');
    ss >> std::hex >> end >> perms_str >> offset_str >> dev_str >> inode_str;
    std::getline(ss, path_str);
    if (!path_str.empty()) {
      auto first = path_str.find_first_not_of(" \t");
      if (first != std::string::npos) {
        path_str.erase(0, first);
      } else {
        path_str.clear();
      }
    }

    memory_region region;
    region.base_address = start;
    region.size = static_cast<size_t>(end - start);
    region.name = path_str;

    int perms = 0;
    if (perms_str.size() > 0 && perms_str[0] == 'r') {
      perms |= PROT_READ;
    }
    if (perms_str.size() > 1 && perms_str[1] == 'w') {
      perms |= PROT_WRITE;
    }
    if (perms_str.size() > 2 && perms_str[2] == 'x') {
      perms |= PROT_EXEC;
    }

    region.protection = platform_to_protection(perms);
    region.is_executable = has_protection(region.protection, memory_protection::execute);
    region.is_system = is_system_region(region);
    regions.push_back(region);
  }

  return ok_result(regions);
}

result<memory_region> region_info(uint64_t address) {
  auto regions = enumerate_regions();
  if (!regions.ok()) {
    return error_result<memory_region>(regions.status_info.code, regions.status_info.message);
  }
  for (const auto& region : regions.value) {
    if (address >= region.base_address && address < (region.base_address + region.size)) {
      return ok_result(region);
    }
  }
  return error_result<memory_region>(error_code::not_found, "address not found in memory map");
}

result<std::vector<uint8_t>> read(uint64_t address, size_t size) {
  std::vector<uint8_t> buffer(size);
  if (size == 0) {
    return ok_result(buffer);
  }
  std::memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);
  return ok_result(buffer);
}

status write(uint64_t address, std::span<const uint8_t> data) {
  if (data.empty()) {
    return ok_status();
  }
  std::memcpy(reinterpret_cast<void*>(address), data.data(), data.size());
  return ok_status();
}

status set_protection(uint64_t address, size_t size, memory_protection protection) {
  if (size == 0) {
    return make_status(error_code::invalid_argument, "size cannot be zero");
  }

  auto page = page_size();
  if (!page.ok()) {
    return page.status_info;
  }

  uint64_t aligned_start = p1ll::utils::align_down(address, page.value);
  uint64_t aligned_end = p1ll::utils::align_up(address + size, page.value);
  if (aligned_end < aligned_start) {
    return make_status(error_code::invalid_argument, "alignment overflow");
  }
  size_t aligned_size = static_cast<size_t>(aligned_end - aligned_start);

  int prot = protection_to_platform(protection);
  if (mprotect(reinterpret_cast<void*>(aligned_start), aligned_size, prot) == -1) {
    return make_status(error_code::protection_error, "mprotect failed");
  }

  return ok_status();
}

status flush_instruction_cache(uint64_t address, size_t size) {
  if (size == 0) {
    return ok_status();
  }
  void* start = reinterpret_cast<void*>(address);
  void* end = reinterpret_cast<void*>(address + size);
  __builtin___clear_cache(start, end);
  return ok_status();
}

result<void*> allocate(size_t size, memory_protection protection) {
  if (size == 0) {
    return error_result<void*>(error_code::invalid_argument, "size must be non-zero");
  }

  void* address = mmap(NULL, size, protection_to_platform(protection), MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (address == MAP_FAILED) {
    return error_result<void*>(error_code::io_error, "mmap failed");
  }

  return ok_result(address);
}

status free(void* address, size_t size) {
  if (!address || size == 0) {
    return make_status(error_code::invalid_argument, "invalid address or size");
  }
  if (munmap(address, size) != 0) {
    return make_status(error_code::io_error, "munmap failed");
  }
  return ok_status();
}

result<size_t> page_size() {
  long page = sysconf(_SC_PAGESIZE);
  if (page <= 0) {
    return error_result<size_t>(error_code::io_error, "sysconf(_SC_PAGESIZE) failed");
  }
  return ok_result(static_cast<size_t>(page));
}

} // namespace p1ll::engine::platform

#endif // __linux__
