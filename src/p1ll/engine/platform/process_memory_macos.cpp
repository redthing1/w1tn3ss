#ifdef __APPLE__

#include "process_memory.hpp"
#include "process_memory_common.hpp"
#include "utils/memory_align.hpp"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <libkern/OSCacheControl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

namespace p1ll::engine::platform {

namespace {

memory_protection platform_to_protection(vm_prot_t prot) {
  memory_protection result = memory_protection::none;
  if (prot & VM_PROT_READ) {
    result = result | memory_protection::read;
  }
  if (prot & VM_PROT_WRITE) {
    result = result | memory_protection::write;
  }
  if (prot & VM_PROT_EXECUTE) {
    result = result | memory_protection::execute;
  }
  return result;
}

int protection_to_platform(memory_protection protection) {
  int result = VM_PROT_NONE;
  if (has_protection(protection, memory_protection::read)) {
    result |= VM_PROT_READ;
  }
  if (has_protection(protection, memory_protection::write)) {
    result |= (VM_PROT_WRITE | VM_PROT_COPY);
  }
  if (has_protection(protection, memory_protection::execute)) {
    result |= VM_PROT_EXECUTE;
  }
  return result;
}

} // namespace

result<std::vector<memory_region>> enumerate_regions() {
  std::vector<memory_region> regions;

  task_t task = mach_task_self();
  mach_vm_address_t address = 0;
  int pid = getpid();

  for (;;) {
    mach_vm_size_t size = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint32_t depth = 1;

    kern_return_t kr = mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_recurse_info_t) &info, &count);
    if (kr != KERN_SUCCESS) {
      break;
    }

    memory_region region;
    region.base_address = address;
    region.size = size;
    region.protection = platform_to_protection(info.protection);
    region.is_executable = has_protection(region.protection, memory_protection::execute);

    char filename[PATH_MAX] = {0};
    if (proc_regionfilename(pid, address, filename, sizeof(filename)) > 0) {
      region.name = filename;
    }
    region.is_system = is_system_region(region);
    regions.push_back(region);

    address += size;
  }

  return ok_result(regions);
}

result<memory_region> region_info(uint64_t address) {
  mach_vm_address_t target_address = address;
  mach_vm_size_t size = 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t object_name;

  kern_return_t kr = mach_vm_region(
      mach_task_self(), &target_address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &info_count,
      &object_name
  );
  if (kr != KERN_SUCCESS) {
    return error_result<memory_region>(error_code::io_error, "mach_vm_region failed");
  }
  if (address < target_address || address >= target_address + size) {
    return error_result<memory_region>(error_code::not_found, "address not found in region");
  }

  memory_region region;
  region.base_address = target_address;
  region.size = size;
  region.protection = platform_to_protection(info.protection);
  region.is_executable = has_protection(region.protection, memory_protection::execute);

  char filename[PATH_MAX] = {0};
  if (proc_regionfilename(getpid(), target_address, filename, sizeof(filename)) > 0) {
    region.name = filename;
    region.is_system = is_system_region(region);
  }

  return ok_result(region);
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
    return page.status;
  }

  uint64_t aligned_start = p1ll::utils::align_down(address, page.value);
  uint64_t aligned_end = p1ll::utils::align_up(address + size, page.value);
  if (aligned_end < aligned_start) {
    return make_status(error_code::invalid_argument, "alignment overflow");
  }

  size_t aligned_size = static_cast<size_t>(aligned_end - aligned_start);
  int prot = protection_to_platform(protection);

  kern_return_t kr = mach_vm_protect(mach_task_self(), aligned_start, aligned_size, FALSE, prot);
  if (kr != KERN_SUCCESS) {
    return make_status(error_code::protection_error, "mach_vm_protect failed");
  }

  return ok_status();
}

status flush_instruction_cache(uint64_t address, size_t size) {
  if (size == 0) {
    return ok_status();
  }
  sys_icache_invalidate(reinterpret_cast<void*>(address), size);
  return ok_status();
}

result<void*> allocate(size_t size, memory_protection protection) {
  if (size == 0) {
    return error_result<void*>(error_code::invalid_argument, "size must be non-zero");
  }

  vm_address_t address = 0;
  kern_return_t kr = vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    return error_result<void*>(error_code::io_error, "vm_allocate failed");
  }

  kr = vm_protect(mach_task_self(), address, size, FALSE, protection_to_platform(protection));
  if (kr != KERN_SUCCESS) {
    vm_deallocate(mach_task_self(), address, size);
    return error_result<void*>(error_code::protection_error, "vm_protect failed");
  }

  return ok_result(reinterpret_cast<void*>(address));
}

status free(void* address, size_t size) {
  if (!address || size == 0) {
    return make_status(error_code::invalid_argument, "invalid address or size");
  }
  if (vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(address), size) != KERN_SUCCESS) {
    return make_status(error_code::io_error, "vm_deallocate failed");
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

#endif // __APPLE__
