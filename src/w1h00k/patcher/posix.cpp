#include "w1h00k/patcher/patcher.hpp"

#include <cstdint>
#include <cstring>

#include <sys/mman.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <pthread.h>
#endif

namespace w1::h00k {
namespace {

size_t page_size() {
  long size = sysconf(_SC_PAGESIZE);
  if (size <= 0) {
    return 4096;
  }
  return static_cast<size_t>(size);
}

bool protect_region(void* address, size_t size, bool writable) {
  if (!address || size == 0) {
    return false;
  }

  const size_t page = page_size();
  const uintptr_t start = reinterpret_cast<uintptr_t>(address);
  const uintptr_t page_start = start & ~(static_cast<uintptr_t>(page) - 1);
  const uintptr_t end = start + size;
  const uintptr_t page_end = (end + page - 1) & ~(static_cast<uintptr_t>(page) - 1);
  const size_t total = page_end - page_start;

#if defined(__APPLE__)
  vm_prot_t prot = writable ? (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) : (VM_PROT_READ | VM_PROT_EXECUTE);
  return vm_protect(mach_task_self(), page_start, total, false, prot) == KERN_SUCCESS;
#else
  int prot = writable ? (PROT_READ | PROT_WRITE) : (PROT_READ | PROT_EXEC);
  return mprotect(reinterpret_cast<void*>(page_start), total, prot) == 0;
#endif
}

void flush_icache(void* address, size_t size) {
  if (!address || size == 0) {
    return;
  }
  auto start = reinterpret_cast<char*>(address);
  __builtin___clear_cache(start, start + size);
}

#if defined(__APPLE__)
bool region_is_writable(void* address) {
  mach_vm_address_t query_address = reinterpret_cast<mach_vm_address_t>(address);
  mach_vm_size_t size = 0;
  vm_region_extended_info_data_t info{};
  mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
  memory_object_name_t object = MACH_PORT_NULL;

  const kern_return_t status = mach_vm_region(mach_task_self(), &query_address, &size, VM_REGION_EXTENDED_INFO,
                                              reinterpret_cast<vm_region_info_t>(&info), &count, &object);
  if (status != KERN_SUCCESS) {
    return false;
  }
  return (info.protection & VM_PROT_WRITE) != 0;
}
#endif

class jit_write_guard {
public:
  jit_write_guard() {
#if defined(__APPLE__)
    pthread_jit_write_protect_np(0);
#endif
  }

  ~jit_write_guard() {
#if defined(__APPLE__)
    pthread_jit_write_protect_np(1);
#endif
  }
};

} // namespace

bool code_patcher::write(void* address, const uint8_t* bytes, size_t size) {
  if (!address || !bytes || size == 0) {
    return false;
  }
#if defined(__APPLE__)
  const bool needs_protection = !region_is_writable(address);
#else
  const bool needs_protection = true;
#endif
  if (needs_protection && !protect_region(address, size, true)) {
    return false;
  }
  jit_write_guard guard;
  std::memcpy(address, bytes, size);
  flush_icache(address, size);
  if (needs_protection) {
    return protect_region(address, size, false);
  }
  return true;
}

bool code_patcher::restore(void* address, const uint8_t* bytes, size_t size) {
  return write(address, bytes, size);
}

} // namespace w1::h00k
