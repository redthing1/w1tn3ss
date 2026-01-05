#ifdef _WIN32

#include "process_memory.hpp"
#include "process_memory_common.hpp"
#include "utils/memory_align.hpp"
#include "utils/windows_compat.hpp"
#include <psapi.h>

namespace p1ll::engine::platform {

namespace {

static constexpr DWORD k_windows_protection_mask = 0xFF;

memory_protection platform_to_protection(DWORD prot) {
  DWORD p = prot & k_windows_protection_mask;
  if (p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY) {
    return memory_protection::read_write_execute;
  }
  if (p == PAGE_EXECUTE_READ) {
    return memory_protection::read_execute;
  }
  if (p == PAGE_EXECUTE) {
    return memory_protection::execute;
  }
  if (p == PAGE_READWRITE) {
    return memory_protection::read_write;
  }
  if (p == PAGE_READONLY || p == PAGE_WRITECOPY) {
    return memory_protection::read;
  }
  return memory_protection::none;
}

DWORD protection_to_platform(memory_protection protection) {
  bool r = has_protection(protection, memory_protection::read);
  bool w = has_protection(protection, memory_protection::write);
  bool x = has_protection(protection, memory_protection::execute);
  if (x && r && w) {
    return PAGE_EXECUTE_READWRITE;
  }
  if (x && r) {
    return PAGE_EXECUTE_READ;
  }
  if (x) {
    return PAGE_EXECUTE;
  }
  if (r && w) {
    return PAGE_READWRITE;
  }
  if (r) {
    return PAGE_READONLY;
  }
  return PAGE_NOACCESS;
}

} // namespace

result<std::vector<memory_region>> enumerate_regions() {
  std::vector<memory_region> regions;

  HANDLE process = GetCurrentProcess();
  SYSTEM_INFO si;
  GetSystemInfo(&si);

  uint64_t current = reinterpret_cast<uint64_t>(si.lpMinimumApplicationAddress);
  uint64_t max_address = reinterpret_cast<uint64_t>(si.lpMaximumApplicationAddress);

  while (current < max_address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi)) == 0) {
      break;
    }

    if (mbi.State == MEM_COMMIT) {
      memory_region region;
      region.base_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
      region.size = mbi.RegionSize;
      region.protection = platform_to_protection(mbi.Protect);
      region.is_executable = has_protection(region.protection, memory_protection::execute);

      char filename[MAX_PATH];
      if (mbi.Type != MEM_PRIVATE && GetMappedFileNameA(process, mbi.BaseAddress, filename, sizeof(filename)) > 0) {
        region.name = filename;
      }

      region.is_system = is_system_region(region);
      regions.push_back(region);
    }

    uint64_t next = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (next <= current) {
      break;
    }
    current = next;
  }

  return ok_result(regions);
}

result<memory_region> region_info(uint64_t address) {
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
    return error_result<memory_region>(error_code::io_error, "VirtualQuery failed");
  }

  memory_region region;
  region.base_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
  region.size = mbi.RegionSize;
  region.protection = platform_to_protection(mbi.Protect);
  region.is_executable = has_protection(region.protection, memory_protection::execute);

  char filename[MAX_PATH];
  if (mbi.Type != MEM_PRIVATE &&
      GetMappedFileNameA(GetCurrentProcess(), mbi.BaseAddress, filename, sizeof(filename)) > 0) {
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
  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytes_read) ||
      bytes_read != size) {
    return error_result<std::vector<uint8_t>>(error_code::io_error, "ReadProcessMemory failed");
  }
  return ok_result(buffer);
}

status write(uint64_t address, std::span<const uint8_t> data) {
  if (data.empty()) {
    return ok_status();
  }
  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(
          GetCurrentProcess(), reinterpret_cast<LPVOID>(address), data.data(), data.size(), &bytes_written
      ) ||
      bytes_written != data.size()) {
    return make_status(error_code::io_error, "WriteProcessMemory failed");
  }
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

  DWORD old_protect;
  if (!VirtualProtect(
          reinterpret_cast<LPVOID>(aligned_start), aligned_size, protection_to_platform(protection), &old_protect
      )) {
    return make_status(error_code::protection_error, "VirtualProtect failed");
  }
  return ok_status();
}

status flush_instruction_cache(uint64_t address, size_t size) {
  if (size == 0) {
    return ok_status();
  }
  if (!FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size)) {
    return make_status(error_code::io_error, "FlushInstructionCache failed");
  }
  return ok_status();
}

result<void*> allocate(size_t size, memory_protection protection) {
  if (size == 0) {
    return error_result<void*>(error_code::invalid_argument, "size must be non-zero");
  }
  void* address = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, protection_to_platform(protection));
  if (!address) {
    return error_result<void*>(error_code::io_error, "VirtualAlloc failed");
  }
  return ok_result(address);
}

status free(void* address, size_t size) {
  if (!address || size == 0) {
    return make_status(error_code::invalid_argument, "invalid address or size");
  }
  if (!VirtualFree(address, 0, MEM_RELEASE)) {
    return make_status(error_code::io_error, "VirtualFree failed");
  }
  return ok_status();
}

result<size_t> page_size() {
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return ok_result(static_cast<size_t>(si.dwPageSize));
}

} // namespace p1ll::engine::platform

#endif // _WIN32
