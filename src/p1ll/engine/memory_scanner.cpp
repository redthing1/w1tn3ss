#include "memory_scanner.hpp"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstring>
#include <map>
#include <algorithm>
#include <regex>
#include <iomanip> // For std::hex

// --- Platform-specific includes ---
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cerrno>
#elif __linux__
#include <sys/mman.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <fcntl.h>
#include <cerrno>
#elif _WIN32
#define NEED_PSAPI
#include "utils/windows_compat.hpp"
#include <algorithm>
#endif

namespace p1ll::engine {

namespace { // anonymous namespace for internal helpers

// formats 64-bit value as hex string for logging
std::string to_hex(uint64_t val) {
  std::stringstream ss;
  ss << "0x" << std::hex << val;
  return ss.str();
}

} // namespace

// --- Constructor ---
memory_scanner::memory_scanner() : log_(redlog::get_logger("p1ll.memory_scanner")) {
  log_.dbg("memory scanner initialized");
}

// --- High-Level Public API ---
std::optional<std::vector<search_result>> memory_scanner::search(const signature_query& query) const {
  log_.dbg("starting memory search...");
  if (query.signature.empty()) {
    log_.wrn("search called with an empty signature");
    return std::vector<search_result>{};
  }

  auto regions_result = get_memory_regions(query.filter);
  if (!regions_result) {
    log_.err("failed to get memory regions for search");
    return std::nullopt;
  }

  std::vector<search_result> all_results;
  pattern_matcher matcher(query.signature);

  for (const auto& region : *regions_result) {
    // skip regions that cannot contain the signature or lack read permissions
    if (region.size < query.signature.size() || !has_protection(region.protection, memory_protection::read)) {
      continue;
    }

    log_.dbg(
        "searching region", redlog::field("name", region.name), redlog::field("base", to_hex(region.base_address)),
        redlog::field("size", region.size)
    );

    auto data_result = read_memory(region.base_address, region.size);
    if (!data_result) {
      // expected for guard pages, unmapped regions, and other non-readable memory areas
      log_.dbg(
          "could not read memory region to search", redlog::field("base", to_hex(region.base_address)),
          redlog::field("region_name", region.name.empty() ? "[anonymous]" : region.name)
      );
      continue;
    }

    // search for signature pattern within this region's memory
    auto offsets = matcher.search(data_result->data(), data_result->size());
    for (uint64_t offset : offsets) {
      // extract just the filename for cleaner result reporting
      std::string region_name =
          region.name.empty() ? "[anonymous]" : std::filesystem::path(region.name).filename().string();
      all_results.emplace_back(region.base_address + offset, region_name, "");
    }
  }

  log_.dbg("search complete", redlog::field("total_found", all_results.size()));
  return all_results;
}

// --- Low-Level Public API ---
std::optional<size_t> memory_scanner::get_page_size() const {
#if defined(__APPLE__) || defined(__linux__)
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size == -1) {
    log_.err("sysconf(_SC_PAGESIZE) failed", redlog::field("errno", errno));
    return std::nullopt;
  }
  return static_cast<size_t>(page_size);
#elif _WIN32
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return static_cast<size_t>(si.dwPageSize);
#else
  log_.err("get_page_size not supported on this platform");
  return std::nullopt;
#endif
}

std::optional<std::vector<memory_region>> memory_scanner::get_memory_regions(
    const signature_query_filter& filter
) const {
  log_.dbg("enumerating memory regions", redlog::field("filter", filter.pattern));

  auto regions_result = enumerate_regions();
  if (!regions_result) {
    log_.err("failed to enumerate raw memory regions");
    return std::nullopt;
  }

  if (filter.is_empty()) {
    log_.dbg("region enumeration complete, no filter", redlog::field("total_regions", regions_result->size()));
    return regions_result;
  }

  std::vector<memory_region> filtered_regions;
  for (const auto& region : *regions_result) {
    if (matches_filter(region, filter)) {
      filtered_regions.push_back(region);
    }
  }

  log_.dbg(
      "region enumeration complete, filter applied", redlog::field("total_regions", regions_result->size()),
      redlog::field("filtered_regions", filtered_regions.size())
  );
  return filtered_regions;
}

std::optional<memory_region> memory_scanner::get_region_info(uint64_t address) const {
#ifdef __APPLE__
  vm_address_t target_address = address;
  vm_size_t size = 0;
  vm_region_basic_info_data_64_t info;
  mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t object_name;

  kern_return_t kr = vm_region_64(
      mach_task_self(), &target_address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t) &info, &info_count,
      &object_name
  );
  if (kr != KERN_SUCCESS) {
    log_.err("vm_region_64 failed", redlog::field("error", mach_error_string(kr)), redlog::field("kr", kr));
    return std::nullopt;
  }
  if (address < target_address || address >= target_address + size) {
    log_.err("address not found in a valid region", redlog::field("address", to_hex(address)));
    return std::nullopt;
  }

  memory_region region;
  region.base_address = target_address;
  region.size = size;
  auto prot_res = platform_to_protection(info.protection);
  region.protection = prot_res.value_or(memory_protection::none);
  region.is_executable = has_protection(region.protection, memory_protection::execute);
  // get filename for region (if available)
  char filename[PATH_MAX] = {0};
  if (proc_regionfilename(getpid(), target_address, filename, sizeof(filename)) > 0) {
    region.name = filename;
    region.is_system = is_system_region(region);
  }
  return region;
#elif __linux__
  auto all_regions = enumerate_regions();
  if (!all_regions) {
    return std::nullopt;
  }
  for (const auto& region : *all_regions) {
    if (address >= region.base_address && address < (region.base_address + region.size)) {
      return region;
    }
  }
  log_.err("address not found in memory map", redlog::field("address", to_hex(address)));
  return std::nullopt;
#elif _WIN32
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
    log_.err("VirtualQuery failed", redlog::field("error", GetLastError()));
    return std::nullopt;
  }

  memory_region region;
  region.base_address = reinterpret_cast<uint64_t>(mbi.BaseAddress);
  region.size = mbi.RegionSize;
  auto prot_res = platform_to_protection(mbi.Protect);
  region.protection = prot_res.value_or(memory_protection::none);
  region.is_executable = has_protection(region.protection, memory_protection::execute);
  char filename[MAX_PATH];
  if (mbi.Type != MEM_PRIVATE &&
      GetMappedFileNameA(GetCurrentProcess(), mbi.BaseAddress, filename, sizeof(filename)) > 0) {
    region.name = filename;
    region.is_system = is_system_region(region);
  }
  return region;
#else
  log_.err("get_region_info not supported on this platform");
  return std::nullopt;
#endif
}

bool memory_scanner::set_memory_protection(uint64_t address, size_t size, memory_protection protection) const {
  if (size == 0) {
    log_.err("set_memory_protection: size cannot be zero");
    return false;
  }

  // convert our generic protection flags to platform-specific values
  auto platform_prot_result = protection_to_platform(protection);
  if (!platform_prot_result) {
    log_.err("failed to convert protection flags to platform format");
    return false;
  }
  int platform_protection = *platform_prot_result;

  log_.dbg(
      "setting memory protection", redlog::field("address", to_hex(address)), redlog::field("size", size),
      redlog::field("protection_flags", static_cast<int>(protection))
  );
#ifdef __APPLE__
  kern_return_t kr = mach_vm_protect(mach_task_self(), address, size, FALSE, platform_protection);
  if (kr != KERN_SUCCESS) {
    log_.err("mach_vm_protect failed", redlog::field("error", mach_error_string(kr)), redlog::field("kr", kr));
    return false;
  }
#elif __linux__
  if (mprotect(reinterpret_cast<void*>(address), size, platform_protection) == -1) {
    log_.err("mprotect failed", redlog::field("errno", errno));
    return false;
  }
#elif _WIN32
  DWORD old_protect;
  if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, platform_protection, &old_protect)) {
    log_.err("VirtualProtect failed", redlog::field("error", GetLastError()));
    return false;
  }
#else
  log_.err("set_memory_protection not supported on this platform");
  return false;
#endif
  return true;
}

// ... (allocate_memory, free_memory, read_memory, write_memory are unchanged and correct) ...
std::optional<void*> memory_scanner::allocate_memory(size_t size, memory_protection protection) const {
  auto page_size_res = get_page_size();
  if (!page_size_res) {
    return std::nullopt;
  }
  if (size == 0 || size % *page_size_res != 0) {
    log_.err(
        "allocate_memory: size must be a non-zero multiple of page size", redlog::field("size", size),
        redlog::field("page_size", *page_size_res)
    );
    return std::nullopt;
  }
  auto platform_prot_result = protection_to_platform(protection);
  if (!platform_prot_result) {
    return std::nullopt;
  }
  int platform_protection = *platform_prot_result;
  log_.dbg("allocating memory", redlog::field("size", size));
#ifdef __APPLE__
  vm_address_t address = 0;
  kern_return_t kr = vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS) {
    log_.err("vm_allocate failed", redlog::field("error", mach_error_string(kr)), redlog::field("kr", kr));
    return std::nullopt;
  }
  kr = vm_protect(mach_task_self(), address, size, FALSE, platform_protection);
  if (kr != KERN_SUCCESS) {
    vm_deallocate(mach_task_self(), address, size);
    log_.err(
        "vm_protect failed on new allocation", redlog::field("error", mach_error_string(kr)), redlog::field("kr", kr)
    );
    return std::nullopt;
  }
  return reinterpret_cast<void*>(address);
#elif __linux__
  void* address = mmap(NULL, size, platform_protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (address == MAP_FAILED) {
    log_.err("mmap failed", redlog::field("errno", errno));
    return std::nullopt;
  }
  return address;
#elif _WIN32
  void* address = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, platform_protection);
  if (address == NULL) {
    log_.err("VirtualAlloc failed", redlog::field("error", GetLastError()));
    return std::nullopt;
  }
  return address;
#else
  log_.err("allocate_memory not supported on this platform");
  return std::nullopt;
#endif
}
bool memory_scanner::free_memory(void* address, size_t size) const {
  log_.dbg(
      "freeing memory", redlog::field("address", to_hex(reinterpret_cast<uint64_t>(address))),
      redlog::field("size", size)
  );
#ifdef __APPLE__
  if (vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(address), size) != KERN_SUCCESS) {
    log_.err("vm_deallocate failed", redlog::field("errno", errno));
    return false;
  }
#elif __linux__
  if (munmap(address, size) != 0) {
    log_.err("munmap failed", redlog::field("errno", errno));
    return false;
  }
#elif _WIN32
  if (!VirtualFree(address, 0, MEM_RELEASE)) {
    log_.err("VirtualFree failed", redlog::field("error", GetLastError()));
    return false;
  }
#else
  log_.err("free_memory not supported on this platform");
  return false;
#endif
  return true;
}
std::optional<std::vector<uint8_t>> memory_scanner::read_memory(uint64_t address, size_t size) const {
  if (size == 0) {
    return std::vector<uint8_t>{};
  }
  auto region_info = get_region_info(address);
  if (!region_info) {
    return std::nullopt;
  }
  if (!has_protection(region_info->protection, memory_protection::read)) {
    log_.err("memory not readable", redlog::field("address", to_hex(address)));
    return std::nullopt;
  }
  if (address + size > region_info->base_address + region_info->size) {
    log_.err(
        "read would cross memory region boundary", redlog::field("address", to_hex(address)),
        redlog::field("size", size)
    );
    return std::nullopt;
  }
  std::vector<uint8_t> buffer(size);
#ifdef _WIN32
  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), buffer.data(), size, &bytes_read) ||
      bytes_read != size) {
    log_.err("ReadProcessMemory failed", redlog::field("error", GetLastError()));
    return std::nullopt;
  }
#else
  std::memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);
#endif
  return buffer;
}
bool memory_scanner::write_memory(uint64_t address, const std::vector<uint8_t>& data) const {
  if (data.empty()) {
    return true;
  }
  size_t size = data.size();
  auto region_info = get_region_info(address);
  if (!region_info) {
    return false;
  }
  if (!has_protection(region_info->protection, memory_protection::write)) {
    log_.err("memory not writable", redlog::field("address", to_hex(address)));
    return false;
  }
  if (address + size > region_info->base_address + region_info->size) {
    log_.err(
        "write would cross memory region boundary", redlog::field("address", to_hex(address)),
        redlog::field("size", size)
    );
    return false;
  }
#ifdef _WIN32
  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(address), data.data(), size, &bytes_written) ||
      bytes_written != size) {
    log_.err("WriteProcessMemory failed", redlog::field("error", GetLastError()));
    return false;
  }
#else
  std::memcpy(reinterpret_cast<void*>(address), data.data(), size);
#endif
  return true;
}

// --- Private Platform-Specific Implementations ---

// enumerates memory regions using platform-specific apis
std::optional<std::vector<memory_region>> memory_scanner::enumerate_regions() const {
  std::vector<memory_region> regions;
#ifdef __APPLE__
  // macOS: Use mach_vm_region_recurse for comprehensive region enumeration
  task_t task = mach_task_self();
  mach_vm_address_t address = 0;
  int pid = getpid();

  // Iterate through all virtual memory regions
  for (;;) {
    mach_vm_size_t size = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    uint32_t depth = 1;

    kern_return_t kr = mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_recurse_info_t) &info, &count);
    if (kr != KERN_SUCCESS) {
      break; // No more regions to enumerate
    }
    // Build region info from mach kernel data
    memory_region region;
    region.base_address = address;
    region.size = size;

    // Convert mach protection flags to our generic format
    auto prot_res = platform_to_protection(info.protection);
    region.protection = prot_res.value_or(memory_protection::none);
    region.is_executable = has_protection(region.protection, memory_protection::execute);

    // Get associated filename (if any) for this memory region
    char filename[PATH_MAX] = {0};
    if (proc_regionfilename(pid, address, filename, sizeof(filename)) > 0) {
      region.name = filename;
    }

    // Determine if this is a system library or user code
    region.is_system = is_system_region(region);
    regions.push_back(region);

    // Move to next region
    address += size;
  }
#elif __linux__
  // Linux: Parse /proc/self/maps for memory region information
  std::ifstream maps("/proc/self/maps");
  if (!maps) {
    log_.err("failed to open /proc/self/maps", redlog::field("errno", errno));
    return std::nullopt;
  }

  std::string line;
  while (std::getline(maps, line)) {
    // Parse /proc/maps line format: address perms offset dev inode pathname
    // Example: 7f1234567000-7f123456a000 r-xp 00000000 08:01 123456 /lib/libc.so
    std::stringstream ss(line);
    uint64_t start, end;
    std::string perms_str, offset_str, dev_str, inode_str, path_str;

    ss >> std::hex >> start;
    ss.ignore(1, '-');
    ss >> std::hex >> end >> perms_str >> offset_str >> dev_str >> inode_str;
    std::getline(ss, path_str);
    path_str.erase(0, path_str.find_first_not_of(" \t")); // Trim leading whitespace

    // Build region from parsed line data
    memory_region region;
    region.base_address = start;
    region.size = end - start;
    region.name = path_str;

    // Parse permission string (rwxp format)
    int perms = 0;
    if (perms_str.length() > 0 && perms_str[0] == 'r') {
      perms |= static_cast<int>(memory_protection::read);
    }
    if (perms_str.length() > 1 && perms_str[1] == 'w') {
      perms |= static_cast<int>(memory_protection::write);
    }
    if (perms_str.length() > 2 && perms_str[2] == 'x') {
      perms |= static_cast<int>(memory_protection::execute);
    }

    region.protection = static_cast<memory_protection>(perms);
    region.is_executable = has_protection(region.protection, memory_protection::execute);
    region.is_system = is_system_region(region);
    regions.push_back(region);
  }
#elif _WIN32
  // Windows: Use VirtualQueryEx to enumerate committed memory regions
  HANDLE process = GetCurrentProcess();
  SYSTEM_INFO si;
  GetSystemInfo(&si);

  uint64_t current_address = (uint64_t) si.lpMinimumApplicationAddress;
  uint64_t max_address = (uint64_t) si.lpMaximumApplicationAddress;

  // Walk through address space querying each region
  while (current_address < max_address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(process, (LPCVOID) current_address, &mbi, sizeof(mbi)) == 0) {
      break; // Query failed
    }

    // Only include committed (allocated and accessible) regions
    if (mbi.State == MEM_COMMIT) {
      // Build region from Windows memory information
      memory_region region;
      region.base_address = (uint64_t) mbi.BaseAddress;
      region.size = mbi.RegionSize;

      // Convert Windows protection flags to our generic format
      auto prot_res = platform_to_protection(mbi.Protect);
      region.protection = prot_res.value_or(memory_protection::none);
      region.is_executable = has_protection(region.protection, memory_protection::execute);

      // Get mapped file name for non-private memory (DLLs, mapped files)
      char filename[MAX_PATH];
      if (mbi.Type != MEM_PRIVATE && GetMappedFileNameA(process, mbi.BaseAddress, filename, sizeof(filename)) > 0) {
        region.name = filename;
      }

      region.is_system = is_system_region(region);
      regions.push_back(region);
    }
    // Move to next region, with overflow protection
    uint64_t next_address = (uint64_t) mbi.BaseAddress + mbi.RegionSize;
    if (next_address <= current_address) {
      break; // Prevent infinite loop on address wraparound
    }
    current_address = next_address;
  }
#endif

  // log all regions
  for (const auto& region : regions) {
    log_.dbg(
        "region", redlog::field("base", to_hex(region.base_address)), redlog::field("size", region.size),
        redlog::field("protection", static_cast<int>(region.protection)), redlog::field("name", region.name),
        redlog::field("is_executable", region.is_executable), redlog::field("is_system", region.is_system)
    );
  }

  return regions;
}

// determines if memory region belongs to system libraries using path heuristics
bool memory_scanner::is_system_region(const memory_region& region) const {
  if (region.name.empty()) {
    return false; // Anonymous regions are not system regions
  }
#ifdef _WIN32
  // Windows: Check if region is in system directory (e.g., C:\Windows\System32)
  char system_path_buf[MAX_PATH];
  if (GetSystemDirectoryA(system_path_buf, MAX_PATH) == 0) {
    return false; // Failed to get system directory
  }

  std::string system_path_str(system_path_buf);
  std::string module_path_str = region.name;

  // Normalize paths for case-insensitive comparison (Windows is case-insensitive)
  std::transform(system_path_str.begin(), system_path_str.end(), system_path_str.begin(), ::tolower);
  std::transform(module_path_str.begin(), module_path_str.end(), module_path_str.begin(), ::tolower);

  return module_path_str.rfind(system_path_str, 0) == 0;
#elif defined(__APPLE__)
  // macOS: Check for system framework and library paths
  return region.name.rfind("/System/", 0) == 0 ||    // System frameworks
         region.name.rfind("/usr/lib/", 0) == 0 ||   // System libraries
         region.name.rfind("/usr/libexec/", 0) == 0; // System executables
#elif defined(__linux__)
  // Linux: Check common system library paths
  return region.name.rfind("/lib/", 0) == 0 ||       // System libraries
         region.name.rfind("/usr/lib/", 0) == 0 ||   // User system libraries
         region.name.rfind("/lib64/", 0) == 0 ||     // 64-bit system libraries
         region.name.rfind("/usr/lib64/", 0) == 0 || // 64-bit user system libraries
         region.name.rfind("/usr/libexec/", 0) == 0; // System executables
#else
  return false;
#endif
}

bool memory_scanner::matches_filter(const memory_region& region, const signature_query_filter& filter) const {
  // if filter is empty, match all regions
  if (filter.is_empty()) {
    return true;
  }

  // apply regex pattern filter to region name
  if (!filter.pattern.empty()) {
    try {
      std::string region_name =
          region.name.empty() ? "[anonymous]" : std::filesystem::path(region.name).filename().string();
      if (!std::regex_search(region_name, std::regex(filter.pattern))) {
        return false;
      }
    } catch (const std::regex_error& e) {
      log_.err("invalid regex in filter", redlog::field("pattern", filter.pattern), redlog::field("error", e.what()));
      return false;
    }
  }

  return true;
}

// ... (protection_to_platform and platform_to_protection are unchanged and correct)
std::optional<int> memory_scanner::protection_to_platform(memory_protection protection) const {
#ifdef __APPLE__
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
#elif __linux__
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
#elif _WIN32
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
#else
  log_.err("protection_to_platform not supported on this platform");
  return std::nullopt;
#endif
}

std::optional<memory_protection> memory_scanner::platform_to_protection(int platform_protection) const {
#ifdef __APPLE__
  memory_protection result = memory_protection::none;
  if (platform_protection & VM_PROT_READ) {
    result = result | memory_protection::read;
  }
  if (platform_protection & VM_PROT_WRITE) {
    result = result | memory_protection::write;
  }
  if (platform_protection & VM_PROT_EXECUTE) {
    result = result | memory_protection::execute;
  }
  return result;
#elif __linux__
  memory_protection result = memory_protection::none;
  if (platform_protection & PROT_READ) {
    result = result | memory_protection::read;
  }
  if (platform_protection & PROT_WRITE) {
    result = result | memory_protection::write;
  }
  if (platform_protection & PROT_EXEC) {
    result = result | memory_protection::execute;
  }
  return result;
#elif _WIN32
  DWORD p = platform_protection & 0xFF;
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
#else
  log_.err("platform_to_protection not supported on this platform");
  return std::nullopt;
#endif
}

} // namespace p1ll::engine