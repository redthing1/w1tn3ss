#pragma once

#include "engine/result.hpp"
#include "engine/types.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace p1ll::engine::platform {

// platform-specific process memory operations
result<std::vector<memory_region>> enumerate_regions();
result<memory_region> region_info(uint64_t address);
result<std::vector<uint8_t>> read(uint64_t address, size_t size);
status write(uint64_t address, std::span<const uint8_t> data);
status set_protection(uint64_t address, size_t size, memory_protection protection);
status flush_instruction_cache(uint64_t address, size_t size);
result<void*> allocate(size_t size, memory_protection protection);
status free(void* address, size_t size);
result<size_t> page_size();

} // namespace p1ll::engine::platform
