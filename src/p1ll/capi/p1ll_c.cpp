/**
 * @file p1ll_c.cpp
 * @brief C API implementation wrapping p1ll C++ functionality
 */

#include "p1ll_c.h"
#include "../p1ll.hpp"
#include "../engine/memory_scanner.hpp"
#include "../engine/pattern_matcher.hpp"
#include "../core/signature.hpp"
#include "../utils/hex_utils.hpp"

#include <memory>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>

// thread-local error storage
thread_local std::string last_error;

// internal helper to set error message
static void set_error(const std::string& msg) { last_error = msg; }

// internal helper to clear error
static void clear_error() { last_error.clear(); }

// convert c++ memory protection to c flags
static int cpp_protection_to_c(p1ll::engine::memory_protection prot) {
  int flags = P1LL_PROT_NONE;
  if (p1ll::engine::has_protection(prot, p1ll::engine::memory_protection::read)) {
    flags |= P1LL_PROT_READ;
  }
  if (p1ll::engine::has_protection(prot, p1ll::engine::memory_protection::write)) {
    flags |= P1LL_PROT_WRITE;
  }
  if (p1ll::engine::has_protection(prot, p1ll::engine::memory_protection::execute)) {
    flags |= P1LL_PROT_EXEC;
  }
  return flags;
}

// convert c flags to c++ memory protection
static p1ll::engine::memory_protection c_protection_to_cpp(int flags) {
  auto prot = p1ll::engine::memory_protection::none;
  if (flags & P1LL_PROT_READ) {
    prot = prot | p1ll::engine::memory_protection::read;
  }
  if (flags & P1LL_PROT_WRITE) {
    prot = prot | p1ll::engine::memory_protection::write;
  }
  if (flags & P1LL_PROT_EXEC) {
    prot = prot | p1ll::engine::memory_protection::execute;
  }
  return prot;
}

// internal scanner wrapper
struct p1ll_scanner {
  std::unique_ptr<p1ll::engine::memory_scanner> scanner;

  p1ll_scanner() : scanner(std::make_unique<p1ll::engine::memory_scanner>()) {}
};

// --- scanner lifecycle ---

p1ll_scanner_t p1ll_scanner_create(void) {
  try {
    clear_error();
    return new p1ll_scanner();
  } catch (const std::exception& e) {
    set_error("failed to create scanner: " + std::string(e.what()));
    return nullptr;
  }
}

void p1ll_scanner_destroy(p1ll_scanner_t scanner) {
  if (scanner) {
    delete scanner;
  }
}

// --- memory region enumeration ---

int p1ll_get_memory_regions(p1ll_scanner_t scanner, p1ll_memory_region_t** out_regions, size_t* out_count) {
  if (!scanner || !out_regions || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto regions = scanner->scanner->get_memory_regions();
    if (!regions.has_value()) {
      set_error("failed to get memory regions");
      return P1LL_ERROR;
    }

    *out_count = regions->size();
    if (*out_count == 0) {
      *out_regions = nullptr;
      return P1LL_SUCCESS;
    }

    // allocate c array
    *out_regions = static_cast<p1ll_memory_region_t*>(calloc(*out_count, sizeof(p1ll_memory_region_t)));

    if (!*out_regions) {
      set_error("failed to allocate memory regions array");
      return P1LL_ERROR;
    }

    // copy region data
    for (size_t i = 0; i < *out_count; ++i) {
      const auto& cpp_region = (*regions)[i];
      auto& c_region = (*out_regions)[i];

      c_region.base_address = cpp_region.base_address;
      c_region.size = cpp_region.size;
      c_region.protection = cpp_protection_to_c(cpp_region.protection);
      c_region.is_executable = cpp_region.is_executable ? 1 : 0;
      c_region.is_system = cpp_region.is_system ? 1 : 0;

      // copy name, truncate if necessary
      strncpy(c_region.name, cpp_region.name.c_str(), sizeof(c_region.name) - 1);
      c_region.name[sizeof(c_region.name) - 1] = '\0';
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in get_memory_regions: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_get_region_at_address(p1ll_scanner_t scanner, uint64_t address, p1ll_memory_region_t* out_region) {
  if (!scanner || !out_region) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto region = scanner->scanner->get_region_info(address);
    if (!region.has_value()) {
      set_error("no region found at address");
      return P1LL_ERROR;
    }

    out_region->base_address = region->base_address;
    out_region->size = region->size;
    out_region->protection = cpp_protection_to_c(region->protection);
    out_region->is_executable = region->is_executable ? 1 : 0;
    out_region->is_system = region->is_system ? 1 : 0;

    strncpy(out_region->name, region->name.c_str(), sizeof(out_region->name) - 1);
    out_region->name[sizeof(out_region->name) - 1] = '\0';

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in get_region_at_address: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

void p1ll_free_memory_regions(p1ll_memory_region_t* regions) { free(regions); }

// --- memory protection management ---

int p1ll_set_memory_protection(p1ll_scanner_t scanner, uint64_t address, size_t size, int protection) {
  if (!scanner) {
    set_error("invalid scanner");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto cpp_prot = c_protection_to_cpp(protection);
    bool success = scanner->scanner->set_memory_protection(address, size, cpp_prot);
    if (!success) {
      set_error("failed to set memory protection");
      return P1LL_ERROR;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in set_memory_protection: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

size_t p1ll_get_page_size(p1ll_scanner_t scanner) {
  if (!scanner) {
    set_error("invalid scanner");
    return 0;
  }

  try {
    clear_error();
    auto page_size = scanner->scanner->get_page_size();
    if (!page_size.has_value()) {
      set_error("failed to get page size");
      return 0;
    }

    return *page_size;
  } catch (const std::exception& e) {
    set_error("exception in get_page_size: " + std::string(e.what()));
    return 0;
  }
}

// --- direct memory access ---

int p1ll_read_memory(p1ll_scanner_t scanner, uint64_t address, uint8_t* buffer, size_t size) {
  if (!scanner || !buffer) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto data = scanner->scanner->read_memory(address, size);
    if (!data.has_value()) {
      set_error("failed to read memory");
      return P1LL_ERROR;
    }

    if (data->size() != size) {
      set_error("partial read");
      return P1LL_ERROR;
    }

    std::memcpy(buffer, data->data(), size);
    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in read_memory: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_write_memory(p1ll_scanner_t scanner, uint64_t address, const uint8_t* data, size_t size) {
  if (!scanner || !data) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    std::vector<uint8_t> write_data(data, data + size);
    bool success = scanner->scanner->write_memory(address, write_data);
    if (!success) {
      set_error("failed to write memory");
      return P1LL_ERROR;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in write_memory: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_patch_memory(p1ll_scanner_t scanner, uint64_t address, const char* hex_pattern) {
  if (!scanner || !hex_pattern) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto compiled = p1ll::compile_patch(hex_pattern);
    if (!compiled.has_value()) {
      set_error("invalid patch pattern");
      return P1LL_ERROR;
    }

    bool success = scanner->scanner->write_memory(address, compiled->data);
    if (!success) {
      set_error("failed to patch memory");
      return P1LL_ERROR;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in patch_memory: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

// --- memory allocation ---

void* p1ll_allocate_memory(p1ll_scanner_t scanner, size_t size, int protection) {
  if (!scanner) {
    set_error("invalid scanner");
    return nullptr;
  }

  try {
    clear_error();
    auto cpp_prot = c_protection_to_cpp(protection);
    auto result = scanner->scanner->allocate_memory(size, cpp_prot);
    if (!result.has_value()) {
      set_error("failed to allocate memory");
      return nullptr;
    }

    return *result;
  } catch (const std::exception& e) {
    set_error("exception in allocate_memory: " + std::string(e.what()));
    return nullptr;
  }
}

int p1ll_free_memory(p1ll_scanner_t scanner, void* address, size_t size) {
  if (!scanner || !address) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    bool success = scanner->scanner->free_memory(address, size);
    if (!success) {
      set_error("failed to free memory");
      return P1LL_ERROR;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in free_memory: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

// --- pattern searching ---

int p1ll_search_pattern(
    p1ll_scanner_t scanner, const char* hex_pattern, p1ll_match_t** out_matches, size_t* out_count
) {
  if (!scanner || !hex_pattern || !out_matches || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto query = p1ll::create_signature_query(hex_pattern);
    if (!query.has_value()) {
      set_error("invalid signature pattern");
      return P1LL_ERROR;
    }

    auto results = scanner->scanner->search(*query);
    if (!results.has_value()) {
      set_error("search failed");
      return P1LL_ERROR;
    }

    *out_count = results->size();
    if (*out_count == 0) {
      *out_matches = nullptr;
      return P1LL_SUCCESS;
    }

    *out_matches = static_cast<p1ll_match_t*>(calloc(*out_count, sizeof(p1ll_match_t)));

    if (!*out_matches) {
      set_error("failed to allocate matches array");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_count; ++i) {
      const auto& cpp_result = (*results)[i];
      auto& c_match = (*out_matches)[i];

      c_match.address = cpp_result.address;
      strncpy(c_match.region_name, cpp_result.region_name.c_str(), sizeof(c_match.region_name) - 1);
      c_match.region_name[sizeof(c_match.region_name) - 1] = '\0';
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in search_pattern: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_search_in_region(
    p1ll_scanner_t scanner, uint64_t region_base, const char* hex_pattern, p1ll_match_t** out_matches, size_t* out_count
) {
  if (!scanner || !hex_pattern || !out_matches || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();

    // get the region to search in
    auto region = scanner->scanner->get_region_info(region_base);
    if (!region.has_value()) {
      set_error("region not found");
      return P1LL_ERROR;
    }

    // read region memory
    auto memory_data = scanner->scanner->read_memory(region->base_address, region->size);
    if (!memory_data.has_value()) {
      set_error("failed to read region memory");
      return P1LL_ERROR;
    }

    // search in buffer
    size_t* offsets;
    size_t offset_count;
    int result = p1ll_search_in_buffer(memory_data->data(), memory_data->size(), hex_pattern, &offsets, &offset_count);
    if (result != P1LL_SUCCESS) {
      return result;
    }

    // convert offsets to matches
    *out_count = offset_count;
    if (*out_count == 0) {
      *out_matches = nullptr;
      p1ll_free_offsets(offsets);
      return P1LL_SUCCESS;
    }

    *out_matches = static_cast<p1ll_match_t*>(calloc(*out_count, sizeof(p1ll_match_t)));

    if (!*out_matches) {
      p1ll_free_offsets(offsets);
      set_error("failed to allocate matches array");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_count; ++i) {
      (*out_matches)[i].address = region->base_address + offsets[i];
      strncpy((*out_matches)[i].region_name, region->name.c_str(), sizeof((*out_matches)[i].region_name) - 1);
      (*out_matches)[i].region_name[sizeof((*out_matches)[i].region_name) - 1] = '\0';
    }

    p1ll_free_offsets(offsets);
    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in search_in_region: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

int p1ll_search_in_buffer(
    const uint8_t* buffer, size_t buffer_size, const char* hex_pattern, size_t** out_offsets, size_t* out_count
) {
  if (!buffer || !hex_pattern || !out_offsets || !out_count) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto compiled = p1ll::compile_signature(hex_pattern);
    if (!compiled.has_value()) {
      set_error("invalid signature pattern");
      return P1LL_ERROR;
    }

    p1ll::engine::pattern_matcher matcher(*compiled);
    auto offsets = matcher.search(buffer, buffer_size);

    *out_count = offsets.size();
    if (*out_count == 0) {
      *out_offsets = nullptr;
      return P1LL_SUCCESS;
    }

    *out_offsets = static_cast<size_t*>(malloc(*out_count * sizeof(size_t)));

    if (!*out_offsets) {
      set_error("failed to allocate offsets array");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_count; ++i) {
      (*out_offsets)[i] = static_cast<size_t>(offsets[i]);
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in search_in_buffer: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

void p1ll_free_matches(p1ll_match_t* matches) { free(matches); }

void p1ll_free_offsets(size_t* offsets) { free(offsets); }

// --- pattern compilation & validation ---

int p1ll_compile_pattern(const char* hex_pattern, p1ll_compiled_pattern_t* out_pattern) {
  if (!hex_pattern || !out_pattern) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    auto compiled = p1ll::compile_signature(hex_pattern);
    if (!compiled.has_value()) {
      set_error("invalid signature pattern");
      return P1LL_ERROR;
    }

    out_pattern->size = compiled->size();

    // allocate bytes array
    out_pattern->bytes = static_cast<uint8_t*>(malloc(compiled->size()));
    if (!out_pattern->bytes) {
      set_error("failed to allocate bytes array");
      return P1LL_ERROR;
    }

    // allocate mask array
    out_pattern->mask = static_cast<uint8_t*>(malloc(compiled->size()));
    if (!out_pattern->mask) {
      free(out_pattern->bytes);
      set_error("failed to allocate mask array");
      return P1LL_ERROR;
    }

    // copy data
    std::memcpy(out_pattern->bytes, compiled->pattern.data(), compiled->size());
    for (size_t i = 0; i < compiled->size(); ++i) {
      out_pattern->mask[i] = compiled->mask[i] ? 1 : 0;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in compile_pattern: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

void p1ll_free_compiled_pattern(p1ll_compiled_pattern_t* pattern) {
  if (pattern) {
    free(pattern->bytes);
    free(pattern->mask);
    pattern->bytes = nullptr;
    pattern->mask = nullptr;
    pattern->size = 0;
  }
}

int p1ll_validate_pattern(const char* hex_pattern) {
  if (!hex_pattern) {
    return 0;
  }

  try {
    return p1ll::validate_signature_pattern(hex_pattern) ? 1 : 0;
  } catch (...) {
    return 0;
  }
}

// --- utility functions ---

int p1ll_hex_string_to_bytes(const char* hex, uint8_t** out_bytes, size_t* out_size) {
  if (!hex || !out_bytes || !out_size) {
    set_error("invalid parameters");
    return P1LL_ERROR;
  }

  try {
    clear_error();
    std::string hex_str = hex;

    // remove spaces and validate
    std::string clean_hex;
    for (char c : hex_str) {
      if (c != ' ') {
        if (!p1ll::utils::is_hex_digit(c)) {
          set_error("invalid hex character");
          return P1LL_ERROR;
        }
        clean_hex += c;
      }
    }

    if (clean_hex.length() % 2 != 0) {
      set_error("hex string must have even length");
      return P1LL_ERROR;
    }

    *out_size = clean_hex.length() / 2;
    *out_bytes = static_cast<uint8_t*>(malloc(*out_size));
    if (!*out_bytes) {
      set_error("failed to allocate bytes array");
      return P1LL_ERROR;
    }

    for (size_t i = 0; i < *out_size; ++i) {
      uint8_t high = p1ll::utils::parse_hex_digit(clean_hex[i * 2]);
      uint8_t low = p1ll::utils::parse_hex_digit(clean_hex[i * 2 + 1]);
      (*out_bytes)[i] = (high << 4) | low;
    }

    return P1LL_SUCCESS;
  } catch (const std::exception& e) {
    set_error("exception in hex_string_to_bytes: " + std::string(e.what()));
    return P1LL_ERROR;
  }
}

char* p1ll_bytes_to_hex_string(const uint8_t* bytes, size_t size) {
  if (!bytes) {
    set_error("invalid parameters");
    return nullptr;
  }

  try {
    clear_error();
    std::vector<uint8_t> byte_vec(bytes, bytes + size);
    std::string hex_str = p1ll::utils::format_bytes(byte_vec);

    char* result = static_cast<char*>(malloc(hex_str.length() + 1));
    if (!result) {
      set_error("failed to allocate string");
      return nullptr;
    }

    std::strcpy(result, hex_str.c_str());
    return result;
  } catch (const std::exception& e) {
    set_error("exception in bytes_to_hex_string: " + std::string(e.what()));
    return nullptr;
  }
}

char* p1ll_format_address(uint64_t address) {
  try {
    clear_error();
    std::string addr_str = p1ll::utils::format_address(address);

    char* result = static_cast<char*>(malloc(addr_str.length() + 1));
    if (!result) {
      set_error("failed to allocate string");
      return nullptr;
    }

    std::strcpy(result, addr_str.c_str());
    return result;
  } catch (const std::exception& e) {
    set_error("exception in format_address: " + std::string(e.what()));
    return nullptr;
  }
}

void p1ll_free_bytes(uint8_t* bytes) { free(bytes); }

void p1ll_free_string(char* str) { free(str); }

// --- error handling ---

const char* p1ll_get_last_error(void) { return last_error.c_str(); }

// --- capability queries ---

int p1ll_has_scripting_support(void) { return p1ll::has_scripting_support() ? 1 : 0; }