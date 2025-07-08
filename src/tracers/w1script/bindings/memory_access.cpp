#include "memory_access.hpp"
#include <w1tn3ss/util/safe_memory.hpp>
#include <redlog.hpp>
#include <cstring>

namespace w1::tracers::script::bindings {

void setup_memory_access(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up safe memory access functions");

  // safe memory read
  w1_module.set_function("read_mem", [&lua](void* vm_ptr, uint64_t address, size_t size) -> sol::optional<sol::table> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

    auto result = w1::util::safe_memory::read_buffer(vm, address, size, size);
    if (!result) {
      return sol::nullopt;
    }

    // convert to lua table
    sol::state_view lua_view = lua.lua_state();
    sol::table data_table = lua_view.create_table();

    for (size_t i = 0; i < result->data.size(); i++) {
      data_table[i + 1] = result->data[i]; // lua arrays start at 1
    }

    return data_table;
  });

  // safe memory write
  w1_module.set_function("write_mem", [](void* vm_ptr, uint64_t address, sol::table data) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

    // convert lua table to vector
    std::vector<uint8_t> bytes;
    for (size_t i = 1; i <= data.size(); i++) {
      sol::optional<uint8_t> byte = data[i];
      if (byte) {
        bytes.push_back(*byte);
      }
    }

    // check if memory is writable
    if (!w1::util::safe_memory::memory_validator().check_access(
            address, bytes.size(), w1::util::memory_range_index::WRITE
        )) {
      return false;
    }

    // perform write
    std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    return true;
  });

  // safe string read
  w1_module.set_function(
      "read_string",
      [](void* vm_ptr, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
        QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
        size_t max_len = max_length.value_or(256);

        auto result = w1::util::safe_memory::read_string(vm, address, max_len);
        if (!result) {
          return sol::nullopt;
        }

        return *result;
      }
  );

  // safe wide string read
  w1_module.set_function(
      "read_wstring",
      [](void* vm_ptr, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
        QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
        size_t max_len = max_length.value_or(256);

        auto result = w1::util::safe_memory::read_wstring(vm, address, max_len);
        if (!result) {
          return sol::nullopt;
        }

        // convert wstring to string for Lua
        std::string str;
        for (wchar_t wc : *result) {
          if (wc <= 0x7F) {
            str += static_cast<char>(wc);
          } else {
            str += '?'; // simple fallback for non-ASCII
          }
        }

        return str;
      }
  );

  // convenience function to read memory as hex string
  w1_module.set_function(
      "read_mem_hex", [&lua](void* vm_ptr, uint64_t address, size_t size) -> sol::optional<std::string> {
        QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

        auto result = w1::util::safe_memory::read_buffer(vm, address, size, size);
        if (!result) {
          return sol::nullopt;
        }

        // convert to hex string
        std::string hex;
        hex.reserve(result->data.size() * 2);
        const char* hex_chars = "0123456789abcdef";

        for (uint8_t byte : result->data) {
          hex += hex_chars[byte >> 4];
          hex += hex_chars[byte & 0xF];
        }

        return hex;
      }
  );

  // convenience function to write memory from hex string
  w1_module.set_function("write_mem_hex", [](void* vm_ptr, uint64_t address, const std::string& hex_data) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

    if (hex_data.length() % 2 != 0) {
      return false;
    }

    // convert hex string to bytes
    std::vector<uint8_t> bytes;
    bytes.reserve(hex_data.length() / 2);

    for (size_t i = 0; i < hex_data.length(); i += 2) {
      std::string byte_str = hex_data.substr(i, 2);
      try {
        bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
      } catch (...) {
        return false;
      }
    }

    // check if memory is writable
    if (!w1::util::safe_memory::memory_validator().check_access(
            address, bytes.size(), w1::util::memory_range_index::WRITE
        )) {
      return false;
    }

    // perform write
    std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
    return true;
  });

  // read typed values
  w1_module.set_function("read_u8", [](void* vm_ptr, uint64_t address) -> sol::optional<uint8_t> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    auto result = w1::util::safe_memory::read<uint8_t>(vm, address);
    if (result) {
      return sol::optional<uint8_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u16", [](void* vm_ptr, uint64_t address) -> sol::optional<uint16_t> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    auto result = w1::util::safe_memory::read<uint16_t>(vm, address);
    if (result) {
      return sol::optional<uint16_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u32", [](void* vm_ptr, uint64_t address) -> sol::optional<uint32_t> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    auto result = w1::util::safe_memory::read<uint32_t>(vm, address);
    if (result) {
      return sol::optional<uint32_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u64", [](void* vm_ptr, uint64_t address) -> sol::optional<uint64_t> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    auto result = w1::util::safe_memory::read<uint64_t>(vm, address);
    if (result) {
      return sol::optional<uint64_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_ptr", [](void* vm_ptr, uint64_t address) -> sol::optional<QBDI::rword> {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    auto result = w1::util::safe_memory::read<QBDI::rword>(vm, address);
    if (result) {
      return sol::optional<QBDI::rword>(*result);
    }
    return sol::nullopt;
  });

  logger.dbg("safe memory access functions registered");
}

} // namespace w1::tracers::script::bindings