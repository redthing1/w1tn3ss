#include "memory_access.hpp"
#include <w1tn3ss/util/safe_memory.hpp>
#include <redlog.hpp>
#include <cstring>
#include <limits>
#include <unordered_map>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

template <typename T> bool write_scalar(uint64_t address, const T& value) {
  if (!w1::util::safe_memory::memory_validator().check_access(
          address, sizeof(T), w1::util::memory_range_index::WRITE
      )) {
    return false;
  }

  std::memcpy(reinterpret_cast<void*>(address), &value, sizeof(T));
  return true;
}

template <typename T, typename Value> bool write_integral(uint64_t address, Value value) {
  if (value < static_cast<Value>(std::numeric_limits<T>::min()) ||
      value > static_cast<Value>(std::numeric_limits<T>::max())) {
    return false;
  }
  return write_scalar(address, static_cast<T>(value));
}

} // namespace

void setup_memory_access(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up safe memory access functions");

  // helper to fetch instruction-scoped memory accesses
  w1_module.set_function("get_memory_accesses", [&lua](QBDI::VM* vm) -> sol::table {
    if (vm == nullptr) {
      throw sol::error("w1.get_memory_accesses called with nil vm");
    }

    auto log = redlog::get_logger("w1.script_bindings");
    static std::unordered_map<QBDI::VM*, bool> recording_state;

    auto [it, inserted] = recording_state.emplace(vm, false);
    if (inserted) {
      bool enabled = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
      it->second = enabled;
      if (enabled) {
        log.dbg("enabled memory access recording for vm", redlog::field("vm", reinterpret_cast<uintptr_t>(vm)));
      }
    }

    if (!it->second) {
      throw sol::error("platform does not support memory access recording");
    }

    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table(accesses.size(), 0);
    for (size_t i = 0; i < accesses.size(); ++i) {
      const auto& access = accesses[i];
      sol::table entry = lua_view.create_table();

      bool is_read = (access.type & QBDI::MEMORY_READ) != 0;
      bool is_write = (access.type & QBDI::MEMORY_WRITE) != 0;
      bool value_known = (access.flags & QBDI::MEMORY_UNKNOWN_VALUE) == 0;

      entry["address"] = access.accessAddress;
      entry["access_address"] = access.accessAddress;
      entry["inst_address"] = access.instAddress;
      entry["size"] = static_cast<uint32_t>(access.size);
      entry["type"] = static_cast<int>(access.type);
      entry["flags"] = static_cast<int>(access.flags);
      entry["is_read"] = is_read;
      entry["is_write"] = is_write;
      entry["value_known"] = value_known;
      entry["value"] = value_known ? sol::make_object(lua_view, access.value) : sol::lua_nil;

      result[i + 1] = entry;
    }

    return result;
  });

  // safe memory read
  w1_module.set_function("read_mem", [&lua](QBDI::VM* vm, uint64_t address, size_t size) -> sol::optional<sol::table> {
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
  w1_module.set_function("write_mem", [](QBDI::VM* vm, uint64_t address, sol::table data) -> bool {
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
      [](QBDI::VM* vm, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
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
      [](QBDI::VM* vm, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
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
      "read_mem_hex", [&lua](QBDI::VM* vm, uint64_t address, size_t size) -> sol::optional<std::string> {
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
  w1_module.set_function("write_mem_hex", [](QBDI::VM* vm, uint64_t address, const std::string& hex_data) -> bool {
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
  w1_module.set_function("read_u8", [](QBDI::VM* vm, uint64_t address) -> sol::optional<uint8_t> {
    auto result = w1::util::safe_memory::read<uint8_t>(vm, address);
    if (result) {
      return sol::optional<uint8_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u16", [](QBDI::VM* vm, uint64_t address) -> sol::optional<uint16_t> {
    auto result = w1::util::safe_memory::read<uint16_t>(vm, address);
    if (result) {
      return sol::optional<uint16_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u32", [](QBDI::VM* vm, uint64_t address) -> sol::optional<uint32_t> {
    auto result = w1::util::safe_memory::read<uint32_t>(vm, address);
    if (result) {
      return sol::optional<uint32_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_u64", [](QBDI::VM* vm, uint64_t address) -> sol::optional<uint64_t> {
    auto result = w1::util::safe_memory::read<uint64_t>(vm, address);
    if (result) {
      return sol::optional<uint64_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_ptr", [](QBDI::VM* vm, uint64_t address) -> sol::optional<QBDI::rword> {
    auto result = w1::util::safe_memory::read<QBDI::rword>(vm, address);
    if (result) {
      return sol::optional<QBDI::rword>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_i8", [](QBDI::VM* vm, uint64_t address) -> sol::optional<int64_t> {
    auto result = w1::util::safe_memory::read<int8_t>(vm, address);
    if (result) {
      return sol::optional<int64_t>(static_cast<int64_t>(*result));
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_i16", [](QBDI::VM* vm, uint64_t address) -> sol::optional<int64_t> {
    auto result = w1::util::safe_memory::read<int16_t>(vm, address);
    if (result) {
      return sol::optional<int64_t>(static_cast<int64_t>(*result));
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_i32", [](QBDI::VM* vm, uint64_t address) -> sol::optional<int64_t> {
    auto result = w1::util::safe_memory::read<int32_t>(vm, address);
    if (result) {
      return sol::optional<int64_t>(static_cast<int64_t>(*result));
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_i64", [](QBDI::VM* vm, uint64_t address) -> sol::optional<int64_t> {
    auto result = w1::util::safe_memory::read<int64_t>(vm, address);
    if (result) {
      return sol::optional<int64_t>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_f32", [](QBDI::VM* vm, uint64_t address) -> sol::optional<double> {
    auto result = w1::util::safe_memory::read<float>(vm, address);
    if (result) {
      return sol::optional<double>(static_cast<double>(*result));
    }
    return sol::nullopt;
  });

  w1_module.set_function("read_f64", [](QBDI::VM* vm, uint64_t address) -> sol::optional<double> {
    auto result = w1::util::safe_memory::read<double>(vm, address);
    if (result) {
      return sol::optional<double>(*result);
    }
    return sol::nullopt;
  });

  w1_module.set_function("write_u8", [](QBDI::VM*, uint64_t address, uint64_t value) -> bool {
    return write_integral<uint8_t>(address, value);
  });

  w1_module.set_function("write_u16", [](QBDI::VM*, uint64_t address, uint64_t value) -> bool {
    return write_integral<uint16_t>(address, value);
  });

  w1_module.set_function("write_u32", [](QBDI::VM*, uint64_t address, uint64_t value) -> bool {
    return write_integral<uint32_t>(address, value);
  });

  w1_module.set_function("write_u64", [](QBDI::VM*, uint64_t address, uint64_t value) -> bool {
    return write_integral<uint64_t>(address, value);
  });

  w1_module.set_function("write_i8", [](QBDI::VM*, uint64_t address, int64_t value) -> bool {
    return write_integral<int8_t>(address, value);
  });

  w1_module.set_function("write_i16", [](QBDI::VM*, uint64_t address, int64_t value) -> bool {
    return write_integral<int16_t>(address, value);
  });

  w1_module.set_function("write_i32", [](QBDI::VM*, uint64_t address, int64_t value) -> bool {
    return write_integral<int32_t>(address, value);
  });

  w1_module.set_function("write_i64", [](QBDI::VM*, uint64_t address, int64_t value) -> bool {
    return write_scalar(address, static_cast<int64_t>(value));
  });

  w1_module.set_function("write_f32", [](QBDI::VM*, uint64_t address, double value) -> bool {
    return write_scalar(address, static_cast<float>(value));
  });

  w1_module.set_function("write_f64", [](QBDI::VM*, uint64_t address, double value) -> bool {
    return write_scalar(address, static_cast<double>(value));
  });

  w1_module.set_function("write_ptr", [](QBDI::VM*, uint64_t address, QBDI::rword value) -> bool {
    return write_scalar(address, value);
  });

  logger.dbg("safe memory access functions registered");
}

} // namespace w1::tracers::script::bindings
