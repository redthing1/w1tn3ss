#include "mem.hpp"

#include <cstring>
#include <unordered_map>
#include <vector>

namespace w1::tracers::script::bindings {

void setup_mem_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  sol::table mem = lua.create_table();

  mem.set_function("accesses", [&lua](QBDI::VM* vm) -> sol::table {
    if (!vm) {
      throw sol::error("w1.mem.accesses called with nil vm");
    }

    static std::unordered_map<QBDI::VM*, bool> recording_state;
    auto [it, inserted] = recording_state.emplace(vm, false);
    if (inserted) {
      it->second = vm->recordMemoryAccess(QBDI::MEMORY_READ_WRITE);
    }

    if (!it->second) {
      throw sol::error("memory access recording not supported on this platform");
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

  mem.set_function(
      "read_bytes", [&lua, &context](QBDI::VM*, uint64_t address, size_t size) -> sol::optional<sol::table> {
        auto bytes = context.memory().read_bytes(address, size);
        if (!bytes) {
          return sol::nullopt;
        }

        sol::state_view lua_view = lua.lua_state();
        sol::table data_table = lua_view.create_table();
        for (size_t i = 0; i < bytes->size(); ++i) {
          data_table[i + 1] = (*bytes)[i];
        }

        return data_table;
      }
  );

  mem.set_function("read_hex", [&context](QBDI::VM*, uint64_t address, size_t size) -> sol::optional<std::string> {
    auto bytes = context.memory().read_bytes(address, size);
    if (!bytes) {
      return sol::nullopt;
    }

    std::string hex;
    hex.reserve(bytes->size() * 2);
    const char* hex_chars = "0123456789abcdef";
    for (uint8_t byte : *bytes) {
      hex += hex_chars[byte >> 4];
      hex += hex_chars[byte & 0xF];
    }
    return hex;
  });

  mem.set_function(
      "read_string",
      [&context](QBDI::VM*, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
        size_t max_len = max_length.value_or(256);
        auto result = context.memory().read_string(address, max_len);
        if (!result) {
          return sol::nullopt;
        }
        return *result;
      }
  );

  mem.set_function(
      "read_wstring",
      [&context](QBDI::VM*, uint64_t address, sol::optional<size_t> max_length) -> sol::optional<std::string> {
        size_t max_len = max_length.value_or(256);
        auto bytes = context.memory().read_bytes(address, max_len * sizeof(wchar_t));
        if (!bytes || bytes->empty()) {
          return sol::nullopt;
        }

        std::string out;
        for (size_t i = 0; i + sizeof(wchar_t) <= bytes->size(); i += sizeof(wchar_t)) {
          wchar_t wc = 0;
          std::memcpy(&wc, bytes->data() + i, sizeof(wchar_t));
          if (wc == 0) {
            break;
          }
          if (wc <= 0x7F) {
            out.push_back(static_cast<char>(wc));
          } else {
            out.push_back('?');
          }
        }

        return out;
      }
  );

  w1_module["mem"] = mem;
}

} // namespace w1::tracers::script::bindings
