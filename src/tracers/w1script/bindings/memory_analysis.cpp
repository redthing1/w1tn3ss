#include "memory_analysis.hpp"
#include <redlog.hpp>
#include <vector>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace w1::tracers::script::bindings {

void setup_memory_analysis(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up memory access and analysis functions");

  // get memory accesses for the current instruction
  // returns a Lua table containing detailed information about all memory accesses
  // performed by the current instruction
  w1_module.set_function("get_memory_accesses", [&lua](void* vm_ptr) -> sol::table {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    for (size_t i = 0; i < accesses.size(); i++) {
      const auto& access = accesses[i];
      sol::table access_table = lua_view.create_table();

      // memory access details
      access_table["address"] = access.accessAddress;    // Address being accessed
      access_table["value"] = access.value;              // Value read/written
      access_table["size"] = access.size;                // Size of access in bytes
      access_table["inst_address"] = access.instAddress; // Address of instruction performing access

      // access type flags
      access_table["is_read"] = (access.type & QBDI::MEMORY_READ) != 0;
      access_table["is_write"] = (access.type & QBDI::MEMORY_WRITE) != 0;

      // additional access information
      access_table["flags"] = access.flags; // Additional flags

      result[i + 1] = access_table; // Lua arrays start at 1
    }

    return result;
  });

  // format memory value as hex string with specified width
  // provides consistent formatting for memory values based on their size
  w1_module.set_function("format_memory_value", [](QBDI::rword value, int size) -> std::string {
    char buffer[32];
    switch (size) {
    case 1:
      snprintf(buffer, sizeof(buffer), "0x%02x", static_cast<uint8_t>(value));
      break;
    case 2:
      snprintf(buffer, sizeof(buffer), "0x%04x", static_cast<uint16_t>(value));
      break;
    case 4:
      snprintf(buffer, sizeof(buffer), "0x%08x", static_cast<uint32_t>(value));
      break;
    case 8:
      snprintf(buffer, sizeof(buffer), "0x%016lx", static_cast<unsigned long>(value));
      break;
    default:
      snprintf(buffer, sizeof(buffer), "0x%lx", static_cast<unsigned long>(value));
      break;
    }
    return std::string(buffer);
  });

  // memory access recording
  // enable automatic memory logging for specified access types
  w1_module.set_function("recordMemoryAccess", [](void* vm_ptr, QBDI::MemoryAccessType type) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    return vm->recordMemoryAccess(type);
  });

  // get current instruction memory accesses (alias for existing function)
  w1_module.set_function("getInstMemoryAccess", [&lua](void* vm_ptr) -> sol::table {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    for (size_t i = 0; i < accesses.size(); i++) {
      const auto& access = accesses[i];
      sol::table access_table = lua_view.create_table();

      access_table["address"] = access.accessAddress;
      access_table["value"] = access.value;
      access_table["size"] = access.size;
      access_table["inst_address"] = access.instAddress;
      access_table["is_read"] = (access.type & QBDI::MEMORY_READ) != 0;
      access_table["is_write"] = (access.type & QBDI::MEMORY_WRITE) != 0;
      access_table["flags"] = access.flags;

      result[i + 1] = access_table;
    }

    return result;
  });

  // get basic block memory accesses
  w1_module.set_function("getBBMemoryAccess", [&lua](void* vm_ptr) -> sol::table {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getBBMemoryAccess();

    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    for (size_t i = 0; i < accesses.size(); i++) {
      const auto& access = accesses[i];
      sol::table access_table = lua_view.create_table();

      access_table["address"] = access.accessAddress;
      access_table["value"] = access.value;
      access_table["size"] = access.size;
      access_table["inst_address"] = access.instAddress;
      access_table["is_read"] = (access.type & QBDI::MEMORY_READ) != 0;
      access_table["is_write"] = (access.type & QBDI::MEMORY_WRITE) != 0;
      access_table["flags"] = access.flags;

      result[i + 1] = access_table;
    }

    return result;
  });

  // memory management
  // allocate managed virtual stack
  w1_module.set_function("allocateVirtualStack", [](void* vm_ptr, uint32_t stackSize) -> sol::optional<QBDI::rword> {
    auto log = redlog::get_logger("w1.script_bindings");
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

    try {
      QBDI::GPRState* state = vm->getGPRState();
      uint8_t* stack = nullptr;

      if (QBDI::allocateVirtualStack(state, stackSize, &stack)) {
        log.dbg(
            "allocated virtual stack of size " + std::to_string(stackSize) + " at address 0x" +
            std::to_string(reinterpret_cast<QBDI::rword>(stack))
        );
        return reinterpret_cast<QBDI::rword>(stack);
      } else {
        log.warn("failed to allocate virtual stack of size " + std::to_string(stackSize));
        return sol::nullopt;
      }
    } catch (const std::exception& e) {
      log.err("exception in allocateVirtualStack: " + std::string(e.what()));
      return sol::nullopt;
    }
  });

  // simulate function call with arguments
  w1_module.set_function("simulateCall", [](void* vm_ptr, QBDI::rword returnAddress, sol::table args) -> bool {
    auto log = redlog::get_logger("w1.script_bindings");
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);

    try {
      QBDI::GPRState* state = vm->getGPRState();
      std::vector<QBDI::rword> argVector;

      // convert Lua table to vector
      for (size_t i = 1; i <= args.size(); i++) {
        sol::optional<QBDI::rword> arg = args[i];
        if (arg) {
          argVector.push_back(arg.value());
        }
      }

      QBDI::simulateCall(state, returnAddress, argVector);
      log.dbg(
          "simulated call with return address 0x" + std::to_string(returnAddress) + " and " +
          std::to_string(argVector.size()) + " arguments"
      );
      return true;
    } catch (const std::exception& e) {
      log.err("exception in simulateCall: " + std::string(e.what()));
      return false;
    }
  });

  // aligned memory allocation
  w1_module.set_function("alignedAlloc", [](size_t size, size_t alignment) -> sol::optional<QBDI::rword> {
    auto log = redlog::get_logger("w1.script_bindings");
    try {
      void* ptr = QBDI::alignedAlloc(size, alignment);
      if (ptr) {
        log.dbg(
            "allocated " + std::to_string(size) + " bytes with alignment " + std::to_string(alignment) +
            " at address 0x" + std::to_string(reinterpret_cast<QBDI::rword>(ptr))
        );
        return reinterpret_cast<QBDI::rword>(ptr);
      } else {
        log.warn("failed to allocate " + std::to_string(size) + " bytes with alignment " + std::to_string(alignment));
        return sol::nullopt;
      }
    } catch (const std::exception& e) {
      log.err("exception in alignedAlloc: " + std::string(e.what()));
      return sol::nullopt;
    }
  });

  // aligned memory free
  w1_module.set_function("alignedFree", [](QBDI::rword ptr) -> bool {
    auto log = redlog::get_logger("w1.script_bindings");
    try {
      if (ptr != 0) {
        QBDI::alignedFree(reinterpret_cast<void*>(ptr));
        log.dbg("freed aligned memory at address 0x" + std::to_string(ptr));
        return true;
      } else {
        log.warn("attempted to free null pointer");
        return false;
      }
    } catch (const std::exception& e) {
      log.err("exception in alignedFree: " + std::string(e.what()));
      return false;
    }
  });

  // memory inspection
  // safe memory reading with error handling
  w1_module.set_function(
      "readMemory", [](void* vm_ptr, QBDI::rword address, size_t size) -> sol::optional<std::string> {
        auto log = redlog::get_logger("w1.script_bindings");

        try {
          // validate parameters
          if (size == 0) {
            log.warn("attempted to read 0 bytes from address 0x" + std::to_string(address));
            return sol::nullopt;
          }

          if (size > 0x10000) { // Limit reads to 64KB for safety
            log.warn(
                "attempted to read " + std::to_string(size) + " bytes from address 0x" + std::to_string(address) +
                " - size too large"
            );
            return sol::nullopt;
          }

          // try to read memory with basic safety checks
          // note: this is still potentially dangerous and should be used carefully
          std::vector<uint8_t> buffer(size);

          // use memcpy for reading - this can still crash if address is invalid
          // but it's the most direct approach available in QBDI context
          std::memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);

          // convert to hex string
          std::ostringstream hex_stream;
          hex_stream << std::hex << std::uppercase;
          for (size_t i = 0; i < size; i++) {
            hex_stream << std::setfill('0') << std::setw(2) << static_cast<int>(buffer[i]);
          }

          log.dbg("successfully read " + std::to_string(size) + " bytes from address 0x" + std::to_string(address));
          return hex_stream.str();

        } catch (const std::exception& e) {
          log.err("exception reading memory at address 0x" + std::to_string(address) + ": " + std::string(e.what()));
          return sol::nullopt;
        } catch (...) {
          log.err("unknown exception reading memory at address 0x" + std::to_string(address));
          return sol::nullopt;
        }
      }
  );

  // unsafe memory writing (deprecated - use write_mem instead)
  w1_module.set_function("writeMemoryUnsafe", [](void* vm_ptr, QBDI::rword address, const std::string& hexData) -> bool {
    auto log = redlog::get_logger("w1.script_bindings");

    try {
      // validate hex string length
      if (hexData.length() % 2 != 0) {
        log.warn("invalid hex data length: " + std::to_string(hexData.length()) + " (must be even)");
        return false;
      }

      size_t size = hexData.length() / 2;
      if (size == 0) {
        log.warn("attempted to write 0 bytes to address 0x" + std::to_string(address));
        return false;
      }

      if (size > 0x10000) { // Limit writes to 64KB for safety
        log.warn(
            "attempted to write " + std::to_string(size) + " bytes to address 0x" + std::to_string(address) +
            " - size too large"
        );
        return false;
      }

      // convert hex string to bytes
      std::vector<uint8_t> buffer(size);
      for (size_t i = 0; i < size; i++) {
        std::string byteStr = hexData.substr(i * 2, 2);
        buffer[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
      }

      // write memory using memcpy - this can still crash if address is invalid
      std::memcpy(reinterpret_cast<void*>(address), buffer.data(), size);

      log.dbg("successfully wrote " + std::to_string(size) + " bytes to address 0x" + std::to_string(address));
      return true;

    } catch (const std::exception& e) {
      log.err("exception writing memory at address 0x" + std::to_string(address) + ": " + std::string(e.what()));
      return false;
    } catch (...) {
      log.err("unknown exception writing memory at address 0x" + std::to_string(address));
      return false;
    }
  });

  // basic address validity check (heuristic-based)
  w1_module.set_function("isAddressValid", [](void* vm_ptr, QBDI::rword address) -> bool {
    auto log = redlog::get_logger("w1.script_bindings");

    try {
      // basic heuristic checks for obviously invalid addresses
      if (address == 0) {
        return false; // null pointer
      }

      // check for obviously invalid addresses (platform-specific)
#if defined(__x86_64__) || defined(_M_X64)
      // on x86-64, user space addresses are typically below 0x00007FFFFFFFFFFF
      if (address > 0x00007FFFFFFFFFFUL) {
        return false;
      }
#elif defined(__i386__) || defined(_M_IX86)
      // on 32-bit, check for reasonable user space range
      if (address > 0xC0000000UL) {
        return false;
      }
#endif

      // try to read a single byte as a basic validity test
      // this is still not foolproof but provides some safety
      try {
        volatile uint8_t test_byte;
        std::memcpy(const_cast<uint8_t*>(&test_byte), reinterpret_cast<const void*>(address), 1);
        return true;
      } catch (...) {
        return false;
      }

    } catch (const std::exception& e) {
      log.err("exception in isAddressValid for address 0x" + std::to_string(address) + ": " + std::string(e.what()));
      return false;
    }
  });

  // memory mapping
  // get process memory layout
  w1_module.set_function("getMemoryMaps", [&lua](void* vm_ptr) -> sol::table {
    auto log = redlog::get_logger("w1.script_bindings");
    sol::state_view lua_view = lua.lua_state();
    sol::table result = lua_view.create_table();

    try {
      std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(true);

      for (size_t i = 0; i < maps.size(); i++) {
        const auto& map = maps[i];
        sol::table map_table = lua_view.create_table();

        map_table["start"] = map.range.start();
        map_table["end"] = map.range.end();
        map_table["size"] = map.range.size();
        map_table["name"] = map.name;
        map_table["readable"] = (map.permission & QBDI::PF_READ) != 0;
        map_table["writable"] = (map.permission & QBDI::PF_WRITE) != 0;
        map_table["executable"] = (map.permission & QBDI::PF_EXEC) != 0;
        map_table["permissions"] = static_cast<int>(map.permission);

        result[i + 1] = map_table;
      }

      log.dbg("retrieved " + std::to_string(maps.size()) + " memory maps");

    } catch (const std::exception& e) {
      log.err("exception in getMemoryMaps: " + std::string(e.what()));
    }

    return result;
  });

  // find memory map containing specific address
  w1_module.set_function("findMemoryMap", [&lua](void* vm_ptr, QBDI::rword address) -> sol::optional<sol::table> {
    auto log = redlog::get_logger("w1.script_bindings");

    try {
      std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(true);

      for (const auto& map : maps) {
        if (map.range.contains(address)) {
          sol::state_view lua_view = lua.lua_state();
          sol::table map_table = lua_view.create_table();

          map_table["start"] = map.range.start();
          map_table["end"] = map.range.end();
          map_table["size"] = map.range.size();
          map_table["name"] = map.name;
          map_table["readable"] = (map.permission & QBDI::PF_READ) != 0;
          map_table["writable"] = (map.permission & QBDI::PF_WRITE) != 0;
          map_table["executable"] = (map.permission & QBDI::PF_EXEC) != 0;
          map_table["permissions"] = static_cast<int>(map.permission);

          log.dbg(
              "found memory map for address 0x" + std::to_string(address) + ": " + map.name + " (0x" +
              std::to_string(map.range.start()) + "-0x" + std::to_string(map.range.end()) + ")"
          );
          return map_table;
        }
      }

      log.dbg("no memory map found for address 0x" + std::to_string(address));
      return sol::nullopt;

    } catch (const std::exception& e) {
      log.err("exception in findMemoryMap for address 0x" + std::to_string(address) + ": " + std::string(e.what()));
      return sol::nullopt;
    }
  });

  // check if address is in executable memory region
  w1_module.set_function("isExecutableAddress", [](void* vm_ptr, QBDI::rword address) -> bool {
    auto log = redlog::get_logger("w1.script_bindings");

    try {
      std::vector<QBDI::MemoryMap> maps = QBDI::getCurrentProcessMaps(false);

      for (const auto& map : maps) {
        if (map.range.contains(address)) {
          bool isExecutable = (map.permission & QBDI::PF_EXEC) != 0;
          log.dbg(
              "address 0x" + std::to_string(address) + " is " + (isExecutable ? "executable" : "not executable") +
              " in region " + map.name + " (0x" + std::to_string(map.range.start()) + "-0x" +
              std::to_string(map.range.end()) + ")"
          );
          return isExecutable;
        }
      }

      log.dbg("address 0x" + std::to_string(address) + " not found in any memory map");
      return false;

    } catch (const std::exception& e) {
      log.err(
          "exception in isExecutableAddress for address 0x" + std::to_string(address) + ": " + std::string(e.what())
      );
      return false;
    }
  });

  // legacy read_memory function (improved implementation)
  w1_module.set_function(
      "read_memory", [](void* vm_ptr, QBDI::rword address, size_t size) -> sol::optional<std::string> {
        auto log = redlog::get_logger("w1.script_bindings");

        try {
          // validate parameters
          if (size == 0) {
            log.warn("attempted to read 0 bytes from address 0x" + std::to_string(address));
            return sol::nullopt;
          }

          if (size > 0x1000) { // Limit to 4KB for legacy function
            log.warn(
                "attempted to read " + std::to_string(size) + " bytes from address 0x" + std::to_string(address) +
                " - size too large for legacy function"
            );
            return sol::nullopt;
          }

          // try to read memory with basic safety checks
          std::vector<uint8_t> buffer(size);
          std::memcpy(buffer.data(), reinterpret_cast<const void*>(address), size);

          // convert to string (assume printable characters)
          std::string result;
          result.reserve(size);
          for (uint8_t byte : buffer) {
            if (byte >= 32 && byte <= 126) { // printable ASCII
              result += static_cast<char>(byte);
            } else {
              result += '.';
            }
          }

          log.dbg(
              "successfully read " + std::to_string(size) + " bytes from address 0x" + std::to_string(address) +
              " (legacy function)"
          );
          return result;

        } catch (const std::exception& e) {
          log.err(
              "exception in legacy read_memory at address 0x" + std::to_string(address) + ": " + std::string(e.what())
          );
          return sol::nullopt;
        } catch (...) {
          log.err("unknown exception in legacy read_memory at address 0x" + std::to_string(address));
          return sol::nullopt;
        }
      }
  );

  // check if a memory access is a read operation
  w1_module.set_function("is_memory_read", [](QBDI::MemoryAccessType type) -> bool {
    return (type & QBDI::MEMORY_READ) != 0;
  });

  // check if a memory access is a write operation
  w1_module.set_function("is_memory_write", [](QBDI::MemoryAccessType type) -> bool {
    return (type & QBDI::MEMORY_WRITE) != 0;
  });

  // get the number of memory accesses for the current instruction
  w1_module.set_function("get_memory_access_count", [](void* vm_ptr) -> size_t {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();
    return accesses.size();
  });

  // check if the current instruction performs any memory accesses
  w1_module.set_function("has_memory_access", [](void* vm_ptr) -> bool {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();
    return !accesses.empty();
  });

  // get the total size of all memory accesses for the current instruction
  w1_module.set_function("get_total_memory_access_size", [](void* vm_ptr) -> size_t {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    std::vector<QBDI::MemoryAccess> accesses = vm->getInstMemoryAccess();

    size_t total_size = 0;
    for (const auto& access : accesses) {
      total_size += access.size;
    }
    return total_size;
  });

  logger.dbg("enhanced memory analysis functions setup complete with 16 functions");
}

} // namespace w1::tracers::script::bindings