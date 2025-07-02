#ifdef WITNESS_SCRIPT_ENABLED

#include "script_bindings.hpp"
#include <redlog/redlog.hpp>
#include <common/ext/jsonstruct.hpp>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cmath>

namespace w1::tracers::script {

// Forward declarations for recursive JSON conversion
static std::string lua_table_to_json(const sol::table& lua_table, int depth);
static std::string lua_table_to_json(const sol::table& lua_table);

void setup_qbdi_bindings(sol::state& lua) {
  auto log = redlog::get_logger("w1script.bindings");
  log.inf("Setting up QBDI bindings");

  // Create w1 module
  sol::table w1_module = lua.create_table();

  // VMAction enum
  w1_module.new_enum(
      "VMAction", "CONTINUE", QBDI::VMAction::CONTINUE, "SKIP_INST", QBDI::VMAction::SKIP_INST, "SKIP_PATCH",
      QBDI::VMAction::SKIP_PATCH, "BREAK_TO_VM", QBDI::VMAction::BREAK_TO_VM, "STOP", QBDI::VMAction::STOP
  );

  // Don't expose the raw QBDI types - they cause sol2 compilation issues
  // Instead we'll pass them as lightuserdata and provide accessor functions

  // InstAnalysis type with useful fields
  lua.new_usertype<QBDI::InstAnalysis>(
      "InstAnalysis", "address", &QBDI::InstAnalysis::address, "instSize", &QBDI::InstAnalysis::instSize,
      "affectControlFlow", &QBDI::InstAnalysis::affectControlFlow, "isBranch", &QBDI::InstAnalysis::isBranch, "isCall",
      &QBDI::InstAnalysis::isCall, "isReturn", &QBDI::InstAnalysis::isReturn, "isCompare",
      &QBDI::InstAnalysis::isCompare, "isPredicable", &QBDI::InstAnalysis::isPredicable, "mayLoad",
      &QBDI::InstAnalysis::mayLoad, "mayStore", &QBDI::InstAnalysis::mayStore, "loadSize",
      &QBDI::InstAnalysis::loadSize, "storeSize", &QBDI::InstAnalysis::storeSize, "condition",
      &QBDI::InstAnalysis::condition
  );

  // Logging functions
  w1_module.set_function("log_info", [](const std::string& msg) {
    auto log = redlog::get_logger("w1script.lua");
    log.inf(msg);
  });

  w1_module.set_function("log_debug", [](const std::string& msg) {
    auto log = redlog::get_logger("w1script.lua");
    log.dbg(msg);
  });

  w1_module.set_function("log_error", [](const std::string& msg) {
    auto log = redlog::get_logger("w1script.lua");
    log.err(msg);
  });

  // Memory access helpers - simplified for now
  w1_module.set_function(
      "read_memory", [](void* vm_ptr, QBDI::rword address, size_t size) -> sol::optional<std::string> {
        // Simplified implementation - would need actual memory reading logic
        // For now just return nullopt to avoid crashes
        return sol::nullopt;
      }
  );

  // Register access helpers - platform specific
  log.inf("Checking architecture macros");
#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
  w1_module.set_function("get_reg_rax", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rax;
  });

  w1_module.set_function("get_reg_rbx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rbx;
  });

  w1_module.set_function("get_reg_rcx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rcx;
  });

  w1_module.set_function("get_reg_rdx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rdx;
  });

  w1_module.set_function("get_reg_rsp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rsp;
  });

  w1_module.set_function("get_reg_rbp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rbp;
  });

  w1_module.set_function("get_reg_rsi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rsi;
  });

  w1_module.set_function("get_reg_rdi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rdi;
  });

  w1_module.set_function("get_reg_rip", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rip;
  });

  log.inf("x86_64 register functions registered");
#elif defined(__aarch64__) || defined(_M_ARM64)
  // ARM64 registers
  w1_module.set_function("get_reg_x0", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x0;
  });

  w1_module.set_function("get_reg_x1", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x1;
  });

  w1_module.set_function("get_reg_sp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->sp;
  });

  w1_module.set_function("get_reg_lr", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->lr;
  });

  w1_module.set_function("get_reg_pc", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->pc;
  });

  log.inf("ARM64 register functions registered");
#elif defined(__arm__) || defined(_M_ARM)
  // ARM32 registers (different from ARM64)
  w1_module.set_function("get_reg_r0", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r0;
  });

  w1_module.set_function("get_reg_r1", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r1;
  });

  w1_module.set_function("get_reg_sp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->sp;
  });

  w1_module.set_function("get_reg_lr", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->lr;
  });

  w1_module.set_function("get_reg_pc", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->pc;
  });

  log.inf("ARM32 register functions registered");
#else
  log.wrn("No register functions available for this architecture");
#endif

  // VM utility functions - we can get PC from GPR state instead
  // lua.set_function("get_instruction_address", [](void* vm_ptr) -> QBDI::rword {
  //     // This method might not exist, we'll use GPR state instead
  //     return 0;
  // });

  w1_module.set_function("format_address", [](QBDI::rword addr) -> std::string {
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%016lx", static_cast<unsigned long>(addr));
    return std::string(buffer);
  });

  // Get disassembly of current instruction
  w1_module.set_function("get_disassembly", [](void* vm_ptr) -> std::string {
    QBDI::VMInstanceRef vm = static_cast<QBDI::VMInstanceRef>(vm_ptr);
    const QBDI::InstAnalysis* analysis = vm->getInstAnalysis();
    if (analysis && analysis->disassembly) {
      return std::string(analysis->disassembly);
    }
    return "unknown";
  });

  // Get memory accesses for current instruction
  w1_module.set_function("get_memory_accesses", [&lua](void* vm_ptr) -> sol::table {
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
      access_table["is_read"] = (access.type & QBDI::MEMORY_READ) != 0;
      access_table["is_write"] = (access.type & QBDI::MEMORY_WRITE) != 0;
      access_table["inst_address"] = access.instAddress;

      result[i + 1] = access_table; // Lua arrays start at 1
    }

    return result;
  });

  // Format memory value as hex string with specified width
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

  // File output functions
  w1_module.set_function("write_file", [](const std::string& filename, const std::string& content) -> bool {
    try {
      std::ofstream file(filename);
      if (file.is_open()) {
        file << content;
        file.close();
        return true;
      }
    } catch (...) {
      // ignore exceptions
    }
    return false;
  });

  w1_module.set_function("append_file", [](const std::string& filename, const std::string& content) -> bool {
    try {
      std::ofstream file(filename, std::ios::app);
      if (file.is_open()) {
        file << content;
        file.close();
        return true;
      }
    } catch (...) {
      // ignore exceptions
    }
    return false;
  });

  // Clean JSON output API
  w1_module.set_function("to_json", [](const sol::table& lua_table) -> std::string {
    return lua_table_to_json(lua_table);
  });

  // Get current timestamp
  w1_module.set_function("get_timestamp", []() -> std::string {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
  });

  // Register the w1 module
  lua["w1"] = w1_module;

  log.inf("w1 module registered with all functions");
}

// Forward declaration for recursive calls
static std::string serialize_lua_value(const sol::object& value, int depth = 0);

// Helper to escape JSON strings properly
static std::string escape_json_string(const std::string& str) {
  std::stringstream ss;
  ss << "\"";
  for (char c : str) {
    switch (c) {
    case '"':
      ss << "\\\"";
      break;
    case '\\':
      ss << "\\\\";
      break;
    case '\b':
      ss << "\\b";
      break;
    case '\f':
      ss << "\\f";
      break;
    case '\n':
      ss << "\\n";
      break;
    case '\r':
      ss << "\\r";
      break;
    case '\t':
      ss << "\\t";
      break;
    default:
      if (c < 0x20) {
        ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned char>(c);
      } else {
        ss << c;
      }
      break;
    }
  }
  ss << "\"";
  return ss.str();
}

// Check if table should be serialized as array (consecutive integer keys starting from 1)
static bool is_lua_array(const sol::table& table) {
  if (table.empty()) {
    return false;
  }

  std::vector<int> indices;
  bool has_non_int_keys = false;

  for (const auto& pair : table) {
    if (pair.first.is<int>()) {
      indices.push_back(pair.first.as<int>());
    } else {
      has_non_int_keys = true;
      break;
    }
  }

  if (has_non_int_keys || indices.empty()) {
    return false;
  }

  // Sort indices and check if they're consecutive starting from 1
  std::sort(indices.begin(), indices.end());
  for (size_t i = 0; i < indices.size(); i++) {
    if (indices[i] != static_cast<int>(i + 1)) {
      return false;
    }
  }

  return true;
}

// Serialize any Lua value to JSON
static std::string serialize_lua_value(const sol::object& value, int depth) {
  // Prevent infinite recursion
  if (depth > 32) {
    return "\"[max_depth_exceeded]\"";
  }

  if (!value.valid()) {
    return "null";
  } else if (value.is<sol::nil_t>()) {
    return "null";
  } else if (value.is<bool>()) {
    return value.as<bool>() ? "true" : "false";
  } else if (value.is<int>()) {
    return std::to_string(value.as<int>());
  } else if (value.is<double>()) {
    double d = value.as<double>();
    if (std::isfinite(d)) {
      return std::to_string(d);
    } else {
      return "null"; // JSON doesn't support NaN/Infinity
    }
  } else if (value.is<float>()) {
    float f = value.as<float>();
    if (std::isfinite(f)) {
      return std::to_string(f);
    } else {
      return "null";
    }
  } else if (value.is<std::string>()) {
    return escape_json_string(value.as<std::string>());
  } else if (value.is<const char*>()) {
    return escape_json_string(std::string(value.as<const char*>()));
  } else if (value.is<sol::table>()) {
    return lua_table_to_json(value.as<sol::table>(), depth + 1);
  } else {
    // Fallback: try to convert to string
    try {
      std::string str_repr = value.as<std::string>();
      return escape_json_string(str_repr);
    } catch (...) {
      return "null";
    }
  }
}

// Main JSON conversion function
static std::string lua_table_to_json(const sol::table& lua_table, int depth) {
  try {
    // Prevent infinite recursion
    if (depth > 32) {
      return "{\"error\":\"max_recursion_depth_exceeded\"}";
    }

    std::stringstream json_stream;

    if (is_lua_array(lua_table)) {
      // Serialize as JSON array
      json_stream << "[";
      bool first = true;

      for (size_t i = 1; i <= lua_table.size(); i++) {
        if (!first) {
          json_stream << ",";
        }
        json_stream << serialize_lua_value(lua_table[i], depth);
        first = false;
      }

      json_stream << "]";
    } else {
      // Serialize as JSON object
      json_stream << "{";
      bool first = true;

      for (const auto& pair : lua_table) {
        if (!first) {
          json_stream << ",";
        }

        // Convert key to string
        std::string key;
        if (pair.first.is<std::string>()) {
          key = pair.first.as<std::string>();
        } else if (pair.first.is<int>()) {
          key = std::to_string(pair.first.as<int>());
        } else if (pair.first.is<double>()) {
          key = std::to_string(pair.first.as<double>());
        } else {
          // Try to convert to string as fallback
          try {
            key = pair.first.as<std::string>();
          } catch (...) {
            continue; // Skip unsupported key types
          }
        }

        json_stream << escape_json_string(key) << ":" << serialize_lua_value(pair.second, depth);
        first = false;
      }

      json_stream << "}";
    }

    return json_stream.str();

  } catch (const std::exception& e) {
    return "{\"error\":\"json_serialization_failed\",\"details\":\"" + std::string(e.what()) + "\"}";
  } catch (...) {
    return "{\"error\":\"unknown_json_serialization_error\"}";
  }
}

// Public interface - wrapper with default depth
static std::string lua_table_to_json(const sol::table& lua_table) { return lua_table_to_json(lua_table, 0); }

} // namespace w1::tracers::script

#endif // WITNESS_SCRIPT_ENABLED