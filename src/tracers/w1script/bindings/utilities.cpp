#include "utilities.hpp"
#include <w1common/platform_utils.hpp>
#include <redlog.hpp>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cmath>

namespace w1::tracers::script::bindings {

// forward declarations for internal functions
static std::string serialize_lua_value(const sol::object& value, int depth = 0);
static std::string lua_table_to_json_internal(const sol::table& lua_table, int depth);

void setup_utilities(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up utility functions");

  // === Logging Functions ===
  // these provide integration with the redlog logging system

  w1_module.set_function("log_info", [](const std::string& msg) {
    auto log = redlog::get_logger("w1.script_lua");
    log.inf(msg);
  });

  w1_module.set_function("log_debug", [](const std::string& msg) {
    auto log = redlog::get_logger("w1.script_lua");
    log.dbg(msg);
  });

  w1_module.set_function("log_error", [](const std::string& msg) {
    auto log = redlog::get_logger("w1.script_lua");
    log.err(msg);
  });

  w1_module.set_function("log_warning", [](const std::string& msg) {
    auto log = redlog::get_logger("w1.script_lua");
    log.wrn(msg);
  });

  // === File I/O Functions ===
  // these provide safe file operations for data output

  w1_module.set_function("write_file", [](const std::string& filename, const std::string& content) -> bool {
    try {
      std::ofstream file(filename);
      if (file.is_open()) {
        file << content;
        file.close();
        return true;
      }
    } catch (...) {
      // log error but don't throw - return false instead
      auto log = redlog::get_logger("w1.script_lua");
      log.err("failed to write file: " + filename);
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
      // log error but don't throw - return false instead
      auto log = redlog::get_logger("w1.script_lua");
      log.err("failed to append to file: " + filename);
    }
    return false;
  });

  // === JSON Serialization ===
  // convert Lua tables to JSON strings for structured output

  w1_module.set_function("to_json", [](const sol::table& lua_table) -> std::string {
    return lua_table_to_json(lua_table);
  });

  // === Timestamp Functions ===
  // generate timestamps for logging and data collection

  w1_module.set_function("get_timestamp", []() -> std::string {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return ss.str();
  });

  w1_module.set_function("get_unix_timestamp", []() -> int64_t {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
  });

  w1_module.set_function("get_millisecond_timestamp", []() -> int64_t {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
  });

  // === String Utilities ===
  // additional string manipulation functions

  w1_module.set_function("escape_string", [](const std::string& str) -> std::string {
    return escape_json_string(str);
  });

  w1_module.set_function("trim_string", [](const std::string& str) -> std::string {
    auto start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) {
      return "";
    }
    auto end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
  });

  // === Platform Detection Functions ===
  // get platform and architecture information

  w1_module.set_function("get_platform", []() -> std::string {
    return w1::common::platform_utils::get_platform_name();
  });

  w1_module.set_function("get_architecture", []() -> std::string {
#if defined(QBDI_ARCH_X86_64)
    return "x86_64";
#elif defined(QBDI_ARCH_X86)
    return "x86";
#elif defined(QBDI_ARCH_ARM)
    return "arm";
#elif defined(QBDI_ARCH_AARCH64)
    return "aarch64";
#else
    return "unknown";
#endif
  });

  w1_module.set_function("get_platform_info", [&lua]() -> sol::table {
    sol::table info = lua.create_table();

    info["os"] = w1::common::platform_utils::get_platform_name();

#if defined(QBDI_ARCH_X86_64)
    info["arch"] = "x86_64";
    info["bits"] = 64;
#elif defined(QBDI_ARCH_X86)
    info["arch"] = "x86";
    info["bits"] = 32;
#elif defined(QBDI_ARCH_ARM)
    info["arch"] = "arm";
    info["bits"] = 32;
#elif defined(QBDI_ARCH_AARCH64)
    info["arch"] = "aarch64";
    info["bits"] = 64;
#else
    info["arch"] = "unknown";
    info["bits"] = 0;
#endif

    return info;
  });

  logger.dbg("utility functions setup complete");
}

// === JSON Serialization Implementation ===

std::string escape_json_string(const std::string& str) {
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

bool is_lua_array(const sol::table& table) {
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

  // sort indices and check if they're consecutive starting from 1
  std::sort(indices.begin(), indices.end());
  for (size_t i = 0; i < indices.size(); i++) {
    if (indices[i] != static_cast<int>(i + 1)) {
      return false;
    }
  }

  return true;
}

static std::string serialize_lua_value(const sol::object& value, int depth) {
  // prevent infinite recursion
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
      return "null"; // json doesn't support NaN/Infinity
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
    return lua_table_to_json_internal(value.as<sol::table>(), depth + 1);
  } else {
    // fallback: try to convert to string
    try {
      std::string str_repr = value.as<std::string>();
      return escape_json_string(str_repr);
    } catch (...) {
      return "null";
    }
  }
}

static std::string lua_table_to_json_internal(const sol::table& lua_table, int depth) {
  try {
    // prevent infinite recursion
    if (depth > 32) {
      return "{\"error\":\"max_recursion_depth_exceeded\"}";
    }

    std::stringstream json_stream;

    if (is_lua_array(lua_table)) {
      // serialize as JSON array
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
      // serialize as JSON object
      json_stream << "{";
      bool first = true;

      for (const auto& pair : lua_table) {
        if (!first) {
          json_stream << ",";
        }

        // convert key to string
        std::string key;
        if (pair.first.is<std::string>()) {
          key = pair.first.as<std::string>();
        } else if (pair.first.is<int>()) {
          key = std::to_string(pair.first.as<int>());
        } else if (pair.first.is<double>()) {
          key = std::to_string(pair.first.as<double>());
        } else {
          // try to convert to string as fallback
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

std::string lua_table_to_json(const sol::table& lua_table) { return lua_table_to_json_internal(lua_table, 0); }

} // namespace w1::tracers::script::bindings