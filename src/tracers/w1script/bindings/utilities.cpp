#include "utilities.hpp"
#include <w1common/platform_utils.hpp>
#include <w1tn3ss/util/jsonl_writer.hpp>
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
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#else
    return "unknown";
#endif
  });

  w1_module.set_function("get_platform_info", [&lua]() -> sol::table {
    sol::table info = lua.create_table();

    info["os"] = w1::common::platform_utils::get_platform_name();

#if defined(__x86_64__) || defined(_M_X64)
    info["arch"] = "x86_64";
    info["bits"] = 64;
#elif defined(__i386__) || defined(_M_IX86)
    info["arch"] = "x86";
    info["bits"] = 32;
#elif defined(__arm__) || defined(_M_ARM)
    info["arch"] = "arm";
    info["bits"] = 32;
#elif defined(__aarch64__) || defined(_M_ARM64)
    info["arch"] = "aarch64";
    info["bits"] = 64;
#else
    info["arch"] = "unknown";
    info["bits"] = 0;
#endif

    return info;
  });

  // === JSONL Writer Functions ===
  // streaming JSONL output for high-performance data collection

  // store the jsonl writer instance as a shared pointer in the lua state
  // this allows us to manage its lifetime properly
  static std::shared_ptr<w1::util::jsonl_writer> jsonl_writer_instance;

  // define a function to load w1.output module after w1 is available
  w1_module.set_function("_init_output_module", [&lua]() {
    lua.script(R"lua(
    -- w1.output module implemented in pure Lua
    w1.output = {}
    local _initialized = false
    local _event_count = 0
    
    function w1.output.init(filename, metadata)
      filename = filename or "trace.jsonl"
      
      if w1.jsonl_is_open() then
        w1.jsonl_close()
      end
      
      if not w1.jsonl_open(filename) then
        w1.log_error("failed to initialize output file: " .. filename)
        return false
      end
      
      metadata = metadata or {}
      metadata.type = "metadata"
      metadata.version = metadata.version or "1.0"
      metadata.timestamp = metadata.timestamp or w1.get_timestamp()
      metadata.tracer = metadata.tracer or "w1script"
      
      if not w1.jsonl_write(metadata) then
        w1.log_error("failed to write metadata")
        w1.jsonl_close()
        return false
      end
      
      _initialized = true
      _event_count = 0
      w1.log_info("output initialized: " .. filename)
      return true
    end
    
    function w1.output.write_event(event)
      if not _initialized then
        w1.log_error("output not initialized - call w1.output.init() first")
        return false
      end
      
      if type(event) ~= "table" then
        w1.log_error("event must be a table")
        return false
      end
      
      event.type = event.type or "event"
      
      local success = w1.jsonl_write(event)
      if success then
        _event_count = _event_count + 1
        if _event_count % 10000 == 0 then
          w1.jsonl_flush()
        end
      end
      return success
    end
    
    function w1.output.close()
      if not _initialized then
        return
      end
      
      if _event_count > 0 then
        w1.jsonl_write({
          type = "summary",
          event_count = _event_count,
          end_timestamp = w1.get_timestamp()
        })
      end
      
      w1.jsonl_close()
      _initialized = false
      w1.log_info("output closed with " .. _event_count .. " events")
    end
    
    function w1.output.ensure_shutdown_handler(tracer)
      local original_shutdown = tracer.shutdown
      tracer.shutdown = function()
        if original_shutdown then
          original_shutdown()
        end
        w1.output.close()
      end
    end
  )lua");
  });

  w1_module.set_function("jsonl_open", [](const std::string& filename) -> bool {
    try {
      // close any existing writer
      if (jsonl_writer_instance && jsonl_writer_instance->is_open()) {
        jsonl_writer_instance->close();
      }

      // create new writer instance
      jsonl_writer_instance = std::make_shared<w1::util::jsonl_writer>(filename);

      if (!jsonl_writer_instance->is_open()) {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("failed to open jsonl file: " + filename);
        jsonl_writer_instance.reset();
        return false;
      }

      return true;
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("jsonl_open error: " + std::string(e.what()));
      return false;
    }
  });

  w1_module.set_function("jsonl_write", [](const sol::object& data) -> bool {
    if (!jsonl_writer_instance || !jsonl_writer_instance->is_open()) {
      return false;
    }

    try {
      std::string json_line;

      // handle different input types
      if (data.is<sol::table>()) {
        json_line = lua_table_to_json(data.as<sol::table>());
      } else if (data.is<std::string>()) {
        // assume it's already json if it's a string
        json_line = data.as<std::string>();
      } else {
        // try to serialize as a simple value
        json_line = serialize_lua_value(data);
      }

      return jsonl_writer_instance->write_line(json_line);
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("jsonl_write error: " + std::string(e.what()));
      return false;
    }
  });

  w1_module.set_function("jsonl_close", []() {
    if (jsonl_writer_instance && jsonl_writer_instance->is_open()) {
      jsonl_writer_instance->close();
    }
    jsonl_writer_instance.reset();
  });

  w1_module.set_function("jsonl_is_open", []() -> bool {
    return jsonl_writer_instance && jsonl_writer_instance->is_open();
  });

  w1_module.set_function("jsonl_flush", []() {
    if (jsonl_writer_instance && jsonl_writer_instance->is_open()) {
      jsonl_writer_instance->flush();
    }
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