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
#include <iostream>
#include <iterator>
#include <ctime>
#include <array>
#include <cctype>

namespace w1::tracers::script::bindings {

namespace {

constexpr char HEX_DIGITS[] = "0123456789abcdef";

std::string format_integer_hex(uint64_t value, size_t width) {
  std::string hex;
  if (value == 0) {
    hex = "0";
  } else {
    while (value > 0) {
      hex.push_back(HEX_DIGITS[value & 0xF]);
      value >>= 4;
    }
    std::reverse(hex.begin(), hex.end());
  }

  if (hex.size() < width) {
    hex.insert(hex.begin(), width - hex.size(), '0');
  }

  return hex;
}

bool extract_bytes(const sol::object& data_obj, std::vector<uint8_t>& out) {
  if (data_obj.get_type() == sol::type::string) {
    const std::string& str = data_obj.as<const std::string&>();
    out.assign(str.begin(), str.end());
    return true;
  }

  if (data_obj.get_type() == sol::type::table) {
    sol::table table = data_obj.as<sol::table>();
    out.clear();
    out.reserve(table.size());

    for (size_t i = 1; i <= table.size(); ++i) {
      sol::optional<uint32_t> value = table[i];
      if (!value) {
        return false;
      }
      out.push_back(static_cast<uint8_t>(*value & 0xFF));
    }
    return true;
  }

  return false;
}

std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t group, const std::string& separator) {
  if (data.empty()) {
    return {};
  }

  std::string result;
  size_t separator_reserve = 0;
  if (group > 0) {
    size_t slots = (data.size() - 1) / group;
    if (!separator.empty()) {
      separator_reserve = slots * separator.size();
    } else {
      separator_reserve = slots;
    }
  }

  result.reserve(data.size() * 2 + separator_reserve);

  for (size_t i = 0; i < data.size(); ++i) {
    if (group > 0 && i > 0 && (i % group) == 0) {
      if (!separator.empty()) {
        result += separator;
      } else {
        result.push_back(' ');
      }
    }

    uint8_t byte = data[i];
    result.push_back(HEX_DIGITS[byte >> 4]);
    result.push_back(HEX_DIGITS[byte & 0x0F]);
  }

  return result;
}

size_t auto_address_width(uint64_t base, size_t length) {
  uint64_t last = length == 0 ? base : base + static_cast<uint64_t>(length - 1);
  size_t width = 1;
  while (last >= 16) {
    last >>= 4;
    ++width;
  }
  return std::clamp(width, static_cast<size_t>(4), static_cast<size_t>(16));
}

std::string build_hexdump(
    const std::vector<uint8_t>& data, size_t line_width, size_t group, bool show_ascii, uint64_t base,
    size_t address_width
) {
  if (data.empty()) {
    return {};
  }

  size_t effective_width = std::max<size_t>(1, line_width);
  std::ostringstream oss;
  oss << std::hex << std::nouppercase;

  size_t resolved_address_width = address_width == 0
                                      ? auto_address_width(base, data.size())
                                      : std::clamp(address_width, static_cast<size_t>(1), static_cast<size_t>(16));

  for (size_t offset = 0; offset < data.size(); offset += effective_width) {
    size_t chunk = std::min(effective_width, data.size() - offset);
    oss << std::setw(resolved_address_width) << std::setfill('0') << (base + offset) << "  ";
    oss << std::setfill(' ');

    for (size_t i = 0; i < effective_width; ++i) {
      if (i < chunk) {
        uint8_t byte = data[offset + i];
        oss << HEX_DIGITS[byte >> 4] << HEX_DIGITS[byte & 0x0F];
      } else {
        oss << "  ";
      }

      if (i + 1 < effective_width) {
        oss << ' ';
        if (group > 0 && ((i + 1) % group) == 0) {
          oss << ' ';
        }
      }
    }

    if (show_ascii) {
      oss << " |";
      for (size_t i = 0; i < chunk; ++i) {
        unsigned char c = data[offset + i];
        oss << (std::isprint(c) ? static_cast<char>(c) : '.');
      }
      for (size_t i = chunk; i < effective_width; ++i) {
        oss << ' ';
      }
      oss << '|';
    }

    if (offset + effective_width < data.size()) {
      oss << '\n';
    }
  }

  return oss.str();
}

} // namespace

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

  w1_module.set_function("read_file_text", [](const std::string& filename) -> sol::optional<std::string> {
    try {
      std::ifstream file(filename, std::ios::in | std::ios::binary);
      if (!file.is_open()) {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("failed to open file for reading: " + filename);
        return sol::nullopt;
      }

      std::ostringstream buffer;
      buffer << file.rdbuf();
      return buffer.str();
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("read_file_text error: " + std::string(e.what()));
      return sol::nullopt;
    }
  });

  w1_module.set_function("write_file_text", [](const std::string& filename, const std::string& content) -> bool {
    try {
      std::ofstream file(filename, std::ios::out | std::ios::binary);
      if (!file.is_open()) {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("failed to open file for writing: " + filename);
        return false;
      }

      file.write(content.data(), static_cast<std::streamsize>(content.size()));
      return file.good();
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("write_file_text error: " + std::string(e.what()));
      return false;
    }
  });

  w1_module.set_function("read_file_bytes", [&lua](const std::string& filename) -> sol::optional<sol::table> {
    try {
      std::ifstream file(filename, std::ios::binary);
      if (!file.is_open()) {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("failed to open file for binary read: " + filename);
        return sol::nullopt;
      }

      std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
      sol::table out = lua.create_table(static_cast<int>(buffer.size()));
      for (size_t i = 0; i < buffer.size(); ++i) {
        out[i + 1] = buffer[i];
      }
      return out;
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("read_file_bytes error: " + std::string(e.what()));
      return sol::nullopt;
    }
  });

  w1_module.set_function("write_file_bytes", [](const std::string& filename, sol::object data_obj) -> bool {
    try {
      std::vector<uint8_t> buffer;

      if (data_obj.is<std::string>()) {
        const std::string& str = data_obj.as<const std::string&>();
        buffer.assign(str.begin(), str.end());
      } else if (data_obj.is<sol::table>()) {
        sol::table data = data_obj.as<sol::table>();
        buffer.reserve(data.size());
        for (size_t i = 1; i <= data.size(); ++i) {
          sol::optional<uint32_t> value = data[i];
          if (!value) {
            continue;
          }
          buffer.push_back(static_cast<uint8_t>(*value & 0xFF));
        }
      } else {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("write_file_bytes expects table or string data");
        return false;
      }

      std::ofstream file(filename, std::ios::binary);
      if (!file.is_open()) {
        auto log = redlog::get_logger("w1.script_lua");
        log.err("failed to open file for binary write: " + filename);
        return false;
      }

      if (!buffer.empty()) {
        file.write(reinterpret_cast<const char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
      }
      return file.good();
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_lua");
      log.err("write_file_bytes error: " + std::string(e.what()));
      return false;
    }
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

  w1_module.set_function(
      "format_time",
      [](sol::optional<std::string> format, sol::optional<int64_t> timestamp_seconds,
         sol::optional<bool> use_local_time) -> std::string {
        const std::string& fmt = format.value_or("%Y-%m-%d %H:%M:%S");

        std::time_t time_value;
        if (timestamp_seconds) {
          time_value = static_cast<std::time_t>(*timestamp_seconds);
        } else {
          time_value = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        }

        std::tm time_info{};
        bool use_local = use_local_time.value_or(false);

#if defined(_WIN32)
        if (use_local) {
          localtime_s(&time_info, &time_value);
        } else {
          gmtime_s(&time_info, &time_value);
        }
#else
        if (use_local) {
          localtime_r(&time_value, &time_info);
        } else {
          gmtime_r(&time_value, &time_info);
        }
#endif

        std::array<char, 128> buffer{};
        if (std::strftime(buffer.data(), buffer.size(), fmt.c_str(), &time_info) == 0) {
          return std::string{};
        }

        return buffer.data();
      }
  );

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

  // === Formatting Helpers ===
  // turn numbers and buffers into lowercase hex

  w1_module.set_function(
      "format_hex", [](sol::object value, sol::optional<sol::table> options) -> sol::optional<std::string> {
        size_t width = 0;
        bool prefix = false;
        size_t group = 0;
        std::string separator;

        if (options) {
          if (sol::optional<int64_t> opt_width = (*options)["width"]; opt_width && *opt_width > 0) {
            width = static_cast<size_t>(*opt_width);
          }
          if (sol::optional<bool> opt_prefix = (*options)["prefix"]; opt_prefix) {
            prefix = *opt_prefix;
          }
          if (sol::optional<std::string> opt_sep = (*options)["separator"]; opt_sep) {
            separator = *opt_sep;
          }
          if (sol::optional<int64_t> opt_group = (*options)["group"]; opt_group && *opt_group > 0) {
            group = static_cast<size_t>(*opt_group);
          }
        }

        if (value.get_type() == sol::type::number) {
          lua_Integer iv = value.as<lua_Integer>();
          bool negative = iv < 0;
          uint64_t magnitude = negative ? static_cast<uint64_t>(-iv) : static_cast<uint64_t>(iv);
          std::string hex = format_integer_hex(magnitude, width);
          if (prefix) {
            hex.insert(0, "0x");
          }
          if (negative) {
            hex.insert(hex.begin(), '-');
          }
          return sol::optional<std::string>(std::move(hex));
        }

        std::vector<uint8_t> bytes;
        if (!extract_bytes(value, bytes)) {
          return sol::nullopt;
        }

        size_t effective_group = group;
        std::string effective_separator = separator;
        if (effective_group == 0 && !effective_separator.empty()) {
          effective_group = 1;
        }
        if (effective_group > 0 && effective_separator.empty()) {
          effective_separator = " ";
        }

        std::string hex = bytes_to_hex(bytes, effective_group, effective_separator);
        return sol::optional<std::string>(std::move(hex));
      }
  );

  w1_module.set_function(
      "hexdump", [](sol::object data, sol::optional<sol::table> options) -> sol::optional<std::string> {
        std::vector<uint8_t> bytes;
        if (!extract_bytes(data, bytes)) {
          return sol::nullopt;
        }

        size_t line_width = 16;
        size_t group = 8;
        bool show_ascii = true;
        uint64_t base = 0;
        size_t address_width = 0;

        if (options) {
          if (sol::optional<int64_t> opt_width = (*options)["width"]; opt_width && *opt_width > 0) {
            line_width = static_cast<size_t>(*opt_width);
          }
          if (sol::optional<int64_t> opt_group = (*options)["group"]; opt_group && *opt_group > 0) {
            group = static_cast<size_t>(*opt_group);
          }
          if (sol::optional<bool> opt_ascii = (*options)["ascii"]; opt_ascii) {
            show_ascii = *opt_ascii;
          }
          if (sol::optional<int64_t> opt_base = (*options)["base"]; opt_base) {
            base = static_cast<uint64_t>(std::max<int64_t>(0, *opt_base));
          }
          if (sol::optional<int64_t> opt_addr_width = (*options)["address_width"];
              opt_addr_width && *opt_addr_width > 0) {
            address_width = static_cast<size_t>(*opt_addr_width);
          }
        }

        std::string dump = build_hexdump(bytes, line_width, group, show_ascii, base, address_width);
        return sol::optional<std::string>(std::move(dump));
      }
  );

  w1_module.set_function("stdin_read_line", [](sol::optional<std::string> prompt) -> sol::optional<std::string> {
    if (prompt && !prompt->empty()) {
      std::cout << *prompt;
      std::cout.flush();
    }

    std::string line;
    if (!std::getline(std::cin, line)) {
      auto log = redlog::get_logger("w1.script_lua");
      log.wrn("stdin_read_line reached end of input");
      return sol::nullopt;
    }

    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    return line;
  });

  // === Platform Detection Functions ===
  // get platform and architecture information

  w1_module.set_function("get_platform", []() -> std::string {
    return w1::common::platform_utils::get_platform_name();
  });

  w1_module.set_function("get_architecture", []() -> std::string {
#if defined(__x86_64__) || defined(_M_X64)
    return "x64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#else
    return "unknown";
#endif
  });

  w1_module.set_function("get_platform_info", [&lua]() -> sol::table {
    sol::table info = lua.create_table();

    info["os"] = w1::common::platform_utils::get_platform_name();

#if defined(__x86_64__) || defined(_M_X64)
    info["arch"] = "x64";
    info["bits"] = 64;
#elif defined(__i386__) || defined(_M_IX86)
    info["arch"] = "x86";
    info["bits"] = 32;
#elif defined(__arm__) || defined(_M_ARM)
    info["arch"] = "arm";
    info["bits"] = 32;
#elif defined(__aarch64__) || defined(_M_ARM64)
    info["arch"] = "arm64";
    info["bits"] = 64;
#else
    info["arch"] = "unknown";
    info["bits"] = 0;
#endif

    return info;
  });

  // === JSONL Writer Functions ===
  // low-level jsonl functions for compatibility
  // note: prefer using w1.output module for high-level api

  static std::shared_ptr<w1::util::jsonl_writer> jsonl_writer_instance;

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
