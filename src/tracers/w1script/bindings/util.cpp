#include "util.hpp"

#include <w1common/platform_utils.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

constexpr char hex_digits[] = "0123456789abcdef";

std::string format_integer_hex(uint64_t value, size_t width) {
  std::string hex;
  if (value == 0) {
    hex = "0";
  } else {
    while (value > 0) {
      hex.push_back(hex_digits[value & 0xF]);
      value >>= 4;
    }
    std::reverse(hex.begin(), hex.end());
  }

  if (hex.size() < width) {
    hex.insert(hex.begin(), width - hex.size(), '0');
  }

  return hex;
}

std::string escape_json(const std::string& input) {
  std::string out;
  out.reserve(input.size() + 2);
  out.push_back('"');

  for (char ch : input) {
    switch (ch) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\b':
      out += "\\b";
      break;
    case '\f':
      out += "\\f";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (static_cast<unsigned char>(ch) < 0x20) {
        std::ostringstream oss;
        oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (static_cast<int>(ch) & 0xFF);
        out += oss.str();
      } else {
        out.push_back(ch);
      }
      break;
    }
  }

  out.push_back('"');
  return out;
}

bool is_array_table(const sol::table& table, size_t& length) {
  length = 0;
  size_t max_index = 0;
  size_t count = 0;

  for (const auto& pair : table) {
    sol::object key = pair.first;
    if (!key.is<int>()) {
      return false;
    }

    int index = key.as<int>();
    if (index <= 0) {
      return false;
    }

    max_index = std::max(max_index, static_cast<size_t>(index));
    ++count;
  }

  if (count == 0) {
    length = 0;
    return true;
  }

  if (max_index != count) {
    return false;
  }

  length = max_index;
  return true;
}

std::string lua_value_to_json(const sol::object& value, int depth);

std::string lua_table_to_json_internal(const sol::table& table, int depth) {
  if (depth > 8) {
    return "null";
  }

  size_t length = 0;
  if (is_array_table(table, length)) {
    std::string out = "[";
    for (size_t i = 1; i <= length; ++i) {
      sol::object item = table[i];
      if (i > 1) {
        out += ',';
      }
      out += lua_value_to_json(item, depth + 1);
    }
    out += "]";
    return out;
  }

  std::string out = "{";
  bool first = true;
  for (const auto& pair : table) {
    sol::object key = pair.first;
    sol::object val = pair.second;

    std::string key_str;
    if (key.is<std::string>()) {
      key_str = key.as<std::string>();
    } else if (key.is<int>()) {
      key_str = std::to_string(key.as<int>());
    } else {
      continue;
    }

    if (!first) {
      out += ',';
    }
    first = false;

    out += escape_json(key_str);
    out += ':';
    out += lua_value_to_json(val, depth + 1);
  }
  out += "}";
  return out;
}

std::string lua_value_to_json(const sol::object& value, int depth) {
  if (!value.valid() || value.get_type() == sol::type::nil) {
    return "null";
  }

  if (value.is<bool>()) {
    return value.as<bool>() ? "true" : "false";
  }

  if (value.is<lua_Number>()) {
    std::ostringstream oss;
    oss << std::setprecision(15) << value.as<lua_Number>();
    return oss.str();
  }

  if (value.is<std::string>()) {
    return escape_json(value.as<std::string>());
  }

  if (value.is<sol::table>()) {
    return lua_table_to_json_internal(value.as<sol::table>(), depth + 1);
  }

  return "null";
}

} // namespace

void setup_util_bindings(sol::state& lua, sol::table& w1_module, uint64_t thread_id) {
  sol::table util = lua.create_table();

  util.set_function("format_address", [](uint64_t address) -> std::string {
    size_t width = sizeof(uintptr_t) * 2;
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(static_cast<int>(width)) << std::setfill('0') << address;
    return oss.str();
  });

  util.set_function(
      "format_hex", [](sol::object value, sol::optional<sol::table> options) -> sol::optional<std::string> {
        size_t width = 0;
        bool prefix = false;

        if (options) {
          if (sol::optional<int64_t> opt_width = (*options)["width"]; opt_width && *opt_width > 0) {
            width = static_cast<size_t>(*opt_width);
          }
          if (sol::optional<bool> opt_prefix = (*options)["prefix"]; opt_prefix) {
            prefix = *opt_prefix;
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

        if (value.is<std::string>()) {
          const auto& str = value.as<const std::string&>();
          std::string hex;
          hex.reserve(str.size() * 2);
          for (unsigned char ch : str) {
            hex.push_back(hex_digits[ch >> 4]);
            hex.push_back(hex_digits[ch & 0x0F]);
          }
          if (prefix) {
            hex.insert(0, "0x");
          }
          return sol::optional<std::string>(std::move(hex));
        }

        if (value.is<sol::table>()) {
          sol::table table = value.as<sol::table>();
          std::string hex;
          for (size_t i = 1; i <= table.size(); ++i) {
            sol::optional<uint32_t> byte = table[i];
            if (!byte) {
              return sol::nullopt;
            }
            uint8_t b = static_cast<uint8_t>(*byte & 0xFF);
            hex.push_back(hex_digits[b >> 4]);
            hex.push_back(hex_digits[b & 0x0F]);
          }
          if (prefix) {
            hex.insert(0, "0x");
          }
          return sol::optional<std::string>(std::move(hex));
        }

        return sol::nullopt;
      }
  );

  util.set_function("thread_id", [thread_id]() { return thread_id; });
  util.set_function("platform", []() { return w1::common::platform_utils::get_platform_name(); });

  util.set_function("architecture", []() -> std::string {
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

  util.set_function("platform_info", [&lua]() -> sol::table {
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

  w1_module["util"] = util;
}

std::string lua_table_to_json(const sol::table& table) { return lua_table_to_json_internal(table, 0); }

} // namespace w1::tracers::script::bindings
