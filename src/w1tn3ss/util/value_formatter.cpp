#include "value_formatter.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>

namespace w1::util {

std::string value_formatter::format_pointer(uint64_t value, const format_options& opts) {
  if (value == 0 && opts.null_as_string) {
    return "NULL";
  }

  std::stringstream ss;
  if (opts.show_hex_for_pointers) {
    ss << "0x" << std::hex << value;
  } else {
    ss << value;
  }
  return ss.str();
}

std::string value_formatter::format_string(const std::string& str, const format_options& opts) {
  std::string result = str;

  // truncate if needed
  if (result.length() > opts.max_string_length) {
    result = result.substr(0, opts.max_string_length) + "...";
  }

  // escape special characters
  result = escape_string(result);

  // add quotes if requested
  if (opts.quote_strings) {
    result = "\"" + result + "\"";
  }

  return result;
}

std::string value_formatter::format_string(const char* str, size_t max_len, const format_options& opts) {
  if (!str) {
    return opts.null_as_string ? "NULL" : "0x0";
  }

  // safely get string length
  size_t len = 0;
  while (len < max_len && str[len] != '\0') {
    len++;
  }

  return format_string(std::string(str, len), opts);
}

std::string value_formatter::format_buffer(const uint8_t* data, size_t size, const format_options& opts) {
  if (!data || size == 0) {
    return "buffer[0]";
  }

  std::stringstream ss;
  ss << "buffer[" << size << "]:";

  // check if it might be a string
  if (opts.show_buffer_ascii && is_printable_buffer(data, size)) {
    ss << "\""
       << escape_string(std::string(reinterpret_cast<const char*>(data), std::min(size, opts.max_string_length)))
       << "\"";
  } else {
    // hex dump
    ss << "{";
    size_t preview_size = std::min(size, opts.max_buffer_preview);

    for (size_t i = 0; i < preview_size; ++i) {
      if (i > 0) {
        ss << " ";
      }
      ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }

    if (size > preview_size) {
      ss << "...";
    }
    ss << "}";
  }

  return ss.str();
}

std::string value_formatter::format_buffer(const std::vector<uint8_t>& buffer, const format_options& opts) {
  return format_buffer(buffer.data(), buffer.size(), opts);
}

std::string value_formatter::format_bool(bool value) { return value ? "true" : "false"; }

std::string value_formatter::format_error_code(int64_t code, bool include_hex) {
  std::stringstream ss;

  if (code == 0) {
    return "0 (success)";
  }

  if (include_hex && code != 0) {
    ss << "0x" << std::hex << code << " (" << std::dec << code << ")";
  } else {
    ss << code;
  }

  // could add errno string lookup here
  if (code == -1) {
    ss << " (error)";
  }

  return ss.str();
}

std::string value_formatter::format_fd(int fd) {
  if (fd < 0) {
    return std::to_string(fd) + " (invalid)";
  }

  switch (fd) {
  case 0:
    return "0 (stdin)";
  case 1:
    return "1 (stdout)";
  case 2:
    return "2 (stderr)";
  default:
    return std::to_string(fd);
  }
}

std::string value_formatter::format_size(size_t size, bool human_readable) {
  if (!human_readable) {
    return std::to_string(size);
  }

  const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  int unit_index = 0;
  double value = static_cast<double>(size);

  while (value >= 1024.0 && unit_index < 4) {
    value /= 1024.0;
    unit_index++;
  }

  std::stringstream ss;
  if (unit_index == 0) {
    ss << size << " " << units[0];
  } else {
    ss << std::fixed << std::setprecision(2) << value << " " << units[unit_index];
  }

  return ss.str();
}

std::string value_formatter::format_value(const value_variant& value, const format_options& opts) {
  return std::visit(
      [&opts](const auto& v) -> std::string {
        using T = std::decay_t<decltype(v)>;

        if constexpr (std::is_same_v<T, std::monostate>) {
          return "<no value>";
        } else if constexpr (std::is_same_v<T, bool>) {
          return format_bool(v);
        } else if constexpr (std::is_same_v<T, int64_t>) {
          return std::to_string(v);
        } else if constexpr (std::is_same_v<T, uint64_t>) {
          return std::to_string(v);
        } else if constexpr (std::is_same_v<T, double>) {
          return std::to_string(v);
        } else if constexpr (std::is_same_v<T, std::string>) {
          return format_string(v, opts);
        } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
          return format_buffer(v, opts);
        }
        return "<unknown>";
      },
      value
  );
}

std::string value_formatter::format_typed_value(uint64_t raw_value, value_type type, const format_options& opts) {
  switch (type) {
  case value_type::POINTER:
    return format_pointer(raw_value, opts);
  case value_type::BOOLEAN:
    return format_bool(raw_value != 0);
  case value_type::INTEGER:
    return std::to_string(static_cast<int64_t>(raw_value));
  case value_type::UNSIGNED:
    return std::to_string(raw_value);
  case value_type::ERROR_CODE:
    return format_error_code(static_cast<int64_t>(raw_value));
  case value_type::FILE_DESCRIPTOR:
    return format_fd(static_cast<int>(raw_value));
  case value_type::SIZE:
    return format_size(raw_value);
  default:
    // generic hex format
    std::stringstream ss;
    ss << "0x" << std::hex << raw_value;
    return ss.str();
  }
}

std::string value_formatter::escape_string(const std::string& str) {
  std::string result;
  result.reserve(str.length() + 10); // reserve extra space for escapes

  for (char c : str) {
    switch (c) {
    case '\n':
      result += "\\n";
      break;
    case '\r':
      result += "\\r";
      break;
    case '\t':
      result += "\\t";
      break;
    case '\\':
      result += "\\\\";
      break;
    case '"':
      result += "\\\"";
      break;
    case '\0':
      result += "\\0";
      break;
    default:
      if (std::isprint(static_cast<unsigned char>(c))) {
        result += c;
      } else {
        // non-printable as hex
        result += "\\x";
        result += "0123456789abcdef"[(c >> 4) & 0xF];
        result += "0123456789abcdef"[c & 0xF];
      }
      break;
    }
  }

  return result;
}

bool value_formatter::is_printable_buffer(const uint8_t* data, size_t size) {
  if (size == 0) {
    return false;
  }

  // check if buffer looks like a string
  size_t printable_count = 0;
  bool has_null = false;

  for (size_t i = 0; i < size && i < 64; ++i) { // check first 64 bytes
    if (data[i] == 0) {
      has_null = true;
      break;
    }
    if (std::isprint(static_cast<unsigned char>(data[i])) || data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
      printable_count++;
    }
  }

  // if 80% printable and has null terminator, likely a string
  return has_null && (printable_count * 100 / size > 80);
}

// argument_formatter implementation
void argument_formatter::add(const std::string& name, const std::string& value) {
  arguments_.emplace_back(name, value);
}

void argument_formatter::add(const std::string& value) { arguments_.emplace_back("", value); }

void argument_formatter::add_pointer(const std::string& name, uint64_t value) {
  add(name, value_formatter::format_pointer(value));
}

void argument_formatter::add_string(const std::string& name, const std::string& value) {
  add(name, value_formatter::format_string(value));
}

void argument_formatter::add_integer(const std::string& name, int64_t value) { add(name, std::to_string(value)); }

void argument_formatter::add_unsigned(const std::string& name, uint64_t value) { add(name, std::to_string(value)); }

void argument_formatter::add_bool(const std::string& name, bool value) {
  add(name, value_formatter::format_bool(value));
}

std::string argument_formatter::build() const { return "(" + build_list() + ")"; }

std::string argument_formatter::build_list() const {
  std::string result;

  for (size_t i = 0; i < arguments_.size(); ++i) {
    if (i > 0) {
      result += ", ";
    }

    const auto& [name, value] = arguments_[i];
    if (!name.empty()) {
      result += name + "=";
    }
    result += value;
  }

  return result;
}

} // namespace w1::util