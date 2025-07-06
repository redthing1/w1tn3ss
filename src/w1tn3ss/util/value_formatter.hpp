#pragma once

#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace w1::util {

/**
 * @brief Utility class for formatting various types of values for display
 *
 * Provides consistent formatting for different data types commonly encountered
 * in dynamic analysis: pointers, strings, buffers, numbers, etc.
 */
class value_formatter {
public:
  // formatting options
  struct format_options {
    size_t max_string_length = 256;
    size_t max_buffer_preview = 16;
    bool show_hex_for_pointers = true;
    bool null_as_string = true; // show NULL instead of 0x0
    bool quote_strings = true;
    bool show_buffer_ascii = false; // show ASCII preview for buffers

    format_options()
        : max_string_length(256), max_buffer_preview(16), show_hex_for_pointers(true), null_as_string(true),
          quote_strings(true), show_buffer_ascii(false) {}
  };

  // format a raw pointer value
  static std::string format_pointer(uint64_t value, const format_options& opts = {});

  // format a string with proper escaping and length limits
  static std::string format_string(const std::string& str, const format_options& opts = {});
  static std::string format_string(const char* str, size_t max_len, const format_options& opts = {});

  // format a buffer/byte array
  static std::string format_buffer(const uint8_t* data, size_t size, const format_options& opts = {});
  static std::string format_buffer(const std::vector<uint8_t>& buffer, const format_options& opts = {});

  // format boolean values
  static std::string format_bool(bool value);

  // format error codes with optional description
  static std::string format_error_code(int64_t code, bool include_hex = true);

  // format file descriptors
  static std::string format_fd(int fd);

  // format memory sizes
  static std::string format_size(size_t size, bool human_readable = false);

  // generic value formatting using variant
  using value_variant = std::variant<
      std::monostate, // no value
      bool, int64_t, uint64_t, double, std::string, std::vector<uint8_t>>;

  static std::string format_value(const value_variant& value, const format_options& opts = {});

  // format with type hint for better output
  enum class value_type {
    UNKNOWN,
    POINTER,
    STRING,
    BUFFER,
    BOOLEAN,
    INTEGER,
    UNSIGNED,
    FLOAT,
    ERROR_CODE,
    FILE_DESCRIPTOR,
    SIZE
  };

  static std::string format_typed_value(uint64_t raw_value, value_type type, const format_options& opts = {});

private:
  // helper to escape special characters in strings
  static std::string escape_string(const std::string& str);

  // helper to check if buffer contains printable ASCII
  static bool is_printable_buffer(const uint8_t* data, size_t size);
};

/**
 * @brief Helper class for building formatted argument lists
 *
 * Useful for creating function call representations
 */
class argument_formatter {
public:
  argument_formatter() = default;

  // add formatted argument
  void add(const std::string& name, const std::string& value);
  void add(const std::string& value); // unnamed argument

  // add with automatic formatting
  void add_pointer(const std::string& name, uint64_t value);
  void add_string(const std::string& name, const std::string& value);
  void add_integer(const std::string& name, int64_t value);
  void add_unsigned(const std::string& name, uint64_t value);
  void add_bool(const std::string& name, bool value);

  // build final formatted string
  std::string build() const;

  // get as comma-separated list without parentheses
  std::string build_list() const;

private:
  std::vector<std::pair<std::string, std::string>> arguments_;
};

} // namespace w1::util