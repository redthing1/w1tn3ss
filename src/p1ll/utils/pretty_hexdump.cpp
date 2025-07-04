#include "pretty_hexdump.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>

namespace p1ll::utils {

namespace {

// color scheme for different element types
constexpr auto offset_color = redlog::color::bright_cyan;
constexpr auto unchanged_color = redlog::color::white;
constexpr auto before_change_color = redlog::color::cyan;
constexpr auto after_change_color = redlog::color::red;
constexpr auto signature_match_color = redlog::color::bright_green;
constexpr auto context_color = redlog::color::bright_black;
constexpr auto ascii_color = redlog::color::bright_black;

/**
 * format a single hex byte with optional color.
 */
std::string format_hex_byte(uint8_t byte, redlog::color color = redlog::color::none) {
  std::ostringstream oss;
  oss << std::hex << std::setw(2) << std::setfill('0') << std::nouppercase << static_cast<int>(byte);
  return redlog::detail::colorize(oss.str(), color);
}

/**
 * format a printable ascii character with optional color.
 */
std::string format_ascii_char(uint8_t byte, redlog::color color = redlog::color::none) {
  char c = (byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.';
  return redlog::detail::colorize(std::string(1, c), color);
}

/**
 * format an address offset with consistent width and color.
 */
std::string format_offset(uint64_t offset) {
  std::ostringstream oss;
  oss << std::hex << std::setw(8) << std::setfill('0') << std::nouppercase << offset << ":";
  return redlog::detail::colorize(oss.str(), offset_color);
}

/**
 * detect which bytes differ between two arrays.
 */
std::vector<bool> find_byte_differences(const uint8_t* a, const uint8_t* b, size_t size) {
  std::vector<bool> differences(size);
  for (size_t i = 0; i < size; ++i) {
    differences[i] = (a[i] != b[i]);
  }
  return differences;
}

/**
 * format a line of hex bytes with optional highlighting.
 */
std::string format_hex_line(
    const uint8_t* data, size_t line_size, size_t bytes_per_line, const std::vector<bool>& highlight_mask = {},
    redlog::color highlight_color = redlog::color::none
) {
  std::ostringstream oss;

  for (size_t i = 0; i < bytes_per_line; ++i) {
    if (i > 0) {
      oss << " ";
    }

    if (i < line_size) {
      redlog::color color = unchanged_color;
      if (!highlight_mask.empty() && i < highlight_mask.size() && highlight_mask[i]) {
        color = highlight_color;
      }
      oss << format_hex_byte(data[i], color);
    } else {
      // padding for incomplete lines
      oss << "  ";
    }

    // add extra space every 8 bytes for readability
    if (i == 7) {
      oss << " ";
    }
  }

  return oss.str();
}

/**
 * format ascii representation of a line with optional highlighting.
 */
std::string format_ascii_line(
    const uint8_t* data, size_t line_size, const std::vector<bool>& highlight_mask = {},
    redlog::color highlight_color = redlog::color::none
) {
  std::ostringstream oss;
  oss << "|";

  for (size_t i = 0; i < line_size; ++i) {
    redlog::color color = ascii_color;
    if (!highlight_mask.empty() && i < highlight_mask.size() && highlight_mask[i]) {
      color = highlight_color;
    }
    oss << format_ascii_char(data[i], color);
  }

  oss << "|";
  return oss.str();
}

} // anonymous namespace

std::string format_hexdump(const uint8_t* data, size_t size, uint64_t base_offset, const hexdump_options& opts) {
  if (!data || size == 0) {
    return "";
  }

  std::ostringstream result;
  size_t lines_shown = 0;

  for (size_t offset = 0; offset < size; offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated, " << (size - offset) << " more bytes)\n";
      break;
    }

    size_t line_size = std::min(opts.bytes_per_line, size - offset);
    uint64_t display_offset = base_offset + offset;

    result << format_offset(display_offset) << "  ";
    result << format_hex_line(data + offset, line_size, opts.bytes_per_line);

    if (opts.show_ascii) {
      result << "  " << format_ascii_line(data + offset, line_size);
    }

    result << "\n";
    lines_shown++;
  }

  return result.str();
}

std::string format_patch_hexdump(
    const uint8_t* before_data, const uint8_t* after_data, size_t size, uint64_t base_offset,
    const hexdump_options& opts
) {
  if (!before_data || !after_data || size == 0) {
    return "";
  }

  std::ostringstream result;
  size_t lines_shown = 0;
  auto differences = find_byte_differences(before_data, after_data, size);

  for (size_t offset = 0; offset < size; offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated, " << (size - offset) << " more bytes)\n";
      break;
    }

    size_t line_size = std::min(opts.bytes_per_line, size - offset);
    uint64_t display_offset = base_offset + offset;

    // extract difference mask for this line
    std::vector<bool> line_differences(differences.begin() + offset, differences.begin() + offset + line_size);

    // before line
    result << format_offset(display_offset) << "  before: ";
    result << format_hex_line(
        before_data + offset, line_size, opts.bytes_per_line, line_differences, before_change_color
    );

    if (opts.show_ascii) {
      result << "  " << format_ascii_line(before_data + offset, line_size, line_differences, before_change_color);
    }
    result << "\n";

    // after line
    result << "           after:  ";
    result << format_hex_line(
        after_data + offset, line_size, opts.bytes_per_line, line_differences, after_change_color
    );

    if (opts.show_ascii) {
      result << "  " << format_ascii_line(after_data + offset, line_size, line_differences, after_change_color);
    }
    result << "\n\n";

    lines_shown++;
  }

  return result.str();
}

std::string format_signature_match_hexdump(
    const uint8_t* data, size_t data_size, size_t match_offset, size_t pattern_size, uint64_t base_offset,
    const hexdump_options& opts
) {
  if (!data || data_size == 0 || match_offset >= data_size) {
    return "";
  }

  // calculate context boundaries
  size_t context_start = (match_offset >= opts.context_bytes) ? match_offset - opts.context_bytes : 0;
  size_t context_end = std::min(data_size, match_offset + pattern_size + opts.context_bytes);
  size_t total_size = context_end - context_start;

  std::ostringstream result;
  size_t lines_shown = 0;

  for (size_t offset = context_start; offset < context_end; offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated)\n";
      break;
    }

    size_t line_size = std::min(opts.bytes_per_line, context_end - offset);
    uint64_t display_offset = base_offset + offset;

    // create highlight mask for matched bytes in this line
    std::vector<bool> highlight_mask(line_size, false);

    for (size_t i = 0; i < line_size; ++i) {
      size_t absolute_pos = offset + i;
      if (absolute_pos >= match_offset && absolute_pos < match_offset + pattern_size) {
        highlight_mask[i] = true;
      }
    }

    result << format_offset(display_offset) << "  ";
    result << format_hex_line(data + offset, line_size, opts.bytes_per_line, highlight_mask, signature_match_color);

    if (opts.show_ascii) {
      result << "  " << format_ascii_line(data + offset, line_size, highlight_mask, signature_match_color);
    }

    result << "\n";
    lines_shown++;
  }

  return result.str();
}

std::string format_patch_hexdump(
    const std::vector<uint8_t>& before, const std::vector<uint8_t>& after, uint64_t base_offset,
    const hexdump_options& opts
) {
  if (before.size() != after.size()) {
    return "error: before and after vectors must be same size\n";
  }

  return format_patch_hexdump(before.data(), after.data(), before.size(), base_offset, opts);
}

std::string format_hexdump(const std::vector<uint8_t>& data, uint64_t base_offset, const hexdump_options& opts) {
  return format_hexdump(data.data(), data.size(), base_offset, opts);
}

} // namespace p1ll::utils