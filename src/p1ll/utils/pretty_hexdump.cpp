#include "pretty_hexdump.hpp"
#include <redlog.hpp>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>

namespace p1ll::utils {

namespace {

// color scheme for different element types
constexpr auto offset_color = redlog::color::bright_black;
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
  oss << std::hex << std::setw(16) << std::setfill('0') << std::nouppercase << offset << ":";
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

  // calculate 16-byte aligned boundaries
  uint64_t aligned_start = base_offset & ~0xF;
  uint64_t aligned_end = (base_offset + size + 15) & ~0xF;

  // calculate padding at start and end
  size_t start_padding = base_offset - aligned_start;
  size_t total_aligned_size = aligned_end - aligned_start;

  for (size_t aligned_offset = 0; aligned_offset < total_aligned_size; aligned_offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated, " << (total_aligned_size - aligned_offset) << " more bytes)\n";
      break;
    }

    uint64_t display_offset = aligned_start + aligned_offset;
    result << format_offset(display_offset) << "  ";

    // format hex bytes for this line
    for (size_t i = 0; i < opts.bytes_per_line; ++i) {
      if (i > 0) {
        result << " ";
      }
      if (i == 8) {
        result << " "; // extra space after 8 bytes
      }

      size_t data_pos = aligned_offset + i;
      if (data_pos < start_padding || data_pos >= start_padding + size) {
        // padding byte
        result << "  ";
      } else {
        // actual data byte
        size_t data_index = data_pos - start_padding;
        result << format_hex_byte(data[data_index], unchanged_color);
      }
    }

    if (opts.show_ascii) {
      result << "  |";
      for (size_t i = 0; i < opts.bytes_per_line; ++i) {
        size_t data_pos = aligned_offset + i;
        if (data_pos < start_padding || data_pos >= start_padding + size) {
          // padding byte
          result << " ";
        } else {
          // actual data byte
          size_t data_index = data_pos - start_padding;
          result << format_ascii_char(data[data_index], ascii_color);
        }
      }
      result << "|";
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

  // find differences in the actual data
  auto differences = find_byte_differences(before_data, after_data, size);

  // iterate through data, showing full 16-byte aligned rows
  for (size_t offset = 0; offset < size; offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated)\n";
      break;
    }

    size_t line_size = std::min(opts.bytes_per_line, size - offset);
    uint64_t display_offset = base_offset + offset;

    // before line
    result << format_offset(display_offset) << "  ";

    // format hex bytes for this line
    for (size_t i = 0; i < opts.bytes_per_line; ++i) {
      if (i > 0) {
        result << " ";
      }
      if (i == 8) {
        result << " "; // extra space after 8 bytes
      }

      if (i < line_size) {
        // actual data byte
        bool is_different = differences[offset + i];
        redlog::color color = is_different ? before_change_color : unchanged_color;
        result << format_hex_byte(before_data[offset + i], color);
      } else {
        // padding for incomplete line
        result << "  ";
      }
    }

    if (opts.show_ascii) {
      result << "  |";
      for (size_t i = 0; i < opts.bytes_per_line; ++i) {
        if (i < line_size) {
          // actual data byte
          bool is_different = differences[offset + i];
          redlog::color color = is_different ? before_change_color : ascii_color;
          result << format_ascii_char(before_data[offset + i], color);
        } else {
          // padding for incomplete line
          result << " ";
        }
      }
      result << "|";
    }
    result << "\n";

    // after line - same offset, no label for clean alignment
    result << format_offset(display_offset) << "  ";

    // format hex bytes for this line
    for (size_t i = 0; i < opts.bytes_per_line; ++i) {
      if (i > 0) {
        result << " ";
      }
      if (i == 8) {
        result << " "; // extra space after 8 bytes
      }

      if (i < line_size) {
        // actual data byte
        bool is_different = differences[offset + i];
        redlog::color color = is_different ? after_change_color : unchanged_color;
        result << format_hex_byte(after_data[offset + i], color);
      } else {
        // padding for incomplete line
        result << "  ";
      }
    }

    if (opts.show_ascii) {
      result << "  |";
      for (size_t i = 0; i < opts.bytes_per_line; ++i) {
        if (i < line_size) {
          // actual data byte
          bool is_different = differences[offset + i];
          redlog::color color = is_different ? after_change_color : ascii_color;
          result << format_ascii_char(after_data[offset + i], color);
        } else {
          // padding for incomplete line
          result << " ";
        }
      }
      result << "|";
    }
    result << "\n";

    lines_shown++;
  }

  std::string output = result.str();
  // remove trailing newline since logging will add one
  if (!output.empty() && output.back() == '\n') {
    output.pop_back();
  }
  return output;
}

std::string format_signature_match_hexdump(
    const uint8_t* data, size_t data_size, size_t match_offset, size_t pattern_size, uint64_t base_offset,
    const hexdump_options& opts
) {
  if (!data || data_size == 0 || match_offset >= data_size) {
    return "";
  }

  // calculate context boundaries with alignment
  size_t context_start = (match_offset >= opts.context_bytes) ? match_offset - opts.context_bytes : 0;
  size_t context_end = std::min(data_size, match_offset + pattern_size + opts.context_bytes);

  // align context boundaries to 16-byte boundaries
  size_t aligned_start = context_start & ~0xF;
  size_t aligned_end = (context_end + 15) & ~0xF;

  // ensure we don't go past data boundaries
  if (aligned_end > data_size) {
    aligned_end = data_size;
  }

  std::ostringstream result;
  size_t lines_shown = 0;

  for (size_t offset = aligned_start; offset < aligned_end; offset += opts.bytes_per_line) {
    if (lines_shown >= opts.max_lines) {
      result << "... (truncated)\n";
      break;
    }

    uint64_t display_offset = base_offset + offset;
    result << format_offset(display_offset) << "  ";

    // format hex bytes for this line
    for (size_t i = 0; i < opts.bytes_per_line; ++i) {
      if (i > 0) {
        result << " ";
      }
      if (i == 8) {
        result << " "; // extra space after 8 bytes
      }

      size_t absolute_pos = offset + i;
      if (absolute_pos >= data_size) {
        // past end of data
        result << "  ";
      } else {
        // determine if this byte is part of the match
        bool is_match = absolute_pos >= match_offset && absolute_pos < match_offset + pattern_size;
        redlog::color color = is_match ? signature_match_color : unchanged_color;
        result << format_hex_byte(data[absolute_pos], color);
      }
    }

    if (opts.show_ascii) {
      result << "  |";
      for (size_t i = 0; i < opts.bytes_per_line; ++i) {
        size_t absolute_pos = offset + i;
        if (absolute_pos >= data_size) {
          // past end of data
          result << " ";
        } else {
          // determine if this byte is part of the match
          bool is_match = absolute_pos >= match_offset && absolute_pos < match_offset + pattern_size;
          redlog::color color = is_match ? signature_match_color : ascii_color;
          result << format_ascii_char(data[absolute_pos], color);
        }
      }
      result << "|";
    }

    result << "\n";
    lines_shown++;
  }

  return result.str();
}

std::string format_signature_pattern(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask) {
  if (bytes.size() != mask.size()) {
    return "invalid signature pattern";
  }

  std::ostringstream oss;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      oss << " ";
    }
    if (mask[i]) {
      oss << format_hex_byte(bytes[i], signature_match_color);
    } else {
      oss << redlog::detail::colorize("??", context_color);
    }
  }

  return oss.str();
}

std::string format_patch_pattern(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask) {
  if (bytes.size() != mask.size()) {
    return "invalid patch pattern";
  }

  std::ostringstream oss;
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      oss << " ";
    }
    if (mask[i]) {
      oss << format_hex_byte(bytes[i], after_change_color);
    } else {
      oss << redlog::detail::colorize("??", context_color);
    }
  }

  return oss.str();
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
