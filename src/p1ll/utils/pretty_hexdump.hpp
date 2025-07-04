#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace p1ll::utils {

/**
 * options for controlling hexdump formatting and appearance.
 */
struct hexdump_options {
  size_t bytes_per_line = 16; // number of bytes to display per line
  bool show_ascii = true;     // include ascii representation column
  bool show_offset = true;    // include offset column
  size_t context_bytes = 8;   // context bytes for signature matches
  size_t max_lines = 32;      // maximum lines to display (prevents spam)
};

/**
 * create a beautiful hexdump of memory data.
 * respects redlog color settings and produces clean, aligned output.
 *
 * @param data pointer to data to dump
 * @param size number of bytes to dump
 * @param base_offset base address offset for display
 * @param opts formatting options
 * @return formatted hexdump string
 */
std::string format_hexdump(
    const uint8_t* data, size_t size, uint64_t base_offset = 0, const hexdump_options& opts = {}
);

/**
 * create a side-by-side patch comparison hexdump showing before/after changes.
 * changed bytes are color-coded: before in cyan, after in red.
 * unchanged bytes remain in default color.
 *
 * @param before_data original data
 * @param after_data patched data
 * @param size number of bytes to compare
 * @param base_offset base address offset for display
 * @param opts formatting options
 * @return formatted side-by-side comparison string
 */
std::string format_patch_hexdump(
    const uint8_t* before_data, const uint8_t* after_data, size_t size, uint64_t base_offset = 0,
    const hexdump_options& opts = {}
);

/**
 * create a signature match hexdump highlighting the matched pattern.
 * matched bytes are highlighted in green with surrounding context in gray.
 *
 * @param data memory data containing the match
 * @param data_size total size of data buffer
 * @param match_offset offset where pattern was found
 * @param pattern_size size of matched pattern
 * @param base_offset base address offset for display
 * @param opts formatting options
 * @return formatted signature match visualization
 */
std::string format_signature_match_hexdump(
    const uint8_t* data, size_t data_size, size_t match_offset, size_t pattern_size, uint64_t base_offset = 0,
    const hexdump_options& opts = {}
);

/**
 * convenience function to create a patch comparison for vectors.
 */
std::string format_patch_hexdump(
    const std::vector<uint8_t>& before, const std::vector<uint8_t>& after, uint64_t base_offset = 0,
    const hexdump_options& opts = {}
);

/**
 * convenience function to create a hexdump for a vector.
 */
std::string format_hexdump(
    const std::vector<uint8_t>& data, uint64_t base_offset = 0, const hexdump_options& opts = {}
);

} // namespace p1ll::utils