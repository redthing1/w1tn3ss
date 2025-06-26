/**
 * @file utils.hpp
 * @brief Utility functions for the w1tn3ss framework
 * 
 * This module provides common utility functions that can be used
 * across the framework and tracers.
 */

#pragma once

#include <string>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace w1::framework::utils {

/**
 * @brief Format a number with thousands separators
 * @param number The number to format
 * @return Formatted string with commas (e.g., "1,234,567")
 */
inline std::string format_number(uint64_t number) {
    std::string result = std::to_string(number);
    std::string formatted;
    int count = 0;
    for (int i = result.length() - 1; i >= 0; --i) {
        if (count && count % 3 == 0) {
            formatted = ',' + formatted;
        }
        formatted = result[i] + formatted;
        count++;
    }
    return formatted;
}

/**
 * @brief Format a 64-bit value as a hex string
 * @param value The value to format
 * @return Formatted hex string (e.g., "0x00000001028b0000")
 */
inline std::string format_hex(uint64_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(16) << value;
    return oss.str();
}

/**
 * @brief Format a 32-bit value as a hex string
 * @param value The value to format
 * @return Formatted hex string (e.g., "0x12345678")
 */
inline std::string format_hex32(uint32_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(8) << value;
    return oss.str();
}

/**
 * @brief Format bytes as a human-readable size
 * @param bytes The number of bytes
 * @return Formatted string (e.g., "1.2 MB", "512 KB")
 */
inline std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double size = static_cast<double>(bytes);
    int unit = 0;
    
    while (size >= 1024.0 && unit < 4) {
        size /= 1024.0;
        unit++;
    }
    
    std::ostringstream oss;
    if (unit == 0) {
        oss << bytes << " " << units[unit];
    } else {
        oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    }
    return oss.str();
}

} // namespace w1::framework::utils