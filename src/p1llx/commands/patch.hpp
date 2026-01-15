#pragma once

#include <string>

namespace p1llx::commands {

/**
 * @brief Apply manual hex patch to file
 *
 * @param address_str Address to patch (hex string)
 * @param replace_data Replacement hex bytes
 * @param input_file Path to input binary file
 * @param output_file Path to output binary file
 * @return 0 for success, 1 for failure
 */
int patch(
    const std::string& address_str, const std::string& replace_data, const std::string& input_file,
    const std::string& output_file
);

/**
 * @brief Apply signature-based patch to file
 *
 * @param signature_pattern Signature hex pattern
 * @param offset_str Offset from signature match (hex or decimal; empty means 0)
 * @param replace_data Replacement hex bytes
 * @param input_file Path to input binary file
 * @param output_file Path to output binary file
 * @param platform_override Optional platform override (e.g., "linux:x64", "darwin:arm64")
 * @return 0 for success, 1 for failure
 */
int patch_signature(
    const std::string& signature_pattern, const std::string& offset_str, const std::string& replace_data,
    const std::string& input_file, const std::string& output_file, const std::string& platform_override = ""
);

} // namespace p1llx::commands
