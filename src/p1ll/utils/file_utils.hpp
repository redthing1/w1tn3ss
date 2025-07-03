#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace p1ll::utils {

// file reading/writing utilities
std::optional<std::vector<uint8_t>> read_file(const std::string& file_path);
std::optional<std::string> read_file_string(const std::string& file_path);
bool write_file(const std::string& file_path, const std::vector<uint8_t>& data);
bool write_file(const std::string& file_path, const std::string& data);

// file system utilities
bool file_exists(const std::string& file_path);
std::optional<size_t> get_file_size(const std::string& file_path);

} // namespace p1ll::utils