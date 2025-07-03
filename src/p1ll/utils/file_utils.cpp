#include "file_utils.hpp"
#include <fstream>
#include <filesystem>
#include <iterator>

namespace p1ll::utils {

std::optional<std::vector<uint8_t>> read_file(const std::string& file_path) {
  std::ifstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    return std::nullopt;
  }

  std::vector<uint8_t> data;
  data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  return data;
}

std::optional<std::string> read_file_string(const std::string& file_path) {
  std::ifstream file(file_path);
  if (!file.is_open()) {
    return std::nullopt;
  }

  std::string content;
  content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
  return content;
}

bool write_file(const std::string& file_path, const std::vector<uint8_t>& data) {
  std::ofstream file(file_path, std::ios::binary);
  if (!file.is_open()) {
    return false;
  }

  file.write(reinterpret_cast<const char*>(data.data()), data.size());
  return file.good();
}

bool write_file(const std::string& file_path, const std::string& data) {
  std::ofstream file(file_path);
  if (!file.is_open()) {
    return false;
  }

  file << data;
  return file.good();
}

bool file_exists(const std::string& file_path) { return std::filesystem::exists(file_path); }

std::optional<size_t> get_file_size(const std::string& file_path) {
  std::error_code ec;
  auto size = std::filesystem::file_size(file_path, ec);
  if (ec) {
    return std::nullopt;
  }
  return size;
}

} // namespace p1ll::utils