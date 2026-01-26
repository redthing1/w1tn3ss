#pragma once

#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>

#include "image_bytes.hpp"

namespace w1replay {

class file_image_reader final : public image_file_reader {
public:
  file_image_reader(std::string path, uint64_t file_size);

  bool read(uint64_t offset, std::span<std::byte> out, std::string& error) override;

  const std::string& path() const { return path_; }
  uint64_t file_size() const { return file_size_; }

private:
  bool ensure_open(std::string& error);

  std::string path_;
  uint64_t file_size_ = 0;
  std::ifstream stream_;
  bool opened_ = false;
  std::mutex mutex_{};
};

bool read_file_size(const std::string& path, uint64_t& out, std::string& error);

} // namespace w1replay
