#include "file_image_reader.hpp"

#include <limits>

namespace w1replay {

file_image_reader::file_image_reader(std::string path, uint64_t file_size)
    : path_(std::move(path)), file_size_(file_size) {}

bool file_image_reader::read(uint64_t offset, std::span<std::byte> out, std::string& error) {
  if (out.empty()) {
    return true;
  }
  if (offset > file_size_ || out.size() > file_size_ - offset) {
    error = "image read out of bounds";
    return false;
  }
  if (offset > static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
      out.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
    error = "image read exceeds host limits";
    return false;
  }

  std::lock_guard<std::mutex> lock(mutex_);
  if (!ensure_open(error)) {
    return false;
  }

  stream_.clear();
  stream_.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
  if (!stream_.good()) {
    error = "image read failed";
    return false;
  }
  stream_.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
  if (static_cast<size_t>(stream_.gcount()) != out.size()) {
    error = "image read short";
    return false;
  }
  return true;
}

bool file_image_reader::ensure_open(std::string& error) {
  if (opened_) {
    return true;
  }
  stream_.open(path_, std::ios::binary | std::ios::in);
  if (!stream_.is_open()) {
    error = "failed to open image: " + path_;
    return false;
  }
  opened_ = true;
  return true;
}

bool read_file_size(const std::string& path, uint64_t& out, std::string& error) {
  error.clear();
  std::ifstream in(path, std::ios::binary | std::ios::in);
  if (!in.is_open()) {
    error = "failed to open image: " + path;
    return false;
  }
  in.seekg(0, std::ios::end);
  auto end_pos = in.tellg();
  if (end_pos <= 0) {
    error = "image size unavailable";
    return false;
  }
  out = static_cast<uint64_t>(end_pos);
  if (out == 0) {
    error = "image size empty";
    return false;
  }
  return true;
}

} // namespace w1replay
