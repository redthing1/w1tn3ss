#pragma once

#include <fstream>
#include <string>
#include <vector>

#include <mach-o/fat.h>
#include <mach-o/loader.h>

namespace w1::import_insertion::backend::macos {

// extracted and refactored from tools/insert_dylib/main.cpp
class MachOProcessor {
private:
  std::fstream file_;
  bool weak_flag_;
  bool strip_codesig_;
  bool ask_mode_; // false = assume yes to all questions

  void zero_fill(std::streamoff offset, size_t len);
  void memory_move(std::streamoff dst, std::streamoff src, size_t len);

  template <typename T> T peek_at(std::streamoff pos);

  bool ask_user(const std::string& question);

  bool check_load_commands(
      struct mach_header* mh, size_t header_offset, size_t commands_offset, const std::string& dylib_path,
      std::streamoff* slice_size
  );

  bool process_fat_binary(const std::string& dylib_path, uint32_t magic);
  bool process_mach_o(const std::string& dylib_path, std::streamoff header_offset, std::streamoff* slice_size);

public:
  MachOProcessor(const std::string& filepath, bool weak, bool strip_codesig, bool ask);
  ~MachOProcessor();

  bool insert_dylib_load_command(const std::string& dylib_path);
};

} // namespace w1::import_insertion::backend::macos