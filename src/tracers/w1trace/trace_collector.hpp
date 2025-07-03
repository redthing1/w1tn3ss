#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <memory>
#include <redlog.hpp>

namespace w1trace {

class trace_collector {
public:
  explicit trace_collector(const std::string& output_file, size_t buffer_size);
  ~trace_collector();

  void add_instruction_address(uint64_t address);
  void flush();
  void shutdown();

  size_t get_instruction_count() const { return instruction_count_; }
  size_t get_flush_count() const { return flush_count_; }
  size_t get_buffer_usage() const { return buffer_pos_; }

private:
  void flush_buffer();
  void ensure_output_file();

  std::string output_file_;
  size_t buffer_size_;
  std::unique_ptr<char[]> buffer_;
  size_t buffer_pos_;
  size_t instruction_count_;
  size_t flush_count_;
  std::ofstream output_stream_;
  redlog::logger log_;
  bool shutdown_called_;
};

} // namespace w1trace