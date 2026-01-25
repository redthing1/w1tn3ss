#pragma once

#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <redlog.hpp>

#include "w1rewind/format/trace_format.hpp"
#include "w1rewind/trace/record_sink.hpp"

namespace w1::rewind {

struct trace_file_writer_config {
  std::string path;
  redlog::logger log;
  trace_compression compression = trace_compression::none;
  uint32_t chunk_size = k_trace_chunk_bytes;
};

class trace_file_writer : public trace_record_sink {
public:
  explicit trace_file_writer(trace_file_writer_config config);
  ~trace_file_writer() override;

  bool open();
  void close();
  bool good() const override { return good_; }

  const std::string& path() const { return path_; }

  bool write_header(const trace_header& header) override;
  bool write_target_info(const target_info_record& record) override;
  bool write_target_environment(const target_environment_record& record) override;
  bool write_register_spec(const register_spec_record& record) override;
  bool write_module_table(const module_table_record& record) override;
  bool write_module_load(const module_load_record& record) override;
  bool write_module_unload(const module_unload_record& record) override;
  bool write_memory_map(const memory_map_record& record) override;
  bool write_thread_start(const thread_start_record& record) override;
  bool write_instruction(const instruction_record& record) override;
  bool write_block_definition(const block_definition_record& record) override;
  bool write_block_exec(const block_exec_record& record) override;
  bool write_register_deltas(const register_delta_record& record) override;
  bool write_register_bytes(const register_bytes_record& record) override;
  bool write_memory_access(const memory_access_record& record) override;
  bool write_snapshot(const snapshot_record& record) override;
  bool write_thread_end(const thread_end_record& record) override;
  void flush() override;

private:
  bool write_record(record_kind kind, uint16_t flags, const std::vector<uint8_t>& payload);
  bool flush_chunk_locked();
  void write_u16(uint16_t value);
  void write_u32(uint32_t value);
  void write_u64(uint64_t value);
  void write_bytes(const void* data, size_t size);
  void mark_failure();
  std::string make_default_path() const;

  trace_file_writer_config config_;
  std::ofstream stream_;
  std::string path_;
  bool good_ = false;
  bool header_written_ = false;
  std::vector<uint8_t> chunk_buffer_;
  std::vector<uint8_t> chunk_encoded_;
  std::mutex mutex_;
};

std::shared_ptr<trace_file_writer> make_trace_file_writer(trace_file_writer_config config);

} // namespace w1::rewind
