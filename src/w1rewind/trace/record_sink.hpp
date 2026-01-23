#pragma once

#include "w1rewind/format/trace_format.hpp"

namespace w1::rewind {

class trace_record_sink {
public:
  virtual ~trace_record_sink() = default;

  virtual bool good() const = 0;
  virtual bool write_header(const trace_header& header) = 0;
  virtual bool write_target_info(const target_info_record& record) = 0;
  virtual bool write_target_environment(const target_environment_record& record) = 0;
  virtual bool write_register_spec(const register_spec_record& record) = 0;
  virtual bool write_module_table(const module_table_record& record) = 0;
  virtual bool write_module_load(const module_load_record& record) = 0;
  virtual bool write_module_unload(const module_unload_record& record) = 0;
  virtual bool write_memory_map(const memory_map_record& record) = 0;
  virtual bool write_thread_start(const thread_start_record& record) = 0;
  virtual bool write_instruction(const instruction_record& record) = 0;
  virtual bool write_block_definition(const block_definition_record& record) = 0;
  virtual bool write_block_exec(const block_exec_record& record) = 0;
  virtual bool write_register_deltas(const register_delta_record& record) = 0;
  virtual bool write_register_bytes(const register_bytes_record& record) = 0;
  virtual bool write_memory_access(const memory_access_record& record) = 0;
  virtual bool write_snapshot(const snapshot_record& record) = 0;
  virtual bool write_thread_end(const thread_end_record& record) = 0;
  virtual void flush() = 0;
};

} // namespace w1::rewind
