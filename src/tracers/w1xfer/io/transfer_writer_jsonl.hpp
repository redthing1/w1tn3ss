#pragma once

#include <memory>
#include <string>

#include "w1formats/jsonl_writer.hpp"
#include "w1runtime/module_catalog.hpp"

#include "model/transfer_types.hpp"

namespace w1xfer {

class transfer_writer_jsonl {
public:
  transfer_writer_jsonl(const std::string& output_path, bool emit_metadata);

  bool is_open() const;

  void ensure_metadata(const w1::runtime::module_catalog& modules);
  void write_record(const transfer_record& record);
  void flush();
  void close();

private:
  std::unique_ptr<w1::io::jsonl_writer> writer_;
  bool emit_metadata_ = true;
  bool metadata_written_ = false;

  void write_metadata(const w1::runtime::module_catalog& modules);
  void write_event(const transfer_record& record);
};

} // namespace w1xfer
