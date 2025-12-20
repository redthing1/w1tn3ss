#pragma once

#include <memory>
#include <string>

#include <w1tn3ss/util/jsonl_writer.hpp>
#include <w1tn3ss/util/module_range_index.hpp>

#include "transfer_types.hpp"

namespace w1xfer {

class transfer_writer_jsonl {
public:
  transfer_writer_jsonl(const std::string& output_path, bool emit_metadata);

  bool is_open() const;

  void ensure_metadata(const w1::util::module_range_index& index);
  void write_record(const transfer_record& record);

private:
  std::unique_ptr<w1::util::jsonl_writer> writer_;
  bool emit_metadata_ = true;
  bool metadata_written_ = false;

  void write_metadata(const w1::util::module_range_index& index);
  void write_event(const transfer_record& record);
};

} // namespace w1xfer
