#pragma once

#include <memory>
#include <string>

#include "w1rewind/replay/replay_context.hpp"
#include "w1rewind/trace/record_stream.hpp"
#include "w1rewind/trace/replay_checkpoint.hpp"
#include "w1rewind/trace/trace_index.hpp"

namespace w1replay::trace_loader {

struct trace_load_options {
  std::string trace_path;
  std::string index_path;
  std::string checkpoint_path;
  bool auto_build_index = true;
  bool auto_build_checkpoint = true;
  uint32_t index_stride = 0;
  uint32_t checkpoint_stride = 0;
  bool checkpoint_include_memory = false;
};

struct trace_load_result {
  std::shared_ptr<w1::rewind::trace_record_stream> stream;
  std::shared_ptr<w1::rewind::trace_index> index;
  std::shared_ptr<w1::rewind::replay_checkpoint_index> checkpoint;
  w1::rewind::replay_context context;
  std::string error;
};

bool load_trace(const trace_load_options& options, trace_load_result& out);

} // namespace w1replay::trace_loader
