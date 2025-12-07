#pragma once

#include <fstream>
#include <string>

#include <redlog.hpp>

#include "trace_source.hpp"

namespace w1::rewind {

struct binary_trace_source_config {
  std::string path;
  redlog::logger log;
};

class binary_trace_source : public trace_source {
public:
  explicit binary_trace_source(binary_trace_source_config config);
  ~binary_trace_source() override;

  bool initialize() override;
  void close() override;
  bool read_event(trace_event& event) override;
  void reset() override;
  bool good() const override { return stream_.good(); }

private:
  bool read_header();
  bool read_registers(trace_event& event);
  bool read_memory_list(std::vector<trace_memory_delta>& accesses);

  binary_trace_source_config config_;
  std::ifstream stream_;
  uint32_t version_ = 0;
};

std::shared_ptr<binary_trace_source> make_binary_trace_source(binary_trace_source_config config);

} // namespace w1::rewind
