#pragma once

#include <string>

#include "flow_types.hpp"
#include "replay_context.hpp"

namespace w1::rewind {

enum class flow_kind { instructions, blocks };

class flow_extractor {
public:
  explicit flow_extractor(const replay_context* context);

  void set_flow_kind(flow_kind kind);
  flow_kind kind() const { return kind_; }
  const replay_context* context() const { return context_; }

  bool try_extract(const trace_record& record, flow_step& out, bool& is_flow, std::string& error) const;
  bool handle_non_flow(
      const trace_record& record, flow_record_observer* observer, uint64_t active_thread_id, std::string& error
  ) const;

private:
  const replay_context* context_ = nullptr;
  flow_kind kind_ = flow_kind::instructions;
};

} // namespace w1::rewind
