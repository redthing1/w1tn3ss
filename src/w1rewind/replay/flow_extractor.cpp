#include "flow_extractor.hpp"

namespace w1::rewind {

flow_extractor::flow_extractor(const replay_context* context) : context_(context) {}

void flow_extractor::set_flow_kind(flow_kind kind) { kind_ = kind; }

bool flow_extractor::try_extract(
    const trace_record& record, flow_step& out, bool& is_flow, std::string& error
) const {
  is_flow = false;
  if (!context_) {
    error = "replay context missing";
    return false;
  }

  if (kind_ == flow_kind::instructions) {
    if (!std::holds_alternative<instruction_record>(record)) {
      return true;
    }
    const auto& inst = std::get<instruction_record>(record);
    out.thread_id = inst.thread_id;
    out.sequence = inst.sequence;
    out.size = inst.size;
    out.address = inst.address;
    out.block_id = 0;
    out.flags = inst.flags;
    out.is_block = false;
    is_flow = true;
    return true;
  }

  if (!std::holds_alternative<block_exec_record>(record)) {
    return true;
  }

  const auto& exec = std::get<block_exec_record>(record);
  auto it = context_->blocks_by_id.find(exec.block_id);
  if (it == context_->blocks_by_id.end()) {
    error = "block id not found";
    return false;
  }

  const auto& def = it->second;
  out.thread_id = exec.thread_id;
  out.sequence = exec.sequence;
  out.size = def.size;
  out.address = def.address;
  out.block_id = exec.block_id;
  out.flags = def.flags;
  out.is_block = true;
  is_flow = true;
  return true;
}

bool flow_extractor::handle_non_flow(
    const trace_record& record, flow_record_observer* observer, uint64_t active_thread_id, std::string& error
) const {
  if (!observer) {
    return true;
  }
  if (!observer->on_record(record, active_thread_id, error)) {
    if (error.empty()) {
      error = "failed to apply trace record";
    }
    return false;
  }
  return true;
}

} // namespace w1::rewind
