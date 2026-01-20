#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/triple_utils.hpp"

namespace w1replay::gdb {

process_info_component::process_info_component(adapter_state& state) : state_(state) {}

std::optional<gdbstub::process_info> process_info_component::get_process_info() const {
  if (!state_.context.target_info.has_value() || !state_.context.target_environment.has_value()) {
    return std::nullopt;
  }
  gdbstub::process_info info{};
  info.pid = state_.context.target_environment->pid == 0 ? 1 : state_.context.target_environment->pid;
  info.endian = (state_.target_endian == endian::big) ? "big" : "little";
  info.ptr_size = static_cast<int>(state_.context.header.arch.pointer_bits / 8);
  info.ostype = state_.context.target_info->os;
  info.triple = build_process_triple(state_.context.header.arch, info.ostype, state_.context.target_info->abi);
  if (info.ptr_size <= 0 || info.triple.empty()) {
    return std::nullopt;
  }
  return info;
}

} // namespace w1replay::gdb
