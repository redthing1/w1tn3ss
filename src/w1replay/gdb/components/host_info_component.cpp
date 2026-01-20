#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/triple_utils.hpp"

namespace w1replay::gdb {

host_info_component::host_info_component(adapter_state& state) : state_(state) {}

std::optional<gdbstub::host_info> host_info_component::get_host_info() const {
  if (!state_.context.target_info.has_value() || !state_.context.target_environment.has_value()) {
    return std::nullopt;
  }
  gdbstub::host_info info{};
  const auto& env = *state_.context.target_environment;
  info.triple =
      build_process_triple(state_.context.header.arch, state_.context.target_info->os, state_.context.target_info->abi);
  info.endian = (state_.target_endian == endian::big) ? "big" : "little";
  info.ptr_size = static_cast<int>(state_.context.header.arch.pointer_bits / 8);
  info.hostname = env.hostname.empty() ? "w1replay" : env.hostname;
  if (env.addressing_bits > 0) {
    info.addressing_bits = static_cast<int>(env.addressing_bits);
  }
  if (env.low_mem_addressing_bits > 0) {
    info.low_mem_addressing_bits = static_cast<int>(env.low_mem_addressing_bits);
  }
  if (env.high_mem_addressing_bits > 0) {
    info.high_mem_addressing_bits = static_cast<int>(env.high_mem_addressing_bits);
  }
  if (!env.os_version.empty()) {
    info.os_version = env.os_version;
  }
  if (info.ptr_size <= 0 || info.triple.empty()) {
    return std::nullopt;
  }
  return info;
}

} // namespace w1replay::gdb
