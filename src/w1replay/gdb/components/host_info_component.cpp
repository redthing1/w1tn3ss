#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/triple_utils.hpp"

namespace w1replay::gdb {

host_info_component::host_info_component(const adapter_services& services) : services_(services) {}

std::optional<gdbstub::host_info> host_info_component::get_host_info() const {
  if (!services_.context) {
    return std::nullopt;
  }
  gdbstub::host_info info{};
  const auto& context = *services_.context;
  const auto* env = context.target_environment ? &*context.target_environment : nullptr;
  std::string os_id;
  std::string abi;
  if (context.target_info) {
    os_id = context.target_info->os;
    abi = context.target_info->abi;
  }
  info.triple = build_process_triple(context.header.arch, os_id, abi);
  info.endian = (services_.target_endian == endian::big) ? "big" : "little";
  info.ptr_size = static_cast<int>(context.header.arch.pointer_bits / 8);
  info.hostname = (env && !env->hostname.empty()) ? env->hostname : "w1replay";
  if (env && env->addressing_bits > 0) {
    info.addressing_bits = static_cast<int>(env->addressing_bits);
  }
  if (env && env->low_mem_addressing_bits > 0) {
    info.low_mem_addressing_bits = static_cast<int>(env->low_mem_addressing_bits);
  }
  if (env && env->high_mem_addressing_bits > 0) {
    info.high_mem_addressing_bits = static_cast<int>(env->high_mem_addressing_bits);
  }
  if (env && !env->os_version.empty()) {
    info.os_version = env->os_version;
  }
  if (env && !env->os_build.empty()) {
    info.os_build = env->os_build;
  }
  if (env && !env->os_kernel.empty()) {
    info.os_kernel = env->os_kernel;
  }
  if (info.ptr_size <= 0 || info.triple.empty()) {
    return std::nullopt;
  }
  return info;
}

} // namespace w1replay::gdb
