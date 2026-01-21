#include "w1replay/gdb/adapter_components.hpp"

#include "w1replay/gdb/triple_utils.hpp"

namespace w1replay::gdb {

process_info_component::process_info_component(const adapter_services& services) : services_(services) {}

std::optional<gdbstub::process_info> process_info_component::get_process_info() const {
  if (!services_.context) {
    return std::nullopt;
  }
  gdbstub::process_info info{};
  const auto& context = *services_.context;
  const auto* env = context.target_environment ? &*context.target_environment : nullptr;
  std::string os_id;
  std::string abi;
  if (context.target_info) {
    os_id = context.target_info->os;
    abi = context.target_info->abi;
  }
  info.pid = (env && env->pid != 0) ? static_cast<int>(env->pid) : 1;
  info.endian = (services_.target_endian == endian::big) ? "big" : "little";
  info.ptr_size = static_cast<int>(context.header.arch.pointer_bits / 8);
  info.ostype = os_id.empty() ? "unknown" : os_id;
  info.triple = build_process_triple(context.header.arch, os_id, abi);
  if (info.ptr_size <= 0 || info.triple.empty()) {
    return std::nullopt;
  }
  return info;
}

} // namespace w1replay::gdb
