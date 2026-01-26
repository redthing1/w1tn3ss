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
  const auto* env = context.environment ? &*context.environment : nullptr;
  std::string os_id = env ? env->os_id : std::string{};
  std::string abi = env ? env->abi : std::string{};
  if (context.arch.has_value()) {
    info.triple = build_process_triple(*context.arch, os_id, abi);
  }
  info.endian = (services_.target_endian == endian::big) ? "big" : "little";
  uint16_t pointer_bits = 0;
  if (context.arch.has_value()) {
    pointer_bits = context.arch->pointer_bits;
    if (pointer_bits == 0) {
      pointer_bits = context.arch->address_bits;
    }
  }
  if (pointer_bits % 8 != 0) {
    pointer_bits = 0;
  }
  info.ptr_size = static_cast<int>(pointer_bits / 8);
  info.hostname = (env && !env->hostname.empty()) ? env->hostname : "w1replay";
  if (info.ptr_size <= 0 || info.triple.empty()) {
    return std::nullopt;
  }
  return info;
}

} // namespace w1replay::gdb
