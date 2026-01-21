#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

breakpoints_component::breakpoints_component(const adapter_services& services) : services_(services) {}

gdbstub::target_status breakpoints_component::set_breakpoint(const gdbstub::breakpoint_request& request) {
  if (request.spec.type != gdbstub::breakpoint_type::software &&
      request.spec.type != gdbstub::breakpoint_type::hardware) {
    return gdbstub::target_status::unsupported;
  }
  if (!services_.breakpoints) {
    return gdbstub::target_status::unsupported;
  }
  services_.breakpoints->add(request.spec.addr);
  return gdbstub::target_status::ok;
}

gdbstub::target_status breakpoints_component::remove_breakpoint(const gdbstub::breakpoint_request& request) {
  if (request.spec.type != gdbstub::breakpoint_type::software &&
      request.spec.type != gdbstub::breakpoint_type::hardware) {
    return gdbstub::target_status::unsupported;
  }
  if (!services_.breakpoints) {
    return gdbstub::target_status::unsupported;
  }
  services_.breakpoints->remove(request.spec.addr);
  return gdbstub::target_status::ok;
}

} // namespace w1replay::gdb
