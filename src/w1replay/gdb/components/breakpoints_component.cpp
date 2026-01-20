#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

breakpoints_component::breakpoints_component(adapter_state& state) : state_(state) {}

gdbstub::target_status breakpoints_component::set_breakpoint(const gdbstub::breakpoint_request& request) {
  if (request.spec.type != gdbstub::breakpoint_type::software &&
      request.spec.type != gdbstub::breakpoint_type::hardware) {
    return gdbstub::target_status::unsupported;
  }
  state_.breakpoints.insert(request.spec.addr);
  if (state_.session) {
    state_.session->add_breakpoint(request.spec.addr);
  }
  return gdbstub::target_status::ok;
}

gdbstub::target_status breakpoints_component::remove_breakpoint(const gdbstub::breakpoint_request& request) {
  if (request.spec.type != gdbstub::breakpoint_type::software &&
      request.spec.type != gdbstub::breakpoint_type::hardware) {
    return gdbstub::target_status::unsupported;
  }
  state_.breakpoints.erase(request.spec.addr);
  if (state_.session) {
    state_.session->remove_breakpoint(request.spec.addr);
  }
  return gdbstub::target_status::ok;
}

} // namespace w1replay::gdb
