#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

loaded_libraries_component::loaded_libraries_component(const adapter_services& services) : services_(services) {}

std::optional<std::string> loaded_libraries_component::loaded_libraries_json(
    const gdbstub::lldb::loaded_libraries_request& request
) {
  if (!services_.loaded_libraries) {
    return std::nullopt;
  }
  return services_.loaded_libraries->loaded_libraries_json(request);
}

std::optional<std::vector<gdbstub::lldb::process_kv_pair>> loaded_libraries_component::process_info_extras() const {
  if (!services_.loaded_libraries || !services_.session) {
    return std::nullopt;
  }
  return services_.loaded_libraries->process_info_extras(services_.session->current_step().address);
}

bool loaded_libraries_component::has_loaded_images() const {
  if (!services_.loaded_libraries) {
    return false;
  }
  return services_.loaded_libraries->has_loaded_images();
}

} // namespace w1replay::gdb
