#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

loaded_libraries_component::loaded_libraries_component(adapter_state& state) : state_(state) {}

std::optional<std::string> loaded_libraries_component::loaded_libraries_json(
    const gdbstub::lldb::loaded_libraries_request& request
) {
  if (!state_.loaded_libraries_provider) {
    return std::nullopt;
  }
  return state_.loaded_libraries_provider->loaded_libraries_json(request);
}

std::optional<std::vector<gdbstub::lldb::process_kv_pair>> loaded_libraries_component::process_info_extras() const {
  if (!state_.loaded_libraries_provider) {
    return std::nullopt;
  }
  return state_.loaded_libraries_provider->process_info_extras(state_.current_pc());
}

bool loaded_libraries_component::has_loaded_images() const {
  if (!state_.loaded_libraries_provider) {
    return false;
  }
  return state_.loaded_libraries_provider->has_loaded_images();
}

} // namespace w1replay::gdb
