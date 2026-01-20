#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

libraries_component::libraries_component(adapter_state& state) : state_(state) {}

std::vector<gdbstub::library_entry> libraries_component::libraries() const {
  const auto& modules = state_.context.modules;
  std::vector<gdbstub::library_entry> out;
  out.reserve(modules.size());
  for (const auto& module : modules) {
    if (module.path.empty()) {
      continue;
    }
    out.push_back(gdbstub::library_entry::section(module.path, {module.base}));
  }
  return out;
}

} // namespace w1replay::gdb
