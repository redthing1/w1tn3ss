#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

libraries_component::libraries_component(const adapter_services& services) : services_(services) {}

std::vector<gdbstub::library_entry> libraries_component::libraries() const {
  if (!services_.context) {
    return {};
  }
  const auto& modules = services_.context->modules;
  std::vector<gdbstub::library_entry> out;
  out.reserve(modules.size());
  for (const auto& module : modules) {
    std::string path = module.path;
    if (services_.module_resolver) {
      if (auto resolved = services_.module_resolver->resolve_module_path(module)) {
        path = *resolved;
      }
    }
    if (path.empty()) {
      continue;
    }
    out.push_back(gdbstub::library_entry::section(path, {module.base}));
  }
  return out;
}

} // namespace w1replay::gdb
