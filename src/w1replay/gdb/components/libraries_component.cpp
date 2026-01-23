#include "w1replay/gdb/adapter_components.hpp"

namespace w1replay::gdb {

libraries_component::libraries_component(const adapter_services& services) : services_(services) {}

std::optional<uint64_t> libraries_component::resolve_main_module_id() const {
  if (main_module_id_.has_value()) {
    return main_module_id_;
  }
  if (services_.context) {
    for (const auto& module : services_.context->modules) {
      if ((module.flags & w1::rewind::module_record_flag_main) != 0) {
        main_module_id_ = module.id;
        return main_module_id_;
      }
    }
  }
  if (!services_.session || !services_.module_index) {
    return std::nullopt;
  }
  uint64_t pc = services_.session->current_step().address;
  auto match = services_.module_index->find(pc, 1);
  if (!match || !match->module) {
    return std::nullopt;
  }
  const auto& module = *match->module;
  const bool file_backed = (module.flags & w1::rewind::module_record_flag_file_backed) != 0 ||
                           module.format != w1::rewind::module_format::unknown;
  if (!file_backed) {
    return std::nullopt;
  }
  main_module_id_ = module.id;
  return main_module_id_;
}

std::vector<gdbstub::library_entry> libraries_component::libraries() const {
  if (!services_.context) {
    return {};
  }
  const auto& modules = services_.context->modules;
  const auto main_module_id = resolve_main_module_id();
  std::vector<gdbstub::library_entry> out;
  out.reserve(modules.size());
  for (const auto& module : modules) {
    if (main_module_id && module.id == *main_module_id) {
      continue;
    }
    const bool file_backed = (module.flags & w1::rewind::module_record_flag_file_backed) != 0 ||
                             module.format != w1::rewind::module_format::unknown;
    if (!file_backed) {
      continue;
    }
    std::string path = module.path;
    if (path.empty()) {
      continue;
    }
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

std::optional<uint64_t> libraries_component::libraries_generation() const {
  if (!services_.context) {
    return std::nullopt;
  }
  const auto& modules = services_.context->modules;
  const auto main_module_id = resolve_main_module_id();
  size_t count = 0;
  for (const auto& module : modules) {
    if (main_module_id && module.id == *main_module_id) {
      continue;
    }
    const bool file_backed = (module.flags & w1::rewind::module_record_flag_file_backed) != 0 ||
                             module.format != w1::rewind::module_format::unknown;
    if (!file_backed) {
      continue;
    }
    if (module.path.empty()) {
      continue;
    }
    ++count;
  }
  return static_cast<uint64_t>(count);
}

} // namespace w1replay::gdb
