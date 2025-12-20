#include "hook.hpp"

#include <w1tn3ss/util/module_range_index.hpp>
#include <redlog.hpp>

#include <cctype>
#include <string>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

const w1::util::module_info* find_module_with_extensions(
    const w1::util::module_range_index& module_index, const std::string& module_name
) {
  auto module_info = module_index.find_by_name(module_name);
  if (module_info) {
    return module_info;
  }

  if (module_name.find('.') != std::string::npos) {
    return nullptr;
  }

  std::vector<std::string> extensions;
#ifdef _WIN32
  extensions = {".exe", ".dll"};
#elif defined(__linux__)
  extensions = {".so"};
#elif defined(__APPLE__)
  extensions = {".dylib"};
#endif

  for (const auto& ext : extensions) {
    module_info = module_index.find_by_name(module_name + ext);
    if (module_info) {
      return module_info;
    }
  }

  if (!extensions.empty()) {
    std::string base_ext = extensions[0];
    module_index.visit_all([&](const w1::util::module_info& mod) {
      if (module_info) {
        return;
      }
      std::string prefix = module_name + base_ext;
      if (mod.name.size() > prefix.size() && mod.name.substr(0, prefix.size()) == prefix) {
        std::string suffix = mod.name.substr(prefix.size());
        if (suffix.size() >= 2 && suffix[0] == '.' && std::isdigit(static_cast<unsigned char>(suffix[1]))) {
          module_info = &mod;
        }
      }
    });
  }

  return module_info;
}

w1::hooking::hook_handler make_handler(sol::protected_function handler) {
  return [handler](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr)
             -> QBDI::VMAction {
    auto log = redlog::get_logger("w1.script_hook");
    auto result = handler(vm, gpr, fpr, addr);
    if (!result.valid()) {
      sol::error err = result;
      log.err("hook handler error", redlog::field("error", err.what()));
      return QBDI::VMAction::CONTINUE;
    }

    if (result.get_type() == sol::type::number) {
      return static_cast<QBDI::VMAction>(result.get<int>());
    }

    sol::optional<QBDI::VMAction> action = result;
    if (action) {
      return *action;
    }

    return QBDI::VMAction::CONTINUE;
  };
}

} // namespace

void setup_hook_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up hook bindings");

  sol::table hook = lua.create_table();

  hook.set_function(
      "address",
      [&context](QBDI::rword address, sol::protected_function handler) -> sol::optional<uint32_t> {
        if (!handler.valid()) {
          return sol::nullopt;
        }

        auto hook_id = context.hook_manager()->hook_addr(address, make_handler(std::move(handler)));
        return hook_id == 0 ? sol::nullopt : sol::optional<uint32_t>(hook_id);
      }
  );

  hook.set_function(
      "range",
      [&context](QBDI::rword start, QBDI::rword end, sol::protected_function handler) -> sol::optional<uint32_t> {
        if (!handler.valid()) {
          return sol::nullopt;
        }

        auto hook_id = context.hook_manager()->hook_range(start, end, make_handler(std::move(handler)));
        return hook_id == 0 ? sol::nullopt : sol::optional<uint32_t>(hook_id);
      }
  );

  hook.set_function(
      "module",
      [&context](const std::string& module_name, QBDI::rword offset, sol::protected_function handler)
          -> sol::optional<uint32_t> {
        if (!handler.valid()) {
          return sol::nullopt;
        }

        const auto* module_info = find_module_with_extensions(context.module_index(), module_name);
        if (!module_info) {
          return sol::nullopt;
        }

        if (offset >= module_info->size) {
          return sol::nullopt;
        }

        QBDI::rword target_address = module_info->base_address + offset;
        auto hook_id = context.hook_manager()->hook_addr(target_address, make_handler(std::move(handler)));
        return hook_id == 0 ? sol::nullopt : sol::optional<uint32_t>(hook_id);
      }
  );

  hook.set_function("remove", [&context](uint32_t hook_id) { return context.hook_manager()->remove_hook(hook_id); });

  hook.set_function("clear", [&context]() { context.hook_manager()->remove_all_hooks(); });

  w1_module["hook"] = hook;
}

} // namespace w1::tracers::script::bindings
