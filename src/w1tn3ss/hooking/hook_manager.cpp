#include "hook_manager.hpp"
#include <w1tn3ss/util/module_range_index.hpp>
#include <w1tn3ss/util/module_scanner.hpp>
#include <stdexcept>

namespace w1::hooking {

hook_manager::~hook_manager() { remove_all_hooks(); }

uint32_t hook_manager::hook_addr(QBDI::rword address, hook_handler handler) {
  uint32_t hook_id = next_hook_id_++;

  hook_info info;
  info.id = hook_id;
  info.handler = std::move(handler);
  info.address = address;

  // register with QBDI
  info.qbdi_id = vm_->addCodeAddrCB(
      address, QBDI::PREINST, hook_callback_wrapper,
      &hooks_[hook_id] // pass hook_info as data
  );

  if (info.qbdi_id == QBDI::INVALID_EVENTID) {
    log_.err("failed to register hook", redlog::field("address", "0x%lx", address));
    return 0;
  }

  hooks_[hook_id] = std::move(info);
  log_.vrb("registered address hook", redlog::field("id", hook_id), redlog::field("address", "0x%lx", address));

  return hook_id;
}

uint32_t hook_manager::hook_module(const std::string& module_name, QBDI::rword offset, hook_handler handler) {
  // find module base address
  util::module_scanner scanner;
  auto modules = scanner.scan_executable_modules();
  util::module_range_index module_index(std::move(modules));

  auto module_info = find_module_with_extensions(module_index, module_name);
  if (!module_info) {
    log_.err("module not found", redlog::field("module", module_name));
    return 0;
  }

  QBDI::rword target_address = module_info->base_address + offset;

  // validate address is within module bounds
  if (offset >= module_info->size) {
    log_.err(
        "offset exceeds module bounds", redlog::field("module", module_name), redlog::field("offset", "0x%lx", offset),
        redlog::field("module_size", "0x%lx", module_info->size)
    );
    return 0;
  }

  log_.trc(
      "hooking module+offset", redlog::field("module", module_name), redlog::field("offset", "0x%lx", offset),
      redlog::field("address", "0x%lx", target_address)
  );

  return hook_addr(target_address, std::move(handler));
}

uint32_t hook_manager::hook_range(QBDI::rword start, QBDI::rword end, hook_handler handler) {
  if (start >= end) {
    log_.err("invalid range", redlog::field("start", "0x%lx", start), redlog::field("end", "0x%lx", end));
    return 0;
  }

  uint32_t hook_id = next_hook_id_++;

  hook_info info;
  info.id = hook_id;
  info.handler = std::move(handler);
  info.range = {start, end};

  // register with QBDI
  info.qbdi_id = vm_->addCodeRangeCB(
      start, end, QBDI::PREINST, hook_callback_wrapper,
      &hooks_[hook_id] // pass hook_info as data
  );

  if (info.qbdi_id == QBDI::INVALID_EVENTID) {
    log_.err(
        "failed to register range hook", redlog::field("start", "0x%lx", start), redlog::field("end", "0x%lx", end)
    );
    return 0;
  }

  hooks_[hook_id] = std::move(info);
  log_.vrb(
      "registered range hook", redlog::field("id", hook_id), redlog::field("start", "0x%lx", start),
      redlog::field("end", "0x%lx", end)
  );

  return hook_id;
}

bool hook_manager::remove_hook(uint32_t hook_id) {
  auto it = hooks_.find(hook_id);
  if (it == hooks_.end()) {
    return false;
  }

  if (it->second.qbdi_id != QBDI::INVALID_EVENTID) {
    vm_->deleteInstrumentation(it->second.qbdi_id);
  }

  hooks_.erase(it);
  log_.dbg("removed hook", redlog::field("id", hook_id));
  return true;
}

void hook_manager::remove_all_hooks() {
  for (auto& [id, info] : hooks_) {
    if (info.qbdi_id != QBDI::INVALID_EVENTID) {
      vm_->deleteInstrumentation(info.qbdi_id);
    }
  }
  hooks_.clear();
  log_.dbg("removed all hooks");
}

QBDI::VMAction hook_manager::hook_callback_wrapper(
    QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data
) {
  if (!data) {
    return QBDI::VMAction::CONTINUE;
  }

  hook_info* info = static_cast<hook_info*>(data);

  // determine current address
  QBDI::rword current_addr = QBDI_GPR_GET(gpr, QBDI::REG_PC);

  try {
    return info->handler(vm, gpr, fpr, current_addr);
  } catch (const std::exception& e) {
    auto log = redlog::get_logger("w1.hook_manager");
    log.err("exception in hook handler", redlog::field("error", e.what()));
    return QBDI::VMAction::CONTINUE;
  }
}

const w1::util::module_info* hook_manager::find_module_with_extensions(
    const w1::util::module_range_index& module_index, const std::string& module_name
) const {
  // first try exact match
  auto module_info = module_index.find_by_name(module_name);
  if (module_info) {
    return module_info;
  }

  // if name already contains a dot, don't try extensions
  if (module_name.find('.') != std::string::npos) {
    return nullptr;
  }

  log_.dbg(
      "module not found with exact name, trying platform-specific extensions", redlog::field("module", module_name)
  );

  // try platform-specific extensions
  std::vector<std::string> extensions;

#ifdef _WIN32
  extensions = {".exe", ".dll"};
#elif defined(__linux__)
  extensions = {".so"};
#elif defined(__APPLE__)
  extensions = {".dylib"};
#endif

  // try base extensions first
  for (const auto& ext : extensions) {
    module_info = module_index.find_by_name(module_name + ext);
    if (module_info) {
      log_.dbg(
          "module found with extension", redlog::field("requested", module_name), redlog::field("found", module_info->name)
      );
      return module_info;
    }
  }

  // for shared libraries, try to find versioned extensions by enumerating all modules
  if (!extensions.empty()) {
    std::string base_ext = extensions[0]; // .so or .dylib

    // enumerate all modules and find ones that start with our name + base extension
    module_index.visit_all([&](const w1::util::module_info& mod) {
      if (module_info) {
        return; // already found
      }

      std::string prefix = module_name + base_ext;
      if (mod.name.size() > prefix.size() && mod.name.substr(0, prefix.size()) == prefix) {

        // check if the remaining part looks like a version (starts with . followed by digits)
        std::string suffix = mod.name.substr(prefix.size());
        if (suffix.size() >= 2 && suffix[0] == '.' && std::isdigit(suffix[1])) {
          log_.dbg(
              "module found with versioned extension", redlog::field("requested", module_name),
              redlog::field("found", mod.name)
          );
          module_info = &mod;
        }
      }
    });
  }

  return module_info;
}

} // namespace w1::hooking
