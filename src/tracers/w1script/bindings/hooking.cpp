#include "hooking.hpp"
#include <w1tn3ss/hooking/hook_manager.hpp>
#include <redlog.hpp>
#include <sol/protected_function.hpp>

namespace w1::tracers::script::bindings {

void setup_hooking(sol::state& lua, sol::table& w1_module, std::shared_ptr<w1::hooking::hook_manager> hook_mgr) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up hook registration functions");

  // hook specific address
  w1_module.set_function("hook_addr", [hook_mgr, &logger](QBDI::rword address, sol::protected_function handler) -> sol::optional<uint32_t> {
    if (!handler.valid()) {
      logger.err("invalid handler function provided to hook_addr");
      return sol::nullopt;
    }
    
    // capture the lua function in the lambda
    auto cpp_handler = [handler, &logger](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr) -> QBDI::VMAction {
      try {
        // call lua handler with raw QBDI objects
        auto result = handler(vm, gpr, fpr, addr);
        
        if (!result.valid()) {
          sol::error err = result;
          logger.err("lua hook handler error", redlog::field("error", err.what()));
          return QBDI::VMAction::CONTINUE;
        }
        
        // check if handler returned a VMAction
        sol::optional<QBDI::VMAction> action = result;
        if (action) {
          return *action;
        }
        
        // default to continue
        return QBDI::VMAction::CONTINUE;
      } catch (const std::exception& e) {
        logger.err("exception in hook handler", redlog::field("error", e.what()));
        return QBDI::VMAction::CONTINUE;
      }
    };
    
    uint32_t id = hook_mgr->hook_addr(address, cpp_handler);
    if (id == 0) {
      return sol::nullopt;
    }
    
    logger.dbg("registered address hook", redlog::field("id", id), redlog::field("address", "0x%lx", address));
    return id;
  });

  // hook module+offset
  w1_module.set_function("hook_module", [hook_mgr, &logger](const std::string& module_name, QBDI::rword offset, sol::protected_function handler) -> sol::optional<uint32_t> {
    if (!handler.valid()) {
      logger.err("invalid handler function provided to hook_module");
      return sol::nullopt;
    }
    
    // capture the lua function in the lambda
    auto cpp_handler = [handler, &logger](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr) -> QBDI::VMAction {
      try {
        // call lua handler with raw QBDI objects
        auto result = handler(vm, gpr, fpr, addr);
        
        if (!result.valid()) {
          sol::error err = result;
          logger.err("lua hook handler error", redlog::field("error", err.what()));
          return QBDI::VMAction::CONTINUE;
        }
        
        // check if handler returned a VMAction
        sol::optional<QBDI::VMAction> action = result;
        if (action) {
          return *action;
        }
        
        // default to continue
        return QBDI::VMAction::CONTINUE;
      } catch (const std::exception& e) {
        logger.err("exception in hook handler", redlog::field("error", e.what()));
        return QBDI::VMAction::CONTINUE;
      }
    };
    
    uint32_t id = hook_mgr->hook_module(module_name, offset, cpp_handler);
    if (id == 0) {
      return sol::nullopt;
    }
    
    logger.dbg(
        "registered module hook", redlog::field("id", id), redlog::field("module", module_name),
        redlog::field("offset", "0x%lx", offset)
    );
    return id;
  });

  // hook address range
  w1_module.set_function("hook_range", [hook_mgr, &logger](QBDI::rword start, QBDI::rword end, sol::protected_function handler) -> sol::optional<uint32_t> {
    if (!handler.valid()) {
      logger.err("invalid handler function provided to hook_range");
      return sol::nullopt;
    }
    
    // capture the lua function in the lambda
    auto cpp_handler = [handler, &logger](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, QBDI::rword addr) -> QBDI::VMAction {
      try {
        // call lua handler with raw QBDI objects
        auto result = handler(vm, gpr, fpr, addr);
        
        if (!result.valid()) {
          sol::error err = result;
          logger.err("lua hook handler error", redlog::field("error", err.what()));
          return QBDI::VMAction::CONTINUE;
        }
        
        // check if handler returned a VMAction
        sol::optional<QBDI::VMAction> action = result;
        if (action) {
          return *action;
        }
        
        // default to continue
        return QBDI::VMAction::CONTINUE;
      } catch (const std::exception& e) {
        logger.err("exception in hook handler", redlog::field("error", e.what()));
        return QBDI::VMAction::CONTINUE;
      }
    };
    
    uint32_t id = hook_mgr->hook_range(start, end, cpp_handler);
    if (id == 0) {
      return sol::nullopt;
    }
    
    logger.dbg(
        "registered range hook", redlog::field("id", id), redlog::field("start", "0x%lx", start),
        redlog::field("end", "0x%lx", end)
    );
    return id;
  });

  // remove specific hook
  w1_module.set_function("remove_hook", [hook_mgr, &logger](uint32_t hook_id) -> bool {
    bool result = hook_mgr->remove_hook(hook_id);
    if (result) {
      logger.dbg("removed hook", redlog::field("id", hook_id));
    } else {
      logger.warn("failed to remove hook", redlog::field("id", hook_id));
    }
    return result;
  });

  // remove all hooks
  w1_module.set_function("remove_all_hooks", [hook_mgr, &logger]() {
    hook_mgr->remove_all_hooks();
    logger.dbg("removed all hooks");
  });

  logger.dbg("hook registration functions registered");
}

} // namespace w1::tracers::script::bindings