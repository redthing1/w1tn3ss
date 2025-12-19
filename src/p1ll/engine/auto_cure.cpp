#include "auto_cure.hpp"
#include "cure_planner.hpp"
#include <redlog.hpp>

namespace p1ll::engine {

auto_cure::auto_cure(const context& ctx) : context_(ctx), address_space_(std::make_unique<process_address_space>()) {
  auto log = redlog::get_logger("p1ll.auto_cure");
  log.dbg("initialized auto-cure");
}

cure_result auto_cure::execute_dynamic(const cure_config& config) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (!context_.is_dynamic()) {
    cure_result result;
    result.add_error("context is not dynamic: cannot execute dynamic patching");
    log.err("context validation failed: not dynamic");
    return result;
  }

  if (!address_space_) {
    cure_result result;
    result.add_error("dynamic address space not initialized");
    log.err("address space not initialized");
    return result;
  }

  return execute_with_space(*address_space_, config);
}

cure_result auto_cure::execute_static(std::vector<uint8_t>& buffer_data, const cure_config& config) {
  auto log = redlog::get_logger("p1ll.auto_cure");

  if (context_.is_dynamic()) {
    cure_result result;
    result.add_error("context is dynamic: cannot execute static buffer patching");
    log.err("context validation failed: is dynamic");
    return result;
  }

  buffer_address_space buffer_space(buffer_data);
  return execute_with_space(buffer_space, config);
}

cure_result auto_cure::execute_with_space(address_space& space, const cure_config& config) {
  auto log = redlog::get_logger("p1ll.auto_cure");
  cure_result result;

  log.inf(
      "starting auto-cure", redlog::field("name", config.meta.name),
      redlog::field("platforms", config.meta.platforms.size())
  );

  cure_planner planner(context_, space);
  auto plan_opt = planner.build_plan(config);
  if (!plan_opt) {
    log.err("cure planning failed", redlog::field("errors", planner.errors().size()));
    if (planner.errors().empty()) {
      result.add_error("cure planning failed");
    } else {
      for (const auto& error : planner.errors()) {
        result.add_error(error);
      }
    }
    return result;
  }

  patch_executor executor(space);
  for (const auto& entry : *plan_opt) {
    auto exec_result = executor.apply(entry);
    if (exec_result.success) {
      result.patches_applied++;
      continue;
    }

    result.patches_failed++;
    if (entry.decl.required) {
      result.add_error("required patch failed: " + entry.decl.signature.pattern);
      for (const auto& error : exec_result.error_messages) {
        result.add_error(error);
      }
      log.err("required patch failed", redlog::field("signature", entry.decl.signature.pattern));
      return result;
    }

    log.wrn("optional patch failed", redlog::field("signature", entry.decl.signature.pattern));
  }

  result.success = (result.patches_failed == 0 && result.patches_applied > 0);
  log.inf(
      "auto-cure completed", redlog::field("success", result.success),
      redlog::field("applied", result.patches_applied), redlog::field("failed", result.patches_failed)
  );

  return result;
}

} // namespace p1ll::engine
