#include "gadget_execution.hpp"
#include <w1tn3ss/gadget/gadget_executor.hpp>
#include <redlog.hpp>
#include <sol/protected_function.hpp>
#include <map>

namespace w1::tracers::script::bindings {

void setup_gadget_execution(
    sol::state& lua, sol::table& w1_module, std::shared_ptr<w1tn3ss::gadget::gadget_executor> gadget_exec
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up gadget execution functions");

  if (!gadget_exec) {
    logger.err("gadget executor is null, skipping gadget function setup");
    return;
  }

  // basic gadget_call: call function with arguments and return value
  w1_module.set_function(
      "gadget_call", [gadget_exec, &lua](QBDI::rword address, sol::optional<sol::table> args_table) -> sol::object {
        try {
          auto log = redlog::get_logger("w1.script_bindings");
          log.vrb("gadget_call invoked", redlog::field("addr", "0x%llx", address));

          if (!gadget_exec) {
            log.err("gadget executor is null");
            return sol::nil;
          }

          // convert lua args to vector
          std::vector<QBDI::rword> args;
          if (args_table) {
            for (size_t i = 1; i <= args_table->size(); i++) {
              sol::optional<QBDI::rword> arg = (*args_table)[i];
              if (arg) {
                args.push_back(*arg);
              }
            }
          }

          log.dbg(
              "executing gadget", redlog::field("addr", "0x%llx", address), redlog::field("args_count", args.size())
          );

          // call gadget and return result
          QBDI::rword result = gadget_exec->gadget_call<QBDI::rword>(address, args);

          log.dbg("gadget execution completed", redlog::field("result", "0x%llx", result));
          return sol::make_object(lua, result);

        } catch (const std::exception& e) {
          auto log = redlog::get_logger("w1.script_bindings");
          log.err("gadget_call exception", redlog::field("error", e.what()));
          return sol::nil;
        }
      }
  );

  // raw gadget execution between addresses
  w1_module.set_function(
      "gadget_run", [gadget_exec, &logger, &lua](QBDI::rword start_addr, QBDI::rword stop_addr) -> sol::table {
        try {
          logger.vrb(
              "executing raw gadget", redlog::field("start", "0x%llx", start_addr),
              redlog::field("stop", "0x%llx", stop_addr)
          );

          auto result = gadget_exec->gadget_run(start_addr, stop_addr);

          // create lua result table
          sol::table result_table = lua.create_table();
          result_table["success"] = result.success;

          if (!result.success) {
            result_table["error"] = result.error;
          }

          // add final register state (simplified - just a few key registers)
          sol::table gpr_table = lua.create_table();
          gpr_table["x0"] = result.gpr.x0;
          gpr_table["x1"] = result.gpr.x1;
          gpr_table["x2"] = result.gpr.x2;
          gpr_table["x3"] = result.gpr.x3;
          gpr_table["sp"] = result.gpr.sp;
          result_table["gpr"] = gpr_table;

          return result_table;

        } catch (const std::exception& e) {
          logger.err("gadget_run exception", redlog::field("error", e.what()));
          sol::table error_result = lua.create_table();
          error_result["success"] = false;
          error_result["error"] = std::string("exception: ") + e.what();
          return error_result;
        }
      }
  );

  logger.dbg("gadget execution functions registered");
}

} // namespace w1::tracers::script::bindings