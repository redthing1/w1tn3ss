#include "gadget.hpp"

#include <redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_gadget_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up gadget bindings");

  auto gadget_exec = context.gadget_executor();
  if (!gadget_exec) {
    logger.err("gadget executor is null");
    return;
  }

  sol::table gadget = lua.create_table();

  gadget.set_function(
      "call",
      [gadget_exec, &lua](QBDI::rword address, sol::optional<sol::table> args_table) -> sol::object {
        try {
          std::vector<QBDI::rword> args;
          if (args_table) {
            for (size_t i = 1; i <= args_table->size(); ++i) {
              sol::optional<QBDI::rword> arg = (*args_table)[i];
              if (arg) {
                args.push_back(*arg);
              }
            }
          }

          QBDI::rword result = gadget_exec->gadget_call<QBDI::rword>(address, args);
          return sol::make_object(lua, result);
        } catch (const std::exception& e) {
          redlog::get_logger("w1.script_bindings").err("gadget call exception", redlog::field("error", e.what()));
          return sol::lua_nil;
        }
      }
  );

  gadget.set_function("run", [gadget_exec, &lua](QBDI::rword start_addr, QBDI::rword stop_addr) -> sol::table {
    try {
      auto result = gadget_exec->gadget_run(start_addr, stop_addr);

      sol::table result_table = lua.create_table();
      result_table["success"] = result.success;
      if (!result.success) {
        result_table["error"] = result.error;
      }

      sol::table gpr_table = lua.create_table();
#if defined(__aarch64__) || defined(_M_ARM64)
      gpr_table["x0"] = result.gpr.x0;
      gpr_table["x1"] = result.gpr.x1;
      gpr_table["x2"] = result.gpr.x2;
      gpr_table["x3"] = result.gpr.x3;
      gpr_table["x4"] = result.gpr.x4;
      gpr_table["x5"] = result.gpr.x5;
      gpr_table["x6"] = result.gpr.x6;
      gpr_table["x7"] = result.gpr.x7;
      gpr_table["x8"] = result.gpr.x8;
      gpr_table["x9"] = result.gpr.x9;
      gpr_table["x10"] = result.gpr.x10;
      gpr_table["x11"] = result.gpr.x11;
      gpr_table["x12"] = result.gpr.x12;
      gpr_table["x13"] = result.gpr.x13;
      gpr_table["x14"] = result.gpr.x14;
      gpr_table["x15"] = result.gpr.x15;
      gpr_table["x16"] = result.gpr.x16;
      gpr_table["x17"] = result.gpr.x17;
      gpr_table["x18"] = result.gpr.x18;
      gpr_table["x19"] = result.gpr.x19;
      gpr_table["x20"] = result.gpr.x20;
      gpr_table["x21"] = result.gpr.x21;
      gpr_table["x22"] = result.gpr.x22;
      gpr_table["x23"] = result.gpr.x23;
      gpr_table["x24"] = result.gpr.x24;
      gpr_table["x25"] = result.gpr.x25;
      gpr_table["x26"] = result.gpr.x26;
      gpr_table["x27"] = result.gpr.x27;
      gpr_table["x28"] = result.gpr.x28;
      gpr_table["x29"] = result.gpr.x29;
      gpr_table["lr"] = result.gpr.lr;
      gpr_table["sp"] = result.gpr.sp;
      gpr_table["pc"] = result.gpr.pc;
#elif defined(__x86_64__) || defined(_M_X64)
      gpr_table["rax"] = result.gpr.rax;
      gpr_table["rbx"] = result.gpr.rbx;
      gpr_table["rcx"] = result.gpr.rcx;
      gpr_table["rdx"] = result.gpr.rdx;
      gpr_table["rsi"] = result.gpr.rsi;
      gpr_table["rdi"] = result.gpr.rdi;
      gpr_table["r8"] = result.gpr.r8;
      gpr_table["r9"] = result.gpr.r9;
      gpr_table["r10"] = result.gpr.r10;
      gpr_table["r11"] = result.gpr.r11;
      gpr_table["r12"] = result.gpr.r12;
      gpr_table["r13"] = result.gpr.r13;
      gpr_table["r14"] = result.gpr.r14;
      gpr_table["r15"] = result.gpr.r15;
      gpr_table["rbp"] = result.gpr.rbp;
      gpr_table["rsp"] = result.gpr.rsp;
      gpr_table["rip"] = result.gpr.rip;
      gpr_table["eflags"] = result.gpr.eflags;
#endif
      result_table["gpr"] = gpr_table;

      return result_table;
    } catch (const std::exception& e) {
      auto log = redlog::get_logger("w1.script_bindings");
      log.err("gadget run exception", redlog::field("error", e.what()));
      sol::table error_table = lua.create_table();
      error_table["success"] = false;
      error_table["error"] = std::string("exception: ") + e.what();
      return error_table;
    }
  });

  w1_module["gadget"] = gadget;
}

} // namespace w1::tracers::script::bindings
