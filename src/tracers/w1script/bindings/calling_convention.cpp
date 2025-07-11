#include "calling_convention.hpp"
#include <w1tn3ss/abi/calling_convention_factory.hpp>
#include <w1tn3ss/abi/calling_convention_base.hpp>
#include <redlog.hpp>
#include <QBDI.h>

namespace w1::tracers::script::bindings {

void setup_calling_convention(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up calling convention functions");

  // important note about calling conventions:
  // - the default convention returned by create_default_calling_convention() is the platform abi
  // - this is correct for system api calls (libc, windows api, etc.)
  // - internal functions may use different conventions:
  //   * static functions often use optimized/custom conventions
  //   * c++ member functions use thiscall on x86 windows
  //   * compiler optimizations may change conventions
  // - when hooking internal functions, you may need to use direct register access
  // - when hooking known system apis, the default convention should work

  // get function arguments using calling convention
  // this is the main function that extracts arguments based on platform abi
  w1_module.set_function(
      "get_args", [&lua](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t count) -> sol::table {
        auto log = redlog::get_logger("w1.script_bindings");

        // get default calling convention for platform
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          log.err("failed to create default calling convention");
          return sol::nil;
        }

        // create extraction context
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;

        // stack reading lambda
        ctx.read_stack = [vm, gpr, cc](uint64_t offset) -> uint64_t {
          uint64_t sp = cc->get_stack_pointer(gpr);
          uint64_t addr = sp + offset;
          uint64_t value = 0;

          // try to read from stack
          try {
            std::memcpy(&value, reinterpret_cast<const void*>(addr), sizeof(uint64_t));
          } catch (...) {
            // stack read failed
          }

          return value;
        };

        // extract integer arguments
        std::vector<uint64_t> args = cc->extract_integer_args(ctx, count);

        // convert to lua table
        sol::state_view lua_view = lua.lua_state();
        sol::table result = lua_view.create_table();

        for (size_t i = 0; i < args.size(); i++) {
          result[i + 1] = args[i]; // lua arrays start at 1
        }

        return result;
      }
  );

  // get function arguments with types
  w1_module.set_function(
      "get_typed_args",
      [&lua](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, sol::table arg_types) -> sol::table {
        auto log = redlog::get_logger("w1.script_bindings");

        // get default calling convention
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          log.err("failed to create default calling convention");
          return sol::nil;
        }

        // convert lua arg types to c++ vector
        std::vector<w1::abi::calling_convention_base::arg_type> types;
        for (size_t i = 1; i <= arg_types.size(); i++) {
          sol::optional<std::string> type_str = arg_types[i];
          if (type_str) {
            w1::abi::calling_convention_base::arg_type arg_type = w1::abi::calling_convention_base::arg_type::INTEGER;

            if (*type_str == "int" || *type_str == "integer") {
              arg_type = w1::abi::calling_convention_base::arg_type::INTEGER;
            } else if (*type_str == "ptr" || *type_str == "pointer") {
              arg_type = w1::abi::calling_convention_base::arg_type::POINTER;
            } else if (*type_str == "float") {
              arg_type = w1::abi::calling_convention_base::arg_type::FLOAT;
            } else if (*type_str == "double") {
              arg_type = w1::abi::calling_convention_base::arg_type::DOUBLE;
            }

            types.push_back(arg_type);
          }
        }

        // create extraction context
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [vm, gpr, cc](uint64_t offset) -> uint64_t {
          uint64_t sp = cc->get_stack_pointer(gpr);
          uint64_t addr = sp + offset;
          uint64_t value = 0;

          try {
            std::memcpy(&value, reinterpret_cast<const void*>(addr), sizeof(uint64_t));
          } catch (...) {
            // stack read failed
          }

          return value;
        };

        // extract typed arguments
        std::vector<w1::abi::calling_convention_base::typed_arg> args = cc->extract_typed_args(ctx, types);

        // convert to lua table
        sol::state_view lua_view = lua.lua_state();
        sol::table result = lua_view.create_table();

        for (size_t i = 0; i < args.size(); i++) {
          sol::table arg_table = lua_view.create_table();

          // add type info
          switch (args[i].type) {
          case w1::abi::calling_convention_base::arg_type::INTEGER:
            arg_table["type"] = "integer";
            arg_table["value"] = args[i].value.integer;
            break;
          case w1::abi::calling_convention_base::arg_type::POINTER:
            arg_table["type"] = "pointer";
            arg_table["value"] = args[i].value.integer;
            break;
          case w1::abi::calling_convention_base::arg_type::FLOAT:
            arg_table["type"] = "float";
            arg_table["value"] = args[i].value.f32;
            break;
          case w1::abi::calling_convention_base::arg_type::DOUBLE:
            arg_table["type"] = "double";
            arg_table["value"] = args[i].value.f64;
            break;
          default:
            arg_table["type"] = "unknown";
            arg_table["value"] = args[i].value.integer;
            break;
          }

          arg_table["from_stack"] = args[i].from_stack;
          if (args[i].from_stack) {
            arg_table["stack_offset"] = args[i].stack_offset;
          }

          result[i + 1] = arg_table;
        }

        return result;
      }
  );

  // get return value
  w1_module.set_function("get_return_value", [](QBDI::GPRState* gpr) -> uint64_t {
    auto cc = w1::abi::create_default_calling_convention();
    if (!cc) {
      return 0;
    }

    return cc->get_integer_return(gpr);
  });

  // get float return value
  w1_module.set_function("get_float_return", [](QBDI::FPRState* fpr) -> double {
    auto cc = w1::abi::create_default_calling_convention();
    if (!cc) {
      return 0.0;
    }

    return cc->get_float_return(fpr);
  });

  // get calling convention info with optional convention name
  w1_module.set_function(
      "get_calling_convention_info", [&lua](sol::optional<std::string> convention_name) -> sol::table {
        w1::abi::calling_convention_ptr cc;

        if (convention_name) {
          // try to create specific convention
          try {
            cc = w1::abi::calling_convention_factory::instance().create_by_name(*convention_name);
          } catch (...) {
            // fall back to default
            cc = w1::abi::create_default_calling_convention();
          }
        } else {
          cc = w1::abi::create_default_calling_convention();
        }

        if (!cc) {
          return sol::nil;
        }

        sol::state_view lua_view = lua.lua_state();
        sol::table info = lua_view.create_table();

        info["id"] = w1::abi::to_string(cc->get_id());
        info["name"] = cc->get_name();
        info["description"] = cc->get_description();
        info["architecture"] = w1::abi::to_string(cc->get_architecture());
        info["is_native"] = cc->is_native_for_current_platform();

        // register info
        auto reg_info = cc->get_register_info();

        sol::table arg_regs = lua_view.create_table();
        for (size_t i = 0; i < reg_info.argument_registers.size(); i++) {
          arg_regs[i + 1] = reg_info.argument_registers[i];
        }
        info["argument_registers"] = arg_regs;

        info["return_register"] = reg_info.return_register;
        info["stack_alignment"] = cc->get_stack_alignment();

        // stack cleanup policy
        switch (cc->get_stack_cleanup()) {
        case w1::abi::calling_convention_base::stack_cleanup::CALLER:
          info["stack_cleanup"] = "caller";
          break;
        case w1::abi::calling_convention_base::stack_cleanup::CALLEE:
          info["stack_cleanup"] = "callee";
          break;
        case w1::abi::calling_convention_base::stack_cleanup::HYBRID:
          info["stack_cleanup"] = "hybrid";
          break;
        }

        return info;
      }
  );

  // convenience function for first few arguments
  w1_module.set_function(
      "get_arg", [](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t index) -> sol::optional<uint64_t> {
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          return sol::nullopt;
        }

        // create extraction context
        w1::abi::calling_convention_base::extraction_context ctx;
        ctx.gpr = gpr;
        ctx.fpr = fpr;
        ctx.read_stack = [](uint64_t) { return 0ULL; }; // simplified for now

        // extract arguments up to requested index
        std::vector<uint64_t> args = cc->extract_integer_args(ctx, index);

        if (index > 0 && index <= args.size()) {
          return args[index - 1]; // convert to 0-based
        }

        return sol::nullopt;
      }
  );

  logger.dbg("calling convention functions registered");
}

} // namespace w1::tracers::script::bindings