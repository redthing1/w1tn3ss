#include "abi.hpp"

#include <w1tn3ss/abi/calling_convention_factory.hpp>
#include <w1tn3ss/abi/calling_convention_base.hpp>
#include <redlog.hpp>

#include <cstring>
#include <vector>

namespace w1::tracers::script::bindings {

void setup_abi_bindings(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up abi bindings");

  sol::table abi = lua.create_table();

  abi.set_function(
      "get_args",
      [&lua](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t count)
          -> sol::optional<sol::table> {
        auto log = redlog::get_logger("w1.script_bindings");
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          log.err("failed to create default calling convention");
          return sol::nullopt;
        }

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
          }
          return value;
        };

        std::vector<uint64_t> args = cc->extract_integer_args(ctx, count);
        sol::state_view lua_view = lua.lua_state();
        sol::table result = lua_view.create_table();
        for (size_t i = 0; i < args.size(); ++i) {
          result[i + 1] = args[i];
        }
        return result;
      }
  );

  abi.set_function(
      "get_typed_args",
      [&lua](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, sol::table arg_types)
          -> sol::optional<sol::table> {
        auto log = redlog::get_logger("w1.script_bindings");
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          log.err("failed to create default calling convention");
          return sol::nullopt;
        }

        std::vector<w1::abi::calling_convention_base::arg_type> types;
        for (size_t i = 1; i <= arg_types.size(); ++i) {
          sol::optional<std::string> type_str = arg_types[i];
          if (!type_str) {
            continue;
          }

          auto arg_type = w1::abi::calling_convention_base::arg_type::INTEGER;
          if (*type_str == "int" || *type_str == "integer" || *type_str == "size_t") {
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
          }
          return value;
        };

        std::vector<w1::abi::calling_convention_base::typed_arg> args = cc->extract_typed_args(ctx, types);
        sol::state_view lua_view = lua.lua_state();
        sol::table result = lua_view.create_table();

        for (size_t i = 0; i < args.size(); ++i) {
          sol::table arg_table = lua_view.create_table();
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

  abi.set_function("get_return_value", [](QBDI::GPRState* gpr) -> uint64_t {
    auto cc = w1::abi::create_default_calling_convention();
    if (!cc) {
      return 0;
    }
    return cc->get_integer_return(gpr);
  });

  abi.set_function("get_float_return", [](QBDI::FPRState* fpr) -> double {
    auto cc = w1::abi::create_default_calling_convention();
    if (!cc) {
      return 0.0;
    }
    return cc->get_float_return(fpr);
  });

  abi.set_function(
      "get_calling_convention",
      [&lua](sol::optional<std::string> convention_name) -> sol::optional<sol::table> {
        w1::abi::calling_convention_ptr cc;

        if (convention_name) {
          try {
            cc = w1::abi::calling_convention_factory::instance().create_by_name(*convention_name);
          } catch (...) {
            cc = w1::abi::create_default_calling_convention();
          }
        } else {
          cc = w1::abi::create_default_calling_convention();
        }

        if (!cc) {
          return sol::nullopt;
        }

        sol::state_view lua_view = lua.lua_state();
        sol::table info = lua_view.create_table();
        info["id"] = w1::abi::to_string(cc->get_id());
        info["name"] = cc->get_name();
        info["description"] = cc->get_description();
        info["architecture"] = w1::abi::to_string(cc->get_architecture());
        info["is_native"] = cc->is_native_for_current_platform();

        auto reg_info = cc->get_register_info();
        sol::table arg_regs = lua_view.create_table();
        for (size_t i = 0; i < reg_info.argument_registers.size(); ++i) {
          arg_regs[i + 1] = reg_info.argument_registers[i];
        }
        info["argument_registers"] = arg_regs;
        info["return_register"] = reg_info.return_register;
        info["stack_alignment"] = cc->get_stack_alignment();

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

  abi.set_function(
      "get_arg", [](QBDI::VM* vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, size_t index) -> sol::optional<uint64_t> {
        auto cc = w1::abi::create_default_calling_convention();
        if (!cc) {
          return sol::nullopt;
        }

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
          }
          return value;
        };

        auto args = cc->extract_integer_args(ctx, index + 1);
        if (args.size() <= index) {
          return sol::nullopt;
        }
        return args[index];
      }
  );

  w1_module["abi"] = abi;
}

} // namespace w1::tracers::script::bindings
