#include "abi.hpp"

namespace w1::tracers::script::bindings {

namespace {

std::string abi_name(w1::analysis::abi_kind kind) {
  switch (kind) {
  case w1::analysis::abi_kind::system_v_amd64:
    return "system_v_amd64";
  case w1::analysis::abi_kind::windows_amd64:
    return "windows_amd64";
  case w1::analysis::abi_kind::aarch64:
    return "aarch64";
  case w1::analysis::abi_kind::x86:
    return "x86";
  default:
    return "unknown";
  }
}

std::vector<std::string> abi_registers(w1::analysis::abi_kind kind) {
  switch (kind) {
  case w1::analysis::abi_kind::system_v_amd64:
    return {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
  case w1::analysis::abi_kind::windows_amd64:
    return {"rcx", "rdx", "r8", "r9"};
  case w1::analysis::abi_kind::aarch64:
    return {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
  default:
    return {};
  }
}

} // namespace

void setup_abi_bindings(sol::state& lua, sol::table& w1_module, runtime::script_context& context) {
  sol::table abi = lua.create_table();

  abi.set_function("get_calling_convention", [&lua, &context]() -> sol::table {
    sol::table info = lua.create_table();
    auto kind = context.abi().kind();
    info["id"] = static_cast<int>(kind);
    info["name"] = abi_name(kind);

    sol::table regs = lua.create_table();
    auto reg_list = abi_registers(kind);
    for (size_t i = 0; i < reg_list.size(); ++i) {
      regs[i + 1] = reg_list[i];
    }
    info["argument_registers"] = regs;
    return info;
  });

  abi.set_function(
      "get_args",
      [&lua, &context](QBDI::VM*, QBDI::GPRState* gpr, QBDI::FPRState*, size_t count) -> sol::table {
        auto args = context.abi().extract_arguments(context.memory(), gpr, count);
        sol::table result = lua.create_table(args.size(), 0);
        for (size_t i = 0; i < args.size(); ++i) {
          sol::table entry = lua.create_table();
          entry["raw_value"] = args[i].raw_value;
          entry["from_register"] = args[i].from_register;
          entry["is_valid"] = args[i].is_valid;
          result[i + 1] = entry;
        }
        return result;
      }
  );

  abi.set_function("get_return_value", [&context](QBDI::GPRState* gpr) {
    return context.abi().extract_return_value(gpr);
  });

  w1_module["abi"] = abi;
}

} // namespace w1::tracers::script::bindings
