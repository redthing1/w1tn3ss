#include "root.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <optional>
#include <string>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

using event_type = runtime::callback_registry::event_type;

const char* system_policy_name(w1::core::system_module_policy policy) {
  switch (policy) {
  case w1::core::system_module_policy::exclude_all:
    return "exclude_all";
  case w1::core::system_module_policy::include_critical:
    return "include_critical";
  case w1::core::system_module_policy::include_all:
    return "include_all";
  }
  return "exclude_all";
}

std::optional<event_type> parse_event(const sol::object& value) {
  if (!value.is<int>()) {
    return std::nullopt;
  }

  auto event = static_cast<event_type>(value.as<int>());
  switch (event) {
  case event_type::thread_start:
  case event_type::thread_stop:
  case event_type::vm_start:
  case event_type::vm_stop:
  case event_type::instruction_pre:
  case event_type::instruction_post:
  case event_type::basic_block_entry:
  case event_type::basic_block_exit:
  case event_type::exec_transfer_call:
  case event_type::exec_transfer_return:
  case event_type::memory_read:
  case event_type::memory_write:
  case event_type::memory_read_write:
    return event;
  }

  return std::nullopt;
}

runtime::callback_registry::registration_options parse_options(const sol::optional<sol::table>& opts) {
  runtime::callback_registry::registration_options options;

  if (!opts) {
    return options;
  }

  sol::table table = *opts;

  if (table["address"].valid()) {
    options.address = table["address"].get<uint64_t>();
  }
  if (table["start"].valid()) {
    options.start = table["start"].get<uint64_t>();
  }
  if (table["end"].valid()) {
    options.end = table["end"].get<uint64_t>();
  }
  if (table["mnemonic"].valid()) {
    options.mnemonic = table["mnemonic"].get<std::string>();
  }
  if (table["access_type"].valid()) {
    options.access_type = static_cast<QBDI::MemoryAccessType>(table["access_type"].get<int>());
  } else if (table["type"].valid()) {
    options.access_type = static_cast<QBDI::MemoryAccessType>(table["type"].get<int>());
  }

  return options;
}

void add_list_table(sol::table& table, const std::vector<std::string>& values) {
  for (size_t i = 0; i < values.size(); ++i) {
    table[i + 1] = values[i];
  }
}

} // namespace

void setup_root_bindings(
    sol::state& lua, sol::table& w1_module, runtime::script_context& context,
    runtime::callback_registry& callback_registry
) {
  auto logger = redlog::get_logger("w1script.bindings");
  logger.dbg("setting up root bindings");

  sol::table log_table = lua.create_table();
  log_table["info"] = [](const std::string& msg) { redlog::get_logger("w1script.lua").inf(msg); };
  log_table["debug"] = [](const std::string& msg) { redlog::get_logger("w1script.lua").dbg(msg); };
  log_table["warn"] = [](const std::string& msg) { redlog::get_logger("w1script.lua").wrn(msg); };
  log_table["error"] = [](const std::string& msg) { redlog::get_logger("w1script.lua").err(msg); };
  w1_module["log"] = log_table;

  w1_module.set_function(
      "on",
      [&callback_registry](sol::object event_obj, sol::protected_function callback, sol::optional<sol::table> opts)
          -> sol::optional<uint64_t> {
        auto event = parse_event(event_obj);
        if (!event) {
          return sol::nullopt;
        }

        auto options = parse_options(opts);
        uint64_t handle = callback_registry.register_callback(*event, std::move(callback), options);
        if (handle == 0) {
          return sol::nullopt;
        }
        return handle;
      }
  );

  w1_module.set_function("off", [&callback_registry](uint64_t handle) {
    return callback_registry.remove_callback(handle);
  });

  sol::table event_table = lua.create_table();
  event_table["THREAD_START"] = static_cast<int>(event_type::thread_start);
  event_table["THREAD_STOP"] = static_cast<int>(event_type::thread_stop);
  event_table["VM_START"] = static_cast<int>(event_type::vm_start);
  event_table["VM_STOP"] = static_cast<int>(event_type::vm_stop);
  event_table["INSTRUCTION_PRE"] = static_cast<int>(event_type::instruction_pre);
  event_table["INSTRUCTION_POST"] = static_cast<int>(event_type::instruction_post);
  event_table["BASIC_BLOCK_ENTRY"] = static_cast<int>(event_type::basic_block_entry);
  event_table["BASIC_BLOCK_EXIT"] = static_cast<int>(event_type::basic_block_exit);
  event_table["EXEC_TRANSFER_CALL"] = static_cast<int>(event_type::exec_transfer_call);
  event_table["EXEC_TRANSFER_RETURN"] = static_cast<int>(event_type::exec_transfer_return);
  event_table["MEMORY_READ"] = static_cast<int>(event_type::memory_read);
  event_table["MEMORY_WRITE"] = static_cast<int>(event_type::memory_write);
  event_table["MEMORY_READ_WRITE"] = static_cast<int>(event_type::memory_read_write);
  w1_module["event"] = event_table;

  sol::table enum_table = lua.create_table();

  sol::table vm_action = lua.create_table();
  vm_action["CONTINUE"] = QBDI::VMAction::CONTINUE;
  vm_action["SKIP_INST"] = QBDI::VMAction::SKIP_INST;
  vm_action["SKIP_PATCH"] = QBDI::VMAction::SKIP_PATCH;
  vm_action["BREAK_TO_VM"] = QBDI::VMAction::BREAK_TO_VM;
  vm_action["STOP"] = QBDI::VMAction::STOP;
  enum_table["vm_action"] = vm_action;

  sol::table inst_position = lua.create_table();
  inst_position["PREINST"] = QBDI::InstPosition::PREINST;
  inst_position["POSTINST"] = QBDI::InstPosition::POSTINST;
  enum_table["inst_position"] = inst_position;

  sol::table analysis_type = lua.create_table();
  analysis_type["ANALYSIS_INSTRUCTION"] = QBDI::AnalysisType::ANALYSIS_INSTRUCTION;
  analysis_type["ANALYSIS_DISASSEMBLY"] = QBDI::AnalysisType::ANALYSIS_DISASSEMBLY;
  analysis_type["ANALYSIS_OPERANDS"] = QBDI::AnalysisType::ANALYSIS_OPERANDS;
  analysis_type["ANALYSIS_SYMBOL"] = QBDI::AnalysisType::ANALYSIS_SYMBOL;
  analysis_type["ANALYSIS_JIT"] = QBDI::AnalysisType::ANALYSIS_JIT;
  enum_table["analysis_type"] = analysis_type;

  sol::table mem_access = lua.create_table();
  mem_access["MEMORY_READ"] = QBDI::MemoryAccessType::MEMORY_READ;
  mem_access["MEMORY_WRITE"] = QBDI::MemoryAccessType::MEMORY_WRITE;
  mem_access["MEMORY_READ_WRITE"] = QBDI::MemoryAccessType::MEMORY_READ_WRITE;
  enum_table["memory_access_type"] = mem_access;

  sol::table mem_flags = lua.create_table();
  mem_flags["MEMORY_NO_FLAGS"] = QBDI::MemoryAccessFlags::MEMORY_NO_FLAGS;
  mem_flags["MEMORY_UNKNOWN_SIZE"] = QBDI::MemoryAccessFlags::MEMORY_UNKNOWN_SIZE;
  mem_flags["MEMORY_MINIMUM_SIZE"] = QBDI::MemoryAccessFlags::MEMORY_MINIMUM_SIZE;
  mem_flags["MEMORY_UNKNOWN_VALUE"] = QBDI::MemoryAccessFlags::MEMORY_UNKNOWN_VALUE;
  enum_table["memory_access_flags"] = mem_flags;

  w1_module["enum"] = enum_table;

  sol::table config_table = lua.create_table();
  for (const auto& [key, value] : context.config().script_args) {
    config_table[key] = value;
  }
  w1_module["config"] = config_table;

  sol::table settings_table = lua.create_table();
  settings_table["script_path"] = context.config().script_path;
  const auto system_policy = context.config().common.instrumentation.system_policy;
  settings_table["system_policy"] = system_policy_name(system_policy);
  settings_table["include_unnamed_modules"] = context.config().common.instrumentation.include_unnamed_modules;
  settings_table["use_default_excludes"] = context.config().common.instrumentation.use_default_excludes;
  settings_table["verbose"] = context.config().common.verbose;

  sol::table include_modules = lua.create_table();
  add_list_table(include_modules, context.config().common.instrumentation.include_modules);
  settings_table["include_modules"] = include_modules;

  sol::table exclude_modules = lua.create_table();
  add_list_table(exclude_modules, context.config().common.instrumentation.exclude_modules);
  settings_table["exclude_modules"] = exclude_modules;

  w1_module["settings"] = settings_table;
}

} // namespace w1::tracers::script::bindings
