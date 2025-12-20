#include "root.hpp"

#include <QBDI.h>
#include <redlog.hpp>

#include <string>
#include <vector>

namespace w1::tracers::script::bindings {

namespace {

using event_type = runtime::callback_registry::event_type;

std::optional<event_type> parse_event(const sol::object& value) {
  if (!value.is<int>()) {
    return std::nullopt;
  }

  auto event = static_cast<event_type>(value.as<int>());
  switch (event) {
  case event_type::vm_start:
  case event_type::instruction_pre:
  case event_type::instruction_post:
  case event_type::sequence_entry:
  case event_type::sequence_exit:
  case event_type::basic_block_entry:
  case event_type::basic_block_exit:
  case event_type::basic_block_new:
  case event_type::exec_transfer_call:
  case event_type::exec_transfer_return:
  case event_type::syscall_entry:
  case event_type::syscall_exit:
  case event_type::signal:
  case event_type::memory_read:
  case event_type::memory_write:
  case event_type::memory_read_write:
  case event_type::code_addr:
  case event_type::code_range:
  case event_type::mnemonic:
  case event_type::memory_addr:
  case event_type::memory_range:
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
    options.address = table["address"].get<QBDI::rword>();
  }
  if (table["start"].valid()) {
    options.start = table["start"].get<QBDI::rword>();
  }
  if (table["end"].valid()) {
    options.end = table["end"].get<QBDI::rword>();
  }
  if (table["position"].valid()) {
    options.position = table["position"].get<QBDI::InstPosition>();
  }
  if (table["priority"].valid()) {
    options.priority = table["priority"].get<int>();
  }
  if (table["mnemonic"].valid()) {
    options.mnemonic = table["mnemonic"].get<std::string>();
  }
  if (table["access_type"].valid()) {
    options.access_type = table["access_type"].get<QBDI::MemoryAccessType>();
  } else if (table["type"].valid()) {
    options.access_type = table["type"].get<QBDI::MemoryAccessType>();
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
    sol::state& lua,
    sol::table& w1_module,
    runtime::script_context& context,
    runtime::callback_registry& callback_registry,
    runtime::api_manager& api_manager
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up root bindings");

  sol::table log_table = lua.create_table();
  log_table["info"] = [](const std::string& msg) { redlog::get_logger("w1.script").inf(msg); };
  log_table["debug"] = [](const std::string& msg) { redlog::get_logger("w1.script").dbg(msg); };
  log_table["warn"] = [](const std::string& msg) { redlog::get_logger("w1.script").wrn(msg); };
  log_table["error"] = [](const std::string& msg) { redlog::get_logger("w1.script").err(msg); };
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

  w1_module.set_function("off", [&callback_registry](uint64_t handle) { return callback_registry.remove_callback(handle); });

  sol::table event_table = lua.create_table();
  event_table["VM_START"] = static_cast<int>(event_type::vm_start);
  event_table["INSTRUCTION_PRE"] = static_cast<int>(event_type::instruction_pre);
  event_table["INSTRUCTION_POST"] = static_cast<int>(event_type::instruction_post);
  event_table["SEQUENCE_ENTRY"] = static_cast<int>(event_type::sequence_entry);
  event_table["SEQUENCE_EXIT"] = static_cast<int>(event_type::sequence_exit);
  event_table["BASIC_BLOCK_ENTRY"] = static_cast<int>(event_type::basic_block_entry);
  event_table["BASIC_BLOCK_EXIT"] = static_cast<int>(event_type::basic_block_exit);
  event_table["BASIC_BLOCK_NEW"] = static_cast<int>(event_type::basic_block_new);
  event_table["EXEC_TRANSFER_CALL"] = static_cast<int>(event_type::exec_transfer_call);
  event_table["EXEC_TRANSFER_RETURN"] = static_cast<int>(event_type::exec_transfer_return);
  event_table["SYSCALL_ENTRY"] = static_cast<int>(event_type::syscall_entry);
  event_table["SYSCALL_EXIT"] = static_cast<int>(event_type::syscall_exit);
  event_table["SIGNAL"] = static_cast<int>(event_type::signal);
  event_table["MEMORY_READ"] = static_cast<int>(event_type::memory_read);
  event_table["MEMORY_WRITE"] = static_cast<int>(event_type::memory_write);
  event_table["MEMORY_READ_WRITE"] = static_cast<int>(event_type::memory_read_write);
  event_table["CODE_ADDR"] = static_cast<int>(event_type::code_addr);
  event_table["CODE_RANGE"] = static_cast<int>(event_type::code_range);
  event_table["MNEMONIC"] = static_cast<int>(event_type::mnemonic);
  event_table["MEMORY_ADDR"] = static_cast<int>(event_type::memory_addr);
  event_table["MEMORY_RANGE"] = static_cast<int>(event_type::memory_range);
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

  sol::table vm_event = lua.create_table();
  vm_event["NO_EVENT"] = QBDI::VMEvent::NO_EVENT;
  vm_event["BASIC_BLOCK_ENTRY"] = QBDI::VMEvent::BASIC_BLOCK_ENTRY;
  vm_event["BASIC_BLOCK_EXIT"] = QBDI::VMEvent::BASIC_BLOCK_EXIT;
  vm_event["BASIC_BLOCK_NEW"] = QBDI::VMEvent::BASIC_BLOCK_NEW;
  vm_event["SEQUENCE_ENTRY"] = QBDI::VMEvent::SEQUENCE_ENTRY;
  vm_event["SEQUENCE_EXIT"] = QBDI::VMEvent::SEQUENCE_EXIT;
  vm_event["EXEC_TRANSFER_CALL"] = QBDI::VMEvent::EXEC_TRANSFER_CALL;
  vm_event["EXEC_TRANSFER_RETURN"] = QBDI::VMEvent::EXEC_TRANSFER_RETURN;
  vm_event["SYSCALL_ENTRY"] = QBDI::VMEvent::SYSCALL_ENTRY;
  vm_event["SYSCALL_EXIT"] = QBDI::VMEvent::SYSCALL_EXIT;
  vm_event["SIGNAL"] = QBDI::VMEvent::SIGNAL;
  enum_table["vm_event"] = vm_event;

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

  sol::table mem_permission = lua.create_table();
  mem_permission["PF_NONE"] = QBDI::PF_NONE;
  mem_permission["PF_READ"] = QBDI::PF_READ;
  mem_permission["PF_WRITE"] = QBDI::PF_WRITE;
  mem_permission["PF_EXEC"] = QBDI::PF_EXEC;
  enum_table["memory_permission"] = mem_permission;

  sol::table analysis_type = lua.create_table();
  analysis_type["ANALYSIS_INSTRUCTION"] = QBDI::AnalysisType::ANALYSIS_INSTRUCTION;
  analysis_type["ANALYSIS_DISASSEMBLY"] = QBDI::AnalysisType::ANALYSIS_DISASSEMBLY;
  analysis_type["ANALYSIS_OPERANDS"] = QBDI::AnalysisType::ANALYSIS_OPERANDS;
  analysis_type["ANALYSIS_SYMBOL"] = QBDI::AnalysisType::ANALYSIS_SYMBOL;
  analysis_type["ANALYSIS_JIT"] = QBDI::AnalysisType::ANALYSIS_JIT;
  enum_table["analysis_type"] = analysis_type;

  sol::table condition_type = lua.create_table();
  condition_type["CONDITION_NONE"] = QBDI::ConditionType::CONDITION_NONE;
  condition_type["CONDITION_ALWAYS"] = QBDI::ConditionType::CONDITION_ALWAYS;
  condition_type["CONDITION_NEVER"] = QBDI::ConditionType::CONDITION_NEVER;
  condition_type["CONDITION_EQUALS"] = QBDI::ConditionType::CONDITION_EQUALS;
  condition_type["CONDITION_NOT_EQUALS"] = QBDI::ConditionType::CONDITION_NOT_EQUALS;
  condition_type["CONDITION_ABOVE"] = QBDI::ConditionType::CONDITION_ABOVE;
  condition_type["CONDITION_BELOW_EQUALS"] = QBDI::ConditionType::CONDITION_BELOW_EQUALS;
  condition_type["CONDITION_ABOVE_EQUALS"] = QBDI::ConditionType::CONDITION_ABOVE_EQUALS;
  condition_type["CONDITION_BELOW"] = QBDI::ConditionType::CONDITION_BELOW;
  condition_type["CONDITION_GREAT"] = QBDI::ConditionType::CONDITION_GREAT;
  condition_type["CONDITION_LESS_EQUALS"] = QBDI::ConditionType::CONDITION_LESS_EQUALS;
  condition_type["CONDITION_GREAT_EQUALS"] = QBDI::ConditionType::CONDITION_GREAT_EQUALS;
  condition_type["CONDITION_LESS"] = QBDI::ConditionType::CONDITION_LESS;
  condition_type["CONDITION_EVEN"] = QBDI::ConditionType::CONDITION_EVEN;
  condition_type["CONDITION_ODD"] = QBDI::ConditionType::CONDITION_ODD;
  condition_type["CONDITION_OVERFLOW"] = QBDI::ConditionType::CONDITION_OVERFLOW;
  condition_type["CONDITION_NOT_OVERFLOW"] = QBDI::ConditionType::CONDITION_NOT_OVERFLOW;
  condition_type["CONDITION_SIGN"] = QBDI::ConditionType::CONDITION_SIGN;
  condition_type["CONDITION_NOT_SIGN"] = QBDI::ConditionType::CONDITION_NOT_SIGN;
  enum_table["condition_type"] = condition_type;

  sol::table operand_type = lua.create_table();
  operand_type["OPERAND_INVALID"] = QBDI::OperandType::OPERAND_INVALID;
  operand_type["OPERAND_IMM"] = QBDI::OperandType::OPERAND_IMM;
  operand_type["OPERAND_GPR"] = QBDI::OperandType::OPERAND_GPR;
  operand_type["OPERAND_PRED"] = QBDI::OperandType::OPERAND_PRED;
  operand_type["OPERAND_FPR"] = QBDI::OperandType::OPERAND_FPR;
  operand_type["OPERAND_SEG"] = QBDI::OperandType::OPERAND_SEG;
  enum_table["operand_type"] = operand_type;

  sol::table operand_flag = lua.create_table();
  operand_flag["OPERANDFLAG_NONE"] = QBDI::OperandFlag::OPERANDFLAG_NONE;
  operand_flag["OPERANDFLAG_ADDR"] = QBDI::OperandFlag::OPERANDFLAG_ADDR;
  operand_flag["OPERANDFLAG_PCREL"] = QBDI::OperandFlag::OPERANDFLAG_PCREL;
  operand_flag["OPERANDFLAG_UNDEFINED_EFFECT"] = QBDI::OperandFlag::OPERANDFLAG_UNDEFINED_EFFECT;
  operand_flag["OPERANDFLAG_IMPLICIT"] = QBDI::OperandFlag::OPERANDFLAG_IMPLICIT;
  enum_table["operand_flag"] = operand_flag;

  sol::table reg_access = lua.create_table();
  reg_access["REGISTER_UNUSED"] = QBDI::RegisterAccessType::REGISTER_UNUSED;
  reg_access["REGISTER_READ"] = QBDI::RegisterAccessType::REGISTER_READ;
  reg_access["REGISTER_WRITE"] = QBDI::RegisterAccessType::REGISTER_WRITE;
  reg_access["REGISTER_READ_WRITE"] = QBDI::RegisterAccessType::REGISTER_READ_WRITE;
  enum_table["register_access_type"] = reg_access;

  sol::table callback_priority = lua.create_table();
  callback_priority["PRIORITY_DEFAULT"] = QBDI::CallbackPriority::PRIORITY_DEFAULT;
  callback_priority["PRIORITY_MEMACCESS_LIMIT"] = QBDI::CallbackPriority::PRIORITY_MEMACCESS_LIMIT;
  enum_table["callback_priority"] = callback_priority;

  sol::table vm_error = lua.create_table();
  vm_error["INVALID_EVENTID"] = QBDI::VMError::INVALID_EVENTID;
  enum_table["vm_error"] = vm_error;

  sol::table vm_options = lua.create_table();
  vm_options["NO_OPT"] = QBDI::Options::NO_OPT;
  vm_options["OPT_DISABLE_FPR"] = QBDI::Options::OPT_DISABLE_FPR;
  vm_options["OPT_DISABLE_OPTIONAL_FPR"] = QBDI::Options::OPT_DISABLE_OPTIONAL_FPR;
  vm_options["OPT_DISABLE_ERRNO_BACKUP"] = QBDI::Options::OPT_DISABLE_ERRNO_BACKUP;
#if defined(__aarch64__) || defined(_M_ARM64)
  vm_options["OPT_DISABLE_LOCAL_MONITOR"] = QBDI::Options::OPT_DISABLE_LOCAL_MONITOR;
  vm_options["OPT_BYPASS_PAUTH"] = QBDI::Options::OPT_BYPASS_PAUTH;
  vm_options["OPT_ENABLE_BTI"] = QBDI::Options::OPT_ENABLE_BTI;
#elif defined(__arm__) || defined(_M_ARM)
  vm_options["OPT_DISABLE_LOCAL_MONITOR"] = QBDI::Options::OPT_DISABLE_LOCAL_MONITOR;
#elif defined(__x86_64__) || defined(_M_X64)
  vm_options["OPT_ATT_SYNTAX"] = QBDI::Options::OPT_ATT_SYNTAX;
  vm_options["OPT_ENABLE_FS_GS"] = QBDI::Options::OPT_ENABLE_FS_GS;
#endif
  enum_table["vm_option"] = vm_options;

  sol::table cpu_mode = lua.create_table();
#if defined(__aarch64__) || defined(_M_ARM64)
  cpu_mode["AARCH64"] = QBDI::CPUMode::AARCH64;
#elif defined(__arm__) || defined(_M_ARM)
  cpu_mode["ARM"] = QBDI::CPUMode::ARM;
#elif defined(__x86_64__) || defined(_M_X64)
  cpu_mode["X86_64"] = QBDI::CPUMode::X86_64;
#elif defined(__i386__) || defined(_M_IX86)
  cpu_mode["X86"] = QBDI::CPUMode::X86;
#endif
  cpu_mode["DEFAULT"] = QBDI::CPUMode::DEFAULT;
  enum_table["cpu_mode"] = cpu_mode;

  w1_module["enum"] = enum_table;

  sol::table config_table = lua.create_table();
  for (const auto& [key, value] : context.cfg().script_config) {
    config_table[key] = value;
  }
  w1_module["config"] = config_table;

  sol::table settings_table = lua.create_table();
  settings_table["script_path"] = context.cfg().script_path;
  settings_table["include_system_modules"] = context.cfg().include_system_modules;
  settings_table["verbose"] = context.cfg().verbose;

  sol::table module_filter = lua.create_table();
  add_list_table(module_filter, context.cfg().module_filter);
  settings_table["module_filter"] = module_filter;

  sol::table force_include = lua.create_table();
  add_list_table(force_include, context.cfg().force_include);
  settings_table["force_include"] = force_include;

  sol::table force_exclude = lua.create_table();
  add_list_table(force_exclude, context.cfg().force_exclude);
  settings_table["force_exclude"] = force_exclude;

  settings_table["use_default_conflicts"] = context.cfg().use_default_conflicts;
  settings_table["use_default_criticals"] = context.cfg().use_default_criticals;
  settings_table["verbose_instrumentation"] = context.cfg().verbose_instrumentation;

  w1_module["settings"] = settings_table;

  w1_module.set_function("api_enabled", [&api_manager]() { return api_manager.has_callbacks(); });
}

} // namespace w1::tracers::script::bindings
