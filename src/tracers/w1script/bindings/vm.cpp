#include "vm.hpp"

#include <w1tn3ss/util/register_access.hpp>
#include <redlog.hpp>

#include <QBDI/Range.h>
#include <QBDI/Memory.hpp>

#include <vector>

namespace w1::tracers::script::bindings {

namespace {

QBDI::VMAction dispatch_vm_callback(
    runtime::callback_store& store, size_t index, QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr
) {
  auto* callback = store.get(index);
  if (!callback) {
    return QBDI::VMAction::CONTINUE;
  }

  auto result = (*callback)(vm, gpr, fpr);
  if (!result.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  if (result.get_type() == sol::type::number) {
    return static_cast<QBDI::VMAction>(result.get<int>());
  }

  sol::optional<QBDI::VMAction> action = result;
  return action.value_or(QBDI::VMAction::CONTINUE);
}

QBDI::VMAction dispatch_vm_event_callback(
    runtime::callback_store& store,
    size_t index,
    QBDI::VMInstanceRef vm,
    const QBDI::VMState* state,
    QBDI::GPRState* gpr,
    QBDI::FPRState* fpr
) {
  auto* callback = store.get(index);
  if (!callback) {
    return QBDI::VMAction::CONTINUE;
  }

  auto result = (*callback)(vm, *state, gpr, fpr);
  if (!result.valid()) {
    return QBDI::VMAction::CONTINUE;
  }

  if (result.get_type() == sol::type::number) {
    return static_cast<QBDI::VMAction>(result.get<int>());
  }

  sol::optional<QBDI::VMAction> action = result;
  return action.value_or(QBDI::VMAction::CONTINUE);
}

std::vector<QBDI::InstrRuleDataCBK> build_instr_rule_callbacks(sol::table rules, runtime::callback_store& store) {
  std::vector<QBDI::InstrRuleDataCBK> callbacks;
  for (size_t i = 1; i <= rules.size(); ++i) {
    sol::object entry_obj = rules[i];
    if (!entry_obj.is<sol::table>()) {
      continue;
    }

    sol::table entry = entry_obj.as<sol::table>();
    sol::optional<sol::protected_function> cb = entry["callback"];
    if (!cb || !cb->valid()) {
      continue;
    }

    QBDI::InstPosition position = QBDI::PREINST;
    if (entry["position"].valid()) {
      position = entry["position"].get<QBDI::InstPosition>();
    }

    int priority = QBDI::PRIORITY_DEFAULT;
    if (entry["priority"].valid()) {
      priority = entry["priority"].get<int>();
    }

    size_t idx = store.add(std::move(cb.value()));
    callbacks.emplace_back(
        position,
        [&store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
          return dispatch_vm_callback(store, idx, vm, gpr, fpr);
        },
        priority
    );
  }
  return callbacks;
}

sol::table memory_map_to_table(sol::state& lua, const QBDI::MemoryMap& map) {
  sol::table info = lua.create_table();
  info["start"] = map.range.start();
  info["end"] = map.range.end();
  info["size"] = map.range.size();
  info["name"] = map.name;
  info["readable"] = (map.permission & QBDI::PF_READ) != 0;
  info["writable"] = (map.permission & QBDI::PF_WRITE) != 0;
  info["executable"] = (map.permission & QBDI::PF_EXEC) != 0;
  info["permissions"] = static_cast<int>(map.permission);
  return info;
}

sol::table inst_operands_to_table(sol::state_view lua, const QBDI::InstAnalysis& analysis) {
  sol::table operands = lua.create_table();
  if (!analysis.operands || analysis.numOperands == 0) {
    return operands;
  }

  for (size_t i = 0; i < analysis.numOperands; ++i) {
    operands[i + 1] = analysis.operands[i];
  }

  return operands;
}

std::vector<QBDI::rword> table_to_rwords(const sol::table& args) {
  std::vector<QBDI::rword> values;
  values.reserve(args.size());
  for (size_t i = 1; i <= args.size(); ++i) {
    sol::optional<QBDI::rword> arg = args[i];
    if (arg) {
      values.push_back(arg.value());
    }
  }
  return values;
}

} // namespace

void setup_vm_bindings(
    sol::state& lua,
    sol::table& w1_module,
    runtime::script_context& context,
    runtime::callback_store& callback_store
) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up vm bindings");

  sol::table vm_module = lua.create_table();

  lua.new_usertype<QBDI::InstAnalysis>(
      "InstAnalysis",
      "address", &QBDI::InstAnalysis::address,
      "instSize", &QBDI::InstAnalysis::instSize,
      "mnemonic", &QBDI::InstAnalysis::mnemonic,
      "disassembly", &QBDI::InstAnalysis::disassembly,
      "cpuMode", &QBDI::InstAnalysis::cpuMode,
      "affectControlFlow", &QBDI::InstAnalysis::affectControlFlow,
      "isBranch", &QBDI::InstAnalysis::isBranch,
      "isCall", &QBDI::InstAnalysis::isCall,
      "isReturn", &QBDI::InstAnalysis::isReturn,
      "isCompare", &QBDI::InstAnalysis::isCompare,
      "isPredicable", &QBDI::InstAnalysis::isPredicable,
      "isMoveImm", &QBDI::InstAnalysis::isMoveImm,
      "mayLoad", &QBDI::InstAnalysis::mayLoad,
      "mayStore", &QBDI::InstAnalysis::mayStore,
      "loadSize", &QBDI::InstAnalysis::loadSize,
      "storeSize", &QBDI::InstAnalysis::storeSize,
      "condition", &QBDI::InstAnalysis::condition,
      "flagsAccess", &QBDI::InstAnalysis::flagsAccess,
      "numOperands", &QBDI::InstAnalysis::numOperands,
      "operands", sol::readonly_property([](const QBDI::InstAnalysis& analysis, sol::this_state state) {
        return inst_operands_to_table(sol::state_view(state), analysis);
      }),
      "symbolName", &QBDI::InstAnalysis::symbolName,
      "symbolOffset", &QBDI::InstAnalysis::symbolOffset,
      "moduleName", &QBDI::InstAnalysis::moduleName,
      "patchAddress", &QBDI::InstAnalysis::patchAddress,
      "patchSize", &QBDI::InstAnalysis::patchSize,
      "patchInstOffset", &QBDI::InstAnalysis::patchInstOffset,
      "patchInstSize", &QBDI::InstAnalysis::patchInstSize,
      "mayLoad_LLVM", &QBDI::InstAnalysis::mayLoad_LLVM,
      "mayStore_LLVM", &QBDI::InstAnalysis::mayStore_LLVM,
      "opcode_LLVM", &QBDI::InstAnalysis::opcode_LLVM
  );

  lua.new_usertype<QBDI::OperandAnalysis>(
      "OperandAnalysis",
      "type", &QBDI::OperandAnalysis::type,
      "flag", &QBDI::OperandAnalysis::flag,
      "value", &QBDI::OperandAnalysis::value,
      "size", &QBDI::OperandAnalysis::size,
      "regOff", &QBDI::OperandAnalysis::regOff,
      "regCtxIdx", &QBDI::OperandAnalysis::regCtxIdx,
      "regName", &QBDI::OperandAnalysis::regName,
      "regAccess", &QBDI::OperandAnalysis::regAccess
  );

  lua.new_usertype<QBDI::MemoryAccess>(
      "MemoryAccess",
      "instAddress", &QBDI::MemoryAccess::instAddress,
      "accessAddress", &QBDI::MemoryAccess::accessAddress,
      "value", &QBDI::MemoryAccess::value,
      "size", &QBDI::MemoryAccess::size,
      "type", &QBDI::MemoryAccess::type,
      "flags", &QBDI::MemoryAccess::flags
  );

  lua.new_usertype<QBDI::VMState>(
      "VMState",
      "event", &QBDI::VMState::event,
      "basicBlockStart", &QBDI::VMState::basicBlockStart,
      "basicBlockEnd", &QBDI::VMState::basicBlockEnd,
      "sequenceStart", &QBDI::VMState::sequenceStart,
      "sequenceEnd", &QBDI::VMState::sequenceEnd,
      "lastSignal", &QBDI::VMState::lastSignal
  );

  lua.new_usertype<QBDI::GPRState>("GPRState");
  lua.new_usertype<QBDI::FPRState>("FPRState");

  auto vm_type = lua.new_usertype<QBDI::VM>(
      "VM",
      sol::constructors<QBDI::VM()>(),
      "clearCache", &QBDI::VM::clearCache,
      "clearAllCache", &QBDI::VM::clearAllCache,
      "getNbExecBlock", &QBDI::VM::getNbExecBlock,
      "reduceCacheTo", &QBDI::VM::reduceCacheTo,
      "precacheBasicBlock", &QBDI::VM::precacheBasicBlock,

      "getGPRState", &QBDI::VM::getGPRState,
      "setGPRState", &QBDI::VM::setGPRState,
      "getFPRState", &QBDI::VM::getFPRState,
      "setFPRState", &QBDI::VM::setFPRState,

      "getOptions", &QBDI::VM::getOptions,
      "setOptions", &QBDI::VM::setOptions,

      "addInstrumentedRange", &QBDI::VM::addInstrumentedRange,
      "addInstrumentedModule", &QBDI::VM::addInstrumentedModule,
      "addInstrumentedModuleFromAddr", &QBDI::VM::addInstrumentedModuleFromAddr,
      "instrumentAllExecutableMaps", &QBDI::VM::instrumentAllExecutableMaps,
      "removeInstrumentedRange", &QBDI::VM::removeInstrumentedRange,
      "removeInstrumentedModule", &QBDI::VM::removeInstrumentedModule,
      "removeInstrumentedModuleFromAddr", &QBDI::VM::removeInstrumentedModuleFromAddr,
      "removeAllInstrumentedRanges", &QBDI::VM::removeAllInstrumentedRanges,

      "run", &QBDI::VM::run,
      "call", sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, const std::vector<QBDI::rword>& args) {
            return vm->call(retval, function, args);
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) { return vm->call(retval, function); }
      ),
      "callA", sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, sol::table args) {
            auto values = table_to_rwords(args);
            return vm->callA(retval, function, static_cast<uint32_t>(values.size()), values.data());
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) {
            return vm->callA(retval, function, 0, nullptr);
          }
      ),
      "callV", sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, sol::table args) {
            auto values = table_to_rwords(args);
            return vm->callA(retval, function, static_cast<uint32_t>(values.size()), values.data());
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) {
            return vm->callA(retval, function, 0, nullptr);
          }
      ),
      "switchStackAndCall", &QBDI::VM::switchStackAndCall,
      "switchStackAndCallA", sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, sol::table args,
             sol::optional<uint32_t> stack_size) {
            auto values = table_to_rwords(args);
            return vm->switchStackAndCallA(
                retval,
                function,
                static_cast<uint32_t>(values.size()),
                values.data(),
                stack_size.value_or(0x20000)
            );
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) {
            return vm->switchStackAndCallA(retval, function, 0, nullptr, 0x20000);
          }
      ),
      "switchStackAndCallV", sol::overload(
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function, sol::table args,
             sol::optional<uint32_t> stack_size) {
            auto values = table_to_rwords(args);
            return vm->switchStackAndCallA(
                retval,
                function,
                static_cast<uint32_t>(values.size()),
                values.data(),
                stack_size.value_or(0x20000)
            );
          },
          [](QBDI::VM* vm, QBDI::rword* retval, QBDI::rword function) {
            return vm->switchStackAndCallA(retval, function, 0, nullptr, 0x20000);
          }
      ),

      "getInstAnalysis", sol::overload(
          [](QBDI::VM* vm) { return vm->getInstAnalysis(); },
          [](QBDI::VM* vm, QBDI::AnalysisType type) { return vm->getInstAnalysis(type); }
      ),
      "getCachedInstAnalysis", sol::overload(
          [](QBDI::VM* vm, QBDI::rword addr) { return vm->getCachedInstAnalysis(addr); },
          [](QBDI::VM* vm, QBDI::rword addr, QBDI::AnalysisType type) { return vm->getCachedInstAnalysis(addr, type); }
      ),
      "getJITInstAnalysis", sol::overload(
          [](QBDI::VM* vm, QBDI::rword addr) { return vm->getJITInstAnalysis(addr); },
          [](QBDI::VM* vm, QBDI::rword addr, QBDI::AnalysisType type) { return vm->getJITInstAnalysis(addr, type); }
      ),

      "recordMemoryAccess", &QBDI::VM::recordMemoryAccess,
      "getInstMemoryAccess", &QBDI::VM::getInstMemoryAccess,
      "getBBMemoryAccess", &QBDI::VM::getBBMemoryAccess,

      "addCodeCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::InstPosition pos, sol::protected_function callback,
                            sol::optional<int> priority) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addCodeCB(
                pos,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                },
                priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addMnemonicCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, const char* mnemonic, QBDI::InstPosition pos,
                            sol::protected_function callback, sol::optional<int> priority) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addMnemonicCB(
                mnemonic, pos,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                },
                priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addCodeAddrCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::rword address, QBDI::InstPosition pos, sol::protected_function callback,
                            sol::optional<int> priority) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addCodeAddrCB(
                address, pos,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                },
                priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addCodeRangeCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::rword start, QBDI::rword end, QBDI::InstPosition pos,
                            sol::protected_function callback, sol::optional<int> priority) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addCodeRangeCB(
                start, end, pos,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                },
                priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addMemAccessCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::MemoryAccessType type, sol::protected_function callback,
                            sol::optional<int> priority) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addMemAccessCB(
                type,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                },
                priority.value_or(QBDI::PRIORITY_DEFAULT)
            );
          }
      ),

      "addVMEventCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::VMEvent mask, sol::protected_function callback) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addVMEventCB(
                mask,
                [&callback_store, idx](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr,
                                       QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_event_callback(callback_store, idx, vm, state, gpr, fpr);
                }
            );
          }
      ),

      "addMemAddrCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::rword address, QBDI::MemoryAccessType type,
                            sol::protected_function callback) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addMemAddrCB(
                address, type,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                }
            );
          }
      ),

      "addMemRangeCB",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::rword start, QBDI::rword end, QBDI::MemoryAccessType type,
                            sol::protected_function callback) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addMemRangeCB(
                start, end, type,
                [&callback_store, idx](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr) -> QBDI::VMAction {
                  return dispatch_vm_callback(callback_store, idx, vm, gpr, fpr);
                }
            );
          }
      ),

      "addInstrRule",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::AnalysisType type, sol::protected_function callback) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addInstrRule(
                [idx, &callback_store](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis)
                    -> std::vector<QBDI::InstrRuleDataCBK> {
                  auto* rule_cb = callback_store.get(idx);
                  if (!rule_cb) {
                    return {};
                  }

                  auto result = (*rule_cb)(vm, analysis);
                  if (!result.valid() || result.get_type() != sol::type::table) {
                    return {};
                  }

                  sol::table rules = result;
                  return build_instr_rule_callbacks(rules, callback_store);
                },
                type
            );
          }
      ),

      "addInstrRuleRange",
      sol::overload(
          [&callback_store](QBDI::VM* vm, QBDI::rword start, QBDI::rword end, QBDI::AnalysisType type,
                            sol::protected_function callback) -> uint32_t {
            size_t idx = callback_store.add(std::move(callback));
            return vm->addInstrRuleRange(
                start, end,
                [idx, &callback_store](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis)
                    -> std::vector<QBDI::InstrRuleDataCBK> {
                  auto* rule_cb = callback_store.get(idx);
                  if (!rule_cb) {
                    return {};
                  }

                  auto result = (*rule_cb)(vm, analysis);
                  if (!result.valid() || result.get_type() != sol::type::table) {
                    return {};
                  }

                  sol::table rules = result;
                  return build_instr_rule_callbacks(rules, callback_store);
                },
                type
            );
          }
      ),

      "addInstrRuleRangeSet",
      sol::overload(
          [&callback_store](QBDI::VM* vm, sol::table ranges, QBDI::AnalysisType type, sol::protected_function callback)
              -> uint32_t {
            QBDI::RangeSet<QBDI::rword> range_set;
            for (size_t i = 1; i <= ranges.size(); ++i) {
              sol::object range_obj = ranges[i];
              if (!range_obj.is<sol::table>()) {
                continue;
              }
              sol::table range_table = range_obj.as<sol::table>();
              if (!range_table["start"].valid() || !range_table["end"].valid()) {
                continue;
              }
              QBDI::rword start = range_table["start"].get<QBDI::rword>();
              QBDI::rword end = range_table["end"].get<QBDI::rword>();
              range_set.add(QBDI::Range<QBDI::rword>(start, end));
            }

            size_t idx = callback_store.add(std::move(callback));
            return vm->addInstrRuleRangeSet(
                range_set,
                [idx, &callback_store](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis)
                    -> std::vector<QBDI::InstrRuleDataCBK> {
                  auto* rule_cb = callback_store.get(idx);
                  if (!rule_cb) {
                    return {};
                  }

                  auto result = (*rule_cb)(vm, analysis);
                  if (!result.valid() || result.get_type() != sol::type::table) {
                    return {};
                  }

                  sol::table rules = result;
                  return build_instr_rule_callbacks(rules, callback_store);
                },
                type
            );
          }
      ),

      "deleteInstrumentation",
      [](QBDI::VM* vm, uint32_t id) -> bool { return vm->deleteInstrumentation(id); },
      "deleteAllInstrumentations",
      [](QBDI::VM* vm) { vm->deleteAllInstrumentations(); },

      "getErrno", &QBDI::VM::getErrno,
      "setErrno", &QBDI::VM::setErrno
  );

  if (!lua["QBDI"].valid()) {
    lua["QBDI"] = lua.create_table();
  }
  lua["QBDI"]["VM"] = vm_type;

  vm_module.set_function("get", [&context]() { return context.vm(); });

  vm_module.set_function("memory_maps", [&lua](sol::optional<bool> full_path) -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table maps = lua_view.create_table();
    bool include = full_path.value_or(false);
    auto map_list = QBDI::getCurrentProcessMaps(include);
    for (size_t i = 0; i < map_list.size(); ++i) {
      maps[i + 1] = memory_map_to_table(lua, map_list[i]);
    }
    return maps;
  });

  vm_module.set_function(
      "memory_map_for",
      [&lua](QBDI::rword address, sol::optional<bool> full_path) -> sol::optional<sol::table> {
        auto map_list = QBDI::getCurrentProcessMaps(full_path.value_or(false));
        for (const auto& map : map_list) {
          if (map.range.contains(address)) {
            return memory_map_to_table(lua, map);
          }
        }
        return sol::nullopt;
      }
  );

  vm_module.set_function("remote_memory_maps", [&lua](QBDI::rword pid, sol::optional<bool> full_path) -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table maps = lua_view.create_table();
    auto map_list = QBDI::getRemoteProcessMaps(pid, full_path.value_or(false));
    for (size_t i = 0; i < map_list.size(); ++i) {
      maps[i + 1] = memory_map_to_table(lua, map_list[i]);
    }
    return maps;
  });

  vm_module.set_function("module_names", [&lua]() -> sol::table {
    sol::state_view lua_view = lua.lua_state();
    sol::table modules = lua_view.create_table();
    auto module_names = QBDI::getModuleNames();
    for (size_t i = 0; i < module_names.size(); ++i) {
      modules[i + 1] = module_names[i];
    }
    return modules;
  });

  vm_module.set_function("allocate_virtual_stack", [](QBDI::VM* vm, uint32_t stack_size) -> sol::optional<QBDI::rword> {
    QBDI::GPRState* state = vm->getGPRState();
    uint8_t* stack = nullptr;
    if (QBDI::allocateVirtualStack(state, stack_size, &stack)) {
      return reinterpret_cast<QBDI::rword>(stack);
    }
    return sol::nullopt;
  });

  vm_module.set_function("simulate_call", [](QBDI::VM* vm, QBDI::rword return_addr, sol::table args) -> bool {
    QBDI::GPRState* state = vm->getGPRState();
    std::vector<QBDI::rword> arg_vector;
    for (size_t i = 1; i <= args.size(); ++i) {
      sol::optional<QBDI::rword> arg = args[i];
      if (arg) {
        arg_vector.push_back(arg.value());
      }
    }
    QBDI::simulateCall(state, return_addr, arg_vector);
    return true;
  });

  vm_module.set_function("aligned_alloc", [](size_t size, size_t alignment) -> sol::optional<QBDI::rword> {
    void* ptr = QBDI::alignedAlloc(size, alignment);
    if (!ptr) {
      return sol::nullopt;
    }
    return reinterpret_cast<QBDI::rword>(ptr);
  });

  vm_module.set_function("aligned_free", [](QBDI::rword ptr) {
    if (ptr != 0) {
      QBDI::alignedFree(reinterpret_cast<void*>(ptr));
    }
  });

  w1_module["vm"] = vm_module;
}

} // namespace w1::tracers::script::bindings
