#pragma once

#include <functional>
#include <iostream>
#include <type_traits>

#include <QBDI.h>
#include <redlog/redlog.hpp>

namespace w1 {

template <typename TTracer> class tracer_engine {
public:
  tracer_engine(QBDI::VMInstanceRef vm, TTracer& tracer)
      : vm_(static_cast<QBDI::VM*>(vm)), tracer_(tracer), owns_vm_(false) {
    log_.inf(
        "tracer engine created with existing QBDI::VM instance", redlog::field("tracer", tracer.get_name()),
        redlog::field("vm", static_cast<void*>(vm_))
    );
  }

  tracer_engine(TTracer& tracer) : tracer_(tracer), owns_vm_(true) {
    try {
      vm_ = new QBDI::VM();
      log_.inf("tracer engine created with new vm", redlog::field("tracer_name", tracer.get_name()));
    } catch (...) {
      vm_ = nullptr;
      owns_vm_ = false;
      log_.error("failed to create QBDI::VM instance, tracer engine will not function");
      // re-throw the exception to be handled by the caller
      throw;
    }
  }

public:
  ~tracer_engine() {
    if (owns_vm_ && vm_) {
      delete vm_;
    }
  }

  bool instrument() {
    if (!vm_) {
      log_.error("QBDI::VM instance is null, cannot instrument");
      return false;
    }

    register_all_callbacks();
    return true;
  }

  bool run(QBDI::rword start, QBDI::rword stop) {
    if (!vm_) {
      log_.error("QBDI::VM instance is null, cannot run");
      return false;
    }

    log_.inf(
        "executing QBDI::VM::run", redlog::field("tracer", tracer_.get_name()), redlog::field("start", "0x%08x", start),
        redlog::field("stop", "0x%08x", stop)
    );
    return vm_->run(start, stop);
  }

  bool call(QBDI::rword* retval, QBDI::rword function_ptr, const std::vector<QBDI::rword>& args) {
    if (!vm_) {
      return false;
    }

    log_.inf(
        "executing QBDI::VM::call", redlog::field("tracer", tracer_.get_name()),
        redlog::field("function_ptr", "0x%08x", function_ptr), redlog::field("args", args)
    );
    return vm_->call(retval, function_ptr, args);
  }

  QBDI::VM* get_vm() const { return vm_; }

  // Parameterized callback registration methods (public interface)

  // Address-specific instruction callbacks
  uint32_t add_code_addr_callback(QBDI::rword address, QBDI::InstPosition pos) {
    if constexpr (has_code_addr_callback_v<TTracer>) {
      log_.vrb(
          "registering code address callback", redlog::field("address", "0x%08x", address),
          redlog::field("position", pos == QBDI::PREINST ? "PREINST" : "POSTINST")
      );

      uint32_t id = vm_->addCodeAddrCB(
          address, pos,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_code_addr(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered code address callback", redlog::field("address", "0x%08x", address), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register code address callback", redlog::field("address", "0x%08x", address),
            redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("code address callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Address range instruction callbacks
  uint32_t add_code_range_callback(QBDI::rword start, QBDI::rword end, QBDI::InstPosition pos) {
    if constexpr (has_code_range_callback_v<TTracer>) {
      log_.vrb(
          "registering code range callback", redlog::field("start", "0x%08x", start),
          redlog::field("end", "0x%08x", end), redlog::field("position", pos == QBDI::PREINST ? "PREINST" : "POSTINST")
      );

      uint32_t id = vm_->addCodeRangeCB(
          start, end, pos,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_code_range(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered code range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register code range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("code range callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Mnemonic-specific instruction callbacks
  uint32_t add_mnemonic_callback(const char* mnemonic, QBDI::InstPosition pos) {
    if constexpr (has_mnemonic_callback_v<TTracer>) {
      log_.vrb(
          "registering mnemonic callback", redlog::field("mnemonic", mnemonic),
          redlog::field("position", pos == QBDI::PREINST ? "PREINST" : "POSTINST")
      );

      uint32_t id = vm_->addMnemonicCB(
          mnemonic, pos,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_mnemonic(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf("registered mnemonic callback", redlog::field("mnemonic", mnemonic), redlog::field("id", id));
      } else {
        log_.error(
            "failed to register mnemonic callback", redlog::field("mnemonic", mnemonic), redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("mnemonic callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Virtual memory address callbacks (high performance cost)
  uint32_t add_mem_addr_callback(QBDI::rword address, QBDI::MemoryAccessType type) {
    if constexpr (has_mem_addr_callback_v<TTracer>) {
      log_.vrb(
          "registering memory address callback", redlog::field("address", "0x%08x", address),
          redlog::field("type", type)
      );

      uint32_t id = vm_->addMemAddrCB(
          address, type,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_mem_addr(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered memory address callback", redlog::field("address", "0x%08x", address), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register memory address callback", redlog::field("address", "0x%08x", address),
            redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("memory address callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Virtual memory range callbacks (high performance cost)
  uint32_t add_mem_range_callback(QBDI::rword start, QBDI::rword end, QBDI::MemoryAccessType type) {
    if constexpr (has_mem_range_callback_v<TTracer>) {
      log_.vrb(
          "registering memory range callback", redlog::field("start", "0x%08x", start),
          redlog::field("end", "0x%08x", end), redlog::field("type", type)
      );

      uint32_t id = vm_->addMemRangeCB(
          start, end, type,
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_mem_range(vm, gpr, fpr);
          },
          this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered memory range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register memory range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("memory range callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Instruction rule callbacks
  uint32_t add_instr_rule_callback(QBDI::AnalysisType type) {
    if constexpr (has_instr_rule_callback_v<TTracer>) {
      log_.vrb("registering instruction rule callback", redlog::field("type", type));

      uint32_t id = vm_->addInstrRule(
          [](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis,
             void* data) -> std::vector<QBDI::InstrRuleDataCBK> {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_instr_rule(vm, analysis, data);
          },
          type, this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf("registered instruction rule callback", redlog::field("type", type), redlog::field("id", id));
      } else {
        log_.error(
            "failed to register instruction rule callback", redlog::field("type", type), redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("instruction rule callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Instruction rule range callbacks
  uint32_t add_instr_rule_range_callback(QBDI::rword start, QBDI::rword end, QBDI::AnalysisType type) {
    if constexpr (has_instr_rule_range_callback_v<TTracer>) {
      log_.vrb(
          "registering instruction rule range callback", redlog::field("start", "0x%08x", start),
          redlog::field("end", "0x%08x", end), redlog::field("type", type)
      );

      uint32_t id = vm_->addInstrRuleRange(
          start, end,
          [](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis,
             void* data) -> std::vector<QBDI::InstrRuleDataCBK> {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_instr_rule_range(vm, analysis, data);
          },
          type, this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered instruction rule range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register instruction rule range callback", redlog::field("start", "0x%08x", start),
            redlog::field("end", "0x%08x", end), redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("instruction rule range callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

  // Instruction rule range set callbacks
  uint32_t add_instr_rule_range_set_callback(const QBDI::RangeSet<QBDI::rword>& range, QBDI::AnalysisType type) {
    if constexpr (has_instr_rule_range_set_callback_v<TTracer>) {
      log_.vrb("registering instruction rule range set callback", redlog::field("type", type));

      uint32_t id = vm_->addInstrRuleRangeSet(
          range,
          [](QBDI::VMInstanceRef vm, const QBDI::InstAnalysis* analysis,
             void* data) -> std::vector<QBDI::InstrRuleDataCBK> {
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);
            return engine->tracer_.on_instr_rule_range_set(vm, analysis, data);
          },
          type, this
      );

      if (id != QBDI::INVALID_EVENTID) {
        log_.inf(
            "registered instruction rule range set callback", redlog::field("type", type), redlog::field("id", id)
        );
      } else {
        log_.error(
            "failed to register instruction rule range set callback", redlog::field("type", type),
            redlog::field("id", id)
        );
      }
      return id;
    } else {
      log_.trc("instruction rule range set callback not supported by tracer");
      return QBDI::INVALID_EVENTID;
    }
  }

private:
  QBDI::VM* vm_;
  TTracer& tracer_;
  bool owns_vm_;
  redlog::logger log_ = redlog::get_logger("w1tn3ss.tracer_engine");

  // - SFINAE detection for callback methods (C++17)

  // -- SFINAE queries

  // Instruction callbacks (addCodeCB)
  template <typename T, typename = void> struct has_instruction_preinst_callback : std::false_type {};
  template <typename T>
  struct has_instruction_preinst_callback<
      T, std::void_t<decltype(std::declval<T>().on_instruction_preinst(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_instruction_postinst_callback : std::false_type {};
  template <typename T>
  struct has_instruction_postinst_callback<
      T, std::void_t<decltype(std::declval<T>().on_instruction_postinst(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // VM event callbacks (addVMEventCB)
  template <typename T, typename = void> struct has_sequence_entry_callback : std::false_type {};
  template <typename T>
  struct has_sequence_entry_callback<
      T, std::void_t<decltype(std::declval<T>().on_sequence_entry(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_sequence_exit_callback : std::false_type {};
  template <typename T>
  struct has_sequence_exit_callback<
      T, std::void_t<decltype(std::declval<T>().on_sequence_exit(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_basic_block_entry_callback : std::false_type {};
  template <typename T>
  struct has_basic_block_entry_callback<
      T, std::void_t<decltype(std::declval<T>().on_basic_block_entry(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_basic_block_exit_callback : std::false_type {};
  template <typename T>
  struct has_basic_block_exit_callback<
      T, std::void_t<decltype(std::declval<T>().on_basic_block_exit(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_basic_block_new_callback : std::false_type {};
  template <typename T>
  struct has_basic_block_new_callback<
      T, std::void_t<decltype(std::declval<T>().on_basic_block_new(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_exec_transfer_call_callback : std::false_type {};
  template <typename T>
  struct has_exec_transfer_call_callback<
      T, std::void_t<decltype(std::declval<T>().on_exec_transfer_call(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_exec_transfer_return_callback : std::false_type {};
  template <typename T>
  struct has_exec_transfer_return_callback<
      T, std::void_t<decltype(std::declval<T>().on_exec_transfer_return(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::VMState*>(), std::declval<QBDI::GPRState*>(),
             std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // Memory access callbacks (addMemAccessCB)
  template <typename T, typename = void> struct has_memory_read_callback : std::false_type {};
  template <typename T>
  struct has_memory_read_callback<
      T, std::void_t<decltype(std::declval<T>().on_memory_read(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_memory_write_callback : std::false_type {};
  template <typename T>
  struct has_memory_write_callback<
      T, std::void_t<decltype(std::declval<T>().on_memory_write(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_memory_read_write_callback : std::false_type {};
  template <typename T>
  struct has_memory_read_write_callback<
      T, std::void_t<decltype(std::declval<T>().on_memory_read_write(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // -- SFINAE results

  // Instruction callbacks
  template <typename T>
  static constexpr bool has_instruction_preinst_callback_v = has_instruction_preinst_callback<T>::value;
  template <typename T>
  static constexpr bool has_instruction_postinst_callback_v = has_instruction_postinst_callback<T>::value;

  // VM event callbacks
  template <typename T> static constexpr bool has_sequence_entry_callback_v = has_sequence_entry_callback<T>::value;
  template <typename T> static constexpr bool has_sequence_exit_callback_v = has_sequence_exit_callback<T>::value;
  template <typename T>
  static constexpr bool has_basic_block_entry_callback_v = has_basic_block_entry_callback<T>::value;
  template <typename T> static constexpr bool has_basic_block_exit_callback_v = has_basic_block_exit_callback<T>::value;
  template <typename T> static constexpr bool has_basic_block_new_callback_v = has_basic_block_new_callback<T>::value;
  template <typename T>
  static constexpr bool has_exec_transfer_call_callback_v = has_exec_transfer_call_callback<T>::value;
  template <typename T>
  static constexpr bool has_exec_transfer_return_callback_v = has_exec_transfer_return_callback<T>::value;

  // Memory access callbacks
  template <typename T> static constexpr bool has_memory_read_callback_v = has_memory_read_callback<T>::value;
  template <typename T> static constexpr bool has_memory_write_callback_v = has_memory_write_callback<T>::value;
  template <typename T>
  static constexpr bool has_memory_read_write_callback_v = has_memory_read_write_callback<T>::value;

  // Address-specific callbacks (addCodeAddrCB, addCodeRangeCB)
  template <typename T, typename = void> struct has_code_addr_callback : std::false_type {};
  template <typename T>
  struct has_code_addr_callback<
      T, std::void_t<decltype(std::declval<T>().on_code_addr(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_code_range_callback : std::false_type {};
  template <typename T>
  struct has_code_range_callback<
      T, std::void_t<decltype(std::declval<T>().on_code_range(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // Mnemonic-specific callbacks (addMnemonicCB)
  template <typename T, typename = void> struct has_mnemonic_callback : std::false_type {};
  template <typename T>
  struct has_mnemonic_callback<
      T, std::void_t<decltype(std::declval<T>().on_mnemonic(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T> static constexpr bool has_code_addr_callback_v = has_code_addr_callback<T>::value;
  template <typename T> static constexpr bool has_code_range_callback_v = has_code_range_callback<T>::value;
  template <typename T> static constexpr bool has_mnemonic_callback_v = has_mnemonic_callback<T>::value;

  // Virtual memory address callbacks (addMemAddrCB, addMemRangeCB)
  template <typename T, typename = void> struct has_mem_addr_callback : std::false_type {};
  template <typename T>
  struct has_mem_addr_callback<
      T, std::void_t<decltype(std::declval<T>().on_mem_addr(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_mem_range_callback : std::false_type {};
  template <typename T>
  struct has_mem_range_callback<
      T, std::void_t<decltype(std::declval<T>().on_mem_range(
             std::declval<QBDI::VMInstanceRef>(), std::declval<QBDI::GPRState*>(), std::declval<QBDI::FPRState*>()
         ))>> : std::true_type {};

  // Instruction rule callbacks (addInstrRule, addInstrRuleRange, addInstrRuleRangeSet)
  template <typename T, typename = void> struct has_instr_rule_callback : std::false_type {};
  template <typename T>
  struct has_instr_rule_callback<
      T, std::void_t<decltype(std::declval<T>().on_instr_rule(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::InstAnalysis*>(), std::declval<void*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_instr_rule_range_callback : std::false_type {};
  template <typename T>
  struct has_instr_rule_range_callback<
      T, std::void_t<decltype(std::declval<T>().on_instr_rule_range(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::InstAnalysis*>(), std::declval<void*>()
         ))>> : std::true_type {};

  template <typename T, typename = void> struct has_instr_rule_range_set_callback : std::false_type {};
  template <typename T>
  struct has_instr_rule_range_set_callback<
      T, std::void_t<decltype(std::declval<T>().on_instr_rule_range_set(
             std::declval<QBDI::VMInstanceRef>(), std::declval<const QBDI::InstAnalysis*>(), std::declval<void*>()
         ))>> : std::true_type {};

  template <typename T> static constexpr bool has_mem_addr_callback_v = has_mem_addr_callback<T>::value;
  template <typename T> static constexpr bool has_mem_range_callback_v = has_mem_range_callback<T>::value;
  template <typename T> static constexpr bool has_instr_rule_callback_v = has_instr_rule_callback<T>::value;
  template <typename T> static constexpr bool has_instr_rule_range_callback_v = has_instr_rule_range_callback<T>::value;
  template <typename T>
  static constexpr bool has_instr_rule_range_set_callback_v = has_instr_rule_range_set_callback<T>::value;

  // - Callback registration macros (to reduce code duplication)

#define W1_REGISTER_INST_CALLBACK(name, position, callback_name)                                                       \
  void register_##name##_callback() {                                                                                  \
    if constexpr (has_##name##_callback_v<TTracer>) {                                                                  \
      log_.vrb("registering callback", redlog::field("callback", #name));                                              \
                                                                                                                       \
      uint32_t id = vm_->addCodeCB(                                                                                    \
          position,                                                                                                    \
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {         \
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);                                                 \
            return engine->tracer_.callback_name(vm, gpr, fpr);                                                        \
          },                                                                                                           \
          this                                                                                                         \
      );                                                                                                               \
                                                                                                                       \
      if (id != QBDI::INVALID_EVENTID) {                                                                               \
        log_.inf("registered callback", redlog::field("callback", #name), redlog::field("id", id));                    \
      } else {                                                                                                         \
        log_.error("failed to register callback", redlog::field("callback", #name), redlog::field("id", id));          \
      }                                                                                                                \
    } else {                                                                                                           \
      log_.trc("not requested", redlog::field("callback", #name));                                                     \
    }                                                                                                                  \
  }

#define W1_REGISTER_VM_EVENT_CALLBACK(name, event, callback_name)                                                      \
  void register_##name##_callback() {                                                                                  \
    if constexpr (has_##name##_callback_v<TTracer>) {                                                                  \
      log_.vrb("registering callback", redlog::field("callback", #name));                                              \
                                                                                                                       \
      uint32_t id = vm_->addVMEventCB(                                                                                 \
          event,                                                                                                       \
          [](QBDI::VMInstanceRef vm, const QBDI::VMState* state, QBDI::GPRState* gpr, QBDI::FPRState* fpr,             \
             void* data) -> QBDI::VMAction {                                                                           \
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);                                                 \
            return engine->tracer_.callback_name(vm, state, gpr, fpr);                                                 \
          },                                                                                                           \
          this                                                                                                         \
      );                                                                                                               \
                                                                                                                       \
      if (id != QBDI::INVALID_EVENTID) {                                                                               \
        log_.inf("registered callback", redlog::field("callback", #name), redlog::field("id", id));                    \
      } else {                                                                                                         \
        log_.error("failed to register callback", redlog::field("callback", #name), redlog::field("id", id));          \
      }                                                                                                                \
    } else {                                                                                                           \
      log_.trc("not requested", redlog::field("callback", #name));                                                     \
    }                                                                                                                  \
  }

#define W1_REGISTER_MEM_ACCESS_CALLBACK(name, access_type, callback_name)                                              \
  void register_##name##_callback() {                                                                                  \
    if constexpr (has_##name##_callback_v<TTracer>) {                                                                  \
      log_.vrb("registering callback", redlog::field("callback", #name));                                              \
                                                                                                                       \
      uint32_t id = vm_->addMemAccessCB(                                                                               \
          access_type,                                                                                                 \
          [](QBDI::VMInstanceRef vm, QBDI::GPRState* gpr, QBDI::FPRState* fpr, void* data) -> QBDI::VMAction {         \
            auto* engine = static_cast<tracer_engine<TTracer>*>(data);                                                 \
            return engine->tracer_.callback_name(vm, gpr, fpr);                                                        \
          },                                                                                                           \
          this                                                                                                         \
      );                                                                                                               \
                                                                                                                       \
      if (id != QBDI::INVALID_EVENTID) {                                                                               \
        log_.inf("registered callback", redlog::field("callback", #name), redlog::field("id", id));                    \
      } else {                                                                                                         \
        log_.error("failed to register callback", redlog::field("callback", #name), redlog::field("id", id));          \
      }                                                                                                                \
    } else {                                                                                                           \
      log_.trc("not requested", redlog::field("callback", #name));                                                     \
    }                                                                                                                  \
  }

  // - Callback registration methods

  // Instruction callbacks (addCodeCB) - using macros
  W1_REGISTER_INST_CALLBACK(instruction_preinst, QBDI::PREINST, on_instruction_preinst)
  W1_REGISTER_INST_CALLBACK(instruction_postinst, QBDI::POSTINST, on_instruction_postinst)

  // VM event callbacks (addVMEventCB) - using macros
  W1_REGISTER_VM_EVENT_CALLBACK(sequence_entry, QBDI::SEQUENCE_ENTRY, on_sequence_entry)
  W1_REGISTER_VM_EVENT_CALLBACK(sequence_exit, QBDI::SEQUENCE_EXIT, on_sequence_exit)
  W1_REGISTER_VM_EVENT_CALLBACK(basic_block_entry, QBDI::BASIC_BLOCK_ENTRY, on_basic_block_entry)
  W1_REGISTER_VM_EVENT_CALLBACK(basic_block_exit, QBDI::BASIC_BLOCK_EXIT, on_basic_block_exit)
  W1_REGISTER_VM_EVENT_CALLBACK(basic_block_new, QBDI::BASIC_BLOCK_NEW, on_basic_block_new)
  W1_REGISTER_VM_EVENT_CALLBACK(exec_transfer_call, QBDI::EXEC_TRANSFER_CALL, on_exec_transfer_call)
  W1_REGISTER_VM_EVENT_CALLBACK(exec_transfer_return, QBDI::EXEC_TRANSFER_RETURN, on_exec_transfer_return)

  // Memory access callbacks (addMemAccessCB) - using macros
  W1_REGISTER_MEM_ACCESS_CALLBACK(memory_read, QBDI::MEMORY_READ, on_memory_read)
  W1_REGISTER_MEM_ACCESS_CALLBACK(memory_write, QBDI::MEMORY_WRITE, on_memory_write)
  W1_REGISTER_MEM_ACCESS_CALLBACK(memory_read_write, QBDI::MEMORY_READ_WRITE, on_memory_read_write)

// Clean up macros to avoid polluting global namespace
#undef W1_REGISTER_INST_CALLBACK
#undef W1_REGISTER_VM_EVENT_CALLBACK
#undef W1_REGISTER_MEM_ACCESS_CALLBACK

  void register_all_callbacks() {
    log_.inf("registering callbacks...");

    // Instruction callbacks (addCodeCB)
    register_instruction_preinst_callback();
    register_instruction_postinst_callback();

    // VM event callbacks (addVMEventCB)
    register_sequence_entry_callback();
    register_sequence_exit_callback();
    register_basic_block_entry_callback();
    register_basic_block_exit_callback();
    register_basic_block_new_callback();
    register_exec_transfer_call_callback();
    register_exec_transfer_return_callback();

    // Memory access callbacks (addMemAccessCB)
    register_memory_read_callback();
    register_memory_write_callback();
    register_memory_read_write_callback();

    // Note: SYSCALL_ENTRY and SYSCALL_EXIT are not implemented in current QBDI version

    log_.inf("callback registration complete");
  }
};

} // namespace w1
