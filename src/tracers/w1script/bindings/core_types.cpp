#include "core_types.hpp"
#include <redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_core_types(sol::state& lua, sol::table& w1_module) {
  auto logger = redlog::get_logger("w1.script_bindings");
  logger.dbg("setting up core qbdi types and enums");

  // vmAction enum - controls VM execution flow
  // used in callbacks to determine how the VM should proceed after instruction execution
  w1_module.new_enum(
      "VMAction", "CONTINUE", QBDI::VMAction::CONTINUE, // Continue normal execution
      "SKIP_INST", QBDI::VMAction::SKIP_INST,           // Skip current instruction
      "SKIP_PATCH", QBDI::VMAction::SKIP_PATCH,         // Skip current patch
      "BREAK_TO_VM", QBDI::VMAction::BREAK_TO_VM,       // Break back to VM
      "STOP", QBDI::VMAction::STOP                      // Stop VM execution
  );

  // InstAnalysis usertype - provides detailed instruction analysis information
  // this contains all the metadata about the currently executing instruction
  lua.new_usertype<QBDI::InstAnalysis>(
      "InstAnalysis",

      // basic instruction properties
      "address", &QBDI::InstAnalysis::address,   // Instruction address
      "instSize", &QBDI::InstAnalysis::instSize, // Instruction size in bytes

      // control flow analysis
      "affectControlFlow", &QBDI::InstAnalysis::affectControlFlow, // Does instruction affect control flow?
      "isBranch", &QBDI::InstAnalysis::isBranch,                   // Is it a branch instruction?
      "isCall", &QBDI::InstAnalysis::isCall,                       // Is it a function call?
      "isReturn", &QBDI::InstAnalysis::isReturn,                   // Is it a return instruction?
      "isCompare", &QBDI::InstAnalysis::isCompare,                 // Is it a comparison instruction?
      "isPredicable", &QBDI::InstAnalysis::isPredicable,           // Can it be predicated?

      // memory access properties
      "mayLoad", &QBDI::InstAnalysis::mayLoad,     // Might load from memory?
      "mayStore", &QBDI::InstAnalysis::mayStore,   // Might store to memory?
      "loadSize", &QBDI::InstAnalysis::loadSize,   // Size of memory load (if any)
      "storeSize", &QBDI::InstAnalysis::storeSize, // Size of memory store (if any)

      // conditional execution
      "condition", &QBDI::InstAnalysis::condition // Execution condition (if any)
  );

  // vmEvent enum - VM state change events
  // used to trigger callbacks at specific execution points
  w1_module.new_enum(
      "VMEvent", "NO_EVENT", QBDI::VMEvent::NO_EVENT,              // No event
      "BASIC_BLOCK_ENTRY", QBDI::VMEvent::BASIC_BLOCK_ENTRY,       // Basic block entry
      "BASIC_BLOCK_EXIT", QBDI::VMEvent::BASIC_BLOCK_EXIT,         // Basic block exit
      "BASIC_BLOCK_NEW", QBDI::VMEvent::BASIC_BLOCK_NEW,           // New basic block
      "SEQUENCE_ENTRY", QBDI::VMEvent::SEQUENCE_ENTRY,             // Sequence entry
      "SEQUENCE_EXIT", QBDI::VMEvent::SEQUENCE_EXIT,               // Sequence exit
      "EXEC_TRANSFER_CALL", QBDI::VMEvent::EXEC_TRANSFER_CALL,     // Execution transfer call
      "EXEC_TRANSFER_RETURN", QBDI::VMEvent::EXEC_TRANSFER_RETURN, // Execution transfer return
      "SYSCALL_ENTRY", QBDI::VMEvent::SYSCALL_ENTRY,               // System call entry
      "SYSCALL_EXIT", QBDI::VMEvent::SYSCALL_EXIT,                 // System call exit
      "SIGNAL", QBDI::VMEvent::SIGNAL                              // Signal event
  );

  // MemoryAccessType enum - types of memory access operations
  // used to filter memory access callbacks by operation type
  w1_module.new_enum(
      "MemoryAccessType", "MEMORY_READ", QBDI::MemoryAccessType::MEMORY_READ, // Memory read operation
      "MEMORY_WRITE", QBDI::MemoryAccessType::MEMORY_WRITE,                   // Memory write operation
      "MEMORY_READ_WRITE", QBDI::MemoryAccessType::MEMORY_READ_WRITE          // Memory read/write operation
  );

  // MemoryAccessFlags enum - flags describing memory access properties
  // provides additional information about memory access operations
  w1_module.new_enum(
      "MemoryAccessFlags", "MEMORY_NO_FLAGS", QBDI::MemoryAccessFlags::MEMORY_NO_FLAGS, // No special flags
      "MEMORY_UNKNOWN_SIZE", QBDI::MemoryAccessFlags::MEMORY_UNKNOWN_SIZE,              // Size is unknown
      "MEMORY_MINIMUM_SIZE", QBDI::MemoryAccessFlags::MEMORY_MINIMUM_SIZE,              // Given size is minimum
      "MEMORY_UNKNOWN_VALUE", QBDI::MemoryAccessFlags::MEMORY_UNKNOWN_VALUE             // Value is unknown
  );

  // InstPosition enum - position relative to instruction execution
  // used to specify when callbacks are triggered relative to instruction
  w1_module.new_enum(
      "InstPosition", "PREINST", QBDI::InstPosition::PREINST, // Before instruction execution
      "POSTINST", QBDI::InstPosition::POSTINST                // After instruction execution
  );

  // AnalysisType enum - types of instruction analysis available
  // used to specify what analysis information should be computed
  w1_module.new_enum(
      "AnalysisType", "ANALYSIS_INSTRUCTION", QBDI::AnalysisType::ANALYSIS_INSTRUCTION, // Basic instruction info
      "ANALYSIS_DISASSEMBLY", QBDI::AnalysisType::ANALYSIS_DISASSEMBLY,                 // Disassembly text
      "ANALYSIS_OPERANDS", QBDI::AnalysisType::ANALYSIS_OPERANDS,                       // Operand analysis
      "ANALYSIS_SYMBOL", QBDI::AnalysisType::ANALYSIS_SYMBOL,                           // Symbol information
      "ANALYSIS_JIT", QBDI::AnalysisType::ANALYSIS_JIT                                  // jit patch information
  );

  // ConditionType enum - instruction condition types
  // used to describe conditional execution properties of instructions
  w1_module.new_enum(
      "ConditionType", "CONDITION_NONE", QBDI::ConditionType::CONDITION_NONE, // Unconditional
      "CONDITION_ALWAYS", QBDI::ConditionType::CONDITION_ALWAYS,              // Always true
      "CONDITION_NEVER", QBDI::ConditionType::CONDITION_NEVER,                // Always false
      "CONDITION_EQUALS", QBDI::ConditionType::CONDITION_EQUALS,              // Equals (==)
      "CONDITION_NOT_EQUALS", QBDI::ConditionType::CONDITION_NOT_EQUALS,      // Not equals (!=)
      "CONDITION_ABOVE", QBDI::ConditionType::CONDITION_ABOVE,                // Above (> unsigned)
      "CONDITION_BELOW_EQUALS", QBDI::ConditionType::CONDITION_BELOW_EQUALS,  // Below/equals (<= unsigned)
      "CONDITION_ABOVE_EQUALS", QBDI::ConditionType::CONDITION_ABOVE_EQUALS,  // Above/equals (>= unsigned)
      "CONDITION_BELOW", QBDI::ConditionType::CONDITION_BELOW,                // Below (< unsigned)
      "CONDITION_GREAT", QBDI::ConditionType::CONDITION_GREAT,                // Greater (> signed)
      "CONDITION_LESS_EQUALS", QBDI::ConditionType::CONDITION_LESS_EQUALS,    // Less/equals (<= signed)
      "CONDITION_GREAT_EQUALS", QBDI::ConditionType::CONDITION_GREAT_EQUALS,  // Greater/equals (>= signed)
      "CONDITION_LESS", QBDI::ConditionType::CONDITION_LESS,                  // Less (< signed)
      "CONDITION_EVEN", QBDI::ConditionType::CONDITION_EVEN,                  // Even
      "CONDITION_ODD", QBDI::ConditionType::CONDITION_ODD,                    // Odd
      "CONDITION_OVERFLOW", QBDI::ConditionType::CONDITION_OVERFLOW,          // Overflow
      "CONDITION_NOT_OVERFLOW", QBDI::ConditionType::CONDITION_NOT_OVERFLOW,  // Not overflow
      "CONDITION_SIGN", QBDI::ConditionType::CONDITION_SIGN,                  // Sign
      "CONDITION_NOT_SIGN", QBDI::ConditionType::CONDITION_NOT_SIGN           // Not sign
  );

  // OperandType enum - types of instruction operands
  // used to categorize operands in instruction analysis
  w1_module.new_enum(
      "OperandType", "OPERAND_INVALID", QBDI::OperandType::OPERAND_INVALID, // Invalid operand
      "OPERAND_IMM", QBDI::OperandType::OPERAND_IMM,                        // Immediate operand
      "OPERAND_GPR", QBDI::OperandType::OPERAND_GPR,                        // General purpose register
      "OPERAND_PRED", QBDI::OperandType::OPERAND_PRED,                      // Predicate operand
      "OPERAND_FPR", QBDI::OperandType::OPERAND_FPR,                        // Floating point register
      "OPERAND_SEG", QBDI::OperandType::OPERAND_SEG                         // Segment/unsupported register
  );

  // OperandFlag enum - flags describing operand properties
  // provides additional metadata about operand usage
  w1_module.new_enum(
      "OperandFlag", "OPERANDFLAG_NONE", QBDI::OperandFlag::OPERANDFLAG_NONE,          // No flags
      "OPERANDFLAG_ADDR", QBDI::OperandFlag::OPERANDFLAG_ADDR,                         // Used for address computation
      "OPERANDFLAG_PCREL", QBDI::OperandFlag::OPERANDFLAG_PCREL,                       // pc-relative value
      "OPERANDFLAG_UNDEFINED_EFFECT", QBDI::OperandFlag::OPERANDFLAG_UNDEFINED_EFFECT, // Undefined role
      "OPERANDFLAG_IMPLICIT", QBDI::OperandFlag::OPERANDFLAG_IMPLICIT                  // Implicit operand
  );

  // RegisterAccessType enum - register access patterns
  // used to describe how registers are accessed in operands
  w1_module.new_enum(
      "RegisterAccessType", "REGISTER_UNUSED", QBDI::RegisterAccessType::REGISTER_UNUSED, // Register not used
      "REGISTER_READ", QBDI::RegisterAccessType::REGISTER_READ,                           // Register read access
      "REGISTER_WRITE", QBDI::RegisterAccessType::REGISTER_WRITE,                         // Register write access
      "REGISTER_READ_WRITE", QBDI::RegisterAccessType::REGISTER_READ_WRITE                // Register read/write access
  );

  // OperandAnalysis usertype - detailed analysis of instruction operands
  // provides comprehensive information about individual operands
  lua.new_usertype<QBDI::OperandAnalysis>(
      "OperandAnalysis",

      // core operand properties
      "type", &QBDI::OperandAnalysis::type,   // Operand type (immediate, register, etc.)
      "flag", &QBDI::OperandAnalysis::flag,   // Operand flags (address, PC-relative, etc.)
      "value", &QBDI::OperandAnalysis::value, // Operand value (immediate) or register ID
      "size", &QBDI::OperandAnalysis::size,   // Operand size in bytes

      // register-specific properties
      "regOff", &QBDI::OperandAnalysis::regOff,       // Sub-register offset in bits
      "regCtxIdx", &QBDI::OperandAnalysis::regCtxIdx, // Register index in VM state
      "regName", &QBDI::OperandAnalysis::regName,     // Register name string
      "regAccess", &QBDI::OperandAnalysis::regAccess  // Register access type (r/w/rw)
  );

  // MemoryAccess usertype - describes a memory access operation
  // contains complete information about memory reads and writes
  lua.new_usertype<QBDI::MemoryAccess>(
      "MemoryAccess",

      // memory access details
      "instAddress", &QBDI::MemoryAccess::instAddress,     // Address of instruction making access
      "accessAddress", &QBDI::MemoryAccess::accessAddress, // Address of accessed memory
      "value", &QBDI::MemoryAccess::value,                 // Value read from or written to memory
      "size", &QBDI::MemoryAccess::size,                   // Size of memory access in bytes
      "type", &QBDI::MemoryAccess::type,                   // Memory access type (read/write)
      "flags", &QBDI::MemoryAccess::flags                  // Memory access flags
  );

  // vmState usertype - describes current VM execution state
  // provides context about VM events and execution boundaries
  lua.new_usertype<QBDI::VMState>(
      "VMState",

      // vm event information
      "event", &QBDI::VMState::event,                     // Event type that triggered callback
      "basicBlockStart", &QBDI::VMState::basicBlockStart, // Current basic block start address
      "basicBlockEnd", &QBDI::VMState::basicBlockEnd,     // Current basic block end address
      "sequenceStart", &QBDI::VMState::sequenceStart,     // Current sequence start address
      "sequenceEnd", &QBDI::VMState::sequenceEnd,         // Current sequence end address
      "lastSignal", &QBDI::VMState::lastSignal            // Last signal (not implemented)
  );

  logger.dbg("core types registered successfully");
}

} // namespace w1::tracers::script::bindings