#ifdef WITNESS_SCRIPT_ENABLED

#include "register_access.hpp"
#include <redlog/redlog.hpp>

namespace w1::tracers::script::bindings {

void setup_register_access(sol::state& lua, sol::table& w1_module) {
  auto log = redlog::get_logger("w1script.bindings.register_access");
  log.dbg("setting up platform-specific register access functions");

  // Platform-specific register access functions
  // These functions take a void* pointer to GPRState and return the register value

#if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)

  log.dbg("registering x86_64 register access functions");

  // General purpose registers
  w1_module.set_function("get_reg_rax", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rax;
  });

  w1_module.set_function("get_reg_rbx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rbx;
  });

  w1_module.set_function("get_reg_rcx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rcx;
  });

  w1_module.set_function("get_reg_rdx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rdx;
  });

  // Stack and frame pointers
  w1_module.set_function("get_reg_rsp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rsp;
  });

  w1_module.set_function("get_reg_rbp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rbp;
  });

  // Index registers
  w1_module.set_function("get_reg_rsi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rsi;
  });

  w1_module.set_function("get_reg_rdi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rdi;
  });

  // Instruction pointer
  w1_module.set_function("get_reg_rip", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->rip;
  });

  // Additional x86_64 registers (R8-R15)
  w1_module.set_function("get_reg_r8", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r8;
  });

  w1_module.set_function("get_reg_r9", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r9;
  });

  w1_module.set_function("get_reg_r10", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r10;
  });

  w1_module.set_function("get_reg_r11", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r11;
  });

  w1_module.set_function("get_reg_r12", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r12;
  });

  w1_module.set_function("get_reg_r13", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r13;
  });

  w1_module.set_function("get_reg_r14", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r14;
  });

  w1_module.set_function("get_reg_r15", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r15;
  });

  // Flags and segment registers
  w1_module.set_function("get_reg_eflags", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->eflags;
  });

  w1_module.set_function("get_reg_fs", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->fs;
  });

  w1_module.set_function("get_reg_gs", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->gs;
  });

  // Set register functions for x86_64
  w1_module.set_function("set_reg_rax", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rax = value;
  });

  w1_module.set_function("set_reg_rbx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rbx = value;
  });

  w1_module.set_function("set_reg_rcx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rcx = value;
  });

  w1_module.set_function("set_reg_rdx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rdx = value;
  });

  w1_module.set_function("set_reg_rsp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rsp = value;
  });

  w1_module.set_function("set_reg_rbp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rbp = value;
  });

  w1_module.set_function("set_reg_rsi", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rsi = value;
  });

  w1_module.set_function("set_reg_rdi", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rdi = value;
  });

  w1_module.set_function("set_reg_rip", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->rip = value;
  });

  w1_module.set_function("set_reg_r8", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r8 = value;
  });

  w1_module.set_function("set_reg_r9", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r9 = value;
  });

  w1_module.set_function("set_reg_r10", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r10 = value;
  });

  w1_module.set_function("set_reg_r11", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r11 = value;
  });

  w1_module.set_function("set_reg_r12", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r12 = value;
  });

  w1_module.set_function("set_reg_r13", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r13 = value;
  });

  w1_module.set_function("set_reg_r14", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r14 = value;
  });

  w1_module.set_function("set_reg_r15", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r15 = value;
  });

  w1_module.set_function("set_reg_eflags", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->eflags = value;
  });

  w1_module.set_function("set_reg_fs", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->fs = value;
  });

  w1_module.set_function("set_reg_gs", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->gs = value;
  });

  log.inf("x86_64 register functions registered");

#elif defined(__aarch64__) || defined(_M_ARM64)

  log.dbg("registering ARM64 register access functions");

  // Parameter and result registers
  w1_module.set_function("get_reg_x0", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x0;
  });

  w1_module.set_function("get_reg_x1", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x1;
  });

  w1_module.set_function("get_reg_x2", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x2;
  });

  w1_module.set_function("get_reg_x3", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x3;
  });

  w1_module.set_function("get_reg_x4", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x4;
  });

  w1_module.set_function("get_reg_x5", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x5;
  });

  w1_module.set_function("get_reg_x6", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x6;
  });

  w1_module.set_function("get_reg_x7", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x7;
  });

  // Stack pointer
  w1_module.set_function("get_reg_sp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->sp;
  });

  // Link register (return address)
  w1_module.set_function("get_reg_lr", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->lr;
  });

  // Missing x8-x29 registers
  w1_module.set_function("get_reg_x8", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x8;
  });

  w1_module.set_function("get_reg_x9", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x9;
  });

  w1_module.set_function("get_reg_x10", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x10;
  });

  w1_module.set_function("get_reg_x11", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x11;
  });

  w1_module.set_function("get_reg_x12", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x12;
  });

  w1_module.set_function("get_reg_x13", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x13;
  });

  w1_module.set_function("get_reg_x14", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x14;
  });

  w1_module.set_function("get_reg_x15", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x15;
  });

  w1_module.set_function("get_reg_x16", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x16;
  });

  w1_module.set_function("get_reg_x17", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x17;
  });

  w1_module.set_function("get_reg_x18", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x18;
  });

  w1_module.set_function("get_reg_x19", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x19;
  });

  w1_module.set_function("get_reg_x20", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x20;
  });

  w1_module.set_function("get_reg_x21", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x21;
  });

  w1_module.set_function("get_reg_x22", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x22;
  });

  w1_module.set_function("get_reg_x23", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x23;
  });

  w1_module.set_function("get_reg_x24", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x24;
  });

  w1_module.set_function("get_reg_x25", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x25;
  });

  w1_module.set_function("get_reg_x26", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x26;
  });

  w1_module.set_function("get_reg_x27", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x27;
  });

  w1_module.set_function("get_reg_x28", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x28;
  });

  w1_module.set_function("get_reg_x29", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->x29;
  });

  // Status flags
  w1_module.set_function("get_reg_nzcv", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->nzcv;
  });

  // Program counter
  w1_module.set_function("get_reg_pc", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->pc;
  });

  // Set register functions for AARCH64
  w1_module.set_function("set_reg_x0", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x0 = value;
  });

  w1_module.set_function("set_reg_x1", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x1 = value;
  });

  w1_module.set_function("set_reg_x2", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x2 = value;
  });

  w1_module.set_function("set_reg_x3", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x3 = value;
  });

  w1_module.set_function("set_reg_x4", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x4 = value;
  });

  w1_module.set_function("set_reg_x5", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x5 = value;
  });

  w1_module.set_function("set_reg_x6", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x6 = value;
  });

  w1_module.set_function("set_reg_x7", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x7 = value;
  });

  w1_module.set_function("set_reg_x8", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x8 = value;
  });

  w1_module.set_function("set_reg_x9", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x9 = value;
  });

  w1_module.set_function("set_reg_x10", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x10 = value;
  });

  w1_module.set_function("set_reg_x11", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x11 = value;
  });

  w1_module.set_function("set_reg_x12", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x12 = value;
  });

  w1_module.set_function("set_reg_x13", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x13 = value;
  });

  w1_module.set_function("set_reg_x14", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x14 = value;
  });

  w1_module.set_function("set_reg_x15", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x15 = value;
  });

  w1_module.set_function("set_reg_x16", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x16 = value;
  });

  w1_module.set_function("set_reg_x17", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x17 = value;
  });

  w1_module.set_function("set_reg_x18", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x18 = value;
  });

  w1_module.set_function("set_reg_x19", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x19 = value;
  });

  w1_module.set_function("set_reg_x20", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x20 = value;
  });

  w1_module.set_function("set_reg_x21", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x21 = value;
  });

  w1_module.set_function("set_reg_x22", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x22 = value;
  });

  w1_module.set_function("set_reg_x23", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x23 = value;
  });

  w1_module.set_function("set_reg_x24", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x24 = value;
  });

  w1_module.set_function("set_reg_x25", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x25 = value;
  });

  w1_module.set_function("set_reg_x26", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x26 = value;
  });

  w1_module.set_function("set_reg_x27", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x27 = value;
  });

  w1_module.set_function("set_reg_x28", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x28 = value;
  });

  w1_module.set_function("set_reg_x29", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->x29 = value;
  });

  w1_module.set_function("set_reg_sp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->sp = value;
  });

  w1_module.set_function("set_reg_lr", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->lr = value;
  });

  w1_module.set_function("set_reg_pc", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->pc = value;
  });

  w1_module.set_function("set_reg_nzcv", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->nzcv = value;
  });

  log.inf("ARM64 register functions registered");

#elif defined(__arm__) || defined(_M_ARM)

  log.dbg("registering ARM32 register access functions");

  // General purpose registers
  w1_module.set_function("get_reg_r0", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r0;
  });

  w1_module.set_function("get_reg_r1", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r1;
  });

  w1_module.set_function("get_reg_r2", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r2;
  });

  w1_module.set_function("get_reg_r3", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r3;
  });

  w1_module.set_function("get_reg_r4", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r4;
  });

  w1_module.set_function("get_reg_r5", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r5;
  });

  w1_module.set_function("get_reg_r6", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r6;
  });

  w1_module.set_function("get_reg_r7", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r7;
  });

  // Stack pointer
  w1_module.set_function("get_reg_sp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->sp;
  });

  // Link register
  w1_module.set_function("get_reg_lr", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->lr;
  });

  // Missing r8-r12 registers
  w1_module.set_function("get_reg_r8", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r8;
  });

  w1_module.set_function("get_reg_r9", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r9;
  });

  w1_module.set_function("get_reg_r10", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r10;
  });

  w1_module.set_function("get_reg_r11", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r11;
  });

  w1_module.set_function("get_reg_r12", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->r12;
  });

  // Status register
  w1_module.set_function("get_reg_cpsr", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->cpsr;
  });

  // Program counter
  w1_module.set_function("get_reg_pc", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->pc;
  });

  // Set register functions for ARM32
  w1_module.set_function("set_reg_r0", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r0 = value;
  });

  w1_module.set_function("set_reg_r1", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r1 = value;
  });

  w1_module.set_function("set_reg_r2", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r2 = value;
  });

  w1_module.set_function("set_reg_r3", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r3 = value;
  });

  w1_module.set_function("set_reg_r4", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r4 = value;
  });

  w1_module.set_function("set_reg_r5", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r5 = value;
  });

  w1_module.set_function("set_reg_r6", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r6 = value;
  });

  w1_module.set_function("set_reg_r7", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r7 = value;
  });

  w1_module.set_function("set_reg_r8", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r8 = value;
  });

  w1_module.set_function("set_reg_r9", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r9 = value;
  });

  w1_module.set_function("set_reg_r10", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r10 = value;
  });

  w1_module.set_function("set_reg_r11", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r11 = value;
  });

  w1_module.set_function("set_reg_r12", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->r12 = value;
  });

  w1_module.set_function("set_reg_sp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->sp = value;
  });

  w1_module.set_function("set_reg_lr", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->lr = value;
  });

  w1_module.set_function("set_reg_pc", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->pc = value;
  });

  w1_module.set_function("set_reg_cpsr", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->cpsr = value;
  });

  log.inf("ARM32 register functions registered");

#elif defined(__i386__) || defined(_M_IX86)

  log.dbg("registering x86 32-bit register access functions");

  // General purpose registers
  w1_module.set_function("get_reg_eax", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->eax;
  });

  w1_module.set_function("get_reg_ebx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->ebx;
  });

  w1_module.set_function("get_reg_ecx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->ecx;
  });

  w1_module.set_function("get_reg_edx", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->edx;
  });

  w1_module.set_function("get_reg_esi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->esi;
  });

  w1_module.set_function("get_reg_edi", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->edi;
  });

  w1_module.set_function("get_reg_ebp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->ebp;
  });

  w1_module.set_function("get_reg_esp", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->esp;
  });

  w1_module.set_function("get_reg_eip", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->eip;
  });

  w1_module.set_function("get_reg_eflags", [](void* gpr_ptr) -> QBDI::rword {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    return gpr->eflags;
  });

  // Set register functions for x86 32-bit
  w1_module.set_function("set_reg_eax", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->eax = value;
  });

  w1_module.set_function("set_reg_ebx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->ebx = value;
  });

  w1_module.set_function("set_reg_ecx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->ecx = value;
  });

  w1_module.set_function("set_reg_edx", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->edx = value;
  });

  w1_module.set_function("set_reg_esi", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->esi = value;
  });

  w1_module.set_function("set_reg_edi", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->edi = value;
  });

  w1_module.set_function("set_reg_ebp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->ebp = value;
  });

  w1_module.set_function("set_reg_esp", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->esp = value;
  });

  w1_module.set_function("set_reg_eip", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->eip = value;
  });

  w1_module.set_function("set_reg_eflags", [](void* gpr_ptr, QBDI::rword value) {
    QBDI::GPRState* gpr = static_cast<QBDI::GPRState*>(gpr_ptr);
    gpr->eflags = value;
  });

  log.inf("x86 32-bit register functions registered");

#else
  log.wrn("no register functions available for this architecture");
#endif

  log.dbg("register access functions setup complete");
}

} // namespace w1::tracers::script::bindings

#endif // WITNESS_SCRIPT_ENABLED