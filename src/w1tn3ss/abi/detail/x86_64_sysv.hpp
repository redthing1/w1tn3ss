#pragma once

#include "../calling_convention.hpp"
#include "../../util/safe_memory.hpp"

namespace w1::abi::detail {

struct x86_64_sysv {
    // System V AMD64 ABI
    static std::vector<uint64_t> extract_integer_args(
        QBDI::GPRState* gpr,
        QBDI::VMInstanceRef vm,
        size_t count) {
        
        std::vector<uint64_t> args;
        args.reserve(count);
        
        // Register arguments - direct struct member access
        if (count > 0) args.push_back(gpr->rdi);
        if (count > 1) args.push_back(gpr->rsi);
        if (count > 2) args.push_back(gpr->rdx);
        if (count > 3) args.push_back(gpr->rcx);
        if (count > 4) args.push_back(gpr->r8);
        if (count > 5) args.push_back(gpr->r9);
        
        // Stack arguments
        if (count > 6) {
            uint64_t sp = gpr->rsp;
            // Skip return address (8 bytes)
            for (size_t i = 6; i < count; ++i) {
                if (auto val = util::safe_memory::read<uint64_t>(
                        vm, sp + 8 + (i - 6) * 8)) {
                    args.push_back(*val);
                } else {
                    args.push_back(0);  // Failed read
                }
            }
        }
        
        return args;
    }
    
    static std::vector<calling_convention::typed_arg> extract_typed_args(
        QBDI::GPRState* gpr,
        QBDI::FPRState* fpr,
        QBDI::VMInstanceRef vm,
        const std::vector<calling_convention::arg_type>& types) {
        
        std::vector<calling_convention::typed_arg> args;
        args.reserve(types.size());
        
        size_t int_reg_idx = 0;
        size_t float_reg_idx = 0;
        size_t stack_offset = 0;
        
        // Helper to get integer register by index
        auto get_int_reg = [&gpr](size_t idx) -> uint64_t {
            switch (idx) {
                case 0: return gpr->rdi;
                case 1: return gpr->rsi;
                case 2: return gpr->rdx;
                case 3: return gpr->rcx;
                case 4: return gpr->r8;
                case 5: return gpr->r9;
                default: return 0;
            }
        };
        
        // Helper to get float from XMM register
        auto get_float_reg = [&fpr](size_t idx) -> double {
            // XMM registers are char[16] arrays
            const char* xmm = nullptr;
            switch (idx) {
                case 0: xmm = fpr->xmm0; break;
                case 1: xmm = fpr->xmm1; break;
                case 2: xmm = fpr->xmm2; break;
                case 3: xmm = fpr->xmm3; break;
                case 4: xmm = fpr->xmm4; break;
                case 5: xmm = fpr->xmm5; break;
                case 6: xmm = fpr->xmm6; break;
                case 7: xmm = fpr->xmm7; break;
                default: return 0.0;
            }
            // Lower 64 bits contain double
            return *reinterpret_cast<const double*>(xmm);
        };
        
        for (auto type : types) {
            calling_convention::typed_arg arg{};
            arg.type = type;
            
            switch (type) {
            case calling_convention::arg_type::INTEGER:
                if (int_reg_idx < 6) {
                    arg.value.integer = get_int_reg(int_reg_idx++);
                } else {
                    // From stack
                    uint64_t sp = gpr->rsp;
                    if (auto val = util::safe_memory::read<uint64_t>(
                            vm, sp + 8 + stack_offset)) {
                        arg.value.integer = *val;
                    }
                    stack_offset += 8;
                }
                break;
                
            case calling_convention::arg_type::FLOAT:
            case calling_convention::arg_type::DOUBLE:
                if (float_reg_idx < 8) {
                    double d = get_float_reg(float_reg_idx++);
                    if (type == calling_convention::arg_type::FLOAT) {
                        arg.value.f32 = static_cast<float>(d);
                    } else {
                        arg.value.f64 = d;
                    }
                } else {
                    // From stack
                    uint64_t sp = gpr->rsp;
                    if (type == calling_convention::arg_type::FLOAT) {
                        if (auto val = util::safe_memory::read<float>(
                                vm, sp + 8 + stack_offset)) {
                            arg.value.f32 = *val;
                        }
                        stack_offset += 8; // Still 8-byte aligned
                    } else {
                        if (auto val = util::safe_memory::read<double>(
                                vm, sp + 8 + stack_offset)) {
                            arg.value.f64 = *val;
                        }
                        stack_offset += 8;
                    }
                }
                break;
                
            case calling_convention::arg_type::SIMD:
                // Not implemented yet
                break;
            }
            
            args.push_back(arg);
        }
        
        return args;
    }
    
    static uint64_t get_integer_return(QBDI::GPRState* gpr) {
        return gpr->rax;
    }
    
    static double get_float_return(QBDI::FPRState* fpr) {
        // XMM0 register, lower 64 bits contain double
        return *reinterpret_cast<const double*>(fpr->xmm0);
    }
    
    static uint64_t get_stack_pointer(QBDI::GPRState* gpr) {
        return gpr->rsp;
    }
    
    static uint64_t calculate_return_address(
        uint64_t call_site,
        QBDI::GPRState* gpr,
        const QBDI::InstAnalysis* inst) {
        
        // For CALL instruction, return address is next instruction
        if (inst) {
            return call_site + inst->instSize;
        }
        
        // Fallback: assume 5-byte CALL
        return call_site + 5;
    }
};

} // namespace w1::abi::detail