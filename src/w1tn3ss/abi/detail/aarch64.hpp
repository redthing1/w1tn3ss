#pragma once

#include "../calling_convention.hpp"
#include "../../util/safe_memory.hpp"

namespace w1::abi::detail {

struct aarch64 {
    // AArch64 ABI - ARM Procedure Call Standard
    static std::vector<uint64_t> extract_integer_args(
        QBDI::GPRState* gpr,
        QBDI::VMInstanceRef vm,
        size_t count) {
        
        std::vector<uint64_t> args;
        args.reserve(count);
        
        // Register arguments (X0-X7)
        // Direct struct member access for AArch64
        if (count > 0) args.push_back(gpr->x0);
        if (count > 1) args.push_back(gpr->x1);
        if (count > 2) args.push_back(gpr->x2);
        if (count > 3) args.push_back(gpr->x3);
        if (count > 4) args.push_back(gpr->x4);
        if (count > 5) args.push_back(gpr->x5);
        if (count > 6) args.push_back(gpr->x6);
        if (count > 7) args.push_back(gpr->x7);
        
        // Stack arguments
        if (count > 8) {
            uint64_t sp = gpr->sp;
            for (size_t i = 8; i < count; ++i) {
                if (auto val = util::safe_memory::read<uint64_t>(
                        vm, sp + (i - 8) * 8)) {
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
                case 0: return gpr->x0;
                case 1: return gpr->x1;
                case 2: return gpr->x2;
                case 3: return gpr->x3;
                case 4: return gpr->x4;
                case 5: return gpr->x5;
                case 6: return gpr->x6;
                case 7: return gpr->x7;
                default: return 0;
            }
        };
        
        // Helper to get float register by index
        auto get_float_reg = [&fpr](size_t idx) -> double {
            // V0-V7 registers, lower 64 bits contain double
            const __uint128_t* vreg = nullptr;
            switch (idx) {
                case 0: vreg = &fpr->v0; break;
                case 1: vreg = &fpr->v1; break;
                case 2: vreg = &fpr->v2; break;
                case 3: vreg = &fpr->v3; break;
                case 4: vreg = &fpr->v4; break;
                case 5: vreg = &fpr->v5; break;
                case 6: vreg = &fpr->v6; break;
                case 7: vreg = &fpr->v7; break;
                default: return 0.0;
            }
            return *reinterpret_cast<const double*>(vreg);
        };
        
        for (auto type : types) {
            calling_convention::typed_arg arg{};
            arg.type = type;
            
            switch (type) {
            case calling_convention::arg_type::INTEGER:
                if (int_reg_idx < 8) {
                    arg.value.integer = get_int_reg(int_reg_idx++);
                } else {
                    // From stack
                    uint64_t sp = gpr->sp;
                    if (auto val = util::safe_memory::read<uint64_t>(
                            vm, sp + stack_offset)) {
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
                    uint64_t sp = gpr->sp;
                    if (type == calling_convention::arg_type::FLOAT) {
                        if (auto val = util::safe_memory::read<float>(
                                vm, sp + stack_offset)) {
                            arg.value.f32 = *val;
                        }
                        stack_offset += 8; // Still 8-byte aligned
                    } else {
                        if (auto val = util::safe_memory::read<double>(
                                vm, sp + stack_offset)) {
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
        return gpr->x0;
    }
    
    static double get_float_return(QBDI::FPRState* fpr) {
        // V0 register, lower 64 bits contain double
        return *reinterpret_cast<const double*>(&fpr->v0);
    }
    
    static uint64_t get_stack_pointer(QBDI::GPRState* gpr) {
        return gpr->sp;
    }
    
    static uint64_t calculate_return_address(
        uint64_t call_site,
        QBDI::GPRState* gpr,
        const QBDI::InstAnalysis* inst) {
        
        // For BL/BLR instruction, return address is next instruction
        if (inst) {
            return call_site + inst->instSize;
        }
        
        // Fallback: assume 4-byte BL
        return call_site + 4;
    }
};

} // namespace w1::abi::detail