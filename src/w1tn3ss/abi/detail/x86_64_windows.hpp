#pragma once

#include "../calling_convention.hpp"
#include <QBDI.h>
#include <array>
#include <cstdint>

namespace w1::abi::detail {

/**
 * @brief windows x64 calling convention implementation
 * 
 * Register usage:
 * - Integer/pointer arguments: RCX, RDX, R8, R9 (first 4), then stack
 * - Floating-point arguments: XMM0-XMM3 (first 4), then stack
 * - Return value: RAX (integer), XMM0 (float/double)
 * - Caller saved: RAX, RCX, RDX, R8-R11, XMM0-XMM5
 * - Callee saved: RBX, RBP, RDI, RSI, RSP, R12-R15, XMM6-XMM15
 * 
 * Stack layout:
 * - 32-byte shadow space reserved by caller
 * - Stack aligned to 16 bytes before call
 * - Parameters beyond 4th passed on stack (right to left)
 * 
 * Special considerations:
 * - Structures larger than 8 bytes passed by reference
 * - __m128 types passed by reference
 * - Varargs use same convention but require different handling
 */
class x86_64_windows_calling_convention : public calling_convention {
public:
    architecture get_architecture() const override {
        return architecture::X86_64;
    }

    std::string get_name() const override {
        return "x86_64_windows";
    }

    std::vector<uint64_t> extract_arguments(
        const QBDI::GPRState* gpr,
        const QBDI::FPRState* fpr,
        size_t num_args,
        std::function<uint64_t(uint64_t)> read_stack
    ) const override {
        std::vector<uint64_t> args;
        args.reserve(num_args);

        // windows x64 uses rcx, rdx, r8, r9 for first 4 integer/pointer args
        const std::array<size_t, 4> int_arg_regs = {
            offsetof(QBDI::GPRState, rcx) / sizeof(QBDI::rword),
            offsetof(QBDI::GPRState, rdx) / sizeof(QBDI::rword),
            offsetof(QBDI::GPRState, r8) / sizeof(QBDI::rword),
            offsetof(QBDI::GPRState, r9) / sizeof(QBDI::rword)
        };

        // extract register arguments
        size_t reg_args = std::min(num_args, int_arg_regs.size());
        for (size_t i = 0; i < reg_args; i++) {
            args.push_back(reinterpret_cast<const QBDI::rword*>(gpr)[int_arg_regs[i]]);
        }

        // extract stack arguments if needed
        if (num_args > int_arg_regs.size()) {
            // stack arguments start after shadow space (32 bytes) and return address (8 bytes)
            // so first stack arg is at rsp + 40
            const uint64_t stack_base = gpr->rsp + 40;
            
            for (size_t i = int_arg_regs.size(); i < num_args; i++) {
                // each argument takes 8 bytes on stack
                uint64_t stack_offset = (i - int_arg_regs.size()) * 8;
                args.push_back(read_stack(stack_base + stack_offset));
            }
        }

        return args;
    }

    uint64_t extract_return_value(
        const QBDI::GPRState* gpr,
        const QBDI::FPRState* fpr
    ) const override {
        // integer/pointer return values in rax
        return gpr->rax;
    }

    std::vector<double> extract_float_arguments(
        const QBDI::FPRState* fpr,
        size_t num_args,
        std::function<uint64_t(uint64_t)> read_stack
    ) const override {
        std::vector<double> args;
        args.reserve(num_args);

        // windows x64 uses xmm0-xmm3 for first 4 float/double args
        const size_t max_fp_regs = 4;
        size_t reg_args = std::min(num_args, max_fp_regs);

        // extract from xmm registers
        for (size_t i = 0; i < reg_args; i++) {
            // xmm registers are 128-bit, we extract lower 64 bits for double
            args.push_back(fpr->xmm[i].reg64[0]);
        }

        // float args beyond 4th are passed on stack
        if (num_args > max_fp_regs) {
            // implementation would need stack reading for float args
            // this is complex as we need to track which args are float vs int
        }

        return args;
    }

    double extract_float_return_value(const QBDI::FPRState* fpr) const override {
        // float/double return values in xmm0
        return fpr->xmm[0].reg64[0];
    }

    bool supports_varargs() const override {
        // windows x64 supports varargs with special handling
        return true;
    }

    std::vector<uint64_t> extract_varargs(
        const QBDI::GPRState* gpr,
        const QBDI::FPRState* fpr,
        size_t min_args,
        std::function<uint64_t(uint64_t)> read_stack
    ) const override {
        // for varargs, all parameters are passed as if they were integers
        // floating point values are also passed in integer registers
        // the callee must know the types to interpret them correctly
        
        // start with a reasonable guess for total args
        const size_t max_scan = 20;
        return extract_arguments(gpr, fpr, max_scan, read_stack);
    }

    std::vector<bool> classify_parameters(const std::vector<param_info>& params) const override {
        std::vector<bool> is_float(params.size(), false);
        
        for (size_t i = 0; i < params.size(); i++) {
            switch (params[i].param_type) {
                case param_info::type::FLOAT:
                case param_info::type::DOUBLE:
                    is_float[i] = true;
                    break;
                default:
                    is_float[i] = false;
                    break;
            }
        }
        
        return is_float;
    }
};

} // namespace w1::abi::detail