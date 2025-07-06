#include "aarch64_aapcs.hpp"
#include <redlog.hpp>

namespace w1::abi::conventions {

std::vector<uint64_t> aarch64_aapcs::extract_integer_args(
    const extraction_context& ctx,
    size_t count) const {
    
    std::vector<uint64_t> args;
    args.reserve(count);
    
    // extract register arguments (x0-x7)
    size_t reg_args = std::min(count, int_arg_regs.size());
    for (size_t i = 0; i < reg_args; i++) {
        args.push_back(reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[i]]);
    }
    
    // extract stack arguments if needed
    if (count > int_arg_regs.size()) {
        // stack arguments start immediately at sp (no return address on stack)
        const uint64_t stack_base = ctx.gpr->sp;
        
        for (size_t i = int_arg_regs.size(); i < count; i++) {
            // each argument takes 8 bytes on stack
            uint64_t stack_offset = (i - int_arg_regs.size()) * 8;
            args.push_back(ctx.read_stack(stack_base + stack_offset));
        }
    }
    
    return args;
}

std::vector<aarch64_aapcs::typed_arg> aarch64_aapcs::extract_typed_args(
    const extraction_context& ctx,
    const std::vector<arg_type>& types) const {
    
    std::vector<typed_arg> args;
    args.reserve(types.size());
    
    size_t int_reg_idx = 0;
    size_t float_reg_idx = 0;
    size_t stack_offset = 0;
    
    for (size_t i = 0; i < types.size(); i++) {
        typed_arg arg;
        arg.type = types[i];
        
        switch (types[i]) {
            case arg_type::INTEGER:
            case arg_type::POINTER:
                if (int_reg_idx < int_arg_regs.size()) {
                    // from register
                    arg.value.integer = reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[int_reg_idx]];
                    arg.from_stack = false;
                    int_reg_idx++;
                } else {
                    // from stack
                    arg.value.integer = ctx.read_stack(ctx.gpr->sp + stack_offset);
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 8;
                }
                break;
                
            case arg_type::FLOAT:
                if (float_reg_idx < max_float_reg_args) {
                    // from v register (s0-s7)
                    // QBDI stores v registers as __uint128_t, we need to extract float
                    const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
                    uint32_t f32_val = static_cast<uint32_t>(v_regs[float_reg_idx]);
                    arg.value.f32 = *reinterpret_cast<float*>(&f32_val);
                    arg.from_stack = false;
                    float_reg_idx++;
                } else {
                    // from stack
                    uint32_t val = static_cast<uint32_t>(ctx.read_stack(ctx.gpr->sp + stack_offset));
                    arg.value.f32 = *reinterpret_cast<float*>(&val);
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 8; // still takes 8 bytes on stack
                }
                break;
                
            case arg_type::DOUBLE:
                if (float_reg_idx < max_float_reg_args) {
                    // from v register (d0-d7)
                    // QBDI stores v registers as __uint128_t, we need to extract double
                    const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
                    uint64_t f64_val = static_cast<uint64_t>(v_regs[float_reg_idx]);
                    arg.value.f64 = *reinterpret_cast<double*>(&f64_val);
                    arg.from_stack = false;
                    float_reg_idx++;
                } else {
                    // from stack
                    uint64_t val = ctx.read_stack(ctx.gpr->sp + stack_offset);
                    arg.value.f64 = *reinterpret_cast<double*>(&val);
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 8;
                }
                break;
                
            case arg_type::SIMD:
                if (float_reg_idx < max_float_reg_args) {
                    // full v register (128-bit)
                    const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
                    memcpy(arg.value.simd, &v_regs[float_reg_idx], 16);
                    arg.from_stack = false;
                    float_reg_idx++;
                } else {
                    // from stack (16 bytes)
                    for (int j = 0; j < 16; j++) {
                        arg.value.simd[j] = static_cast<uint8_t>(
                            ctx.read_stack(ctx.gpr->sp + stack_offset + j) & 0xFF
                        );
                    }
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 16;
                }
                break;
                
            case arg_type::STRUCT_BY_VALUE:
                // small structs may be passed in registers
                // larger structs are passed on stack
                // this is simplified - real implementation would need size info
                if (int_reg_idx < int_arg_regs.size()) {
                    arg.value.struct_data.data[0] = reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[int_reg_idx]];
                    arg.value.struct_data.size = 8;
                    arg.from_stack = false;
                    int_reg_idx++;
                } else {
                    arg.value.struct_data.data[0] = ctx.read_stack(ctx.gpr->sp + stack_offset);
                    arg.value.struct_data.size = 8;
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 8;
                }
                break;
                
            case arg_type::STRUCT_BY_REF:
                // passed as pointer
                if (int_reg_idx < int_arg_regs.size()) {
                    arg.value.integer = reinterpret_cast<const QBDI::rword*>(ctx.gpr)[int_arg_regs[int_reg_idx]];
                    arg.from_stack = false;
                    int_reg_idx++;
                } else {
                    arg.value.integer = ctx.read_stack(ctx.gpr->sp + stack_offset);
                    arg.from_stack = true;
                    arg.stack_offset = stack_offset;
                    stack_offset += 8;
                }
                break;
        }
        
        args.push_back(arg);
    }
    
    return args;
}

aarch64_aapcs::typed_arg aarch64_aapcs::get_typed_return(
    const QBDI::GPRState* gpr,
    const QBDI::FPRState* fpr,
    arg_type type) const {
    
    typed_arg ret;
    ret.type = type;
    ret.from_stack = false;
    
    switch (type) {
        case arg_type::INTEGER:
        case arg_type::POINTER:
        case arg_type::STRUCT_BY_REF:
            ret.value.integer = gpr->x0;
            break;
            
        case arg_type::FLOAT:
            {
                uint32_t f32_val = static_cast<uint32_t>(fpr->v0);
                ret.value.f32 = *reinterpret_cast<float*>(&f32_val);
            }
            break;
            
        case arg_type::DOUBLE:
            {
                uint64_t f64_val = static_cast<uint64_t>(fpr->v0);
                ret.value.f64 = *reinterpret_cast<double*>(&f64_val);
            }
            break;
            
        case arg_type::SIMD:
            memcpy(ret.value.simd, &fpr->v0, 16);
            break;
            
        case arg_type::STRUCT_BY_VALUE:
            // small structs returned in x0/x1
            ret.value.struct_data.data[0] = gpr->x0;
            ret.value.struct_data.data[1] = gpr->x1;
            ret.value.struct_data.size = 16;
            break;
    }
    
    return ret;
}

std::optional<aarch64_aapcs::variadic_info> aarch64_aapcs::get_variadic_info(
    const extraction_context& ctx,
    size_t fixed_arg_count) const {
    
    // aarch64 uses a va_list structure similar to x86-64 system v
    variadic_info info;
    info.fixed_args = fixed_arg_count;
    info.gp_offset = fixed_arg_count * 8; // simplified
    info.fp_offset = 0;
    info.overflow_arg_area = ctx.gpr->sp; // stack args
    info.reg_save_area = 0; // would need to be set up by caller
    
    return info;
}

aarch64_aapcs::register_info aarch64_aapcs::get_register_info() const {
    return {
        .callee_saved_gpr = {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", 
                            "x27", "x28", "x29", "sp"},
        .caller_saved_gpr = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                            "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                            "x16", "x17", "x18", "x30"},
        .callee_saved_fpr = {"v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15"},
        .caller_saved_fpr = {"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
                            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
                            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"},
        .return_register = "x0",
        .argument_registers = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}
    };
}

std::vector<double> aarch64_aapcs::extract_float_args(
    const extraction_context& ctx,
    size_t count) const {
    
    std::vector<double> args;
    args.reserve(count);
    
    // first 8 float/double args in v0-v7
    size_t reg_args = std::min(count, max_float_reg_args);
    const __uint128_t* v_regs = reinterpret_cast<const __uint128_t*>(ctx.fpr);
    for (size_t i = 0; i < reg_args; i++) {
        uint64_t f64_val = static_cast<uint64_t>(v_regs[i]);
        args.push_back(*reinterpret_cast<double*>(&f64_val));
    }
    
    // remaining args on stack
    if (count > max_float_reg_args) {
        const uint64_t stack_base = ctx.gpr->sp;
        
        for (size_t i = max_float_reg_args; i < count; i++) {
            uint64_t stack_offset = (i - max_float_reg_args) * 8;
            uint64_t val = ctx.read_stack(stack_base + stack_offset);
            args.push_back(*reinterpret_cast<double*>(&val));
        }
    }
    
    return args;
}

} // namespace w1::abi::conventions