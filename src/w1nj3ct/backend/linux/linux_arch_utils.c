#include "linux_shellcode.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/user.h>

#if defined(__aarch64__) || defined(__arm__)
#include <asm/ptrace.h>
#endif

// Architecture information table
static const linux_arch_info_t arch_info_table[] = {
    [ARCH_X86_64] = {
        .arch = ARCH_X86_64,
        .reg_size = sizeof(struct user_regs_struct),
        .ptr_size = 8,
        .register_layout = {
#ifdef __x86_64__
            .pc_offset = offsetof(struct user_regs_struct, rip),
            .sp_offset = offsetof(struct user_regs_struct, rsp),
            .ret_offset = offsetof(struct user_regs_struct, rax)
#else
            .pc_offset = 128, // rip offset
            .sp_offset = 152, // rsp offset
            .ret_offset = 80  // rax offset
#endif
        }
    },
    [ARCH_I386] = {
        .arch = ARCH_I386,
        .reg_size = sizeof(struct user_regs_struct),
        .ptr_size = 4,
        .register_layout = {
#ifdef __i386__
            .pc_offset = offsetof(struct user_regs_struct, eip),
            .sp_offset = offsetof(struct user_regs_struct, esp),
            .ret_offset = offsetof(struct user_regs_struct, eax)
#else
            .pc_offset = 48, // eip offset
            .sp_offset = 60, // esp offset
            .ret_offset = 24 // eax offset
#endif
        }
    },
    [ARCH_ARM64] = {
        .arch = ARCH_ARM64,
#if defined(__aarch64__)
        .reg_size = sizeof(struct user_regs_struct),
        .ptr_size = 8,
        .register_layout = {
            .pc_offset = offsetof(struct user_regs_struct, pc),
            .sp_offset = offsetof(struct user_regs_struct, sp),
            .ret_offset = 0 // regs[0] (x0) for return value
        }
#else
        .reg_size = 272, // sizeof(struct user_pt_regs) on ARM64
        .ptr_size = 8,
        .register_layout = {
            .pc_offset = 248, // pc offset in user_pt_regs
            .sp_offset = 240, // sp offset in user_pt_regs
            .ret_offset = 0   // regs[0] for return value
        }
#endif
    },
    [ARCH_ARM32] = {
        .arch = ARCH_ARM32,
        .reg_size = 72, // ARM32 user_regs size
        .ptr_size = 4,
        .register_layout = {
            .pc_offset = 60, // ARM PC register offset
            .sp_offset = 52, // ARM SP register offset
            .ret_offset = 0  // r0 for return value
        }
    }
};

const linux_arch_info_t* linux_get_arch_info(linux_arch_t arch) {
    if (arch > ARCH_UNKNOWN && arch < (sizeof(arch_info_table) / sizeof(arch_info_table[0]))) {
        return &arch_info_table[arch];
    }
    return NULL;
}

int linux_set_instruction_pointer(void* regs, linux_arch_t arch, uint64_t address) {
    const linux_arch_info_t* info = linux_get_arch_info(arch);
    if (!info || !regs) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    if (info->ptr_size == 8) {
        *((uint64_t*)((char*)regs + info->register_layout.pc_offset)) = address;
    } else {
        *((uint32_t*)((char*)regs + info->register_layout.pc_offset)) = (uint32_t)address;
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_get_return_value(void* regs, linux_arch_t arch, void** result) {
    const linux_arch_info_t* info = linux_get_arch_info(arch);
    if (!info || !regs || !result) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    if (info->ptr_size == 8) {
        *result = (void*)*((uint64_t*)((char*)regs + info->register_layout.ret_offset));
    } else {
        *result = (void*)(uintptr_t)*((uint32_t*)((char*)regs + info->register_layout.ret_offset));
    }
    
    return LINUX_SHELLCODE_SUCCESS;
}

int linux_set_register_value(void* regs, linux_arch_t arch, int reg_num, uint64_t value) {
    const linux_arch_info_t* info = linux_get_arch_info(arch);
    if (!info || !regs) {
        return LINUX_SHELLCODE_ERROR_INVALID_ARGS;
    }
    
    // Implementation for ARM64 general purpose registers
    if (arch == ARCH_ARM64 && reg_num < 31) {
#ifdef __aarch64__
        ((struct user_regs_struct*)regs)->regs[reg_num] = value;
#else
        *((uint64_t*)((char*)regs + reg_num * 8)) = value;
#endif
        return LINUX_SHELLCODE_SUCCESS;
    }
    
    return LINUX_SHELLCODE_ERROR_UNSUPPORTED_ARCH;
}