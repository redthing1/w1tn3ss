-- hook_demo_direct.lua
-- cross-platform hooking demonstration using direct register access
-- automatically adapts to different architectures and operating systems
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_demo_direct.lua \
--   -s ./build-release/tests/programs/hook_test_target

local tracer = {}

-- platform-specific register mappings
local REGISTERS = {
    aarch64 = {
        args = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"},
        sp = "sp", ret = "x0"
    },
    x86_64 = {
        linux = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp", ret = "rax"
        },
        macos = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp", ret = "rax"
        },
        windows = {
            args = {"rcx", "rdx", "r8", "r9"},
            sp = "rsp", ret = "rax"
        }
    },
    x86 = {
        -- x86 typically uses stack for args
        sp = "esp", ret = "eax"
    },
    arm = {
        args = {"r0", "r1", "r2", "r3"},
        sp = "sp", ret = "r0"
    }
}

-- helper to get platform-specific registers
local function get_platform_regs(plat_info)
    local arch_regs = REGISTERS[plat_info.arch]
    if not arch_regs then return nil end
    
    -- aarch64 and arm use same regs across all OS
    if plat_info.arch == "aarch64" or plat_info.arch == "arm" then
        return arch_regs
    end
    
    -- x86_64 differs by OS
    if plat_info.arch == "x86_64" then
        return arch_regs[plat_info.os] or arch_regs.linux
    end
    
    return arch_regs
end

-- helper to get argument register
local function get_arg_reg(regs, n)
    if regs and regs.args and regs.args[n] then
        return regs.args[n]
    end
    return nil
end

function tracer.init()
    w1.log_info("=== hook demonstration - direct register access ===")
    
    -- detect and log platform info
    local plat_info = w1.get_platform_info()
    w1.log_info("platform information:")
    w1.log_info(string.format("  os: %s", plat_info.os))
    w1.log_info(string.format("  architecture: %s", plat_info.arch))
    w1.log_info(string.format("  bits: %d", plat_info.bits))
    
    -- get platform registers
    local regs = get_platform_regs(plat_info)
    if regs and regs.args then
        w1.log_info(string.format("  calling convention: %s", 
            plat_info.arch == "x86_64" and plat_info.os or "standard"))
        w1.log_info(string.format("  argument registers: %s", table.concat(regs.args, ", ")))
        w1.log_info(string.format("  return register: %s", regs.ret))
    else
        w1.log_info("  calling convention: stack-based")
    end
    w1.log_info("")
    
    -- find target module
    local modules = w1.module_list_all()
    local target_module = nil
    
    for _, mod in pairs(modules) do
        if string.find(mod.path, "hook_test_target") then
            target_module = mod
            break
        end
    end
    
    if not target_module then
        w1.log_error("target module 'hook_test_target' not found")
        return
    end
    
    w1.log_info(string.format("target module: %s", target_module.path))
    w1.log_info(string.format("base address: 0x%x", target_module.base_address))
    w1.log_info("")
    
    -- hook calculate_secret
    local calculate_secret_addr = target_module.base_address + 0x840
    local hook_id = w1.hook_addr(calculate_secret_addr, function(vm, gpr, fpr, address)
        local a = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local b = w1.get_reg(gpr, get_arg_reg(regs, 2))
        
        w1.log_info(string.format("[calculate_secret] a=%d, b=%d, result=%d", 
                                  a, b, 3 * a + 2 * b))
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked calculate_secret at 0x%x", calculate_secret_addr))
    end
    
    -- hook format_message
    local format_message_addr = target_module.base_address + 0x88c
    hook_id = w1.hook_addr(format_message_addr, function(vm, gpr, fpr, address)
        local buffer_ptr = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local name_ptr = w1.get_reg(gpr, get_arg_reg(regs, 2))
        local value = w1.get_reg(gpr, get_arg_reg(regs, 3))
        
        -- read string from memory
        local name_str = w1.read_string(vm, name_ptr, 256)
        
        if name_str then
            w1.log_info(string.format("[format_message] name='%s', value=%d", name_str, value))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked format_message at 0x%x", format_message_addr))
    end
    
    -- hook compare_strings
    local compare_strings_addr = target_module.base_address + 0x940
    hook_id = w1.hook_addr(compare_strings_addr, function(vm, gpr, fpr, address)
        local str1_ptr = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local str2_ptr = w1.get_reg(gpr, get_arg_reg(regs, 2))
        
        -- read both strings
        local str1 = w1.read_string(vm, str1_ptr, 256)
        local str2 = w1.read_string(vm, str2_ptr, 256)
        
        if str1 and str2 then
            w1.log_info(string.format("[compare_strings] '%s' vs '%s'", str1, str2))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked compare_strings at 0x%x", compare_strings_addr))
    end
    
    -- hook allocate_buffer
    local allocate_buffer_addr = target_module.base_address + 0x8e4
    hook_id = w1.hook_addr(allocate_buffer_addr, function(vm, gpr, fpr, address)
        local size = w1.get_reg(gpr, get_arg_reg(regs, 1))
        
        w1.log_info(string.format("[allocate_buffer] size=%d bytes", size))
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked allocate_buffer at 0x%x", allocate_buffer_addr))
    end
    
    -- hook unsafe_copy using module+offset for security monitoring
    local unsafe_copy_hook = w1.hook_module("hook_test_target", 0x98c, function(vm, gpr, fpr, address)
        local dst = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local src = w1.get_reg(gpr, get_arg_reg(regs, 2))
        
        -- read source content to detect potentially dangerous operations
        local src_content = w1.read_string(vm, src, 256)
        
        if src_content then
            w1.log_warning(string.format("[unsafe_copy] security risk! copying '%s'", src_content))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if unsafe_copy_hook then
        w1.log_info("✓ hooked unsafe_copy for security monitoring")
    end
    
    w1.log_info("")
    w1.log_info("ready to trace")
end

tracer.callbacks = {}

return tracer