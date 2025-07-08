-- hook_demo_abi.lua
-- cross-platform hooking using calling convention apis
-- portable across architectures without hardcoding register names
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_demo_abi.lua \
--   -s ./build-release/tests/programs/hook_test_target

local tracer = {}

function tracer.init()
    w1.log_info("=== hook demonstration - calling convention apis ===")
    
    -- detect and log platform info
    local plat_info = w1.get_platform_info()
    w1.log_info("platform information:")
    w1.log_info(string.format("  os: %s", plat_info.os))
    w1.log_info(string.format("  architecture: %s", plat_info.arch))
    w1.log_info(string.format("  bits: %d", plat_info.bits))
    
    -- get calling convention details
    local cc_info = w1.get_calling_convention_info()
    if cc_info then
        w1.log_info("calling convention:")
        w1.log_info(string.format("  name: %s", cc_info.name))
        w1.log_info(string.format("  id: %s", cc_info.id))
        
        if cc_info.argument_registers then
            w1.log_info(string.format("  argument registers: %s", 
                                      table.concat(cc_info.argument_registers, ", ")))
        end
        
        w1.log_info(string.format("  return register: %s", cc_info.return_register))
        w1.log_info(string.format("  stack alignment: %d bytes", cc_info.stack_alignment))
        w1.log_info(string.format("  stack cleanup: %s", cc_info.stack_cleanup))
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
    
    -- hook calculate_secret with abi-aware argument extraction
    local calculate_secret_addr = target_module.base_address + 0x840
    local hook_id = w1.hook_addr(calculate_secret_addr, function(vm, gpr, fpr, address)
        -- extract arguments using calling convention
        local args = w1.get_args(vm, gpr, fpr, 2)
        
        if args then
            w1.log_info(string.format("[calculate_secret] a=%d, b=%d, result=%d", 
                                      args[1], args[2], 3 * args[1] + 2 * args[2]))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked calculate_secret at 0x%x", calculate_secret_addr))
    end
    
    -- hook format_message with typed arguments
    local format_message_addr = target_module.base_address + 0x88c
    hook_id = w1.hook_addr(format_message_addr, function(vm, gpr, fpr, address)
        -- extract typed arguments: char*, const char*, int
        local typed_args = w1.get_typed_args(vm, gpr, fpr, {"pointer", "pointer", "integer"})
        
        if typed_args then
            -- read string from second pointer argument
            local name_str = w1.read_string(vm, typed_args[2].value, 256)
            
            if name_str then
                w1.log_info(string.format("[format_message] name='%s', value=%d", 
                                          name_str, typed_args[3].value))
            end
            
            -- log argument details for debugging (use -vvv to see)
            w1.log_debug("  argument details:")
            for i, arg in ipairs(typed_args) do
                w1.log_debug(string.format("    arg%d: type=%s, value=0x%x, from_stack=%s",
                                          i, arg.type, arg.value, tostring(arg.from_stack)))
            end
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked format_message at 0x%x", format_message_addr))
    end
    
    -- hook compare_strings
    local compare_strings_addr = target_module.base_address + 0x940
    hook_id = w1.hook_addr(compare_strings_addr, function(vm, gpr, fpr, address)
        -- use convenience function for individual args
        local str1_ptr = w1.get_arg(vm, gpr, fpr, 1)
        local str2_ptr = w1.get_arg(vm, gpr, fpr, 2)
        
        if str1_ptr and str2_ptr then
            -- read both strings
            local str1 = w1.read_string(vm, str1_ptr, 256)
            local str2 = w1.read_string(vm, str2_ptr, 256)
            
            if str1 and str2 then
                w1.log_info(string.format("[compare_strings] '%s' vs '%s'", str1, str2))
            end
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked compare_strings at 0x%x", compare_strings_addr))
    end
    
    -- hook allocate_buffer
    local allocate_buffer_addr = target_module.base_address + 0x8e4
    hook_id = w1.hook_addr(allocate_buffer_addr, function(vm, gpr, fpr, address)
        -- extract single argument
        local size = w1.get_arg(vm, gpr, fpr, 1)
        
        if size then
            w1.log_info(string.format("[allocate_buffer] size=%d bytes", size))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked allocate_buffer at 0x%x", allocate_buffer_addr))
    end
    
    -- hook unsafe_copy using module+offset for security monitoring
    local unsafe_copy_hook = w1.hook_module("hook_test_target", 0x98c, function(vm, gpr, fpr, address)
        -- extract two pointer arguments portably
        local args = w1.get_args(vm, gpr, fpr, 2)
        
        if args then
            -- read source content to detect potentially dangerous operations
            local src_content = w1.read_string(vm, args[2], 256)
            
            if src_content then
                w1.log_warning(string.format("[unsafe_copy] security risk! copying '%s'", src_content))
            end
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