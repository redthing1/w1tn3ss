-- hook_test_demo.lua
-- demonstration of w1script hooking capabilities with memory reading
-- works with tests/programs/hook_test_target
--
-- this demo shows:
-- 1. address-based hooking with w1.hook_addr()
-- 2. module+offset hooking with w1.hook_module()
-- 3. reading register values for function arguments
-- 4. safely reading strings from memory pointers
-- 5. security monitoring (detecting unsafe functions)
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_test_demo.lua \
--   -s ./build-release/tests/programs/hook_test_target

local tracer = {}

-- init function called at start
function tracer.init()
    w1.log_info("=== w1tn3ss hook test demo ===")
    w1.log_info("demonstrating function hooking with safe memory reading")
    
    -- find target module
    local modules = w1.module_list_all()
    local target_module = nil
    
    for i, mod in pairs(modules) do
        if string.find(mod.path, "hook_test_target") then
            target_module = mod
            break
        end
    end
    
    if not target_module then
        w1.log_error("target module 'hook_test_target' not found")
        return
    end
    
    w1.log_info(string.format("found target: %s at base 0x%x", 
                              target_module.path, target_module.base_address))
    
    -- hook calculate_secret to demonstrate basic register access
    -- this shows how to read function arguments from registers
    local calculate_secret_addr = target_module.base_address + 0x840
    local hook_id = w1.hook_addr(calculate_secret_addr, function(vm, gpr, fpr, address)
        local pc = w1.get_reg_pc(gpr)
        local a = w1.get_reg(gpr, "x0")  -- first argument
        local b = w1.get_reg(gpr, "x1")  -- second argument
        
        w1.log_info(string.format("[calculate_secret] called at 0x%x", address))
        w1.log_info(string.format("[calculate_secret] a=%d, b=%d, expected_result=%d", 
                                a, b, 3 * a + 2 * b))
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id then
        w1.log_info(string.format("✓ hooked calculate_secret at 0x%x", calculate_secret_addr))
    else
        w1.log_error("failed to hook calculate_secret")
    end
    
    -- hook format_message to demonstrate reading string arguments
    -- this shows how to safely read memory to get string content
    local format_message_addr = target_module.base_address + 0x88c
    local hook_id2 = w1.hook_addr(format_message_addr, function(vm, gpr, fpr, address)
        local buffer_ptr = w1.get_reg(gpr, "x0")
        local name_ptr = w1.get_reg(gpr, "x1")
        local value = w1.get_reg(gpr, "x2")
        
        -- safely read the name string from memory
        local name_str = w1.read_string(vm, name_ptr, 256)
        
        if name_str then
            w1.log_info(string.format("[format_message] buffer=0x%x, name_ptr=0x%x", 
                                    buffer_ptr, name_ptr))
            w1.log_info(string.format("[format_message] name='%s', value=%d", 
                                    name_str, value))
        else
            w1.log_info(string.format("[format_message] buffer=0x%x, name_ptr=0x%x", 
                                    buffer_ptr, name_ptr))
            w1.log_info(string.format("[format_message] name=<read failed>, value=%d", 
                                    value))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id2 then
        w1.log_info(string.format("✓ hooked format_message at 0x%x", format_message_addr))
    else
        w1.log_error("failed to hook format_message")
    end
    
    -- hook compare_strings to demonstrate reading multiple string arguments
    -- this shows reading two string pointers and comparing their content
    local compare_strings_addr = target_module.base_address + 0x940
    local hook_id3 = w1.hook_addr(compare_strings_addr, function(vm, gpr, fpr, address)
        local str1_ptr = w1.get_reg(gpr, "x0")
        local str2_ptr = w1.get_reg(gpr, "x1")
        
        -- safely read both strings
        local str1 = w1.read_string(vm, str1_ptr, 256)
        local str2 = w1.read_string(vm, str2_ptr, 256)
        
        if str1 and str2 then
            w1.log_info(string.format("[compare_strings] str1_ptr=0x%x, str2_ptr=0x%x", 
                                    str1_ptr, str2_ptr))
            w1.log_info(string.format("[compare_strings] str1='%s', str2='%s', match=%s", 
                                    str1, str2, tostring(str1 == str2)))
        else
            w1.log_info(string.format("[compare_strings] str1_ptr=0x%x, str2_ptr=0x%x", 
                                    str1_ptr, str2_ptr))
            w1.log_info(string.format("[compare_strings] str1='%s', str2='%s'", 
                                    str1 or "<read failed>", str2 or "<read failed>"))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id3 then
        w1.log_info(string.format("✓ hooked compare_strings at 0x%x", compare_strings_addr))
    else
        w1.log_error("failed to hook compare_strings")
    end
    
    -- hook unsafe_copy to demonstrate security analysis with memory reading
    -- shows how hooking can detect potentially dangerous operations and read content
    local unsafe_copy_hook = w1.hook_module("hook_test_target", 0x98c, function(vm, gpr, fpr, address)
        local dst = w1.get_reg(gpr, "x0")
        local src = w1.get_reg(gpr, "x1")
        
        -- try to read the source string to see what's being copied
        local src_content = w1.read_string(vm, src, 256)
        
        if src_content then
            w1.log_warning(string.format("[unsafe_copy] security risk! dst=0x%x, src=0x%x", 
                                       dst, src))
            w1.log_warning(string.format("[unsafe_copy] content='%s', length=%d", 
                                       src_content, #src_content))
        else
            w1.log_warning(string.format("[unsafe_copy] security risk! dst=0x%x, src=0x%x", 
                                       dst, src))
            w1.log_warning("[unsafe_copy] content=<read failed>")
        end
        
        -- in a real security analysis, you might want to:
        -- 1. check buffer sizes
        -- 2. validate memory regions
        -- 3. log the operation for audit
        -- 4. potentially block the operation
        
        return w1.VMAction.CONTINUE
    end)
    
    if unsafe_copy_hook then
        w1.log_info("✓ hooked unsafe_copy for security monitoring")
    else
        w1.log_error("failed to hook unsafe_copy")
    end
    
    -- demonstrate reading raw memory bytes
    -- useful for inspecting buffers, structures, or unknown data
    local allocate_buffer_addr = target_module.base_address + 0x8e4
    local hook_id4 = w1.hook_addr(allocate_buffer_addr, function(vm, gpr, fpr, address)
        local size = w1.get_reg(gpr, "x0")
        
        w1.log_info(string.format("[allocate_buffer] allocating %d bytes", size))
        
        -- you could also hook the return to see what was allocated
        -- by reading the return value from x0 after the function completes
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook_id4 then
        w1.log_info(string.format("✓ hooked allocate_buffer at 0x%x", allocate_buffer_addr))
    else
        w1.log_error("failed to hook allocate_buffer")
    end
    
    w1.log_info("")
    w1.log_info("=== hook summary ===")
    w1.log_info("- address hooks demonstrate precise function targeting")
    w1.log_info("- module+offset hooks work across aslr/relocation")
    w1.log_info("- memory reading apis enable string/data inspection")
    w1.log_info("- security monitoring can detect dangerous operations")
    w1.log_info("")
    w1.log_info("ready to trace - hooks will trigger when functions are called")
    
    -- the safe memory apis demonstrated:
    -- - w1.read_string(address, max_length): read null-terminated strings
    -- - w1.read_memory(address, size): read raw bytes as table
    -- these apis handle invalid addresses gracefully and return nil on failure
end

tracer.callbacks = {}

return tracer