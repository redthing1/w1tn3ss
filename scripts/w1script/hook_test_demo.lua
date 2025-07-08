-- hook_test_demo.lua
-- demonstration of w1script hooking capabilities
-- works with tests/programs/hook_test_target
--
-- this demo shows:
-- 1. address-based hooking with w1.hook_addr()
-- 2. module+offset hooking with w1.hook_module()
-- 3. reading register values for function arguments
-- 4. security monitoring (detecting unsafe functions)
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_test_demo.lua \
--   -s ./build-release/tests/programs/hook_test_target

local tracer = {}

-- helper to read c strings from memory
local function read_cstring(ptr, max_len)
    if not ptr or ptr == 0 then
        return "(null)"
    end
    
    local bytes = w1.read_memory(ptr, max_len or 256)
    if not bytes then
        return "(error reading memory)"
    end
    
    local str = ""
    for i = 1, #bytes do
        local byte = bytes[i]
        if byte == 0 then break end
        str = str .. string.char(byte)
    end
    return str
end

function tracer.init()
    w1.log_info("=== w1tn3ss hook test demo ===")
    w1.log_info("demonstrating function hooking with w1script")
    
    -- find the target module
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
    
    local hook1 = w1.hook_addr(calculate_secret_addr, function(vm, gpr, fpr, address)
        -- arm64: arguments in x0, x1
        local a = w1.get_reg(gpr, "x0")
        local b = w1.get_reg(gpr, "x1")
        
        w1.log_info(string.format("[calculate_secret] called with a=%d, b=%d", a, b))
        w1.log_info(string.format("[calculate_secret] expected result: %d", a * 3 + b * 2))
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook1 then
        w1.log_info(string.format("✓ hooked calculate_secret at 0x%x", calculate_secret_addr))
    end
    
    -- hook allocate_buffer using module+offset
    -- this demonstrates position-independent hooking
    local hook2 = w1.hook_module("hook_test_target", 0x8e4, function(vm, gpr, fpr, address)
        local size = w1.get_reg(gpr, "x0")
        w1.log_info(string.format("[allocate_buffer] allocating %d bytes", size))
        return w1.VMAction.CONTINUE
    end)
    
    if hook2 then
        w1.log_info("✓ hooked allocate_buffer via module+offset")
    end
    
    -- hook unsafe_copy to demonstrate security monitoring
    -- this shows how to detect potentially dangerous function calls
    local unsafe_copy_addr = target_module.base_address + 0x98c
    
    local hook3 = w1.hook_addr(unsafe_copy_addr, function(vm, gpr, fpr, address)
        local dest_ptr = w1.get_reg(gpr, "x0")
        local src_ptr = w1.get_reg(gpr, "x1")
        
        w1.log_warning("[unsafe_copy] security warning: strcpy() detected")
        w1.log_warning(string.format("[unsafe_copy] dest=0x%x, src=0x%x", dest_ptr, src_ptr))
        
        -- note: string reading may fail if pointers aren't set up yet
        -- this is common when hooking at function entry
        
        return w1.VMAction.CONTINUE
    end)
    
    if hook3 then
        w1.log_info(string.format("✓ hooked unsafe_copy at 0x%x", unsafe_copy_addr))
    end
    
    w1.log_info("")
    w1.log_info("=== hook summary ===")
    w1.log_info("- use w1.hook_addr() for absolute address hooking")
    w1.log_info("- use w1.hook_module() for module+offset hooking")
    w1.log_info("- use w1.hook_range() to monitor code regions")
    w1.log_info("- for signature-based hooking, use w1.hook_sig()")
    w1.log_info("")
    w1.log_info("ready to trace - hooks will trigger when functions are called")
    
    -- note about hooking limitations:
    -- when hooking at function entry (especially with marker bytes),
    -- register values may not reflect the actual function arguments yet.
    -- for more reliable argument capture, consider:
    -- 1. hooking a few instructions into the function
    -- 2. using signature-based hooks that target specific patterns
    -- 3. hooking at call sites instead of function entries
end

tracer.callbacks = {}

return tracer