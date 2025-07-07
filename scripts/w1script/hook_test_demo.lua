-- hook_test_demo.lua
-- Clean demonstration of signature-based function hooking

local tracer = {}

function tracer.init()
    w1.log_info("=== Signature-based Hooking Demo ===")
    
    -- Get platform info
    local platform = w1.get_platform_info()
    w1.log_info(string.format("Platform: %s/%s", platform.os, platform.arch))
    
    -- Helper to get argument registers based on platform
    local function get_arg_regs()
        if platform.arch == "x86_64" then
            return {"rdi", "rsi", "rdx", "rcx", "r8", "r9"}  -- System V ABI
        elseif platform.arch == "aarch64" then
            return {"x0", "x1", "x2", "x3", "x4", "x5"}
        else
            w1.log_error("Unsupported architecture: " .. platform.arch)
            return {}
        end
    end
    
    local arg_regs = get_arg_regs()
    
    -- Define our function signatures based on platform
    local signatures = {}
    
    if platform.arch == "x86_64" then
        -- x64: movabs $0xDEADBEEF00001111, %rax -> 48 b8 11 11 00 00 ef be ad de
        signatures = {
            calculate_secret = "48 b8 11 11 00 00 ef be ad de",
            format_message = "48 b8 22 22 00 00 ef be ad de",
            allocate_buffer = "48 b8 33 33 00 00 ef be ad de",
            compare_strings = "48 b8 44 44 00 00 ef be ad de",
            unsafe_copy = "48 b8 55 55 00 00 ef be ad de"
        }
    elseif platform.arch == "aarch64" then
        -- ARM64: mov x0, #0x1111 -> different encoding
        -- These are approximate - actual encoding depends on assembler
        signatures = {
            calculate_secret = "20 22 82 d2",  -- mov x0, #0x1111
            format_message = "40 44 84 d2",    -- mov x0, #0x2222
            allocate_buffer = "60 66 86 d2",   -- mov x0, #0x3333
            compare_strings = "80 88 88 d2",   -- mov x0, #0x4444
            unsafe_copy = "a0 aa 8a d2"        -- mov x0, #0x5555
        }
    end
    
    -- Define our functions with their hooks
    local functions = {
        {
            name = "calculate_secret",
            sig = p1.sig(signatures.calculate_secret),
            hook = function(vm, gpr, fpr, addr)
                local a = w1.get_reg(gpr, arg_regs[1])
                local b = w1.get_reg(gpr, arg_regs[2])
                w1.log_info(string.format("calculate_secret(%d, %d) called", a, b))
                return w1.VMAction.CONTINUE
            end
        },
        {
            name = "format_message", 
            sig = p1.sig(signatures.format_message),
            hook = function(vm, gpr, fpr, addr)
                local buffer = w1.get_reg(gpr, arg_regs[1])
                local name_ptr = w1.get_reg(gpr, arg_regs[2])
                local value = w1.get_reg(gpr, arg_regs[3])
                
                local name = w1.read_string(vm, name_ptr, 256)
                w1.log_info(string.format("format_message(buffer=0x%x, name=\"%s\", value=%d)", 
                           buffer, name or "?", value))
                return w1.VMAction.CONTINUE
            end
        },
        {
            name = "allocate_buffer",
            sig = p1.sig(signatures.allocate_buffer),
            hook = function(vm, gpr, fpr, addr)
                local size = w1.get_reg(gpr, arg_regs[1])
                w1.log_info(string.format("allocate_buffer(%d) called", size))
                return w1.VMAction.CONTINUE
            end
        },
        {
            name = "compare_strings",
            sig = p1.sig(signatures.compare_strings),
            hook = function(vm, gpr, fpr, addr)
                local str1_ptr = w1.get_reg(gpr, arg_regs[1])
                local str2_ptr = w1.get_reg(gpr, arg_regs[2])
                
                local str1 = w1.read_string(vm, str1_ptr, 256)
                local str2 = w1.read_string(vm, str2_ptr, 256)
                
                w1.log_info(string.format("compare_strings(\"%s\", \"%s\")", 
                           str1 or "?", str2 or "?"))
                return w1.VMAction.CONTINUE
            end
        },
        {
            name = "unsafe_copy",
            sig = p1.sig(signatures.unsafe_copy),
            hook = function(vm, gpr, fpr, addr)
                local dst = w1.get_reg(gpr, arg_regs[1])
                local src_ptr = w1.get_reg(gpr, arg_regs[2])
                
                local src = w1.read_string(vm, src_ptr, 256)
                w1.log_warn(string.format("UNSAFE: strcpy(dst=0x%x, src=\"%s\")", 
                           dst, src or "?"))
                return w1.VMAction.CONTINUE
            end
        }
    }
    
    -- Hook each function using its signature
    for _, func in ipairs(functions) do
        local hook_id = w1.hook_sig(func.sig, func.hook)
        
        if hook_id then
            w1.log_info(string.format("✓ Hooked %s", func.name))
        else
            w1.log_error(string.format("✗ Failed to hook %s", func.name))
        end
    end
    
    w1.log_info("Ready to trace!")
end

tracer.callbacks = {}

function tracer.shutdown()
    w1.log_info("Shutting down...")
    w1.remove_all_hooks()
end

return tracer