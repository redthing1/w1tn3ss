-- hook_demo_sig.lua
-- cross-platform hooking demonstration using signature-based function discovery
-- automatically finds functions by their unique assembly signatures
-- supports x86_64 and aarch64 architectures
--
-- approach:
-- 1. use p1.search_signature() to find functions by their unique byte patterns
-- 2. filter results to specific modules to avoid false positives
-- 3. hook found addresses with w1.hook_addr()
--
-- signature format:
-- - lowercase hex bytes grouped by instruction (e.g., "202282d2 e0ddb7f2 a0d5dbf2")
-- - supports wildcards with ?? for flexible matching (e.g., "????82d2" matches any mov)
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_demo_sig.lua \
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

-- helper to search and hook a signature with proper filtering
local function hook_signature(name, pattern, filter, handler)
    w1.log_info(string.format("searching for %s signature...", name))
    
    local search_results = p1.search_signature(pattern, filter)
    if search_results and #search_results > 0 then
        w1.log_info(string.format("found %d matches for %s signature", #search_results, name))
        
        -- only hook if we found exactly one match in the target module
        if #search_results == 1 then
            local addr = search_results[1].address
            w1.log_info(string.format("  hooking %s at 0x%x", name, addr))
            
            local hook_id = w1.hook_addr(addr, handler)
            if hook_id then
                w1.log_info(string.format("✓ hooked %s using signature", name))
                return true
            else
                w1.log_error(string.format("failed to hook %s at 0x%x", name, addr))
            end
        else
            w1.log_warning(string.format("found multiple matches (%d) for %s, expected 1", #search_results, name))
            for i, result in ipairs(search_results) do
                w1.log_info(string.format("  match %d: address=0x%x", i, result.address))
            end
        end
    else
        w1.log_error(string.format("failed to find %s signature", name))
    end
    return false
end

-- example of using wildcards for more flexible matching:
-- "202282d2 e0ddb7f2 a0d5dbf2" could become "????82d2 e0ddb7f2 a0d5dbf2" 
-- to match any mov instruction followed by the specific movk instructions
--
-- platform-specific considerations for x86_64:
-- - Linux/macOS with GCC/Clang: inline assembly works as shown
-- - Windows with MSVC: no inline assembly support on x64, would need:
--   1. External .asm files with MASM syntax
--   2. Intrinsics that generate predictable patterns
--   3. Compiler-specific pragmas or attributes
-- - Windows with MinGW/Clang: supports GCC-style inline assembly

function tracer.init()
    w1.log_info("=== hook demonstration - signature-based hooking ===")
    
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
    
    -- check if p1 module is available
    w1.log_info("checking p1 module availability...")
    if not p1 or not p1.search_signature then
        w1.log_error("p1 module or search_signature function not available!")
        return
    end
    w1.log_info("p1 module ready")
    
    -- define unique signatures for each function based on UNIQUE_SIGNATURE macros
    local signatures = {}
    
    if plat_info.arch == "x86_64" then
        -- x86_64: movabs $0xDEADBEEF0000XXXX, %rax (AT&T syntax)
        -- Note: Windows MSVC doesn't support inline assembly on x64, would need different approach
        -- 48b8 = REX.W + mov rax, imm64 instruction
        -- Immediate value is stored in little-endian order
        
        if plat_info.os == "windows" then
            -- Windows/MSVC typically uses intrinsics or separate ASM files
            -- These signatures assume MASM-style assembly if used
            w1.log_warning("Windows x64 may require different signature approach")
        end
        
        -- GCC/Clang on Linux/macOS use AT&T syntax inline assembly
        -- movabs $0xDEADBEEF00001111, %rax becomes:
        -- 48 = REX.W prefix (64-bit operand)
        -- b8 = mov rax, imm64 opcode
        -- Following 8 bytes are the immediate value in little-endian:
        -- 0xDEADBEEF00001111 -> 11 11 00 00 ef be ad de
        signatures.calculate_secret = "48b8 11110000efbeadde"  -- movabs $0xDEADBEEF00001111, %rax
        signatures.format_message   = "48b8 22220000efbeadde"  -- movabs $0xDEADBEEF00002222, %rax
        signatures.allocate_buffer  = "48b8 33330000efbeadde"  -- movabs $0xDEADBEEF00003333, %rax
        signatures.compare_strings  = "48b8 44440000efbeadde"  -- movabs $0xDEADBEEF00004444, %rax
        signatures.unsafe_copy      = "48b8 55550000efbeadde"  -- movabs $0xDEADBEEF00005555, %rax
        
        -- Alternative: Use wildcards if the upper bytes might vary:
        -- "48b8 1111????????de" to match any value with 0x1111 in lower 16 bits
    elseif plat_info.arch == "aarch64" then
        -- aarch64: Three instruction sequence for loading 48-bit constant
        -- mov x0, #imm16; movk x0, #0xbeef, lsl #16; movk x0, #0xdead, lsl #32
        signatures.calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2"  -- mov x0,#0x1111; movk x0,#0xbeef,lsl#16; movk x0,#0xdead,lsl#32
        signatures.format_message   = "404484d2 e0ddb7f2 a0d5dbf2"  -- mov x0,#0x2222; movk x0,#0xbeef,lsl#16; movk x0,#0xdead,lsl#32
        signatures.allocate_buffer  = "606686d2 e0ddb7f2 a0d5dbf2"  -- mov x0,#0x3333; movk x0,#0xbeef,lsl#16; movk x0,#0xdead,lsl#32
        signatures.compare_strings  = "808888d2 e0ddb7f2 a0d5dbf2"  -- mov x0,#0x4444; movk x0,#0xbeef,lsl#16; movk x0,#0xdead,lsl#32
        signatures.unsafe_copy      = "a0aa8ad2 e0ddb7f2 a0d5dbf2"  -- mov x0,#0x5555; movk x0,#0xbeef,lsl#16; movk x0,#0xdead,lsl#32
    else
        w1.log_error("unsupported architecture for signature-based hooking")
        return
    end
    
    -- hook calculate_secret
    hook_signature("calculate_secret", signatures.calculate_secret, "hook_test_target", function(vm, gpr, fpr, address)
        local a = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local b = w1.get_reg(gpr, get_arg_reg(regs, 2))
        
        w1.log_info(string.format("[calculate_secret] a=%d, b=%d, result=%d", 
                                  a, b, 3 * a + 2 * b))
        
        return w1.VMAction.CONTINUE
    end)
    
    
    -- hook format_message
    hook_signature("format_message", signatures.format_message, "hook_test_target", function(vm, gpr, fpr, address)
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
    
    -- hook compare_strings
    hook_signature("compare_strings", signatures.compare_strings, "hook_test_target", function(vm, gpr, fpr, address)
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
    
    -- hook allocate_buffer
    hook_signature("allocate_buffer", signatures.allocate_buffer, "hook_test_target", function(vm, gpr, fpr, address)
        local size = w1.get_reg(gpr, get_arg_reg(regs, 1))
        
        w1.log_info(string.format("[allocate_buffer] size=%d bytes", size))
        
        return w1.VMAction.CONTINUE
    end)
    
    -- hook unsafe_copy for security monitoring
    hook_signature("unsafe_copy", signatures.unsafe_copy, "hook_test_target", function(vm, gpr, fpr, address)
        local dst = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local src = w1.get_reg(gpr, get_arg_reg(regs, 2))
        
        -- read source content to detect potentially dangerous operations
        local src_content = w1.read_string(vm, src, 256)
        
        if src_content then
            w1.log_warning(string.format("[unsafe_copy] security risk! copying '%s'", src_content))
        end
        
        return w1.VMAction.CONTINUE
    end)
    
    w1.log_info("")
    w1.log_info("ready to trace")
end

tracer.callbacks = {}

return tracer