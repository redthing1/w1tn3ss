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

-- ============================================================================
-- register mappings
-- ============================================================================

-- platform-specific register mappings for different architectures and calling conventions
local REGISTERS = {
    aarch64 = {
        args = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"},
        sp = "sp",
        ret = "x0"
    },
    x86_64 = {
        linux = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp",
            ret = "rax"
        },
        macos = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp",
            ret = "rax"
        },
        windows = {
            args = {"rcx", "rdx", "r8", "r9"},
            sp = "rsp",
            ret = "rax"
        }
    },
    x86 = {
        sp = "esp",
        ret = "eax" -- x86 typically uses stack for args
    },
    arm = {
        args = {"r0", "r1", "r2", "r3"},
        sp = "sp",
        ret = "r0"
    }
}

-- ============================================================================
-- utility functions
-- ============================================================================

-- get platform-specific registers based on architecture and OS
local function get_platform_regs(plat_info)
    local arch_regs = REGISTERS[plat_info.arch]
    if not arch_regs then
        return nil
    end

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

-- get argument register by index (1-based)
local function get_arg_reg(regs, n)
    if regs and regs.args and regs.args[n] then
        return regs.args[n]
    end
    return nil
end

-- helper to build wildcard patterns with specified gap size
local function wildcards(count)
    local pattern = ""
    for i = 1, count do
        pattern = pattern .. " ????????"
    end
    return pattern
end

-- ============================================================================
-- signature definitions
-- ============================================================================

-- define platform-specific signatures for each function
local function get_signatures(plat_info)
    local signatures = {}

    if plat_info.arch == "x86_64" then
        if plat_info.os == "windows" then
            -- windows msvc x64 pattern:
            -- all functions start with mov rax, 0xdeadbeefcafebabe
            -- followed by xor operations and function-specific code
            local msvc_base = "48b8 bebafecaefbeadde" -- mov rax, 0xdeadbeefcafebabe

            -- distinguish functions by their unique operations after the prologue
            signatures.calculate_secret = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 8bfa 4889442440"
            signatures.format_message = "4053 4883ec40 48b8bebafecaefbeadde 488bd9 4889442468 48b8efbeaddebebafeca"
            signatures.allocate_buffer = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bf9 4889442438"
            signatures.compare_strings = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bda 4889442440"
            signatures.unsafe_copy = "4053 4883ec20 48b8bebafecaefbeadde 488bd9 4889442440"

            w1.log_info("using msvc x64 signatures")
        else
            -- gcc/clang use inline assembly with unique constants
            -- movabs $0xDEADBEEF0000XXXX, %rax
            signatures.calculate_secret = "48b8 11110000efbeadde" -- 0xDEADBEEF00001111
            signatures.format_message = "48b8 22220000efbeadde" -- 0xDEADBEEF00002222
            signatures.allocate_buffer = "48b8 33330000efbeadde" -- 0xDEADBEEF00003333
            signatures.compare_strings = "48b8 44440000efbeadde" -- 0xDEADBEEF00004444
            signatures.unsafe_copy = "48b8 55550000efbeadde" -- 0xDEADBEEF00005555

            w1.log_info("using gcc/clang x64 signatures")
        end
    elseif plat_info.arch == "aarch64" then
        -- aarch64: three instruction sequence to load 48-bit constant
        -- mov x0, #imm16; movk x0, #0xbeef, lsl #16; movk x0, #0xdead, lsl #32
        signatures.calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2" -- 0x1111
        signatures.format_message = "404484d2 e0ddb7f2 a0d5dbf2" -- 0x2222
        signatures.allocate_buffer = "606686d2 e0ddb7f2 a0d5dbf2" -- 0x3333
        signatures.compare_strings = "808888d2 e0ddb7f2 a0d5dbf2" -- 0x4444
        signatures.unsafe_copy = "a0aa8ad2 e0ddb7f2 a0d5dbf2" -- 0x5555

        w1.log_info("using aarch64 signatures")
    end

    return signatures
end

-- ============================================================================
-- hooking functions
-- ============================================================================

-- search for a signature and hook the found address
local function hook_signature(name, pattern, filter, handler)
    w1.log_info(string.format("searching for %s signature...", name))

    local search_results = p1.search_signature(pattern, filter)
    if not search_results or #search_results == 0 then
        w1.log_error(string.format("failed to find %s signature", name))
        return false
    end

    w1.log_info(string.format("found %d matches for %s signature", #search_results, name))

    -- only hook if we found exactly one match
    if #search_results ~= 1 then
        w1.log_warning(string.format("found multiple matches (%d) for %s, expected 1", #search_results, name))
        for i, result in ipairs(search_results) do
            w1.log_info(string.format("  match %d: address=0x%x", i, result.address))
        end
        return false
    end

    local addr = search_results[1].address
    w1.log_info(string.format("  hooking %s at 0x%x", name, addr))

    local hook_id = w1.hook_addr(addr, handler)
    if hook_id then
        w1.log_info(string.format("✓ hooked %s using signature", name))
        return true
    else
        w1.log_error(string.format("failed to hook %s at 0x%x", name, addr))
        return false
    end
end

-- ============================================================================
-- hook handlers
-- ============================================================================

-- create hook handlers for each function
local function create_handlers(regs)
    local handlers = {}

    handlers.calculate_secret = function(vm, gpr, fpr, address)
        local a = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local b = w1.get_reg(gpr, get_arg_reg(regs, 2))
        w1.log_info(string.format("[hook:calculate_secret] a=%d, b=%d, result=%d", a, b, 3 * a + 2 * b))
        return w1.VMAction.CONTINUE
    end

    handlers.format_message = function(vm, gpr, fpr, address)
        local buffer_ptr = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local name_ptr = w1.get_reg(gpr, get_arg_reg(regs, 2))
        local value = w1.get_reg(gpr, get_arg_reg(regs, 3))
        local name_str = w1.read_string(vm, name_ptr, 256)
        if name_str then
            w1.log_info(string.format("[hook:format_message] name='%s', value=%d", name_str, value))
        end
        return w1.VMAction.CONTINUE
    end

    handlers.compare_strings = function(vm, gpr, fpr, address)
        local str1_ptr = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local str2_ptr = w1.get_reg(gpr, get_arg_reg(regs, 2))
        local str1 = w1.read_string(vm, str1_ptr, 256)
        local str2 = w1.read_string(vm, str2_ptr, 256)
        if str1 and str2 then
            w1.log_info(string.format("[hook:compare_strings] '%s' vs '%s'", str1, str2))
        end
        return w1.VMAction.CONTINUE
    end

    handlers.allocate_buffer = function(vm, gpr, fpr, address)
        local size = w1.get_reg(gpr, get_arg_reg(regs, 1))
        w1.log_info(string.format("[hook:allocate_buffer] size=%d bytes", size))
        return w1.VMAction.CONTINUE
    end

    handlers.unsafe_copy = function(vm, gpr, fpr, address)
        local dst = w1.get_reg(gpr, get_arg_reg(regs, 1))
        local src = w1.get_reg(gpr, get_arg_reg(regs, 2))
        local src_content = w1.read_string(vm, src, 256)
        if src_content then
            w1.log_warning(string.format("[hook:unsafe_copy] security risk! copying '%s'", src_content))
        end
        return w1.VMAction.CONTINUE
    end

    return handlers
end

-- ============================================================================
-- main initialization
-- ============================================================================

function tracer.init()
    w1.log_info("=== hook demonstration - signature-based hooking ===")

    -- detect platform
    local plat_info = w1.get_platform_info()
    w1.log_info("platform information:")
    w1.log_info(string.format("  os: %s", plat_info.os))
    w1.log_info(string.format("  architecture: %s", plat_info.arch))
    w1.log_info(string.format("  bits: %d", plat_info.bits))

    -- get platform registers
    local regs = get_platform_regs(plat_info)
    if regs and regs.args then
        w1.log_info(string.format("  calling convention: %s", plat_info.arch == "x86_64" and plat_info.os or "standard"))
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

    -- check p1 module availability
    w1.log_info("checking p1 module availability...")
    if not p1 or not p1.search_signature then
        w1.log_error("p1 module or search_signature function not available!")
        return
    end
    w1.log_info("p1 module ready")

    -- get signatures for this platform
    local signatures = get_signatures(plat_info)
    if not signatures or not next(signatures) then
        w1.log_error("no signatures defined for this platform")
        return
    end

    -- create handlers
    local handlers = create_handlers(regs)

    -- hook all functions
    local functions = {"calculate_secret", "format_message", "compare_strings", "allocate_buffer", "unsafe_copy"}

    for _, func in ipairs(functions) do
        if signatures[func] and handlers[func] then
            hook_signature(func, signatures[func], "hook_test_target", handlers[func])
        end
    end

    w1.log_info("")
    w1.log_info("ready to trace")
end

tracer.callbacks = {}

return tracer
