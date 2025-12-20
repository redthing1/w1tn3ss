-- hook_demo_sig.lua
-- hooking demo using signature-based function discovery
local tracer = {}

local REGISTERS = {
    arm64 = {
        args = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"},
        sp = "sp",
        ret = "x0",
        abi = "AAPCS64"
    },
    x64 = {
        linux = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp",
            ret = "rax",
            abi = "System V AMD64"
        },
        darwin = {
            args = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
            sp = "rsp",
            ret = "rax",
            abi = "System V AMD64"
        },
        windows = {
            args = {"rcx", "rdx", "r8", "r9"},
            sp = "rsp",
            ret = "rax",
            abi = "Microsoft x64"
        }
    },
    x86 = {
        sp = "esp",
        ret = "eax",
        abi = "cdecl"
    }
}

local function get_platform_regs(plat_info)
    local arch_regs = REGISTERS[plat_info.arch]
    if not arch_regs then
        return nil
    end

    if plat_info.arch == "x64" then
        return arch_regs[plat_info.os] or arch_regs.linux
    end

    return arch_regs
end

local function get_arg_reg(regs, n)
    return regs and regs.args and regs.args[n]
end

local function get_signatures(plat_info)
    local signatures = {}

    if plat_info.arch == "x64" then
        if plat_info.os == "windows" then
            signatures.calculate_secret = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 8bfa 4889442440"
            signatures.format_message = "4053 4883ec40 48b8bebafecaefbeadde 488bd9 4889442468 48b8efbeaddebebafeca"
            signatures.allocate_buffer = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bf9 4889442438"
            signatures.compare_strings = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bda 4889442440"
            signatures.unsafe_copy = "4053 4883ec20 48b8bebafecaefbeadde 488bd9 4889442440"
            w1.log.info("using msvc x64 signatures")
        end
    elseif plat_info.arch == "arm64" then
        if plat_info.os == "darwin" then
            signatures.calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2"
            signatures.format_message = "404484d2 e0ddb7f2 a0d5dbf2"
            signatures.allocate_buffer = "606686d2 e0ddb7f2 a0d5dbf2"
            signatures.compare_strings = "808888d2 e0ddb7f2 a0d5dbf2"
            signatures.unsafe_copy = "a0aa8ad2 e0ddb7f2 a0d5dbf2"
            w1.log.info("using arm64 signatures")
        end
    end

    return signatures
end

local function hook_func_sig(name, pattern, filter, handler)
    w1.log.info(string.format("searching for %s signature...", name))

    local addr = w1.p1ll.search_sig(pattern, {
        filter = filter,
        single = true
    })

    if not addr then
        w1.log.error(string.format("failed to find unique %s signature", name))
        return false
    end

    w1.log.info(string.format("trying to hook %s @ 0x%x", name, addr))

    local hook_id = w1.hook.address(addr, handler)
    if hook_id then
        w1.log.info(string.format("hooked %s @ 0x%x", name, addr))
        return true
    end

    w1.log.error(string.format("failed to hook %s @ 0x%x", name, addr))
    return false
end

local function create_handlers(regs)
    return {
        calculate_secret = function(vm, gpr, fpr, address)
            local a = w1.reg.get(gpr, get_arg_reg(regs, 1))
            local b = w1.reg.get(gpr, get_arg_reg(regs, 2))
            w1.log.info(string.format("[hook:calculate_secret] a=%d, b=%d, result=%d", a or 0, b or 0, 3 * (a or 0) + 2 * (b or 0)))
            return w1.enum.vm_action.CONTINUE
        end,

        format_message = function(vm, gpr, fpr, address)
            local buffer_ptr = w1.reg.get(gpr, get_arg_reg(regs, 1))
            local name_ptr = w1.reg.get(gpr, get_arg_reg(regs, 2))
            local value = w1.reg.get(gpr, get_arg_reg(regs, 3))
            local name_str = name_ptr and w1.mem.read_string(vm, name_ptr, 256) or nil
            if name_str then
                w1.log.info(string.format("[hook:format_message] name='%s', value=%d", name_str, value or 0))
            end
            return w1.enum.vm_action.CONTINUE
        end,

        compare_strings = function(vm, gpr, fpr, address)
            local str1_ptr = w1.reg.get(gpr, get_arg_reg(regs, 1))
            local str2_ptr = w1.reg.get(gpr, get_arg_reg(regs, 2))
            local str1 = str1_ptr and w1.mem.read_string(vm, str1_ptr, 256) or nil
            local str2 = str2_ptr and w1.mem.read_string(vm, str2_ptr, 256) or nil
            if str1 and str2 then
                w1.log.info(string.format("[hook:compare_strings] '%s' vs '%s'", str1, str2))
            end
            return w1.enum.vm_action.CONTINUE
        end,

        allocate_buffer = function(vm, gpr, fpr, address)
            local size = w1.reg.get(gpr, get_arg_reg(regs, 1))
            w1.log.info(string.format("[hook:allocate_buffer] size=%d bytes", size or 0))
            return w1.enum.vm_action.CONTINUE
        end,

        unsafe_copy = function(vm, gpr, fpr, address)
            local dst = w1.reg.get(gpr, get_arg_reg(regs, 1))
            local src = w1.reg.get(gpr, get_arg_reg(regs, 2))
            local src_content = src and w1.mem.read_string(vm, src, 256) or nil
            if src_content then
                w1.log.warn(string.format("[hook:unsafe_copy] security risk! copying '%s'", src_content))
            end
            return w1.enum.vm_action.CONTINUE
        end
    }
end

function tracer.init()
    w1.log.info("hook demo (manual register access)")

    local plat_info = w1.util.platform_info()
    w1.log.info(string.format("platform: %s %s (%d-bit)", plat_info.os, plat_info.arch, plat_info.bits))

    local regs = get_platform_regs(plat_info)
    if regs then
        w1.log.info(string.format("calling convention: %s", regs.abi or "unknown"))
        if regs.args then
            w1.log.info(string.format("argument registers: %s", table.concat(regs.args, ", ")))
        else
            w1.log.info("arguments: stack-based")
        end
    end

    local target_module = w1.module.list("hook_test_target")[1]
    if not target_module then
        w1.log.error("target module 'hook_test_target' not found")
        return
    end

    w1.log.info(string.format("target: %s @ 0x%x", target_module.path, target_module.base_address))

    local signatures = get_signatures(plat_info)
    if not signatures or not next(signatures) then
        w1.log.error("no signatures defined for this platform")
        return
    end

    local handlers = create_handlers(regs)
    local functions = {"calculate_secret", "format_message", "compare_strings", "allocate_buffer", "unsafe_copy"}

    for _, func in ipairs(functions) do
        if signatures[func] and handlers[func] then
            hook_func_sig(func, signatures[func], "hook_test_target", handlers[func])
        end
    end

    w1.log.info("ready to trace")
end

return tracer
