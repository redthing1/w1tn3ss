-- hook_demo_abi.lua
-- cross-platform hooking using calling convention apis
local tracer = {}

local SIGNATURES = {
    x64 = {
        windows = {
            calculate_secret = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 8bfa 4889442440",
            format_message = "4053 4883ec40 48b8bebafecaefbeadde 488bd9 4889442468 48b8efbeaddebebafeca",
            allocate_buffer = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bf9 4889442438",
            compare_strings = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bda 4889442440",
            unsafe_copy = "4053 4883ec20 48b8bebafecaefbeadde 488bd9 4889442440"
        }
    },
    arm64 = {
        darwin = {
            calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2",
            format_message = "404484d2 e0ddb7f2 a0d5dbf2",
            allocate_buffer = "606686d2 e0ddb7f2 a0d5dbf2",
            compare_strings = "808888d2 e0ddb7f2 a0d5dbf2",
            unsafe_copy = "a0aa8ad2 e0ddb7f2 a0d5dbf2"
        }
    }
}

local HOOKS = {
    {
        name = "calculate_secret",
        types = {"integer", "integer"},
        handler = function(args)
            local result = 3 * args[1].value + 2 * args[2].value
            return string.format("a=%d, b=%d -> expecting result=%d", args[1].value, args[2].value, result)
        end
    },
    {
        name = "format_message",
        types = {"pointer", "pointer", "integer"},
        handler = function(args, vm)
            local name = w1.mem.read_string(vm, args[2].value, 256)
            return string.format("buffer=0x%016x, name='%s', value=%d", args[1].value, name or "", args[3].value)
        end
    },
    {
        name = "allocate_buffer",
        types = {"size_t"},
        handler = function(args)
            return string.format("size=%d bytes", args[1].value)
        end
    },
    {
        name = "compare_strings",
        types = {"pointer", "pointer"},
        handler = function(args, vm)
            local str1 = w1.mem.read_string(vm, args[1].value, 256)
            local str2 = w1.mem.read_string(vm, args[2].value, 256)
            return string.format("'%s' vs '%s'", str1 or "", str2 or "")
        end
    },
    {
        name = "unsafe_copy",
        types = {"pointer", "pointer"},
        handler = function(args, vm)
            local src = w1.mem.read_string(vm, args[2].value, 256)
            return string.format("dst=0x%016x, src='%s'", args[1].value, src or "")
        end,
        warning = true
    }
}

local function create_hook(hook_def)
    return function(vm, gpr, fpr, address)
        local args = w1.abi.get_typed_args(vm, gpr, fpr, hook_def.types)
        if args then
            local msg = hook_def.handler(args, vm)
            local log_fn = hook_def.warning and w1.log.warn or w1.log.info
            log_fn(string.format("[hook:%s] %s", hook_def.name, msg))
        end
        return w1.enum.vm_action.CONTINUE
    end
end

function tracer.init()
    w1.log.info("hooked demo (abi aware arguments)")

    local plat = w1.util.platform_info()
    w1.log.info(string.format("platform: %s %s (%d-bit)", plat.os, plat.arch, plat.bits))

    local cc = w1.abi.get_calling_convention()
    if cc then
        w1.log.info(string.format("calling convention: %s (%s)", cc.name, cc.id))
        if cc.argument_registers then
            w1.log.info(string.format("arg registers: %s", table.concat(cc.argument_registers, ", ")))
        end
    end

    local target = w1.module.list("hook_test_target")[1]
    if not target then
        w1.log.error("target not found")
        return
    end
    w1.log.info(string.format("target: %s @ 0x%016x", target.path, target.base_address))

    local sigs = SIGNATURES[plat.arch] and SIGNATURES[plat.arch][plat.os]
    if not sigs then
        w1.log.error("no signatures for this platform")
        return
    end

    local hooked = 0
    for _, hook_def in ipairs(HOOKS) do
        local sig = sigs[hook_def.name]
        if sig then
            local addr = w1.p1ll.search_sig(sig, {
                filter = target.name,
                single = true
            })
            if not addr then
                w1.log.error(string.format("signature not found for %s", hook_def.name))
            else
                local hook_fn = create_hook(hook_def)
                if w1.hook.address(addr, hook_fn) then
                    w1.log.info(string.format("hooked %s @ 0x%016x", hook_def.name, addr))
                    hooked = hooked + 1
                else
                    w1.log.error(string.format("failed to hook %s @ 0x%016x", hook_def.name, addr))
                end
            end
        end
    end

    w1.log.info(string.format("hooked %d functions using typed abi apis", hooked))
end

return tracer
