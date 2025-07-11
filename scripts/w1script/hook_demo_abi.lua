-- hook_demo_abi.lua
-- cross-platform hooking using calling convention apis
-- portable across architectures without hardcoding register names
--
-- run with:
-- ./build-release/w1tool tracer -n w1script \
--   -c script=./scripts/w1script/hook_demo_abi.lua \
--   -s ./build-release/tests/programs/hook_test_target
local tracer = {}

-- platform-specific function signatures
local SIGNATURES = {
    x86_64 = {
        windows = {
            calculate_secret = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 8bfa 4889442440",
            format_message = "4053 4883ec40 48b8bebafecaefbeadde 488bd9 4889442468 48b8efbeaddebebafeca",
            allocate_buffer = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bf9 4889442438",
            compare_strings = "48895c2408 57 4883ec20 48b8bebafecaefbeadde 488bda 4889442440",
            unsafe_copy = "4053 4883ec20 48b8bebafecaefbeadde 488bd9 4889442440"
        }
    },
    aarch64 = {
        macos = {
            calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2",
            format_message = "404484d2 e0ddb7f2 a0d5dbf2",
            allocate_buffer = "606686d2 e0ddb7f2 a0d5dbf2",
            compare_strings = "808888d2 e0ddb7f2 a0d5dbf2",
            unsafe_copy = "a0aa8ad2 e0ddb7f2 a0d5dbf2"
        }
    }
}

-- simple hook handlers using abi apis
local function hook_calculate_secret(vm, gpr, fpr, address)
    -- get two integer arguments portably
    local a = w1.get_arg(vm, gpr, fpr, 1)
    local b = w1.get_arg(vm, gpr, fpr, 2)

    if a and b then
        local result = 3 * a + 2 * b
        w1.log_info(string.format("[hook:calculate_secret] a=%d, b=%d → result=%d", a, b, result))
    end

    return w1.VMAction.CONTINUE
end

local function hook_format_message(vm, gpr, fpr, address)
    -- get three arguments: buffer*, name*, value
    local buffer_ptr = w1.get_arg(vm, gpr, fpr, 1)
    local name_ptr = w1.get_arg(vm, gpr, fpr, 2)
    local value = w1.get_arg(vm, gpr, fpr, 3)

    if name_ptr then
        local name_str = w1.read_string(vm, name_ptr, 256)
        if name_str then
            w1.log_info(string.format("[hook:format_message] name='%s', value=%d", name_str, value or 0))
        end
    end

    return w1.VMAction.CONTINUE
end

local function hook_compare_strings(vm, gpr, fpr, address)
    -- get two string pointers
    local str1_ptr = w1.get_arg(vm, gpr, fpr, 1)
    local str2_ptr = w1.get_arg(vm, gpr, fpr, 2)

    if str1_ptr and str2_ptr then
        local str1 = w1.read_string(vm, str1_ptr, 256)
        local str2 = w1.read_string(vm, str2_ptr, 256)
        if str1 and str2 then
            w1.log_info(string.format("[hook:compare_strings] '%s' vs '%s'", str1, str2))
        end
    end

    return w1.VMAction.CONTINUE
end

local function hook_allocate_buffer(vm, gpr, fpr, address)
    -- get size argument
    local size = w1.get_arg(vm, gpr, fpr, 1)

    if size then
        w1.log_info(string.format("[hook:allocate_buffer] size=%d bytes", size))
    end

    return w1.VMAction.CONTINUE
end

local function hook_unsafe_copy(vm, gpr, fpr, address)
    -- get dst and src pointers
    local dst = w1.get_arg(vm, gpr, fpr, 1)
    local src = w1.get_arg(vm, gpr, fpr, 2)

    if src then
        local src_content = w1.read_string(vm, src, 256)
        if src_content then
            w1.log_warning(string.format("[hook:unsafe_copy] security risk! copying '%s'", src_content))
        end
    end

    return w1.VMAction.CONTINUE
end

-- main initialization
function tracer.init()
    w1.log_info("abi hooking demonstration")
    w1.log_info("")

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
            w1.log_info(string.format("  argument registers: %s", table.concat(cc_info.argument_registers, ", ")))
        end

        w1.log_info(string.format("  return register: %s", cc_info.return_register))
        w1.log_info(string.format("  stack alignment: %d bytes", cc_info.stack_alignment))
        w1.log_info(string.format("  stack cleanup: %s", cc_info.stack_cleanup))
    end
    w1.log_info("")

    -- find target module
    local target_module = w1.module_list("hook_test_target")[1]
    if not target_module then
        w1.log_error("target module 'hook_test_target' not found")
        return
    end

    w1.log_info(string.format("target module: %s", target_module.path))
    w1.log_info(string.format("base address: 0x%x", target_module.base_address))
    w1.log_info("")

    -- get platform signatures
    local arch_sigs = SIGNATURES[plat_info.arch]
    if not arch_sigs then
        w1.log_error("no signatures for this architecture")
        return
    end

    local signatures = arch_sigs[plat_info.os]
    if not signatures then
        w1.log_error("no signatures for this os")
        return
    end

    -- hook functions using signatures
    local hooks = {{
        name = "calculate_secret",
        handler = hook_calculate_secret
    }, {
        name = "format_message",
        handler = hook_format_message
    }, {
        name = "allocate_buffer",
        handler = hook_allocate_buffer
    }, {
        name = "compare_strings",
        handler = hook_compare_strings
    }, {
        name = "unsafe_copy",
        handler = hook_unsafe_copy
    }}

    local hooked = 0
    for _, hook in ipairs(hooks) do
        if signatures[hook.name] then
            local addr = p1.search_sig(signatures[hook.name], {
                filter = "hook_test_target",
                single = true
            })

            if addr then
                if w1.hook_addr(addr, hook.handler) then
                    w1.log_info(string.format("hooked %s @ 0x%x", hook.name, addr))
                    hooked = hooked + 1
                else
                    w1.log_error(string.format("failed to hook %s at 0x%x", hook.name, addr))
                end
            else
                w1.log_error(string.format("failed to find signature for %s", hook.name))
            end
        end
    end

    w1.log_info(string.format("hooked %d/%d functions", hooked, #hooks))
    w1.log_info("ready to trace")
end

return tracer
