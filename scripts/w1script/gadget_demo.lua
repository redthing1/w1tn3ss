-- gadget_demo.lua
-- demonstrates gadget execution from w1script lua callbacks
local tracer = {}

-- platform-specific signatures
local SIGNATURES = {
    arm64 = {
        darwin = {
            -- hook targets (with UNIQUE_SIGNATURE macros)
            calculate_secret = "202282d2 e0ddb7f2 a0d5dbf2",
            compare_strings = "808888d2 e0ddb7f2 a0d5dbf2",

            -- utility functions (with UNIQUE_SIGNATURE macros)
            get_string_length = "e80300aa c0cc8cd2 e0ddb7f2 a0d5dbf2",
            contains_pattern = "e90300aa 08008052 e0ee8ed2",
            compute_hash = "e80300aa 001191d2 e0ddb7f2",
            get_process_id = "203393d2 e0ddb7f2 a0d5dbf2",
            is_valid_pointer = "e80300aa 405595d2 e0ddb7f2"
        }
    }
    -- add other platforms here as needed
}

local state = {
    platform = nil,
    signatures = nil,
    target_base = nil,
    executed = false,
    allocated_memory = {},
    vm = nil
}

local function allocate_string(str)
    local addr = w1.vm.aligned_alloc(#str + 1, 8)
    if not addr then
        return nil
    end

    local bytes = {}
    for i = 1, #str do
        table.insert(bytes, string.byte(str, i))
    end
    table.insert(bytes, 0)

    if not w1.mem.write_bytes(state.vm, addr, bytes) then
        w1.vm.aligned_free(addr)
        return nil
    end

    table.insert(state.allocated_memory, addr)
    return addr
end

local function cleanup_memory()
    for _, addr in ipairs(state.allocated_memory) do
        w1.vm.aligned_free(addr)
    end
    state.allocated_memory = {}
end

local function find_function(name, pattern)
    local addr = w1.p1ll.search_sig(pattern, {
        filter = "hook_test_target",
        single = true
    })

    if addr then
        w1.log.info(string.format("found %s @ %s", name, w1.util.format_address(addr)))
    end
    return addr
end

local function execute_demo()
    w1.log.info("\n=== gadget execution demonstration ===")

    local functions = {}
    local utility_funcs = {
        "get_string_length",
        "contains_pattern",
        "compute_hash",
        "get_process_id",
        "is_valid_pointer"
    }

    for _, name in ipairs(utility_funcs) do
        functions[name] = find_function(name, state.signatures[name])
    end

    if functions.get_process_id then
        local pid = w1.gadget.call(functions.get_process_id, {})
        w1.log.info(string.format("get_process_id() = %d", pid or 0))
    end

    if functions.is_valid_pointer then
        local test_ptrs = {
            {addr = 0, desc = "null"},
            {addr = 0x1000, desc = "low"},
            {addr = functions.get_process_id or 0x100000000, desc = "code"},
            {addr = 0x8000000000000000, desc = "kernel"}
        }

        for _, test in ipairs(test_ptrs) do
            local valid = w1.gadget.call(functions.is_valid_pointer, {test.addr})
            w1.log.info(string.format("is_valid_pointer(0x%x) [%s] = %s", test.addr, test.desc,
                valid ~= 0 and "true" or "false"))
        end
    end

    if functions.get_string_length then
        local test_strings = {"hello", "gadget test", ""}

        for _, str in ipairs(test_strings) do
            local str_addr = allocate_string(str)
            if str_addr then
                local len = w1.gadget.call(functions.get_string_length, {str_addr})
                w1.log.info(string.format("get_string_length(\"%s\") = %d", str, len or 0))
            end
        end
    end

    if functions.compute_hash then
        local test_data = {
            {data = "test", desc = "simple"},
            {data = "w1tn3ss", desc = "project"},
            {data = string.rep("A", 64), desc = "64 A's"}
        }

        for _, test in ipairs(test_data) do
            local data_addr = allocate_string(test.data)
            if data_addr then
                local hash = w1.gadget.call(functions.compute_hash, {data_addr, #test.data})
                w1.log.info(string.format("compute_hash(\"%s\", %d) = 0x%x [%s]",
                    test.data:sub(1, 10), #test.data, hash or 0, test.desc))
            end
        end
    end

    if functions.contains_pattern then
        local haystack = "the quick brown fox"
        local needle = "brown"
        local hay_addr = allocate_string(haystack)
        local needle_addr = allocate_string(needle)

        if hay_addr and needle_addr then
            local found = w1.gadget.call(functions.contains_pattern, {hay_addr, needle_addr})
            w1.log.info(string.format("contains_pattern(\"%s\", \"%s\") = %s", haystack, needle,
                found ~= 0 and "found" or "not found"))
        end
    end

    cleanup_memory()
    w1.log.info("=== demonstration complete ===\n")
end

function tracer.init()
    w1.log.info("gadget execution demo initializing")

    state.vm = w1.vm.get()
    state.platform = w1.util.platform_info()
    local sigs = SIGNATURES[state.platform.arch] and SIGNATURES[state.platform.arch][state.platform.os]

    if not sigs then
        w1.log.error(string.format("no signatures for %s %s", state.platform.os, state.platform.arch))
        return
    end

    state.signatures = sigs

    local modules = w1.module.list("hook_test_target")
    if not modules or #modules == 0 then
        w1.log.error("target module not found")
        return
    end

    state.target_base = modules[1].base_address

    local trigger_addr = find_function("compare_strings", sigs.compare_strings)
    if trigger_addr then
        w1.hook.address(trigger_addr, function(vm, gpr, fpr, address)
            if not state.executed then
                state.executed = true
                execute_demo()
            end
            return w1.enum.vm_action.CONTINUE
        end)
        w1.log.info("ready - demo will execute on compare_strings call")
    else
        execute_demo()
    end
end

return tracer
