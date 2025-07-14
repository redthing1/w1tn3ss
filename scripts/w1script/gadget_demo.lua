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
            get_string_length = "e80300aa c0cc8cd2 e0ddb7f2 a0d5dbf2", -- mov x8, x0; mov x0, #0x6666; ...
            contains_pattern = "e90300aa 08008052 e0ee8ed2", -- mov x9, x0; mov w8, #0x0; mov x0, #0x7777
            compute_hash = "e80300aa 001191d2 e0ddb7f2", -- mov x8, x0; mov x0, #0x8888; ...
            get_process_id = "203393d2 e0ddb7f2 a0d5dbf2", -- mov x0, #0x9999; ...
            is_valid_pointer = "e80300aa 405595d2 e0ddb7f2" -- mov x8, x0; mov x0, #0xaaaa; ...
        }
    }
    -- add other platforms here as needed
}

local state = {
    platform = nil,
    signatures = nil,
    target_base = nil,
    executed = false,
    allocated_memory = {}
}

-- allocate memory for string arguments
local function allocate_string(str)
    local addr = w1.alignedAlloc(#str + 1, 8)
    if not addr then
        return nil
    end

    local bytes = {}
    for i = 1, #str do
        table.insert(bytes, string.byte(str, i))
    end
    table.insert(bytes, 0) -- null terminator

    if not w1.write_mem(nil, addr, bytes) then
        w1.alignedFree(addr)
        return nil
    end

    table.insert(state.allocated_memory, addr)
    return addr
end

-- cleanup allocated memory
local function cleanup_memory()
    for _, addr in ipairs(state.allocated_memory) do
        w1.alignedFree(addr)
    end
    state.allocated_memory = {}
end

-- find function by signature
local function find_function(name, pattern)
    local addr = p1.search_sig(pattern, {
        filter = "hook_test_target",
        single = true
    })

    if addr then
        w1.log_info(string.format("found %s @ 0x%x", name, addr))
    end
    return addr
end

-- execute gadget demonstration
local function execute_demo()
    w1.log_info("\n=== gadget execution demonstration ===")

    -- find all utility functions
    local functions = {}
    local utility_funcs =
        {"get_string_length", "contains_pattern", "compute_hash", "get_process_id", "is_valid_pointer"}

    for _, name in ipairs(utility_funcs) do
        functions[name] = find_function(name, state.signatures[name])
    end

    -- test 1: simple no-arg function
    if functions.get_process_id then
        local pid = w1.gadget_call(functions.get_process_id, {})
        w1.log_info(string.format("get_process_id() = %d", pid))
    end

    -- test 2: pointer validation
    if functions.is_valid_pointer then
        local test_ptrs = {{
            addr = 0,
            desc = "null"
        }, {
            addr = 0x1000,
            desc = "low"
        }, {
            addr = functions.get_process_id or 0x100000000,
            desc = "code"
        }, {
            addr = 0x8000000000000000,
            desc = "kernel"
        }}

        for _, test in ipairs(test_ptrs) do
            local valid = w1.gadget_call(functions.is_valid_pointer, {test.addr})
            w1.log_info(string.format("is_valid_pointer(0x%x) [%s] = %s", test.addr, test.desc,
                valid ~= 0 and "true" or "false"))
        end
    end

    -- test 3: string operations
    if functions.get_string_length then
        local test_strings = {"hello", "gadget test", ""}

        for _, str in ipairs(test_strings) do
            local str_addr = allocate_string(str)
            if str_addr then
                local len = w1.gadget_call(functions.get_string_length, {str_addr})
                w1.log_info(string.format("get_string_length(\"%s\") = %d", str, len))
            end
        end
    end

    -- test 4: multiple arguments
    if functions.compute_hash then
        local test_data = {{
            data = "test",
            desc = "simple"
        }, {
            data = "w1tn3ss",
            desc = "project"
        }, {
            data = string.rep("A", 64),
            desc = "64 A's"
        }}

        for _, test in ipairs(test_data) do
            local data_addr = allocate_string(test.data)
            if data_addr then
                local hash = w1.gadget_call(functions.compute_hash, {data_addr, #test.data})
                w1.log_info(string.format("compute_hash(\"%s\", %d) = 0x%x [%s]", test.data:sub(1, 10), #test.data,
                    hash, test.desc))
            end
        end
    end

    -- test 5: pattern matching
    if functions.contains_pattern then
        local haystack = "the quick brown fox"
        local needle = "brown"
        local hay_addr = allocate_string(haystack)
        local needle_addr = allocate_string(needle)

        if hay_addr and needle_addr then
            local found = w1.gadget_call(functions.contains_pattern, {hay_addr, needle_addr})
            w1.log_info(string.format("contains_pattern(\"%s\", \"%s\") = %s", haystack, needle,
                found ~= 0 and "found" or "not found"))
        end
    end

    cleanup_memory()
    w1.log_info("=== demonstration complete ===\n")
end

-- initialization
function tracer.init()
    w1.log_info("gadget execution demo initializing")

    -- platform detection
    state.platform = w1.get_platform_info()
    local sigs = SIGNATURES[state.platform.arch] and SIGNATURES[state.platform.arch][state.platform.os]

    if not sigs then
        w1.log_error(string.format("no signatures for %s %s", state.platform.os, state.platform.arch))
        return
    end

    state.signatures = sigs

    -- find target module
    local modules = w1.module_list("hook_test_target")
    if not modules or #modules == 0 then
        w1.log_error("target module not found")
        return
    end

    state.target_base = modules[1].base_address

    -- hook trigger function
    local trigger_addr = find_function("compare_strings", sigs.compare_strings)
    if trigger_addr then
        w1.hook_addr(trigger_addr, function(vm, gpr, fpr, address)
            if not state.executed then
                state.executed = true
                execute_demo()
            end
            return w1.VMAction.CONTINUE
        end)
        w1.log_info("ready - demo will execute on compare_strings call")
    else
        -- execute immediately if no trigger
        execute_demo()
    end
end

return tracer
