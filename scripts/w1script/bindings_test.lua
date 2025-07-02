-- w1script comprehensive bindings test
-- validates enhanced QBDI API availability across all modules
-- this is primarily a development/testing script to verify bindings completeness

w1.log_info("starting comprehensive w1script bindings validation")

-- test core types and enums
w1.log_info("=== testing core types and enums ===")

local vmaction_continue = w1.VMAction.CONTINUE
local vmaction_skip = w1.VMAction.SKIP_INST
w1.log_info("vmaction.continue = " .. tostring(vmaction_continue))
w1.log_info("vmaction.skip_inst = " .. tostring(vmaction_skip))

local event_bb_entry = w1.VMEvent.BASIC_BLOCK_ENTRY
local event_bb_exit = w1.VMEvent.BASIC_BLOCK_EXIT
w1.log_info("vmevent.basic_block_entry = " .. tostring(event_bb_entry))
w1.log_info("vmevent.basic_block_exit = " .. tostring(event_bb_exit))

local mem_read = w1.MemoryAccessType.MEMORY_READ
local mem_write = w1.MemoryAccessType.MEMORY_WRITE
w1.log_info("memoryaccesstype.memory_read = " .. tostring(mem_read))
w1.log_info("memoryaccesstype.memory_write = " .. tostring(mem_write))

w1.log_info("core types test completed")

-- test register access functions (architecture-specific)
w1.log_info("=== testing register access functions ===")

local register_functions = {
    "get_reg_x0", "set_reg_x0", "get_reg_x1", "set_reg_x1",
    "get_reg_x2", "set_reg_x2", "get_reg_x3", "set_reg_x3",
    "get_reg_sp", "set_reg_sp", "get_reg_lr", "set_reg_lr",
    "get_reg_pc", "set_reg_pc", "get_reg_nzcv", "set_reg_nzcv"
}

local register_count = 0
for _, func_name in ipairs(register_functions) do
    if w1[func_name] then
        register_count = register_count + 1
    end
end

w1.log_info("found " .. register_count .. " register access functions")

-- test vm control functions
w1.log_info("=== testing vm control functions ===")

local vm_functions = {
    "run", "call", "getOptions", "setOptions",
    "addInstrumentedRange", "addInstrumentedModule",
    "removeInstrumentedRange", "removeAllInstrumentedRanges",
    "getGPRState", "setGPRState", "getFPRState", "setFPRState",
    "clearCache", "clearAllCache", "precacheBasicBlock",
    "getCurrentProcessMaps", "getModuleNames"
}

local vm_count = 0
for _, func_name in ipairs(vm_functions) do
    if w1[func_name] then
        vm_count = vm_count + 1
    end
end

w1.log_info("found " .. vm_count .. " vm control functions")

-- test memory analysis functions
w1.log_info("=== testing memory analysis functions ===")

local memory_functions = {
    "recordMemoryAccess", "getInstMemoryAccess", "getBBMemoryAccess",
    "allocateVirtualStack", "simulateCall",
    "alignedAlloc", "alignedFree",
    "readMemory", "writeMemory", "isAddressValid",
    "getMemoryMaps", "findMemoryMap", "isExecutableAddress"
}

local memory_count = 0
for _, func_name in ipairs(memory_functions) do
    if w1[func_name] then
        memory_count = memory_count + 1
    end
end

w1.log_info("found " .. memory_count .. " memory analysis functions")

-- test callback system functions
w1.log_info("=== testing callback system functions ===")

local callback_functions = {
    "addCodeCB", "addCodeAddrCB", "addCodeRangeCB", "addMnemonicCB",
    "addMemAccessCB", "addMemAddrCB", "addMemRangeCB",
    "addVMEventCB", "addInstrRule",
    "deleteInstrumentation", "deleteAllInstrumentations"
}

local callback_count = 0
for _, func_name in ipairs(callback_functions) do
    if w1[func_name] then
        callback_count = callback_count + 1
    end
end

w1.log_info("found " .. callback_count .. " callback system functions")

-- test utility functions
w1.log_info("=== testing utility functions ===")

local utility_functions = {
    "log_info", "log_debug", "log_error",
    "format_address", "format_memory_value",
    "write_file", "append_file", "to_json", "get_timestamp"
}

local utility_count = 0
for _, func_name in ipairs(utility_functions) do
    if w1[func_name] then
        utility_count = utility_count + 1
    end
end

w1.log_info("found " .. utility_count .. " utility functions")

-- test json serialization
w1.log_info("=== testing json serialization ===")

local test_table = {
    name = "test",
    value = 42,
    nested = {
        array = {1, 2, 3},
        flag = true
    }
}

local json_result = w1.to_json(test_table)
w1.log_info("json serialization result: " .. json_result)

-- test file i/o
w1.log_info("=== testing file i/o ===")

local test_content = "w1script bindings test - " .. w1.get_timestamp()
local test_file = "/tmp/w1script_bindings_test.txt"

if w1.write_file(test_file, test_content) then
    w1.log_info("file write test passed")
    if w1.append_file(test_file, "\nappended line") then
        w1.log_info("file append test passed")
    else
        w1.log_error("file append test failed")
    end
else
    w1.log_error("file write test failed")
end

-- test address formatting
w1.log_info("=== testing address formatting ===")

local test_address = 0x7ffff7dd5000
local formatted = w1.format_address(test_address)
w1.log_info("formatted address: " .. formatted)

local test_value = 0xDEADBEEF
local formatted_value = w1.format_memory_value(test_value, 4)
w1.log_info("formatted memory value: " .. formatted_value)

-- validation summary
w1.log_info("=== validation summary ===")
local total_functions = register_count + vm_count + memory_count + callback_count + utility_count
w1.log_info("total functions found: " .. total_functions)
w1.log_info("register access: " .. register_count .. " functions")
w1.log_info("vm control: " .. vm_count .. " functions") 
w1.log_info("memory analysis: " .. memory_count .. " functions")
w1.log_info("callback system: " .. callback_count .. " functions")
w1.log_info("utilities: " .. utility_count .. " functions")

if total_functions >= 60 then
    w1.log_info("enhanced bindings validation passed - comprehensive api available")
else
    w1.log_error("enhanced bindings validation failed - missing functions detected")
end

w1.log_info("w1script bindings validation completed")

-- return minimal tracer for testing purposes
return {
    callbacks = { "instruction_postinst" },
    
    on_instruction_postinst = function(vm, gpr, fpr)
        return w1.VMAction.CONTINUE
    end,
    
    shutdown = function()
        w1.log_info("bindings test tracer shutdown completed")
    end
}