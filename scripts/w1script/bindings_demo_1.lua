-- w1script enhanced bindings demonstration
-- demonstrates key enhanced QBDI API features including register access,
-- json export, and file output capabilities

local instruction_count = 0
local basic_block_count = 0

-- test enhanced bindings availability on script load
local function verify_bindings()
    w1.log_info("=== verifying enhanced bindings ===")
    
    -- test core enums
    w1.log_info("vmaction.continue = " .. tostring(w1.VMAction.CONTINUE))
    w1.log_info("memoryaccesstype.memory_read = " .. tostring(w1.MemoryAccessType.MEMORY_READ))
    
    -- test utility functions
    w1.log_info("timestamp: " .. w1.get_timestamp())
    w1.log_info("formatted address: " .. w1.format_address(0x7fff00000000))
    
    -- test json serialization
    local test_obj = {test = "value", number = 42}
    w1.log_info("json test: " .. w1.to_json(test_obj))
    
    -- count available key functions
    local function_count = 0
    local key_functions = {
        "VMAction", "MemoryAccessType", "InstPosition",
        "get_reg_x0", "get_reg_pc", "get_reg_sp",
        "getCurrentProcessMaps", "getModuleNames",
        "readMemory", "writeMemory", "getMemoryMaps",
        "addCodeCB", "addMemAccessCB", "addVMEventCB",
        "log_info", "to_json", "get_timestamp", "format_address"
    }
    
    for _, func in ipairs(key_functions) do
        if w1[func] then
            function_count = function_count + 1
        end
    end
    
    w1.log_info("enhanced functions available: " .. function_count .. "/" .. #key_functions)
    
    if function_count >= #key_functions * 0.8 then
        w1.log_info("enhanced bindings verification passed")
    else
        w1.log_error("enhanced bindings verification failed")
    end
end

-- run verification test
verify_bindings()

local tracer = {}
tracer.callbacks = { "instruction_postinst", "basic_block_entry" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- show progress every 1000 instructions using enhanced register access
    if instruction_count % 1000 == 0 then
        local pc = w1.get_reg_pc(gpr)
        w1.log_info("progress - instructions: " .. instruction_count .. ", pc: " .. w1.format_address(pc))
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.on_basic_block_entry(vm, gpr, fpr)
    basic_block_count = basic_block_count + 1
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("=== execution statistics ===")
    w1.log_info("total instructions: " .. instruction_count)
    w1.log_info("basic blocks: " .. basic_block_count)
    
    -- demonstrate json export using enhanced bindings
    local stats = {
        timestamp = w1.get_timestamp(),
        instructions = instruction_count,
        basic_blocks = basic_block_count,
        enhanced_bindings_active = true
    }
    
    local json_output = w1.to_json(stats)
    w1.log_info("json stats: " .. json_output)
    
    -- demonstrate file output capability
    if w1.write_file("/tmp/w1script_enhanced_demo.json", json_output) then
        w1.log_info("successfully exported stats to /tmp/w1script_enhanced_demo.json")
    else
        w1.log_error("failed to export stats file")
    end
    
    w1.log_info("enhanced w1script demo completed")
end

return tracer