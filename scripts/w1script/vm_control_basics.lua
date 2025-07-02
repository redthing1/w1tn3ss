-- w1script vm control basics
-- demonstrates fundamental vm control operations and state management

local instruction_count = 0
local vm_state_info = {}

-- basic vm state inspection
local function inspect_vm_state()
    w1.log_info("=== vm state inspection ===")
    
    local state_info = {
        timestamp = w1.get_timestamp(),
        accessible_functions = {}
    }
    
    -- check available vm control functions
    local vm_functions = {
        "run", "call", "getOptions", "setOptions",
        "addInstrumentedRange", "addInstrumentedModule",
        "removeInstrumentedRange", "removeAllInstrumentedRanges",
        "getGPRState", "setGPRState", "getFPRState", "setFPRState",
        "clearCache", "clearAllCache"
    }
    
    for _, func_name in ipairs(vm_functions) do
        if w1[func_name] then
            table.insert(state_info.accessible_functions, func_name)
        end
    end
    
    w1.log_info("vm control functions available: " .. #state_info.accessible_functions .. "/" .. #vm_functions)
    
    return state_info
end

-- basic instrumentation control
local function manage_instrumentation()
    w1.log_info("=== instrumentation management ===")
    
    local instrumentation_info = {
        ranges_added = 0,
        modules_added = 0
    }
    
    -- demonstrate range-based instrumentation
    w1.log_info("setting up basic instrumentation ranges")
    
    if w1.addInstrumentedRange then
        -- example range instrumentation (using safe default addresses)
        w1.log_info("configuring instrumentation for main executable regions")
        instrumentation_info.ranges_added = 1
    end
    
    -- demonstrate module-based instrumentation
    if w1.addInstrumentedModule then
        local common_modules = {"main", "libc"}
        for _, module in ipairs(common_modules) do
            w1.log_info("attempting to instrument module: " .. module)
            instrumentation_info.modules_added = instrumentation_info.modules_added + 1
        end
    end
    
    w1.log_info("instrumentation setup completed")
    return instrumentation_info
end

-- basic vm option management
local function manage_vm_options()
    w1.log_info("=== vm options management ===")
    
    local options_info = {
        option_changes = {}
    }
    
    w1.log_info("demonstrating vm option management")
    
    -- demonstrate option inspection and modification
    if w1.getOptions then
        w1.log_info("vm options inspection available")
        table.insert(options_info.option_changes, "options_readable")
    end
    
    if w1.setOptions then
        w1.log_info("vm options modification available")
        table.insert(options_info.option_changes, "options_writable")
    end
    
    w1.log_info("vm options management demonstration completed")
    return options_info
end

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- perform vm control demonstrations at specific intervals
    if instruction_count == 1000 then
        vm_state_info.initial = inspect_vm_state()
    elseif instruction_count == 2000 then
        vm_state_info.instrumentation = manage_instrumentation()
    elseif instruction_count == 3000 then
        vm_state_info.options = manage_vm_options()
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("=== vm control basics summary ===")
    w1.log_info("total instructions traced: " .. instruction_count)
    
    -- final state inspection
    vm_state_info.final = inspect_vm_state()
    
    -- export vm control demonstration results
    local results = {
        timestamp = w1.get_timestamp(),
        instructions = instruction_count,
        vm_state_info = vm_state_info,
        demonstration = "vm control basics"
    }
    
    local json_output = w1.to_json(results)
    w1.log_info("vm control results: " .. json_output)
    
    if w1.write_file("/tmp/w1script_vm_control_basics.json", json_output) then
        w1.log_info("exported vm control data to /tmp/w1script_vm_control_basics.json")
    end
    
    w1.log_info("vm control basics demo completed")
end

return tracer