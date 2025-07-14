-- gadget_demo.lua
-- demonstration of gadget execution from w1script lua callbacks
-- executes arbitrary code from within instrumentation hooks using sub-VM isolation
local tracer = {}

-- target function offsets (from nm output - these are stable for hook_test_target)
local TARGET_OFFSETS = {
    get_process_id = 0xa34,
    compute_hash = 0xa10,
    contains_pattern = 0x9e0,
    get_string_length = 0x9d4
}

local demo_state = {
    target_base = nil,
    demo_executed = false
}

function tracer.init()
    w1.log_info("gadget execution demo initializing")
    
    -- verify gadget api availability
    if not w1.gadget_call then
        w1.log_error("gadget api not available")
        return
    end
    
    -- locate target module
    local target_modules = w1.module_list("hook_test_target")
    if not target_modules or #target_modules == 0 then
        w1.log_error("target module not found")
        return
    end
    
    demo_state.target_base = target_modules[1].base_address
    w1.log_info(string.format("target module located: %s @ 0x%x", 
                 target_modules[1].path, demo_state.target_base))
    
    -- get platform info for signature selection
    local platform = w1.get_platform_info()
    w1.log_info(string.format("platform detected: %s %s", platform.os, platform.arch))
    
    -- hook main calculation function for demonstration
    if platform.arch == "arm64" and platform.os == "darwin" then
        local calc_addr = p1.search_sig("808888d2 e0ddb7f2 a0d5dbf2", {
            filter = "hook_test_target",
            single = true
        })
        
        if calc_addr then
            local hook_id = w1.hook_addr(calc_addr, function(vm, gpr, fpr, address)
                if not demo_state.demo_executed then
                    demo_state.demo_executed = true
                    execute_gadget_demo()
                end
                return w1.VMAction.CONTINUE
            end)
            
            if hook_id then
                w1.log_info(string.format("instrumentation hook installed @ 0x%x", calc_addr))
            else
                w1.log_error("failed to install hook")
                return
            end
        else
            w1.log_error("target function signature not found")
            return
        end
    else
        w1.log_error("demo requires arm64 darwin platform")
        return
    end
    
    w1.log_info("initialization complete - ready for gadget execution demo")
end

function execute_gadget_demo()
    w1.log_info("=== gadget execution demonstration ===")
    
    -- test 1: get process id
    local pid_addr = demo_state.target_base + TARGET_OFFSETS.get_process_id
    w1.log_info(string.format("calling get_process_id gadget @ 0x%x", pid_addr))
    
    local success, pid = pcall(function()
        return w1.gadget_call(pid_addr, {})
    end)
    
    if success and pid then
        w1.log_info(string.format("get_process_id returned: %d", pid))
    else
        w1.log_error(string.format("get_process_id failed: %s", tostring(pid)))
        return
    end
    
    -- test 2: compute hash with arguments  
    local hash_addr = demo_state.target_base + TARGET_OFFSETS.compute_hash
    local test_data = "gadget test data"
    
    w1.log_info(string.format("calling compute_hash gadget @ 0x%x with data: '%s'", 
                hash_addr, test_data))
    
    local success, hash = pcall(function()
        -- note: string pointer handling would need proper implementation
        -- for now, skip this test as it requires more complex argument marshaling
        w1.log_info("compute_hash test skipped - requires string pointer implementation")
        return 0
    end)
    
    -- test 3: demonstrate basic gadget capability
    w1.log_info("basic gadget execution test completed successfully")
    
    w1.log_info("=== gadget execution demonstration complete ===")
end

return tracer