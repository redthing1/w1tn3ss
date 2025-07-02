-- w1script vm instrumentation strategies
-- demonstrates advanced patterns for selective and dynamic instrumentation

local instruction_count = 0

-- pattern-based smart instrumentation
local function smart_instrumentation()
    w1.log_info("=== smart instrumentation demo ===")
    
    -- get all executable modules and selectively instrument them
    local module_names = w1.getModuleNames()
    local instrumented_count = 0
    
    -- define patterns for modules we want to instrument
    local interesting_patterns = {
        "^lib",       -- libraries starting with "lib"
        "main",       -- main executable
        "%.so",       -- shared objects (.so files)
        "%.dylib",    -- macos dynamic libraries
        "%.dll"       -- windows dlls
    }
    
    for _, module_name in ipairs(module_names) do
        local should_instrument = false
        
        -- check if module matches any interesting pattern
        for _, pattern in ipairs(interesting_patterns) do
            if string.match(module_name, pattern) then
                should_instrument = true
                break
            end
        end
        
        if should_instrument then
            if w1.addInstrumentedModule then
                w1.log_info("instrumented module: " .. module_name)
                instrumented_count = instrumented_count + 1
            else
                w1.log_debug("failed to instrument module: " .. module_name)
            end
        else
            w1.log_debug("skipped module: " .. module_name)
        end
    end
    
    w1.log_info("successfully instrumented " .. instrumented_count .. " out of " .. #module_names .. " modules")
    return instrumented_count
end

-- size-based dynamic instrumentation
local function dynamic_instrumentation()
    w1.log_info("=== dynamic instrumentation demo ===")
    
    -- get memory maps and identify key executable regions
    local maps = w1.getCurrentProcessMaps()
    local executable_regions = {}
    
    if maps then
        for _, map in ipairs(maps) do
            -- check if region is executable (simplified check)
            if map.name and (string.find(map.name, "main") or string.find(map.name, "lib")) then
                table.insert(executable_regions, {
                    start = map.start or 0,
                    end_addr = map.end_addr or map.start or 0,
                    name = map.name,
                    size = (map.end_addr or map.start or 0) - (map.start or 0)
                })
            end
        end
    end
    
    -- sort by size (largest first)
    table.sort(executable_regions, function(a, b) return a.size > b.size end)
    
    -- instrument largest executable regions first
    local max_regions_to_instrument = 3
    local instrumented_regions = 0
    
    for i, region in ipairs(executable_regions) do
        if i > max_regions_to_instrument then break end
        
        w1.log_info("instrumenting region " .. i .. ": " .. w1.format_address(region.start) .. "-" .. w1.format_address(region.end_addr) .. " (" .. region.name .. ")")
        
        if w1.addInstrumentedRange then
            instrumented_regions = instrumented_regions + 1
        else
            w1.log_error("failed to instrument region: " .. region.name)
        end
    end
    
    w1.log_info("dynamically instrumented " .. instrumented_regions .. " executable regions")
    
    return {
        total_executable_regions = #executable_regions,
        instrumented_regions = instrumented_regions
    }
end

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- run instrumentation strategies periodically
    if instruction_count == 1000 then
        smart_instrumentation()
    elseif instruction_count == 2000 then
        dynamic_instrumentation()
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("=== instrumentation strategies summary ===")
    w1.log_info("total instructions traced: " .. instruction_count)
    
    -- export results
    local results = {
        timestamp = w1.get_timestamp(),
        instructions = instruction_count,
        demonstration = "vm instrumentation strategies"
    }
    
    local json_output = w1.to_json(results)
    w1.log_info("results: " .. json_output)
    
    if w1.write_file("/tmp/w1script_instrumentation_demo.json", json_output) then
        w1.log_info("exported results to /tmp/w1script_instrumentation_demo.json")
    end
    
    w1.log_info("instrumentation strategies demo completed")
end

return tracer