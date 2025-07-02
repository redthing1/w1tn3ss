-- w1script vm memory analysis
-- comprehensive memory mapping analysis and reporting tool

local instruction_count = 0
local analysis_results = {}

-- comprehensive memory mapping analysis
local function analyze_memory_mappings()
    w1.log_info("=== memory mapping analysis ===")
    
    -- get current process maps
    local maps = w1.getCurrentProcessMaps()
    
    local analysis = {
        total_maps = 0,
        executable_maps = 0,
        writable_maps = 0,
        readable_maps = 0,
        total_size = 0,
        executable_size = 0,
        largest_map = nil,
        smallest_map = nil,
        modules = {}
    }
    
    if not maps then
        w1.log_error("failed to get memory maps")
        return analysis
    end
    
    analysis.total_maps = #maps
    
    -- analyze each memory map
    for _, map in ipairs(maps) do
        local size = (map.end_addr or map.start or 0) - (map.start or 0)
        analysis.total_size = analysis.total_size + size
        
        -- simplified permission analysis
        if map.name then
            -- assume executable if it's a library or main executable
            if string.find(map.name, "lib") or string.find(map.name, "main") or string.find(map.name, "%.so") or string.find(map.name, "%.dylib") then
                analysis.executable_maps = analysis.executable_maps + 1
                analysis.executable_size = analysis.executable_size + size
            end
            
            -- count as readable/writable based on typical patterns
            analysis.readable_maps = analysis.readable_maps + 1
            if string.find(map.name, "heap") or string.find(map.name, "stack") or string.find(map.name, "data") then
                analysis.writable_maps = analysis.writable_maps + 1
            end
        end
        
        -- track largest and smallest maps
        if not analysis.largest_map or size > ((analysis.largest_map.end_addr or 0) - (analysis.largest_map.start or 0)) then
            analysis.largest_map = map
        end
        if not analysis.smallest_map or size < ((analysis.smallest_map.end_addr or 0) - (analysis.smallest_map.start or 0)) then
            analysis.smallest_map = map
        end
        
        -- collect unique module names
        if map.name and map.name ~= "" and map.name ~= "[anonymous]" then
            analysis.modules[map.name] = (analysis.modules[map.name] or 0) + 1
        end
    end
    
    -- report analysis results
    w1.log_info("memory analysis results:")
    w1.log_info("  total maps: " .. analysis.total_maps)
    w1.log_info("  readable maps: " .. analysis.readable_maps)
    w1.log_info("  writable maps: " .. analysis.writable_maps)
    w1.log_info("  executable maps: " .. analysis.executable_maps)
    w1.log_info("  total memory size: " .. string.format("0x%x", analysis.total_size) .. " (" .. math.floor(analysis.total_size / 1024 / 1024) .. " mb)")
    w1.log_info("  executable memory size: " .. string.format("0x%x", analysis.executable_size) .. " (" .. math.floor(analysis.executable_size / 1024 / 1024) .. " mb)")
    
    if analysis.largest_map then
        local largest_size = (analysis.largest_map.end_addr or 0) - (analysis.largest_map.start or 0)
        w1.log_info("  largest map: " .. w1.format_address(analysis.largest_map.start or 0) .. "-" .. w1.format_address(analysis.largest_map.end_addr or 0) .. " (" .. string.format("0x%x", largest_size) .. ") " .. (analysis.largest_map.name or "unknown"))
    end
    
    if analysis.smallest_map then
        local smallest_size = (analysis.smallest_map.end_addr or 0) - (analysis.smallest_map.start or 0)
        w1.log_info("  smallest map: " .. w1.format_address(analysis.smallest_map.start or 0) .. "-" .. w1.format_address(analysis.smallest_map.end_addr or 0) .. " (" .. string.format("0x%x", smallest_size) .. ") " .. (analysis.smallest_map.name or "unknown"))
    end
    
    -- count unique modules
    local unique_module_count = 0
    for module_name, count in pairs(analysis.modules) do
        unique_module_count = unique_module_count + 1
    end
    w1.log_info("  unique modules: " .. unique_module_count)
    
    return analysis
end

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- perform memory analysis at specific intervals
    if instruction_count == 5000 then
        analysis_results = analyze_memory_mappings()
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("=== memory analysis summary ===")
    w1.log_info("total instructions traced: " .. instruction_count)
    
    -- final memory analysis if not done yet
    if not analysis_results or not analysis_results.total_maps then
        analysis_results = analyze_memory_mappings()
    end
    
    -- export detailed results
    local results = {
        timestamp = w1.get_timestamp(),
        instructions = instruction_count,
        memory_analysis = analysis_results,
        demonstration = "vm memory analysis"
    }
    
    local json_output = w1.to_json(results)
    w1.log_info("detailed results: " .. json_output)
    
    if w1.write_file("/tmp/w1script_memory_analysis.json", json_output) then
        w1.log_info("exported detailed analysis to /tmp/w1script_memory_analysis.json")
    end
    
    w1.log_info("memory analysis demo completed")
end

return tracer