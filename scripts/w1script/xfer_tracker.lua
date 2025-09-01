-- execution transfer tracker
-- tracks function calls and returns with detailed logging and module info

local call_stack = {}
local total_calls = 0
local total_returns = 0
local unique_call_targets = {}
local unique_return_sources = {}
local max_call_depth = 0
local current_call_depth = 0
local module_call_stats = {}
local module_return_stats = {}

local tracer = {}

function tracer.on_exec_transfer_call(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local source_addr = w1.format_address(state.sequenceStart)
    local target_addr = w1.format_address(pc)
    
    -- get module names for source and target addresses
    local source_module = w1.module_get_name(state.sequenceStart)
    local target_module = w1.module_get_name(pc)
    
    total_calls = total_calls + 1
    current_call_depth = current_call_depth + 1
    
    -- track unique call targets for statistics
    if not unique_call_targets[target_addr] then
        unique_call_targets[target_addr] = true
    end
    
    -- track module statistics for call analysis
    module_call_stats[target_module] = (module_call_stats[target_module] or 0) + 1
    
    -- update max call depth
    if current_call_depth > max_call_depth then
        max_call_depth = current_call_depth
    end
    
    -- push call info onto stack for return matching
    table.insert(call_stack, {
        source = source_addr,
        target = target_addr,
        source_module = source_module,
        target_module = target_module,
        depth = current_call_depth
    })
    
    -- log the call transfer with module info
    w1.log_info(string.format("call: %s (%s) -> %s (%s) (depth: %d)", source_addr, source_module, target_addr, target_module, current_call_depth))
    
    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_return(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local source_addr = w1.format_address(state.sequenceStart)
    local target_addr = w1.format_address(pc)
    
    -- get module names for source and target addresses
    local source_module = w1.module_get_name(state.sequenceStart)
    local target_module = w1.module_get_name(pc)
    
    total_returns = total_returns + 1
    current_call_depth = math.max(0, current_call_depth - 1)
    
    -- track unique return sources for statistics
    if not unique_return_sources[source_addr] then
        unique_return_sources[source_addr] = true
    end
    
    -- track module statistics for return analysis
    module_return_stats[source_module] = (module_return_stats[source_module] or 0) + 1
    
    -- pop from call stack if available for return matching
    local call_info = nil
    if #call_stack > 0 then
        call_info = table.remove(call_stack)
    end
    
    -- log the return transfer with module info
    if call_info then
        w1.log_info(string.format("return: %s (%s) -> %s (%s) (from call %s -> %s at depth %d)", 
            source_addr, source_module, target_addr, target_module, 
            call_info.source_module, call_info.target_module, call_info.depth))
    else
        w1.log_info(string.format("return: %s (%s) -> %s (%s) (unmatched return)", 
            source_addr, source_module, target_addr, target_module))
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local unique_call_count = 0
    for _ in pairs(unique_call_targets) do
        unique_call_count = unique_call_count + 1
    end
    
    local unique_return_count = 0
    for _ in pairs(unique_return_sources) do
        unique_return_count = unique_return_count + 1
    end
    
    w1.log_info("execution transfer summary:")
    w1.log_info("  total calls: " .. total_calls)
    w1.log_info("  total returns: " .. total_returns)
    w1.log_info("  unique call targets: " .. unique_call_count)
    w1.log_info("  unique return sources: " .. unique_return_count)
    w1.log_info("  max call depth: " .. max_call_depth)
    w1.log_info("  final call depth: " .. current_call_depth)
    w1.log_info("  unmatched calls: " .. #call_stack)
    w1.log_info("  total modules discovered: " .. w1.module_count())
    
    -- log module call statistics
    w1.log_info("module call statistics:")
    for module, count in pairs(module_call_stats) do
        w1.log_info(string.format("  %s: %d calls", module, count))
    end
    
    -- log module return statistics  
    w1.log_info("module return statistics:")
    for module, count in pairs(module_return_stats) do
        w1.log_info(string.format("  %s: %d returns", module, count))
    end
end

return tracer