-- execution transfer tracker
-- tracks function calls and returns with detailed logging

local call_stack = {}
local total_calls = 0
local total_returns = 0
local unique_call_targets = {}
local unique_return_sources = {}
local max_call_depth = 0
local current_call_depth = 0

local tracer = {}
tracer.callbacks = { "exec_transfer_call", "exec_transfer_return" }

function tracer.on_exec_transfer_call(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local source_addr = w1.format_address(state.sequenceStart)
    local target_addr = w1.format_address(pc)
    
    total_calls = total_calls + 1
    current_call_depth = current_call_depth + 1
    
    -- track unique call targets
    if not unique_call_targets[target_addr] then
        unique_call_targets[target_addr] = true
    end
    
    -- update max call depth
    if current_call_depth > max_call_depth then
        max_call_depth = current_call_depth
    end
    
    -- push call info onto stack
    table.insert(call_stack, {
        source = source_addr,
        target = target_addr,
        depth = current_call_depth
    })
    
    -- log the call transfer
    w1.log_info("call: " .. source_addr .. " -> " .. target_addr .. " (depth: " .. current_call_depth .. ")")
    
    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_return(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local source_addr = w1.format_address(state.sequenceStart)
    local target_addr = w1.format_address(pc)
    
    total_returns = total_returns + 1
    current_call_depth = math.max(0, current_call_depth - 1)
    
    -- track unique return sources
    if not unique_return_sources[source_addr] then
        unique_return_sources[source_addr] = true
    end
    
    -- pop from call stack if available
    local call_info = nil
    if #call_stack > 0 then
        call_info = table.remove(call_stack)
    end
    
    -- log the return transfer
    if call_info then
        w1.log_info("return: " .. source_addr .. " -> " .. target_addr .. " (from call at depth " .. call_info.depth .. ")")
    else
        w1.log_info("return: " .. source_addr .. " -> " .. target_addr .. " (unmatched return)")
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
end

return tracer