-- example showing how to access vmstate fields
-- this demonstrates the fix for vmstate userdata access

local event_counts = {}

local tracer = {}
tracer.callbacks = { "basic_block_entry", "sequence_entry", "exec_transfer_call", "exec_transfer_return" }

function tracer.on_basic_block_entry(vm, state, gpr, fpr)
    -- access vmstate fields directly
    local event = state.event
    local bb_start = state.basicBlockStart
    local bb_end = state.basicBlockEnd
    
    -- count events
    event_counts[event] = (event_counts[event] or 0) + 1
    
    -- log first few basic block entries
    if event_counts[event] <= 5 then
        w1.log_info("bb entry: " .. w1.format_address(bb_start) .. " (event: " .. event .. ")")
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.on_sequence_entry(vm, state, gpr, fpr)
    -- access vmstate fields
    local event = state.event
    local seq_start = state.sequenceStart
    local seq_end = state.sequenceEnd
    
    -- count events
    event_counts[event] = (event_counts[event] or 0) + 1
    
    -- log first few sequence entries
    if event_counts[event] <= 3 then
        w1.log_info("sequence entry: " .. w1.format_address(seq_start) .. " -> " .. w1.format_address(seq_end) .. " (event: " .. event .. ")")
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_call(vm, state, gpr, fpr)
    -- access vmstate fields for call transfers
    local event = state.event
    local bb_start = state.basicBlockStart
    
    event_counts[event] = (event_counts[event] or 0) + 1
    
    if event_counts[event] <= 3 then
        w1.log_info("call transfer at: " .. w1.format_address(bb_start) .. " (event: " .. event .. ")")
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_return(vm, state, gpr, fpr)
    -- access vmstate fields for return transfers
    local event = state.event
    local bb_start = state.basicBlockStart
    
    event_counts[event] = (event_counts[event] or 0) + 1
    
    if event_counts[event] <= 3 then
        w1.log_info("return transfer at: " .. w1.format_address(bb_start) .. " (event: " .. event .. ")")
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("vmstate example completed:")
    for event, count in pairs(event_counts) do
        w1.log_info("  event " .. event .. ": " .. count .. " times")
    end
end

return tracer