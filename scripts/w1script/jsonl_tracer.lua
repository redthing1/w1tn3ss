-- jsonl tracer
-- demonstrates jsonl streaming output for execution tracing
local tracer = {}

local stats = {
    blocks = 0,
    calls = 0,
    returns = 0
}

function tracer.init()
    local output_file = config.output or "trace.jsonl"
    w1.log_info("initializing jsonl tracer, output file: " .. output_file)
    w1.output.init(output_file, {
        tracer = "jsonl_tracer",
        version = "1.0"
    })
end

function tracer.on_basic_block_entry(vm, state, gpr, fpr)
    stats.blocks = stats.blocks + 1

    -- write block events for new blocks only
    if stats.blocks <= 100 then
        w1.output.write_event({
            type = "block",
            address = w1.format_address(state.basicBlockStart),
            size = state.basicBlockEnd - state.basicBlockStart
        })
    end

    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_call(vm, state, gpr, fpr)
    stats.calls = stats.calls + 1

    w1.output.write_event({
        type = "call",
        from = w1.format_address(state.sequenceStart),
        to = w1.format_address(w1.get_reg_pc(gpr)),
        from_module = w1.module_get_name(state.sequenceStart),
        to_module = w1.module_get_name(w1.get_reg_pc(gpr))
    })

    return w1.VMAction.CONTINUE
end

function tracer.on_exec_transfer_return(vm, state, gpr, fpr)
    stats.returns = stats.returns + 1

    w1.output.write_event({
        type = "return",
        from = w1.format_address(state.sequenceStart),
        to = w1.format_address(w1.get_reg_pc(gpr)),
        from_module = w1.module_get_name(state.sequenceStart)
    })

    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.output.write_event({
        type = "stats",
        total_blocks = stats.blocks,
        total_calls = stats.calls,
        total_returns = stats.returns
    })

    w1.log_info("trace complete: " .. stats.blocks .. " blocks, " .. stats.calls .. " calls, " .. stats.returns ..
                    " returns")
end

return tracer
