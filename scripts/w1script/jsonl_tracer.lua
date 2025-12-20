-- jsonl tracer
-- demonstrates jsonl streaming output for execution tracing
local tracer = {}

local stats = {
    blocks = 0,
    calls = 0,
    returns = 0
}

function tracer.init()
    local output_file = w1.config.output or "trace.jsonl"
    w1.log.info("initializing jsonl tracer, output file: " .. output_file)
    w1.output.open(output_file, {
        tracer = "jsonl_tracer",
        version = "1.0"
    })

    w1.on(w1.event.BASIC_BLOCK_ENTRY, function(vm, state, gpr, fpr)
        stats.blocks = stats.blocks + 1

        if stats.blocks <= 100 then
            w1.output.write({
                type = "block",
                address = w1.util.format_address(state.basicBlockStart),
                size = state.basicBlockEnd - state.basicBlockStart
            })
        end

        return w1.enum.vm_action.CONTINUE
    end)

    w1.on(w1.event.EXEC_TRANSFER_CALL, function(vm, state, gpr, fpr)
        stats.calls = stats.calls + 1

        local pc = w1.reg.pc(gpr) or 0
        w1.output.write({
            type = "call",
            from = w1.util.format_address(state.sequenceStart),
            to = w1.util.format_address(pc),
            from_module = w1.module.name(state.sequenceStart),
            to_module = w1.module.name(pc)
        })

        return w1.enum.vm_action.CONTINUE
    end)

    w1.on(w1.event.EXEC_TRANSFER_RETURN, function(vm, state, gpr, fpr)
        stats.returns = stats.returns + 1

        local pc = w1.reg.pc(gpr) or 0
        w1.output.write({
            type = "return",
            from = w1.util.format_address(state.sequenceStart),
            to = w1.util.format_address(pc),
            from_module = w1.module.name(state.sequenceStart)
        })

        return w1.enum.vm_action.CONTINUE
    end)
end

function tracer.shutdown()
    w1.output.write({
        type = "stats",
        total_blocks = stats.blocks,
        total_calls = stats.calls,
        total_returns = stats.returns
    })

    w1.output.close()

    w1.log.info("trace complete: " .. stats.blocks .. " blocks, " .. stats.calls .. " calls, " .. stats.returns ..
                    " returns")
end

return tracer
