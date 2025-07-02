-- simple instruction counter
-- counts executed instructions with minimal overhead

local instruction_count = 0

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("executed " .. instruction_count .. " instructions")
end

return tracer