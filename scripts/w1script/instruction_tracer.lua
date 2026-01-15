-- instruction tracer with disassembly
-- logs every instruction with address and assembly code
local instruction_count = 0

local tracer = {}

local function on_instruction(vm, gpr, fpr)
    instruction_count = instruction_count + 1

    local pc = w1.reg.pc(gpr) or 0
    local disasm = w1.inst.disasm(vm) or "<unknown>"

    w1.log.info(w1.util.format_address(pc) .. ": " .. disasm)
    return w1.enum.vm_action.CONTINUE
end

function tracer.init()
    w1.on(w1.event.INSTRUCTION_PRE, on_instruction)
end

function tracer.shutdown()
    w1.log.info("traced " .. instruction_count .. " instructions")
end

return tracer
