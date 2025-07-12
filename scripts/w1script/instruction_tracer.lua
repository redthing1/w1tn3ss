-- instruction tracer with disassembly
-- logs every instruction with address and assembly code
local instruction_count = 0

local tracer = {}

function tracer.on_instruction_preinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1

    -- get program counter and disassembly
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local disasm = w1.get_disassembly(vm)

    -- log instruction with address and disassembly
    w1.log_info(w1.format_address(pc) .. ": " .. disasm)

    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("traced " .. instruction_count .. " instructions")
end

return tracer
