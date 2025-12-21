-- symbol resolution demo
-- resolves and displays symbol information during execution
local first_run = true
local instruction_count = 0
local unique_symbols = {}

local tracer = {}

local function on_instruction(vm, gpr, fpr)
    instruction_count = instruction_count + 1

    local pc = w1.reg.pc(gpr) or 0
    local sym = w1.symbol.resolve_address(pc)
    if sym then
        unique_symbols[sym.name] = true
        local disasm = w1.inst.disasm(vm) or "<unknown>"
        w1.log.info(string.format("%s: %s+0x%x: %s", w1.util.format_address(pc), sym.name, sym.offset, disasm))
    end

    if first_run then
        first_run = false

        w1.log.info("symbol backend: " .. w1.symbol.backend())
    end

    return w1.enum.vm_action.CONTINUE
end

function tracer.init()
    w1.on(w1.event.INSTRUCTION_PRE, on_instruction)
end

function tracer.shutdown()
    local symbol_count = 0
    for _ in pairs(unique_symbols) do
        symbol_count = symbol_count + 1
    end

    w1.log.info(string.format("traced %d instructions in %d unique functions", instruction_count, symbol_count))
end

return tracer
