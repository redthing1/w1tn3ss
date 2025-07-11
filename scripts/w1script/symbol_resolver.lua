-- symbol resolution demo
-- resolves and displays symbol information during execution
local first_run = true
local instruction_count = 0
local unique_symbols = {}

local tracer = {}

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1

    -- get program counter
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0

    -- resolve current instruction location
    local sym = w1.symbol_resolve_address(pc)
    if sym then
        unique_symbols[sym.name] = true
        local disasm = w1.get_disassembly(vm)
        w1.log_info(string.format("%s: %s+0x%x: %s", w1.format_address(pc), sym.name, sym.offset, disasm))
    end

    -- on first run, demonstrate other capabilities
    if first_run then
        first_run = false

        -- show backend
        w1.log_info("symbol backend: " .. w1.symbol_get_backend())

        -- resolve common function
        local malloc_addr = w1.symbol_resolve_name("malloc")
        if malloc_addr then
            w1.log_info(string.format("malloc @ %s", w1.format_address(malloc_addr)))
        end
    end

    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    -- count unique symbols
    local symbol_count = 0
    for _ in pairs(unique_symbols) do
        symbol_count = symbol_count + 1
    end

    w1.log_info(string.format("traced %d instructions in %d unique functions", instruction_count, symbol_count))
end

return tracer
