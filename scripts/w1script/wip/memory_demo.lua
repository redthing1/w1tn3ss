-- memory access demo
-- demonstrates safe memory read/write functions

local tracer = {}

function tracer.init()
    w1.log_info("memory demo initializing")
end

-- hook instruction execution to demonstrate memory access
tracer.callbacks = { "instruction_postinst" }

local instruction_count = 0

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- only check every 1000 instructions to reduce overhead
    if instruction_count % 1000 == 0 then
        -- example: read string from stack
        local sp = w1.get_sp(gpr)
        local str = w1.read_string(vm, sp, 64)
        if str then
            w1.log_info("String at stack pointer: " .. str)
        end
        
        -- example: read memory as hex
        local hex = w1.read_mem_hex(vm, sp, 16)
        if hex then
            w1.log_info("Stack data: " .. hex)
        end
        
        -- example: read typed values
        local ptr = w1.read_ptr(vm, sp)
        if ptr then
            w1.log_info(string.format("Pointer at SP: 0x%x", ptr))
        end
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    w1.log_info("traced " .. instruction_count .. " instructions")
end

return tracer