-- configuration demo
-- shows how to use w1tool tracer config parameters

local instruction_count = 0
local max_instructions = tonumber(config and config.max_instructions) or 100
local sample_rate = tonumber(config and config.sample_rate) or 1

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- sample according to configured rate
    if instruction_count % sample_rate == 0 then
        local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
        local disassembly = w1.get_disassembly(vm)
        local sample_number = instruction_count / sample_rate
        
        w1.log_info("sample " .. sample_number .. ": " .. 
                    w1.format_address(pc) .. " " .. disassembly)
    end
    
    -- stop at configured limit
    if instruction_count >= max_instructions then
        w1.log_info("reached instruction limit (" .. max_instructions .. "), stopping")
        return w1.VMAction.STOP
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local samples_taken = math.floor(instruction_count / sample_rate)
    
    w1.log_info("configuration demo finished:")
    w1.log_info("  total instructions: " .. instruction_count)
    w1.log_info("  max_instructions: " .. max_instructions)  
    w1.log_info("  sample_rate: " .. sample_rate)
    w1.log_info("  samples taken: " .. samples_taken)
end

return tracer