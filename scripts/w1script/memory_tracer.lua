-- memory access tracer with values
-- monitors memory read and write operations with detailed logging

local read_count = 0
local write_count = 0

local tracer = {}

local function log_memory_access(access_type, count, pc, address, size, value, instruction)
    local msg = string.format("%s #%d @ %s [%s] size=%d value=%s inst: %s",
        access_type,
        count,
        w1.format_address(pc),
        w1.format_address(address),
        size,
        value,
        instruction)
    w1.log_info(msg)
end

function tracer.on_instruction_postinst(vm, gpr, fpr)
    local memory_accesses = w1.get_memory_accesses(vm)
    
    if #memory_accesses > 0 then
        local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
        local instruction = w1.get_disassembly(vm)
        
        for _, access in ipairs(memory_accesses) do
            local formatted_value = w1.format_memory_value(access.value, access.size)
            
            if access.is_read then
                read_count = read_count + 1
                log_memory_access("read", read_count, pc, access.address, 
                                access.size, formatted_value, instruction)
            end
            
            if access.is_write then
                write_count = write_count + 1
                log_memory_access("write", write_count, pc, access.address, 
                                access.size, formatted_value, instruction)
            end
        end
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local total_operations = read_count + write_count
    
    w1.log_info("memory operations summary:")
    w1.log_info(string.format("  reads: %d", read_count))
    w1.log_info(string.format("  writes: %d", write_count))
    w1.log_info(string.format("  total: %d", total_operations))
end

return tracer