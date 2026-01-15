-- memory access tracer with values
-- monitors memory read and write operations with detailed logging

local read_count = 0
local write_count = 0

local tracer = {}

local function format_value(access)
    if not access.value_known or access.value == nil then
        return "<??>"
    end

    local hex = w1.util.format_hex(access.value, {prefix = true, width = access.size * 2})
    return hex or tostring(access.value)
end

local function log_memory_access(access_type, count, pc, address, size, value, instruction)
    local msg = string.format("%s #%d @ %s [%s] size=%d value=%s inst: %s",
        access_type,
        count,
        w1.util.format_address(pc),
        w1.util.format_address(address),
        size,
        value,
        instruction)
    w1.log.info(msg)
end

local function on_instruction(vm, gpr, fpr)
    local memory_accesses = w1.mem.accesses(vm)

    if #memory_accesses > 0 then
        local pc = w1.reg.pc(gpr) or 0
        local instruction = w1.inst.disasm(vm) or "<unknown>"

        for _, access in ipairs(memory_accesses) do
            local formatted_value = format_value(access)

            if access.is_read then
                read_count = read_count + 1
                log_memory_access("read", read_count, pc, access.address, access.size, formatted_value, instruction)
            end

            if access.is_write then
                write_count = write_count + 1
                log_memory_access("write", write_count, pc, access.address, access.size, formatted_value, instruction)
            end
        end
    end

    return w1.enum.vm_action.CONTINUE
end

function tracer.init()
    w1.on(w1.event.INSTRUCTION_POST, on_instruction)
end

function tracer.shutdown()
    local total_operations = read_count + write_count

    w1.log.info("memory operations summary:")
    w1.log.info(string.format("  reads: %d", read_count))
    w1.log.info(string.format("  writes: %d", write_count))
    w1.log.info(string.format("  total: %d", total_operations))
end

return tracer
