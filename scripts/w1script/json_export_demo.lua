-- json export demo
-- demonstrates comprehensive json output capabilities

local discovered_blocks = {}
local instruction_count = 0
local memory_operation_count = 0

local tracer = {}
tracer.callbacks = { "instruction_postinst", "basic_block_entry", "memory_read", "memory_write" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    return w1.VMAction.CONTINUE
end

function tracer.on_basic_block_entry(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local block_address = w1.format_address(pc)
    
    if not discovered_blocks[block_address] then
        discovered_blocks[block_address] = {
            address = block_address,
            hit_count = 0
        }
    end
    
    discovered_blocks[block_address].hit_count = discovered_blocks[block_address].hit_count + 1
    return w1.VMAction.CONTINUE
end

function tracer.on_memory_read(vm, gpr, fpr)
    memory_operation_count = memory_operation_count + 1
    return w1.VMAction.CONTINUE
end

function tracer.on_memory_write(vm, gpr, fpr)
    memory_operation_count = memory_operation_count + 1
    return w1.VMAction.CONTINUE
end

local function build_summary_statistics()
    local unique_block_count = 0
    local total_block_hits = 0
    
    for _, block_info in pairs(discovered_blocks) do
        unique_block_count = unique_block_count + 1
        total_block_hits = total_block_hits + block_info.hit_count
    end
    
    return {
        instruction_count = instruction_count,
        unique_blocks = unique_block_count,
        total_block_hits = total_block_hits,
        memory_operations = memory_operation_count
    }
end

local function build_blocks_array()
    local blocks = {}
    
    for _, block_info in pairs(discovered_blocks) do
        table.insert(blocks, {
            address = block_info.address,
            hit_count = block_info.hit_count
        })
    end
    
    return blocks
end

function tracer.shutdown()
    local report = {
        metadata = {
            version = "1.0",
            timestamp = w1.get_timestamp(),
            tracer = "w1script_json_demo"
        },
        summary = build_summary_statistics(),
        blocks = build_blocks_array()
    }
    
    -- convert to json and save
    local json_output = w1.to_json(report)
    local output_filename = (config and config.output) or "trace_report.json"
    
    if w1.write_file(output_filename, json_output) then
        w1.log_info("json report exported: " .. output_filename)
        w1.log_info("captured " .. report.summary.unique_blocks .. " unique blocks")
        w1.log_info("total instructions: " .. instruction_count)
    else
        w1.log_error("failed to write json report")
    end
end

return tracer