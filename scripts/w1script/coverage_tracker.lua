-- coverage tracker
-- counts unique basic blocks and total block hits

local discovered_blocks = {}
local total_block_hits = 0
local unique_block_count = 0

local tracer = {}
tracer.callbacks = { "basic_block_entry" }

function tracer.on_basic_block_entry(vm, state, gpr, fpr)
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local block_address = w1.format_address(pc)
    
    total_block_hits = total_block_hits + 1
    
    -- track newly discovered blocks
    if not discovered_blocks[block_address] then
        discovered_blocks[block_address] = true
        unique_block_count = unique_block_count + 1
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local avg_hits = unique_block_count > 0 and (total_block_hits / unique_block_count) or 0
    
    w1.log_info("coverage summary:")
    w1.log_info("  unique blocks: " .. unique_block_count)
    w1.log_info("  total hits: " .. total_block_hits)
    w1.log_info("  average hits per block: " .. string.format("%.2f", avg_hits))
end

return tracer