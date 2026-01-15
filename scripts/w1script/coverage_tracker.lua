-- coverage tracker
-- counts unique basic blocks and total block hits
local discovered_blocks = {}
local total_block_hits = 0
local unique_block_count = 0

local tracer = {}

local function on_basic_block(vm, state, gpr, fpr)
    local block_address = state.basicBlockStart or 0
    local block_key = w1.util.format_address(block_address)

    total_block_hits = total_block_hits + 1

    if not discovered_blocks[block_key] then
        discovered_blocks[block_key] = true
        unique_block_count = unique_block_count + 1
    end

    return w1.enum.vm_action.CONTINUE
end

function tracer.init()
    w1.on(w1.event.BASIC_BLOCK_ENTRY, on_basic_block)
end

function tracer.shutdown()
    local avg_hits = unique_block_count > 0 and (total_block_hits / unique_block_count) or 0

    w1.log.info("coverage summary:")
    w1.log.info("  unique blocks: " .. unique_block_count)
    w1.log.info("  total hits: " .. total_block_hits)
    w1.log.info("  average hits per block: " .. string.format("%.2f", avg_hits))
end

return tracer
