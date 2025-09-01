-- mnemonic tracker
-- tracks specific instruction mnemonics using manual callback registration

local mnemonic_counts = {}
local matched_instructions = 0
local unique_sites = {}
local arch_targets = {}

-- architecture-specific default mnemonics
local default_mnemonics = {
    arm64 = {"B*", "BL*", "BR*", "BLR*", "RET*"},
    x64 = {"CALL*", "JMP*", "RET*", "TAI*"},
    x86 = {"CALL*", "JMP*", "RET*", "TAI*"}
}

local tracer = {}
local vm_instance = nil
local callback_ids = {}

function tracer.init()
    local arch = w1.get_architecture()
    w1.log_info("mnemonic tracker initialized for " .. arch)
    
    -- set up target mnemonics based on architecture
    arch_targets = default_mnemonics[arch] or {}
    
    -- initialize counts
    for _, mnemonic in ipairs(arch_targets) do
        mnemonic_counts[mnemonic] = 0
    end
end

function tracer.instrument(vm)
    -- store VM instance for manual callback registration
    vm_instance = vm
    
    if not vm_instance then
        w1.log_error("VM instance is nil")
        return false
    end
    
    -- manually register mnemonic callbacks
    for _, mnemonic in ipairs(arch_targets) do
        local callback_id = vm_instance:addMnemonicCB(mnemonic, w1.PREINST, 
            function(vm, gpr, fpr)
                -- get instruction analysis
                local analysis = vm:getInstAnalysis()
                if not analysis then return w1.CONTINUE end
                
                local address = analysis.address
                local actual_mnemonic = analysis.mnemonic or ""
                
                -- track matched instruction
                matched_instructions = matched_instructions + 1
                
                -- track unique sites
                if not unique_sites[address] then
                    unique_sites[address] = true
                end
                
                -- count by the pattern that matched (not the actual mnemonic)
                mnemonic_counts[mnemonic] = mnemonic_counts[mnemonic] + 1

                -- log
                w1.log_debug("mnemonic matched: " .. mnemonic .. " (address=" .. address .. ", actual=" .. actual_mnemonic .. ")")
                
                return w1.CONTINUE
            end
        )
        
        if callback_id then
            table.insert(callback_ids, callback_id)
            w1.log_info("registered mnemonic callback for " .. mnemonic .. " (id=" .. callback_id .. ")")
        else
            w1.log_error("failed to register mnemonic callback for " .. mnemonic)
        end
    end
    
    w1.log_info("registered " .. #callback_ids .. " mnemonic callbacks")
    return true
end

function tracer.shutdown()
    -- count unique sites
    local unique_count = 0
    for _ in pairs(unique_sites) do
        unique_count = unique_count + 1
    end
    
    w1.log_info("mnemonic summary:")
    w1.log_info("  matched instructions: " .. matched_instructions)
    w1.log_info("  unique sites: " .. unique_count)
    w1.log_info("  target patterns: " .. #arch_targets)
    
    -- sort and display non-zero counts
    local sorted = {}
    for mnemonic, count in pairs(mnemonic_counts) do
        if count > 0 then
            table.insert(sorted, {mnemonic = mnemonic, count = count})
        end
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)
    
    if #sorted > 0 then
        w1.log_info("  breakdown by pattern:")
        for _, entry in ipairs(sorted) do
            local pct = matched_instructions > 0 and (entry.count / matched_instructions * 100) or 0
            w1.log_info("    " .. entry.mnemonic .. ": " .. entry.count .. " (" .. string.format("%.1f%%", pct) .. ")")
        end
    end
end

return tracer