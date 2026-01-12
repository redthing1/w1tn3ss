-- mnemonic tracker
-- tracks specific instruction mnemonics using explicit callback registration

local mnemonic_counts = {}
local matched_instructions = 0
local unique_sites = {}
local arch_targets = {}

local default_mnemonics = {
    arm64 = {"B*", "BL*", "BR*", "BLR*", "RET*"},
    x64 = {"CALL*", "JMP*", "RET*", "TAI*"},
    x86 = {"CALL*", "JMP*", "RET*", "TAI*"}
}

local tracer = {}

local function register_mnemonic(pattern)
    w1.on(w1.event.INSTRUCTION_PRE, function(vm, gpr, fpr)
        local analysis = w1.inst.current(vm)
        if not analysis then
            return w1.enum.vm_action.CONTINUE
        end

        local address = analysis.address
        local actual_mnemonic = analysis.mnemonic or ""

        matched_instructions = matched_instructions + 1
        if not unique_sites[address] then
            unique_sites[address] = true
        end

        mnemonic_counts[pattern] = (mnemonic_counts[pattern] or 0) + 1

        w1.log.debug(string.format("mnemonic matched: %s (address=0x%016x, actual=%s)",
            pattern, address, actual_mnemonic))

        return w1.enum.vm_action.CONTINUE
    end, {
        mnemonic = pattern
    })
end

function tracer.init()
    local arch = w1.util.architecture()
    w1.log.info("mnemonic tracker initialized for " .. arch)

    arch_targets = default_mnemonics[arch] or {}

    for _, mnemonic in ipairs(arch_targets) do
        mnemonic_counts[mnemonic] = 0
        register_mnemonic(mnemonic)
    end

    w1.log.info("registered " .. #arch_targets .. " mnemonic callbacks")
end

function tracer.shutdown()
    local unique_count = 0
    for _ in pairs(unique_sites) do
        unique_count = unique_count + 1
    end

    w1.log.info("mnemonic summary:")
    w1.log.info("  matched instructions: " .. matched_instructions)
    w1.log.info("  unique sites: " .. unique_count)
    w1.log.info("  target patterns: " .. #arch_targets)

    local sorted = {}
    for mnemonic, count in pairs(mnemonic_counts) do
        if count > 0 then
            table.insert(sorted, {mnemonic = mnemonic, count = count})
        end
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    if #sorted > 0 then
        w1.log.info("  breakdown by pattern:")
        for _, entry in ipairs(sorted) do
            local pct = matched_instructions > 0 and (entry.count / matched_instructions * 100) or 0
            w1.log.info(string.format("    %s: %d (%.1f%%)", entry.mnemonic, entry.count, pct))
        end
    end
end

return tracer
