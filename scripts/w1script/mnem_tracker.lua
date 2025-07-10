-- mnemonic tracker
-- tracks specific instruction mnemonics by architecture (calls, jumps, returns)

local mnemonic_counts = {}
local total_instructions = 0
local matched_instructions = 0
local arch_targets = {}

-- architecture-specific default mnemonics (actual LLVM opcodes)
local default_mnemonics = {
    aarch64 = {"B", "BL", "BR", "BLR", "RET", "BLRAA", "BLRAB", "RETAA", "RETAB"},
    x86_64 = {"CALL64pcrel32", "CALL64r", "CALL64m", "CALL64r_NT", "CALL64m_NT", "JMP64m", "JMP64r", "JMP64m_NT", "JMP64r_NT", "JMP64m_REX", "JMP64r_REX", "JMPABS64i", "JMP_1", "JMP_2", "JMP_4", "RET", "RET64", "LRET64", "IRET64", "SYSRET64", "TAILJMPd64", "TAILJMPr64", "TAILJMPm64", "TAILJMPd64_CC", "TAILJMPm64_REX", "TAILJMPr64_REX", "TCRETURNdi64", "TCRETURNmi64", "TCRETURNri64"},
    x86 = {"CALL32r", "CALL32m", "CALLpcrel32", "CALL32r_NT", "CALL32m_NT", "CALLpcrel16", "CALL16r", "CALL16m", "JMP32m", "JMP32r", "JMP32m_NT", "JMP32r_NT", "JMP16m", "JMP16r", "JMP_1", "JMP_2", "JMP_4", "RET", "RET32", "RET16", "LRET32", "LRET16", "IRET32", "IRET16", "SYSRET", "TAILJMPd", "TAILJMPr", "TAILJMPm", "TAILJMPd_CC", "TCRETURNdi", "TCRETURNmi", "TCRETURNri"}
}

local tracer = {}
tracer.callbacks = {"instruction_preinst"}

function tracer.initialize(custom_targets)
    local arch = w1.get_architecture()
    local targets = custom_targets or default_mnemonics[arch] or default_mnemonics.x86_64
    
    -- build target set for fast lookup
    for _, mnemonic in ipairs(targets) do
        arch_targets[mnemonic] = true
        mnemonic_counts[mnemonic] = 0
    end
    
    w1.log_info("mnemonic tracker initialized for " .. arch .. " with " .. #targets .. " targets")
end

function tracer.on_instruction_preinst(vm, state, gpr, fpr)
    total_instructions = total_instructions + 1
    
    local analysis = w1.get_inst_analysis and w1.get_inst_analysis(vm)
    if not analysis then return w1.VMAction.CONTINUE end
    
    local mnemonic = analysis.mnemonic or ""
    
    if arch_targets[mnemonic] then
        mnemonic_counts[mnemonic] = mnemonic_counts[mnemonic] + 1
        matched_instructions = matched_instructions + 1
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local match_rate = total_instructions > 0 and (matched_instructions / total_instructions * 100) or 0
    
    w1.log_info("mnemonic summary:")
    w1.log_info("  total instructions: " .. total_instructions)
    w1.log_info("  matched instructions: " .. matched_instructions)
    w1.log_info("  match rate: " .. string.format("%.1f%%", match_rate))
    
    -- sort and display non-zero counts
    local sorted = {}
    for mnemonic, count in pairs(mnemonic_counts) do
        if count > 0 then
            table.insert(sorted, {mnemonic = mnemonic, count = count})
        end
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)
    
    if #sorted > 0 then
        w1.log_info("  breakdown:")
        for _, entry in ipairs(sorted) do
            local pct = matched_instructions > 0 and (entry.count / matched_instructions * 100) or 0
            w1.log_info("    " .. entry.mnemonic .. ": " .. entry.count .. " (" .. string.format("%.1f%%", pct) .. ")")
        end
    end
end

tracer.initialize()
return tracer