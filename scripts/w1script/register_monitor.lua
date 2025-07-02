-- register monitor
-- demonstrates register access across different cpu architectures

local instruction_count = 0
local sample_rate = 10

local tracer = {}
tracer.callbacks = { "instruction_postinst" }

local function get_architecture_registers(gpr)
    local registers = {}
    
    if w1.get_reg_x0 then
        -- arm64 architecture
        registers.arch = "arm64"
        registers.param = w1.format_address(w1.get_reg_x0(gpr))
        registers.stack = w1.format_address(w1.get_reg_sp(gpr))
        registers.param_name = "x0"
    elseif w1.get_reg_rax then
        -- x86_64 architecture
        registers.arch = "x86_64"
        registers.param = w1.format_address(w1.get_reg_rax(gpr))
        registers.stack = w1.format_address(w1.get_reg_rsp(gpr))
        registers.param_name = "rax"
    elseif w1.get_reg_r0 then
        -- arm32 architecture
        registers.arch = "arm32"
        registers.param = w1.format_address(w1.get_reg_r0(gpr))
        registers.stack = w1.format_address(w1.get_reg_sp(gpr))
        registers.param_name = "r0"
    else
        registers.arch = "unknown"
        registers.param = "0x0"
        registers.stack = "0x0"
        registers.param_name = "n/a"
    end
    
    return registers
end

function tracer.on_instruction_postinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- sample every nth instruction to reduce noise
    if instruction_count % sample_rate == 0 then
        local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
        local registers = get_architecture_registers(gpr)
        local sample_number = instruction_count / sample_rate
        
        local info = string.format("sample %d: pc=%s %s=%s sp=%s",
            sample_number,
            w1.format_address(pc),
            registers.param_name,
            registers.param,
            registers.stack)
            
        w1.log_info(info)
    end
    
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    local total_samples = math.floor(instruction_count / sample_rate)
    
    w1.log_info("sampled " .. total_samples .. " register states from " .. instruction_count .. " instructions")
end

return tracer