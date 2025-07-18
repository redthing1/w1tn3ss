-- process dump demonstration
-- equivalent to: w1tool dump -s ./target --memory --filter all:simple_demo --filter data:_anon --max-region-size 5M

local tracer = {}
local dumped = false

function tracer.on_vm_start(vm)
    w1.log_info("dump demo: vm started")
    return w1.VMAction.CONTINUE
end

function tracer.on_instruction_preinst(vm, gpr, fpr)
    if not dumped then
        dumped = true
        
        -- get module name for filter
        local module_name = w1.module_get_name(w1.get_reg_pc(gpr))
        w1.log_info("dumping process (module: " .. module_name .. ")")
        
        -- equivalent to the canonical dump command
        w1.dump_process(vm, gpr, fpr, {
            output = "process.w1dump",
            dump_memory = true,                     -- --memory flag
            filters = {
                "all:" .. module_name,              -- --filter all:simple_demo
                "data:_anon"                        -- --filter data:_anon
            },
            max_region_size = 5 * 1024 * 1024      -- --max-region-size 5M
        })
        
        w1.log_info("dump complete, stopping")
        return w1.VMAction.STOP
    end
    
    return w1.VMAction.CONTINUE
end

return tracer