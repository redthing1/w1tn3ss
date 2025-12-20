-- process dump demonstration
-- equivalent to: w1tool dump -s ./target --memory --filter all:simple_demo --filter data:_anon --max-region-size 5M

local tracer = {}
local dumped = false

local function on_vm_start(vm)
    w1.log.info("dump demo: vm started")
    return w1.enum.vm_action.CONTINUE
end

local function on_instruction(vm, gpr, fpr)
    if dumped then
        return w1.enum.vm_action.CONTINUE
    end

    dumped = true

    local pc = w1.reg.pc(gpr) or 0
    local module_name = w1.module.name(pc)
    w1.log.info("dumping process (module: " .. module_name .. ")")

    w1.dump.process(vm, gpr, fpr, {
        output = "process.w1dump",
        dump_memory = true,
        filters = {
            "all:" .. module_name,
            "data:_anon"
        },
        max_region_size = 5 * 1024 * 1024
    })

    w1.log.info("dump complete, stopping")
    return w1.enum.vm_action.STOP
end

function tracer.init()
    w1.on(w1.event.VM_START, on_vm_start)
    w1.on(w1.event.INSTRUCTION_PRE, on_instruction)
end

return tracer
