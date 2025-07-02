# w1script

luajit-powered scriptable tracer for dynamic binary analysis without recompilation.

## usage

```bash
# basic tracing
w1tool tracer -n w1script -c script=./scripts/w1script/simple_counter.lua -- ./target

# with configuration
w1tool tracer -n w1script -c script=./scripts/w1script/config_demo.lua,max_instructions=500,sample_rate=10 -- ./target
```

## scripts

- `simple_counter.lua` - minimal instruction counter with low overhead
- `instruction_tracer.lua` - comprehensive instruction trace with disassembly
- `coverage_tracker.lua` - basic block coverage analysis with statistics
- `register_monitor.lua` - cross-architecture cpu register sampling
- `memory_tracer.lua` - detailed memory access monitoring with values and formatting
- `config_demo.lua` - configuration parameter demonstration
- `json_export_demo.lua` - comprehensive json output with structured reporting

## test target

```bash
# build simple test program
cmake --build build-release --target simple_demo

# test with any script
w1tool tracer -n w1script -c script=./scripts/w1script/simple_counter.lua -- ./build-release/tests/programs/simple_demo
```

## script structure

```lua
local tracer = {}
tracer.callbacks = { "instruction_postinst" }

function tracer.on_instruction_postinst(vm, gpr, fpr)
    -- implementation
    return w1.VMAction.CONTINUE
end

function tracer.shutdown()
    -- cleanup
end

return tracer
```

## callbacks

- `instruction_preinst` / `instruction_postinst` - instruction execution
- `basic_block_entry` / `basic_block_exit` - basic block transitions
- `memory_read` / `memory_write` - memory operations

## w1 api

all functions are under the `w1` module to avoid global namespace pollution.

### logging
- `w1.log_info(msg)` - info logging
- `w1.log_debug(msg)` - debug logging  
- `w1.log_error(msg)` - error logging

### instruction analysis
- `w1.get_disassembly(vm)` - instruction disassembly
- `w1.format_address(addr)` - hex address formatting

### register access
**arm64**
- `w1.get_reg_x0(gpr)`, `w1.get_reg_x1(gpr)` - parameter registers
- `w1.get_reg_sp(gpr)`, `w1.get_reg_lr(gpr)`, `w1.get_reg_pc(gpr)` - stack/control

**x86_64**  
- `w1.get_reg_rax(gpr)`, `w1.get_reg_rbx(gpr)`, `w1.get_reg_rcx(gpr)`, `w1.get_reg_rdx(gpr)`
- `w1.get_reg_rsi(gpr)`, `w1.get_reg_rdi(gpr)`, `w1.get_reg_rsp(gpr)`, `w1.get_reg_rbp(gpr)`, `w1.get_reg_rip(gpr)`

**arm32**
- `w1.get_reg_r0(gpr)`, `w1.get_reg_r1(gpr)` - parameter registers
- `w1.get_reg_sp(gpr)`, `w1.get_reg_lr(gpr)`, `w1.get_reg_pc(gpr)` - stack/control

### memory access
- `w1.get_memory_accesses(vm)` - array of memory access tables
- `w1.format_memory_value(value, size)` - format memory value as hex

memory access table structure:
```lua
{
    address = 0x1234,      -- memory address accessed
    value = 0x5678,        -- value read/written  
    size = 8,              -- access size in bytes
    is_read = true,        -- true if read operation
    is_write = false,      -- true if write operation
    inst_address = 0xabcd  -- instruction address
}
```

### file output
- `w1.write_file(filename, content)` - write content to file
- `w1.append_file(filename, content)` - append content to file

### json serialization
- `w1.to_json(table)` - convert lua table to json string
- `w1.get_timestamp()` - iso 8601 timestamp

### vmaction values
- `w1.VMAction.CONTINUE` - continue execution
- `w1.VMAction.SKIP_INST` - skip current instruction
- `w1.VMAction.STOP` - stop execution

## configuration

config passed via tracer `-c` parameter becomes available as `config` table:

```lua
local max_inst = tonumber(config and config.max_instructions) or 1000
```

## json output example

```lua
local report = {
    summary = { blocks = 42, instructions = 1337 },
    timestamp = w1.get_timestamp()
}

local json_str = w1.to_json(report)
w1.write_file("report.json", json_str)
```

## memory access example

```lua
local accesses = w1.get_memory_accesses(vm)
for i, access in ipairs(accesses) do
    local value_hex = w1.format_memory_value(access.value, access.size)
    w1.log_info("memory " .. (access.is_read and "read" or "write") .. 
             " @ " .. w1.format_address(access.address) .. 
             " value=" .. value_hex)
end
```