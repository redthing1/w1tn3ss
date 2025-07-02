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

### basic examples
- `simple_counter.lua` - minimal instruction counter with low overhead
- `instruction_tracer.lua` - comprehensive instruction trace with disassembly
- `coverage_tracker.lua` - basic block coverage analysis with statistics
- `register_monitor.lua` - cross-architecture cpu register sampling
- `memory_tracer.lua` - detailed memory access monitoring with values and formatting

### configuration and output
- `config_demo.lua` - configuration parameter demonstration
- `json_export_demo.lua` - comprehensive json output with structured reporting

### vm control and management
- `vm_control_basics.lua` - fundamental vm control operations and state management
- `vm_instrumentation_strategies.lua` - advanced patterns for selective and dynamic instrumentation
- `vm_memory_analysis.lua` - comprehensive memory mapping analysis and reporting
- `vm_performance_tuning.lua` - cache management and vm configuration optimization
- `vm_health_monitoring.lua` - comprehensive vm status checking and health reporting

### enhanced api demonstrations
- `bindings_demo_1.lua` - key enhanced qbdi api features demonstration
- `bindings_test.lua` - comprehensive bindings validation and testing

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

## VM Control API

The w1script module provides comprehensive VM control methods for advanced dynamic binary analysis.

### Execution Control
- `w1.vm_run(vm_ptr, start_addr, stop_addr)` - execute code from start to stop address
- `w1.vm_call(vm_ptr, function_addr, args_table)` - call function with DBI, returns result
- `w1.vm_switch_stack_and_call(vm_ptr, function_addr, args_table, stack_size)` - call with new stack
- `w1.vm_get_options(vm_ptr)` - get current VM options bitmask
- `w1.vm_set_options(vm_ptr, options)` - set VM configuration options

### Instrumentation Range Management
- `w1.vm_add_instrumented_range(vm_ptr, start, end)` - add address range for instrumentation
- `w1.vm_add_instrumented_module(vm_ptr, name)` - add module by name
- `w1.vm_add_instrumented_module_from_addr(vm_ptr, addr)` - add module containing address
- `w1.vm_instrument_all_executable_maps(vm_ptr)` - instrument all executable memory
- `w1.vm_remove_instrumented_range(vm_ptr, start, end)` - remove range
- `w1.vm_remove_instrumented_module(vm_ptr, name)` - remove module
- `w1.vm_remove_all_instrumented_ranges(vm_ptr)` - clear all ranges

### State Management
- `w1.vm_get_gpr_state(vm_ptr)` - get general purpose registers pointer
- `w1.vm_get_fpr_state(vm_ptr)` - get floating point registers pointer
- `w1.vm_get_errno(vm_ptr)` - get error number
- `w1.vm_set_errno(vm_ptr, value)` - set error number

### Cache and Performance
- `w1.vm_clear_cache(vm_ptr, start, end)` - clear translation cache for range
- `w1.vm_clear_all_cache(vm_ptr)` - clear entire translation cache
- `w1.vm_precache_basic_block(vm_ptr, pc)` - pre-cache optimization
- `w1.vm_get_nb_exec_block(vm_ptr)` - get number of cached blocks
- `w1.vm_reduce_cache_to(vm_ptr, nb)` - reduce cache to specific size

### Memory Management
- `w1.vm_get_current_process_maps(full_path)` - get current process memory layout
- `w1.vm_get_remote_process_maps(pid, full_path)` - get remote process memory layout
- `w1.vm_get_module_names()` - list loaded modules
- `w1.vm_allocate_virtual_stack(gpr_ptr, stack_size)` - allocate new stack
- `w1.vm_simulate_call(gpr_ptr, return_addr, args_table)` - simulate function call

### VM Options Constants
- `w1.Options.NO_OPT` - no options enabled
- `w1.Options.OPT_DISABLE_FPR` - disable floating point registers
- `w1.Options.OPT_DISABLE_OPTIONAL_FPR` - disable optional FPR
- `w1.Options.OPT_DISABLE_LOCAL_MONITOR` - disable local monitoring
- `w1.Options.OPT_DISABLE_ERRNO_BACKUP` - disable errno backup
- `w1.Options.OPT_ENABLE_FS_GS` - enable FS/GS segment registers
- `w1.Options.OPT_BYPASS_PAUTH` - bypass pointer authentication
- `w1.Options.OPT_ATT_SYNTAX` - use AT&T assembly syntax

### Memory Permission Constants
- `w1.Permission.PF_NONE` - no access
- `w1.Permission.PF_READ` - read access
- `w1.Permission.PF_WRITE` - write access  
- `w1.Permission.PF_EXEC` - execution access

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

## VM Control Usage Examples

### Basic VM Control Script Structure

```lua
local tracer = {}
tracer.callbacks = { "instruction_postinst" }

-- Access VM pointer in callbacks
function tracer.on_instruction_postinst(vm, gpr, fpr)
    -- vm parameter can be used with VM control functions
    local options = w1.vm_get_options(vm)
    local cache_blocks = w1.vm_get_nb_exec_block(vm)
    
    return w1.VMAction.CONTINUE
end

return tracer
```

### Memory Analysis Example

```lua
-- Get process memory layout
local maps = w1.vm_get_current_process_maps(true)  -- true for full paths
for i, map in ipairs(maps) do
    local perm_str = ""
    if (map.permission & w1.Permission.PF_READ) ~= 0 then perm_str = perm_str .. "r" end
    if (map.permission & w1.Permission.PF_WRITE) ~= 0 then perm_str = perm_str .. "w" end
    if (map.permission & w1.Permission.PF_EXEC) ~= 0 then perm_str = perm_str .. "x" end
    
    w1.log_info("Map: " .. w1.format_address(map.start) .. "-" .. 
                w1.format_address(map.end) .. " " .. perm_str .. " " .. map.name)
end
```

### Dynamic Instrumentation Example

```lua
function tracer.setup(vm)
    -- Remove all existing instrumentation
    w1.vm_remove_all_instrumented_ranges(vm)
    
    -- Get loaded modules and instrument specific ones
    local modules = w1.vm_get_module_names()
    for _, module_name in ipairs(modules) do
        if string.match(module_name, "^lib") then  -- Libraries starting with "lib"
            if w1.vm_add_instrumented_module(vm, module_name) then
                w1.log_info("Instrumented module: " .. module_name)
            end
        end
    end
    
    -- Or instrument all executable maps
    if w1.vm_instrument_all_executable_maps(vm) then
        w1.log_info("Instrumented all executable maps")
    end
end
```

### Cache Management Example

```lua
function tracer.manage_cache(vm)
    local cache_blocks = w1.vm_get_nb_exec_block(vm)
    if cache_blocks and cache_blocks > 200 then
        w1.log_info("Cache large (" .. cache_blocks .. " blocks), reducing to 100")
        w1.vm_reduce_cache_to(vm, 100)
    end
    
    -- Clear cache for specific range if needed
    w1.vm_clear_cache(vm, 0x400000, 0x500000)
end
```

### Function Call Example

```lua
function tracer.call_function(vm)
    -- Prepare arguments
    local args = {42, 0x1000, 0x2000}  -- Example arguments
    local function_addr = 0x401234      -- Function address
    
    -- Call function with DBI
    local result = w1.vm_call(vm, function_addr, args)
    if result then
        w1.log_info("Function returned: " .. w1.format_address(result))
    end
    
    -- Call with new stack (128KB)
    local result2 = w1.vm_switch_stack_and_call(vm, function_addr, args, 0x20000)
    if result2 then
        w1.log_info("Function with new stack returned: " .. w1.format_address(result2))
    end
end
```

### VM Options Configuration Example

```lua
function tracer.optimize_vm(vm)
    -- Get current options
    local current_options = w1.vm_get_options(vm)
    w1.log_info("Current options: 0x" .. string.format("%x", current_options))
    
    -- Set performance-optimized options
    local new_options = w1.Options.OPT_DISABLE_FPR | w1.Options.OPT_DISABLE_LOCAL_MONITOR
    if w1.vm_set_options(vm, new_options) then
        w1.log_info("Applied performance optimizations")
    end
end
```