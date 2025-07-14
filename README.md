# w1tn3ss

a cross-platform dynamic binary analysis and instrumentation framework powered by [qbdi](https://github.com/QBDI/QBDI).

## features

+ framework for writing dynamic tracers (`w1tn3ss`)
+ built-in tracers: coverage (`w1cov`), call tracing (`w1xfer`), memory (`w1mem`), instructions (`w1inst`)
+ real-time library call interception with argument extraction (`api_analyzer`)
+ signature scanning and binary patching (`p1ll`/`p1llx`)
+ scriptable tracing and patching with with [luajit](https://luajit.org/)
+ cross-platform injection library with multiple techniques (`w1nj3ct`)
+ symbol resolution and calling convention modeling for intercepting arguments and return values
+ **hooking**, **scanning**, **patching**, **gadgeting**, control execution, and more

## build

build for any platform (with script and lief enabled):
```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON
cmake --build build-release --parallel
```

to use a specific arch, configure `WITNESS_ARCH` (`x64`, `x86`, `arm64`)

## `w1tool` guide

this is a brief guide to using `w1tool`, a ready-to-use command line for running tracers

### coverage & tracing

code coverage helps us learn what code in a program gets run and how often. the `w1cov` tracer is purpose built to collect detailed code coverage information, with only modest performance overhead.

the drcov format is ideal for coverage tracing, as it includes metadata about loaded modules. `w1cov` also supports collecting data in a superset of the drcov format, which also records hit counts of coverage units. this can be useful to record the execution frequency of a block.
my other project [covtool](https://github.com/redthing1/covtool) provides a powerful tool for viewing, editing, and browsing coverage traces.

collect coverage in drcov format using `w1cov`:
```sh
# macos/linux
./build-release/w1tool cover -s ./build-release/tests/programs/simple_demo
# windows
.\build-release\w1tool.exe cover -s .\build-release\tests\programs\simple_demo.exe
```

output will resemble:
```
[w1cov.preload] [inf] coverage data export completed      output_file=simple_demo_coverage.drcov
[w1cov.tracer] [inf] coverage collection completed       coverage_units=59 modules=50 total_hits=71
```

the default block tracing mode is significantly more efficient than per-instruction tracing as it requires less frequent callback interuptions. however, qbdi detects basic blocks dynamically, so recorded block boundaries may differ from those detected by static analysis tools. this usually isn't an issue, as you can script your disassembler to fix any discrepancies when marking basic block coverage.

you can also trace coverage in the same drcov format by passing `--inst` to `cover`, which will use instruction callbacks.

for a more primitive form of tracing which simply records the instruction pointer, use `w1trace`:
```sh
# macos/linux
./build-release/w1tool tracer -n w1trace -c output=simple_demo_trace.txt -s ./build-release/tests/programs/simple_dem
# windows
.\build-release\w1tool.exe tracer -n w1trace -c output=simple_demo_trace.txt -s .\build-release\tests\programs\simple_demo.exe
```

### real-time api call analysis

often it is valuable to learn what system library apis a program is called. for example, we can learn a lot about the behavior of a program by observing its calls to `libc`. the `w1xfer` tracer, powered by qbdi's [`ExecBroker`](https://qbdi.readthedocs.io/en/stable/tutorial_ExecBrokerEvent.html) mechanism, can intercept and observe calls from and returns back to instrumented code.

in addition to detecting calls crossing the instrumentation boundary, `w1xfer` also contains an `api_analyzer` system, which resolves the symbols of these calls, and extracts function arguments based on platform-specific calling convention models. this allows for very rich interception and tracing of the arguments and return values of common library apis. this can be extended by adding to the `api_knowledge_db` component.

trace api calls in real time with `w1xfer`:
```sh
# macos/linux
./build-release/w1tool -v tracer -n w1xfer -c analyze_apis=true -c output=test_transfers.jsonl -s ./build-release/tests/programs/simple_demo
# windows
.\build-release\w1tool.exe -v tracer -n w1xfer -c analyze_apis=true -c output=test_transfers.jsonl -s .\build-release\tests\programs\simple_demo.exe
```

output will resemble:
```sh
registered platform conventions     platform=aarch64 count=1
...
call=malloc(size=64) category=Heap module=libsystem_malloc.dylib
return=malloc() = 0x600003b982c0 raw_value=105553178755776 module=libsystem_malloc.dylib
...
call=puts(s="simple demo finished") category=I/O module=libsystem_c.dylib
simple demo finished
return=puts() = 10 raw_value=10 module=libsystem_c.dylib
call=intercept_exit(?) category= module=w1xfer_qbdipreload.dylib
```

as seen above, this can successfully intercept calls to many common `libc` apis!

### scripting

w1tn3ss supports writing custom tracers in luajit through the `w1script` tracer.
scripts can hook various callbacks and directly access vm state, registers, and memory.

here's a simple instruction tracer:
```lua
local instruction_count = 0

local tracer = {}

function tracer.on_instruction_preinst(vm, gpr, fpr)
    instruction_count = instruction_count + 1
    
    -- get program counter and disassembly
    local pc = w1.get_reg_pc and w1.get_reg_pc(gpr) or 0
    local disasm = w1.get_disassembly(vm)
    
    -- log instruction with address and disassembly
    w1.log_info(w1.format_address(pc) .. ": " .. disasm)
    
    return w1.VMAction.CONTINUE
end

return tracer
```

run it:
```sh
# macos/linux
./build-release/w1tool tracer -n w1script -c script=./scripts/w1script/instruction_tracer.lua -s ./build-release/tests/programs/simple_demo
# windows
.\build-release\w1tool.exe tracer -n w1script -c script=./scripts/w1script/instruction_tracer.lua -s .\build-release\tests\programs\simple_demo.exe
```

this will produce a trace of disassembled instructions as they are executed.

see the [example scripts](./scripts/w1script/), which demonstrate memory tracing, function hooking, coverage collection, and api interception.

## `p1ll` guide

patching binaries is an essential part of a reversing or cracking workflow. `p1ll` is a portable signature scanning and patching library that can patch binaries statically on disk or dynamically in memory.
`p1llx` provides a nifty command line to run and inspect patches.

### static patching

patch a binary on disk:
```sh
./build-release/p1llx -vv cure -c ./patch_script.lua -i ./target_binary -o ./patched_binary
```

on macos, statically patched binaries require codesigning:
```sh
codesign -fs - ./patched_binary
```

the `d0ct0r.py` script provides intelligent patch development features; it automatically backs up the input file, and handles permissions and codesigning.

### dynamic patching

patch a running process in memory:
```sh
# spawn new process
./build-release/p1llx -vv poison -c ./patch_script.lua -s ./target_binary
# attach to existing process
./build-release/p1llx -vv poison -c ./patch_script.lua -n target_binary
```

### patch scripts

`p1ll` uses scripts to define signatures and patching. this is designed to be used through the declarative `auto_cure` api, which can define platform-specific signatures and patches.

example patch script:
```lua
-- validation signature
local SIG_DEMO_NAME = p1.sig(p1.str2hex("Demo Program"))
-- unique signature for this string
local SIG_ANGERY = p1.sig(p1.str2hex("Angery"), {single = true})

-- find a function by signature (optional module filter)
local SIG_CHECK_LICENSE_WIN_X64 = p1.sig([[
  4885c0          -- test rax, rax
  74??            -- je <offset>
  b001            -- mov al, 1
]], {filter = "demo_program"})

-- patch: fall through the check by nopping it
local FIX_CHECK_LICENSE_WIN_X64 = [[
  ??????
  9090            -- nop nop
  ????
]]

local meta = { -- declarative patch
  name = "demo_program",
  platforms = {"windows:x64"}, -- platforms supported by this patch
  sigs = {
    ["*"] = { -- wildcard signatures are checked on all platforms
      SIG_DEMO_NAME,
      SIG_ANGERY,
    }
  },
  patches = {
    ["windows:x64"] = { -- patch only on windows:x64
        p1.patch(SIG_CHECK_LICENSE_WIN_X64, 0, FIX_CHECK_LICENSE_WIN_X64)
    },
    ["*"] = { -- wildcard patches are used on all platforms
      p1.patch(SIG_ANGERY, 0, p1.str2hex("Happey"))
    }
  }
}

function cure()
  return p1.auto_cure(meta)
end
```

key concepts:
- `p1.sig()`: define byte patterns (with `??` for wildcards)
- `p1.patch()`: specify signature, offset, and replacement
- `meta` table: organize sigs and patches by platform

`p1ll` is an excellent and powerful tool for binary modification!

## acknowledgements

+ many thanks to quarkslab for [qbdi](https://github.com/QBDI/QBDI)!
