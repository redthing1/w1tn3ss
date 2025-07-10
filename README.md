# w1tn3ss

a cross-platform dynamic binary analysis platform powered by [qbdi](https://github.com/QBDI/QBDI) and [lief](https://github.com/lief-project/LIEF).

## features

+ a framework for writing dynamic tracers
+ built-in tracers: coverage, memory, instruction, etc.
+ real-time shared library call tracing via abi analysis
+ scriptable tracers with [luajit](https://luajit.org/)
+ cross-platform library injection library
+ a tool for easy tracer injection

## build

build for any platform (with script and lief enabled):
```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON
cmake --build build-release --parallel
```

to use a specific arch, configure `WITNESS_ARCH` (`x64`, `x86`, `arm64`)

## `w1tool` guide

this is a brief guide to using `w1tool`, a ready-to-use command line for running tracers

### coverage & tracing

code coverage helps us learn what code in a program gets run and how often. the `w1cov` tracer is purpose built to collect detailed code coverage information, with only modest performance overhead.

the drcov format is ideal for coverage tracing, as it includes metadata about loaded modules. `w1cov` also supports collecting data in a superset of the drcov format, which also records hit counts of coverage units. this can be useful to record the execution frequency of a block.

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
```
[w1.calling_convention_factory] [inf] registered platform conventions     platform=aarch64 count=1
...
[w1.api_analyzer] [vrb] analyzed api call                   call=malloc(size=64) category=Heap module=libsystem_malloc.dylib
[w1.api_analyzer] [vrb] analyzed api return                 return=malloc() = 0x600003b982c0 raw_value=105553178755776 module=libsystem_malloc.dylib
...
[w1.api_analyzer] [vrb] analyzed api call                   call=puts(s="simple demo finished") category=I/O module=libsystem_c.dylib
simple demo finished
[w1.api_analyzer] [vrb] analyzed api return                 return=puts() = 10 raw_value=10 module=libsystem_c.dylib
[w1.api_analyzer] [vrb] analyzed api call                   call=intercept_exit(?) category= module=w1xfer_qbdipreload.dylib
[w1.preload] [inf] w1xfer preload exit                 status=0
```

as seen above, this can successfully intercept calls to many common `libc` apis!
