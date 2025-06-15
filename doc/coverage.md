# Coverage Tools

Dynamic binary coverage analysis using QBDI instrumentation with DrCov export format.

**Platform Support:**
- macOS/Linux: Full support (spawn + runtime injection)
- Windows: Runtime injection only (no spawn mode)

## Quick Start

### macOS
```bash
# Build
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel

# Coverage trace
./build-release/w1tool cover -L ./build-release/w1cov_qbdipreload.dylib -s ./target

# Analyze results  
./build-release/w1tool read-drcov --file target_coverage.drcov
```

### Linux
```bash
# Build
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --parallel

# Coverage trace
./build-linux/w1tool cover -L ./build-linux/w1cov_qbdipreload.so -s ./target

# Analyze results
./build-linux/w1tool read-drcov --file target_coverage.drcov
```

### Windows
```bash
# Build
cmake -B build-windows -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows --parallel

# Runtime injection only (no spawn mode)
./build-windows/w1tool.exe cover -L ./build-windows/w1cov_qbdipreload.dll --pid 1234

# Analyze results
./build-windows/w1tool.exe read-drcov --file target_coverage.drcov
```

## Commands

### Coverage Collection
```bash
w1tool cover [OPTIONS]
```

**Required:**
- `-L, --w1cov-library <path>` - w1cov library path
- `-s, --spawn` + `<binary>` - spawn target binary (macOS/Linux only)
- `--pid <pid>` OR `--name <name>` - attach to process (all platforms)

**Optional:**
- `-o, --output <path>` - output file (default: `{binary}_coverage.drcov`)
- `--exclude-system` - exclude system libraries from coverage
- `--debug` - enable verbose debug output
- `--format <format>` - output format (`drcov`, `text`)

**Arguments:**
```bash
# Pass arguments to spawned binary (macOS/Linux only)
./w1tool cover -L ./w1cov.dylib -s ./program -- arg1 arg2 arg3
```

### Coverage Analysis
```bash
w1tool read-drcov [OPTIONS]
```

**Required:**
- `--file <path>` - DrCov file to analyze

**Optional:**
- `--detailed` - show all basic block addresses
- `--module <name>` - filter by module name

## Examples

### Basic Coverage
```bash
# macOS/Linux (spawn mode)
./w1tool cover -L ./w1cov_qbdipreload.dylib -s ./my_program
./w1tool cover -L ./w1cov_qbdipreload.so -s ./my_program

# Windows (runtime injection only)
./w1tool.exe cover -L ./w1cov_qbdipreload.dll --pid 1234
./w1tool.exe cover -L ./w1cov_qbdipreload.dll --name my_program.exe
```

### Custom Output
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -s ./target -o my_coverage.drcov
```

### System Library Exclusion
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -s ./target --exclude-system
```

### Debug Mode
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -s ./target --debug
```

### Analysis
```bash
# Basic analysis
./w1tool read-drcov --file coverage.drcov

# Detailed view
./w1tool read-drcov --file coverage.drcov --detailed

# Module-specific
./w1tool read-drcov --file coverage.drcov --module my_program
```

## Environment Variables

Configure behavior without command line flags:

```bash
# Enable coverage
export W1COV_ENABLED=1

# Debug output
export W1COV_DEBUG=1

# Custom output file
export W1COV_OUTPUT_FILE=custom.drcov

# Output format
export W1COV_FORMAT=drcov

# Exclude system libraries
export W1COV_EXCLUDE_SYSTEM=1

# Store full module paths
export W1COV_TRACK_FULL_PATHS=1
```

**Direct Usage:**
```bash
# macOS
W1COV_ENABLED=1 DYLD_INSERT_LIBRARIES=./w1cov_qbdipreload.dylib ./target

# Linux
W1COV_ENABLED=1 LD_PRELOAD=./w1cov_qbdipreload.so ./target

# Windows (no direct preload support)
# Use w1tool cover --pid instead
```

## Platform Libraries

| Platform | Library Name | Spawn Mode | Runtime Injection |
|----------|--------------|------------|-------------------|
| macOS | `w1cov_qbdipreload.dylib` | ✅ `DYLD_INSERT_LIBRARIES` | ✅ |
| Linux | `w1cov_qbdipreload.so` | ✅ `LD_PRELOAD` | ✅ |
| Windows | `w1cov_qbdipreload.dll` | ❌ Not supported | ✅ |

## Testing

### Automated Testing
```bash
# Cross-platform test script
python3 ./tests/test_w1cov.py --build-dir build-release    # macOS
python3 ./tests/test_w1cov.py --build-dir build-linux     # Linux  
python3 ./tests/test_w1cov.py --build-dir build-windows   # Windows
```

### Manual Testing
```bash
# Test different program types
# macOS/Linux
./w1tool cover -L ./w1cov_qbdipreload.* -s ./tests/programs/simple_target
./w1tool cover -L ./w1cov_qbdipreload.* -s ./tests/programs/multi_threaded_target

# Windows (start program first, then inject)
start /B simple_target.exe
./w1tool.exe cover -L ./w1cov_qbdipreload.dll --name simple_target.exe
```

## Output Format

Coverage data is exported in DrCov format compatible with:
- **Lighthouse** - IDA Pro plugin for coverage visualization
- **IDA Pro** - Load as basic block coverage 
- **Binary Ninja** - Coverage analysis and visualization
- **Ghidra** - Coverage import plugins

### Sample Output
```
=== DrCov File Analysis ===
File: target_coverage.drcov
Version: 2
Flavor: drcov-hits
Has Hitcounts: Yes

=== Summary ===
Total Modules: 3
Total Basic Blocks: 159
Total Coverage: 636 B
Total Hits: 195
Average Hits per Block: 1.23

=== Module Coverage ===
ID  Blocks  Size        Total Hits  Base Address        Name
------------------------------------------------------------------------
0   9       36 B        9           0x18c5a8000               libdyld.dylib
1   59      236 B       59          0x18c1fc000               dyld
2   91      364 B       127         0x100ca4000               target
```

## Performance

**Typical Results:**
- Simple programs: 150-200 basic blocks
- Multi-threaded: 200-300 basic blocks  
- Complex programs: 800-1000+ basic blocks

**Overhead:**
- Runtime: ~10-20% performance impact
- Memory: ~50-100MB additional usage
- Thread-safe operation confirmed

## Requirements

### macOS
- macOS 10.15+
- QBDI framework
- Release build recommended for runtime injection

### Linux
- Linux kernel 4.4+
- glibc 2.28+
- For runtime injection: `CAP_SYS_PTRACE` or root privileges

### Windows  
- Windows 10+
- MSVC 2019+ or MinGW
- Administrator privileges for runtime injection

## Troubleshooting

### Common Issues

**Library not found:**
```bash
# Use absolute paths
./w1tool cover -L $(pwd)/w1cov_qbdipreload.dylib -s ./target
```

**Permission denied (Linux):**
```bash
# Grant ptrace capability
sudo setcap cap_sys_ptrace+ep ./w1tool

# Or run as root
sudo ./w1tool cover -L ./w1cov_qbdipreload.so -s ./target
```

**No coverage generated:**
```bash
# Enable debug mode
./w1tool cover -L ./w1cov_qbdipreload.* -s ./target --debug
```

**System library noise:**
```bash
# Exclude system libraries
./w1tool cover -L ./w1cov_qbdipreload.* -s ./target --exclude-system
```

**Windows spawn mode fails:**
```bash
# Error: technique_not_supported
# Solution: Use runtime injection instead
start /B target.exe
./w1tool.exe cover -L ./w1cov_qbdipreload.dll --name target.exe
```

### Debug Information
```bash
# Verbose logging
./w1tool -vv cover -L ./w1cov_qbdipreload.* -s ./target

# Check environment
env | grep W1COV

# Verify library
file ./w1cov_qbdipreload.*
```