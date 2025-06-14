# Coverage Tools

Dynamic binary coverage analysis using QBDI instrumentation with DrCov export format.

## Quick Start

### macOS
```bash
# Build
cmake -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release --parallel

# Coverage trace
./build-release/w1tool cover -L ./build-release/w1cov_qbdipreload.dylib -b ./target

# Analyze results  
./build-release/w1tool read-drcov --file target_coverage.drcov
```

### Linux
```bash
# Build
cmake -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --parallel

# Coverage trace
./build-linux/w1tool cover -L ./build-linux/w1cov_qbdipreload.so -b ./target

# Analyze results
./build-linux/w1tool read-drcov --file target_coverage.drcov
```

### Windows
```bash
# Build
cmake -B build-windows -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows --parallel

# Coverage trace
./build-windows/w1tool.exe cover -L ./build-windows/w1cov_qbdipreload.dll -b ./target.exe

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
- `-b, --binary <path>` - target binary

**Optional:**
- `-o, --output <path>` - output file (default: `{binary}_coverage.drcov`)
- `--exclude-system` - exclude system libraries from coverage
- `--debug` - enable verbose debug output
- `--format <format>` - output format (`drcov`, `text`)

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
# macOS
./w1tool cover -L ./w1cov_qbdipreload.dylib -b ./my_program

# Linux  
./w1tool cover -L ./w1cov_qbdipreload.so -b ./my_program

# Windows
./w1tool.exe cover -L ./w1cov_qbdipreload.dll -b ./my_program.exe
```

### Custom Output
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -b ./target -o my_coverage.drcov
```

### System Library Exclusion
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -b ./target --exclude-system
```

### Debug Mode
```bash
./w1tool cover -L ./w1cov_qbdipreload.dylib -b ./target --debug
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

# Windows (requires DLL injection setup)
set W1COV_ENABLED=1 && ./target.exe
```

## Platform Libraries

| Platform | Library Name | Injection Method |
|----------|--------------|------------------|
| macOS | `w1cov_qbdipreload.dylib` | `DYLD_INSERT_LIBRARIES` |
| Linux | `w1cov_qbdipreload.so` | `LD_PRELOAD` |
| Windows | `w1cov_qbdipreload.dll` | DLL injection |

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
./w1tool cover -L ./w1cov_qbdipreload.* -b ./tests/programs/simple_target
./w1tool cover -L ./w1cov_qbdipreload.* -b ./tests/programs/multi_threaded_target
./w1tool cover -L ./w1cov_qbdipreload.* -b ./tests/programs/control_flow_1
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
Flavor: w1cov

=== Summary ===
Total Modules: 3
Total Basic Blocks: 159
Total Coverage: 636 bytes

=== Module Coverage ===
ID  Blocks  Size        Base Address        Name
------------------------------------------------------------
0   9       36 bytes    0x18c5a8000         libdyld.dylib
1   59      236 bytes   0x18c1fc000         dyld
2   91      364 bytes   0x100ca4000         target
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
./w1tool cover -L $(pwd)/w1cov_qbdipreload.dylib -b ./target
```

**Permission denied (Linux):**
```bash
# Grant ptrace capability
sudo setcap cap_sys_ptrace+ep ./w1tool

# Or run as root
sudo ./w1tool cover -L ./w1cov_qbdipreload.so -b ./target
```

**No coverage generated:**
```bash
# Enable debug mode
./w1tool cover -L ./w1cov_qbdipreload.* -b ./target --debug
```

**System library noise:**
```bash
# Exclude system libraries
./w1tool cover -L ./w1cov_qbdipreload.* -b ./target --exclude-system
```

### Debug Information
```bash
# Verbose logging
./w1tool -vv cover -L ./w1cov_qbdipreload.* -b ./target

# Check environment
env | grep W1COV

# Verify library
file ./w1cov_qbdipreload.*
```