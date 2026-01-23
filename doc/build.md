
# build guide

a guide to building on all platforms.

## common

initialize submodules:
```sh
git submodule update --init --recursive
```

common options:
```sh
-DWITNESS_SCRIPT=ON
-DWITNESS_SCRIPT_ENGINE=js # js/lua
-DWITNESS_LIEF=ON
-DWITNESS_ASMR=ON
```

zstd:
```sh
-DW1_REQUIRE_ZSTD=ON
```

## linux

```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON -DWITNESS_ASMR=ON -DWITNESS_SCRIPT_ENGINE=js
cmake --build build-release --parallel
```

## macos

```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON -DWITNESS_ASMR=ON -DWITNESS_SCRIPT_ENGINE=js
cmake --build build-release --parallel
```

## windows

```powershell
$vcpkg = $Env:VCPKG_ROOT
$toolchain = "$vcpkg/scripts/buildsystems/vcpkg.cmake"
```

### windows x64

```powershell
$triplet = "x64-windows-static"
$zstd = "$vcpkg/installed/$triplet/share/zstd"
python .\tools\windows\run_cmd.py --arch x64 -- cmake -G Ninja -B build-release `
  -DCMAKE_BUILD_TYPE=Release `
  -DWITNESS_SCRIPT=ON `
  -DWITNESS_LIEF=ON `
  -DWITNESS_ASMR=ON `
  -DWITNESS_SCRIPT_ENGINE=js `
  -DW1_REQUIRE_ZSTD=ON `
  -DCMAKE_TOOLCHAIN_FILE=$toolchain `
  -DVCPKG_TARGET_TRIPLET=$triplet `
  -Dzstd_DIR=$zstd
python .\tools\windows\run_cmd.py --arch x64 -- cmake --build build-release --parallel
```

### windows x86

```powershell
$triplet = "x86-windows-static"
$zstd = "$vcpkg/installed/$triplet/share/zstd"
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake -G Ninja -B build-win32 `
  -DCMAKE_BUILD_TYPE=Release `
  -DWITNESS_ARCH=x86 `
  -DWITNESS_SCRIPT=ON `
  -DWITNESS_LIEF=ON `
  -DWITNESS_ASMR=ON `
  -DWITNESS_SCRIPT_ENGINE=js `
  -DW1_REQUIRE_ZSTD=ON `
  -DCMAKE_TOOLCHAIN_FILE=$toolchain `
  -DVCPKG_TARGET_TRIPLET=$triplet `
  -Dzstd_DIR=$zstd
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake --build build-win32 --parallel
```

### tests

```powershell
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- ctest --test-dir build-win32 --output-on-failure
```

### lldb tests

```powershell
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 `
  --env "LLDB_PATH=C:\Program Files\LLVM\bin\lldb.exe" `
  --prepend-path "C:\Program Files\LLVM\bin;C:\Path\To\Python\Python310" `
  -- ctest -R lldb --test-dir build-win32 --output-on-failure
```

### tips

- use `tools/windows/run_cmd.py` for cmake/ctest in the dev shell
- if using `--prepend-path`, pass a single value with `;` separators
- lldb tests need `LLDB_PATH` and may depend on a python dll they were built against (e.g. `python310.dll`). if it fails with missing `python310.dll`, install and prepend to `PATH`

## tests

```sh
ctest --test-dir build-release --output-on-failure
```

## packaging

build a zip from install rules:
```sh
cpack --config build-release\CPackConfig.cmake
```
