
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

## windows (x64)

```powershell
python .\tools\windows\run_cmd.py --arch x64 -- cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON -DWITNESS_ASMR=ON -DWITNESS_SCRIPT_ENGINE=js -DW1_REQUIRE_ZSTD=ON -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static -Dzstd_DIR=%VCPKG_ROOT%/installed/x64-windows-static/share/zstd
python .\tools\windows\run_cmd.py --arch x64 -- cmake --build build-release --parallel
```

## windows (x86)

```powershell
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake -G Ninja -B build-win32 -DCMAKE_BUILD_TYPE=Release -DWITNESS_ARCH=x86 -DWITNESS_SCRIPT=ON -DWITNESS_LIEF=ON -DWITNESS_ASMR=ON -DWITNESS_SCRIPT_ENGINE=js -DW1_REQUIRE_ZSTD=ON -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x86-windows-static -Dzstd_DIR=%VCPKG_ROOT%/installed/x86-windows-static/share/zstd
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake --build build-win32 --parallel
```

## tests

```sh
ctest --test-dir build-release --output-on-failure
```

```powershell
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- ctest --test-dir build-win32 --output-on-failure
```

## packaging

build a zip from install rules:
```sh
cpack --config build-release\CPackConfig.cmake
```
