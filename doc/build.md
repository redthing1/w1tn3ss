
# build guide

a guide to building on all platforms.

## common

initialize submodules:
```sh
git submodule update --init --recursive
```

## linux

```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON
cmake --build build-release --parallel
```

## macos

```sh
cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON
cmake --build build-release --parallel
```

## windows (x64)

```powershell
python .\tools\windows\run_cmd.py --arch x64 -- cmake -G Ninja -B build-release -DCMAKE_BUILD_TYPE=Release -DWITNESS_SCRIPT=ON
python .\tools\windows\run_cmd.py --arch x64 -- cmake --build build-release --parallel
```

## windows (x86)

```powershell
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake -G Ninja -B build-win32 -DCMAKE_BUILD_TYPE=Release -DWITNESS_ARCH=x86 -DWITNESS_SCRIPT=ON
python .\tools\windows\run_cmd.py --arch x86 --host-arch amd64 -- cmake --build build-win32 --parallel
```

## tests

```sh
ctest --test-dir build-release --output-on-failure
```
