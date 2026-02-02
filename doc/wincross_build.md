# wincross build (linux host)

build w1tn3ss for windows on a linux host using the wincross toolchain.

## prerequisites

- docker
- `msvc-wine` buildtools image (e.g. `msvc-wine:buildtools-trim-v0.1.0`)
- a windows llvm prebuild (must include `clang-cl.exe`, `lld-link.exe`, `llvm-lib.exe`)
- submodules initialized (`git submodule update --init --recursive`)

## quick start

one-time init:

```sh
python3 scripts/windows/wincross.py init \
  --toolchain llvm=/path/to/llvm-prebuild:/opt/llvm-21:ro
```

configure + build:

```sh
python3 scripts/windows/wincross.py configure
python3 scripts/windows/wincross.py build
```

artifacts land in `.wincross/build-windows`.

## tests

```sh
python3 scripts/windows/wincross.py test
```

## config locations

- project defaults: `tools/wincross-config/wincross.toml`
- machine state: `.wincross/build_config.json`

notes:
- the toolchain mount name (`llvm`) and container path (`/opt/llvm-21`) must match
  `tools/wincross-config/wincross.toml`.
- vcpkg is enabled by default and installs `zstd` using the
  `x64-windows-wincross-static` triplet.

## useful overrides

```sh
python3 scripts/windows/wincross.py init --image msvc-wine:buildtools-trim-v0.1.0
python3 scripts/windows/wincross.py configure --cmake-args "-DWITNESS_BUILD_ALL=ON"
python3 scripts/windows/wincross.py shell
```
