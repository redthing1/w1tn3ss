# p1ll Python bindings (nanobind)

This document describes the optional Python bindings for the p1ll engine. The bindings expose scanning, memory region enumeration, and patch application without enabling the scripting engines.

## Build and import

Create a venv, configure CMake with `-DWITNESS_PYTHON=ON`, and build the `p1ll_python` target:

```sh
python3 -m venv .venv-p1ll
source .venv-p1ll/bin/activate
python -m pip install --upgrade pip
cmake -G Ninja -B build-release \
  -DCMAKE_BUILD_TYPE=Release \
  -DWITNESS_SCRIPT=OFF \
  -DWITNESS_PYTHON=ON \
  -DPython_EXECUTABLE="$VIRTUAL_ENV/bin/python"
cmake --build build-release --target p1ll_python
```

Import the module from the build tree:

```sh
PYTHONPATH=build-release/python "$VIRTUAL_ENV/bin/python" -c "import p1ll; print(p1ll.has_scripting_support())"
```

## Sample scripts

Sample scripts live under `scripts/python` and accept CLI arguments so they mirror the p1ll workflows in `README.md`.

If you do not already have the sample binary, build it first:

```sh
cmake --build build-release --target simple_demo
```

Scan a file for a text signature:

```sh
PYTHONPATH=build-release/python "$VIRTUAL_ENV/bin/python" scripts/python/p1ll_scan.py \
  --input build-release/samples/programs/simple_demo \
  --pattern-text "hello world"
```

Patch a file on disk using a text-to-hex patch (writes an output copy):

```sh
PYTHONPATH=build-release/python "$VIRTUAL_ENV/bin/python" scripts/python/p1ll_patch.py \
  --input build-release/samples/programs/simple_demo \
  --output /tmp/simple_demo.patched \
  --pattern-text "hello world" \
  --patch-text "hello there" \
  --single --show-bytes
```

List regions from the current process:

```sh
PYTHONPATH=build-release/python "$VIRTUAL_ENV/bin/python" scripts/python/p1ll_regions.py --limit 5
```

## Wheel build (optional)

Use the pyproject under `src/p1ll/bindings/python` to build a wheel:

```sh
cd src/p1ll/bindings/python
"$VIRTUAL_ENV/bin/python" -m pip install --upgrade scikit-build-core build
"$VIRTUAL_ENV/bin/python" -m build --wheel
```

Install the resulting wheel in a fresh venv and rerun the scripts to confirm.

## Error handling

Most operations raise `p1ll.EngineError` when a p1ll status is not ok. The exception includes a `code` attribute (the engine error code) and a `message` attribute for the human-readable error string.
