# p1ll python bindings

## build

```sh
cmake -G Ninja -S src/p1ll/bindings/python -B build-p1ll-python -DCMAKE_BUILD_TYPE=Release -DPython_EXECUTABLE="$VIRTUAL_ENV/bin/python"
cmake --build build-p1ll-python
PYTHONPATH=build-p1ll-python "$VIRTUAL_ENV/bin/python" -c "import p1ll; print(p1ll.has_scripting_support())"
```

# git install

```sh
python -m pip install "git+https://github.com/redthing1/w1tn3ss.git@<ref>#subdirectory=src/p1ll/bindings/python"
```
