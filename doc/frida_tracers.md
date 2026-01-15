
# frida tracers

this repo also contains some frida scripts which may be useful for tracing.
in general i find that frida often causes issues or weird behavior in applications, on windows, macos, and linux.
that's part of the reason `w1tn3ss` exists!

but here's how to use them:

```sh
uv tool run --from frida-tools python ./frida/stalk_drcov.py -v -s ./build-release/samples/programs/simple_demo
```

this assumes frida was installed via `uv tool install -U frida-tools` for the `frida` command.
