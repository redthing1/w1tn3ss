# tools

utilities for working with w1tn3ss.

## macos_signing

code signing tools for injection on macos.

### files

- `genkey.sh` - generates code signing certificate
- `sign.sh` - signs executables with debugger entitlements  
- `entitlement.xml` - debugger privilege entitlements

### setup

generate certificate:
```sh
./tools/macos_signing/genkey.sh "w1tn3ss-dev"
```

sign w1tool:
```sh
./tools/macos_signing/sign.sh "w1tn3ss-dev" ./build-macos/w1tool
```

### notes

- installing the certificate requires sudo
- each build of the binary must be signed with the entitlements
- you can't inject as a non-root user on macos without the `com.apple.security.cs.debugger` entitlement
