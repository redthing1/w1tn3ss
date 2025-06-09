# tools

utility scripts for w1tn3ss development.

## macos-signing

code signing tools for injection on macos.

### files

- `genkey.sh` - generates code signing certificate
- `sign.sh` - signs executables with debugger entitlements  
- `entitlement.xml` - debugger privilege entitlements

### setup

generate certificate:
```sh
./tools/macos-signing/genkey.sh "w1tn3ss-dev"
```

sign w1tool:
```sh
./tools/macos-signing/sign.sh "w1tn3ss-dev" ./build-macos/w1tool
```

### notes

- certificate install requires sudo
- signing needed after each build
- required for injection on macos
- development only - not for distribution