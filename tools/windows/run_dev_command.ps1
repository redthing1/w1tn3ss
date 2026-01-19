param(
  [string]$Command = "",
  [string]$Program = "",
  [object[]]$ProgramArgs = @(),
  [string]$VsPath = "",
  [string]$DevCmdArgs = "-arch=amd64",
  [switch]$UseCmd  # when set, run through cmd /c (default); otherwise Invoke-Expression in PowerShell
)

# Helper: enter a VS dev shell (MSVC) then run an arbitrary command. Nothing is hardcoded; VS is discovered via
# vswhere when not provided. Example:
#   powershell -ExecutionPolicy Bypass -File scripts/windows/run_dev_command.ps1 `
#     -Command "cmake --build build-windows-msvc --parallel"

function Resolve-VsPath {
  param([string]$Override)
  if ($Override -and (Test-Path $Override)) {
    return $Override
  }
  $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found and no VsPath provided. Install VS or supply -VsPath."
    exit 1
  }
  $path = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
  if (-not $path) {
    Write-Error "Unable to locate a Visual Studio installation via vswhere."
    exit 1
  }
  return $path.Trim()
}

$vsRoot = Resolve-VsPath -Override $VsPath
$devShellDll = Join-Path $vsRoot "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
if (-not (Test-Path $devShellDll)) {
  Write-Error "DevShell DLL not found at $devShellDll. Provide a valid -VsPath."
  exit 1
}

Import-Module $devShellDll
Enter-VsDevShell -VsInstallPath $vsRoot -SkipAutomaticLocation -DevCmdArguments $DevCmdArgs

if ($Command -and $Command.Trim() -ne "") {
  if ($UseCmd.IsPresent) {
    & cmd.exe /c $Command
  } else {
    Invoke-Expression $Command
  }
  exit $LASTEXITCODE
}

if ($Program -and $Program.Trim() -ne "") {
  & $Program @ProgramArgs
  exit $LASTEXITCODE
}

Write-Host "MSVC dev environment initialized. PATH is updated. Supply -Command or -Program/-ProgramArgs to run a command."
