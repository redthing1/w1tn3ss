param(
  [string]$Command = "",
  [string]$Program = "",
  [object[]]$ProgramArgs = @(),
  [string]$VsPath = "",
  [string]$DevCmdArgs = "-arch=amd64",
  [string[]]$Env = @(),
  [string[]]$PrependPath = @(),
  [string[]]$AppendPath = @(),
  [string]$WorkingDirectory = "",
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

function Apply-EnvPairs {
  param([string[]]$Pairs)
  foreach ($pair in $Pairs) {
    if ($pair -match '^(?<key>[^=]+)=(?<value>.*)$') {
      $key = $Matches['key']
      $value = $Matches['value']
      Set-Item -Path ("env:" + $key) -Value $value
    } else {
      Write-Error "Invalid env pair (expected KEY=VALUE): $pair"
      exit 1
    }
  }
}

function Update-Path {
  param(
    [string[]]$Prepend,
    [string[]]$Append
  )
  $prefix = @()
  foreach ($entry in $Prepend) {
    if ($entry -and $entry.Trim() -ne "") {
      $prefix += $entry
    }
  }
  $suffix = @()
  foreach ($entry in $Append) {
    if ($entry -and $entry.Trim() -ne "") {
      $suffix += $entry
    }
  }
  if ($prefix.Count -gt 0) {
    $env:PATH = ($prefix -join ";") + ";" + $env:PATH
  }
  if ($suffix.Count -gt 0) {
    $env:PATH = $env:PATH + ";" + ($suffix -join ";")
  }
}

$vsRoot = Resolve-VsPath -Override $VsPath
$devShellDll = Join-Path $vsRoot "Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
if (-not (Test-Path $devShellDll)) {
  Write-Error "DevShell DLL not found at $devShellDll. Provide a valid -VsPath."
  exit 1
}

Import-Module $devShellDll
Enter-VsDevShell -VsInstallPath $vsRoot -SkipAutomaticLocation -DevCmdArguments $DevCmdArgs

if ($Env.Count -gt 0) {
  Apply-EnvPairs -Pairs $Env
}
if ($PrependPath.Count -gt 0 -or $AppendPath.Count -gt 0) {
  Update-Path -Prepend $PrependPath -Append $AppendPath
}
if ($WorkingDirectory -and $WorkingDirectory.Trim() -ne "") {
  Set-Location -Path $WorkingDirectory
}

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
