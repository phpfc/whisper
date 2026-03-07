$ErrorActionPreference = 'Stop'

$packageName = 'whisper'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Remove the executable
$exePath = Join-Path $toolsDir 'whisper.exe'
if (Test-Path $exePath) {
  Remove-Item $exePath -Force
}
