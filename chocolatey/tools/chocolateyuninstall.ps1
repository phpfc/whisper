$ErrorActionPreference = 'Stop'

$packageName = 't-chat'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Remove the executable
$exePath = Join-Path $toolsDir 't-chat.exe'
if (Test-Path $exePath) {
  Remove-Item $exePath -Force
}
