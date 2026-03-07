$ErrorActionPreference = 'Stop'

$packageName = 'whisper'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"

# Version and URLs
$version = '0.1.0'
$url64 = "https://github.com/phpfc/whisper/releases/download/v$version/whisper-x86_64-pc-windows-msvc.zip"

# Checksum (update after building release)
$checksum64 = 'PLACEHOLDER_SHA256'
$checksumType64 = 'sha256'

$packageArgs = @{
  packageName    = $packageName
  unzipLocation  = $toolsDir
  url64bit       = $url64
  checksum64     = $checksum64
  checksumType64 = $checksumType64
}

Install-ChocolateyZipPackage @packageArgs
