# AutoSecure-VPN Loader
# This file loads the split module files for development.

$devPath = Join-Path $PSScriptRoot "dev"

if (Test-Path $devPath) {
    . (Join-Path $devPath "core.ps1")
    . (Join-Path $devPath "openvpn.ps1")
    . (Join-Path $devPath "wireguard.ps1")
}
else {
    Write-Error "Development files not found in $devPath. This file is a loader for the development environment."
}
