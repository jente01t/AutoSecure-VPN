# AutoSecureVPN Function Reference

This document provides a detailed list of functions available in the AutoSecureVPN module, categorized by their respective components.

## Core Component (`Core.ps1`)

Foundational utility functions used across the entire module.

- **`Show-Menu`**: Displays interactive menus, success messages, or error boxes.
- **`Wait-Input`**: Pauses execution and waits for user confirmation.
- **`Test-IsAdmin`**: Checks if the current PowerShell session has Administrator privileges.
- **`Write-Log`**: Handles logging to both the console and the log file.
- **`Set-Firewall`**: Helper function to configure Windows Firewall rules.
- **`Set-ModuleSettings`**: Initializes module settings from configuration files.

---

## OpenVPN Component (`OpenVPN.ps1`)

Functions dedicated to OpenVPN server and client management.

- **`Install-OpenVPN`**: Downloads and installs the OpenVPN MSI.
- **`Initialize-EasyRSA`**: Downloads and prepares the EasyRSA environment.
- **`Initialize-Certificates`**: Generates CA, Server, and DH parameters using EasyRSA.
- **`New-ServerConfig`**: Generates the `server.ovpn` configuration file.
- **`Start-VPNService`**: Manages the OpenVPN Windows service.
- **`New-ClientPackage`**: Generates client certificates and packages them into a ZIP/OVPN file.
- **`Import-ClientConfiguration`**: Expands and imports a client configuration package.
- **`Test-TAPAdapter`**: Checks for the presence of the OpenVPN TAP adapter.
- **`Start-VPNConnection`**: Initiates a VPN connection using the OpenVPN GUI.
- **`Test-VPNConnection`**: Verifies connectivity through the VPN tunnel.
- **`Install-RemoteServer`**: Orchestrates a full OpenVPN server deployment on a remote machine.
- **`Install-RemoteClient`**: Orchestrates an OpenVPN client setup on a remote machine.
- **`Invoke-BatchRemoteClientInstall`**: Parallel deployment of OpenVPN clients to multiple machines.

---

## WireGuard Component (`WireGuard.ps1`)

Functions for modern, high-performance WireGuard VPN management.

- **`Install-WireGuard`**: Downloads and installs WireGuard for Windows.
- **`Initialize-WireGuardKeys`**: Generates public/private key pairs using `wg.exe`.
- **`New-WireGuardServerConfig`**: Creates the `wg0.conf` server configuration.
- **`New-WireGuardClientConfig`**: Creates client configuration files.
- **`Start-WireGuardService`**: Installs and starts the WireGuard tunnel service.
- **`Stop-WireGuardService`**: Stops and removes WireGuard tunnel services.
- **`New-WireGuardQRCode`**: Generates a QR code for easy mobile client configuration.
- **`Install-RemoteWireGuardServer`**: Remote deployment of a WireGuard server.
- **`Install-RemoteWireGuardClient`**: Remote deployment of a WireGuard client.
