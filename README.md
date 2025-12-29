# AutoSecure-VPN

A comprehensive PowerShell automation framework for **OpenVPN** and **WireGuard** setup on Windows. AutoSecure-VPN streamlines the entire VPN deployment process, from installation to configuration, certificate management, and connection establishment.

## 🚀 Key Features

- **Dual Protocol Support**: Full automation for both OpenVPN and WireGuard.
- **Automated Installation**: Downloads and installs the latest stable versions of OpenVPN and WireGuard.
- **Certificate & Key Management**:
  - Automated EasyRSA integration for OpenVPN CA and certificates.
  - Native key generation for WireGuard using `wg.exe`.
- **Modern UI**: Interactive console menus with intuitive navigation.
- **Remote Deployment**: Deploy VPN infrastructure to remote Windows machines via PowerShell Remoting.
- **Batch Operations**: Configure multiple VPN clients simultaneously using CSV files.
- **Comprehensive Logging**: Detailed audit trails and troubleshooting logs.
- **QR Code Generation**: Easily configure mobile clients for WireGuard with generated QR codes.

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+.
- **PowerShell**: Version 7.0 or higher is recommended.
- **Administrator Rights**: Required for system-level configuration.
- **Internet Connection**: For downloading installers and updates.

### Remote Requirements
- PowerShell Remoting enabled on target machines (`Enable-PSRemoting`).
- Execution Policy set to Unrestricted on target machines.
- Administrator credentials for remote systems.
- Network connectivity to remote hosts.

## 🔧 Installation & Setup

1. **Clone the Repository**
   ```powershell
   git clone https://github.com/yourusername/AutoSecure-VPN.git
   cd AutoSecure-VPN
   ```

2. **Configure Settings**
   The project uses PSD1 files for configuration. Copy the templates and customize them:
   ```powershell
   # Move to config directory
   cd src/config
   Copy-Item Stable.psd1.example Stable.psd1
   Copy-Item Variable.psd1.example Variable.psd1
   ```

3. **Customize your VPN**
   Edit `src/config/Variable.psd1` with your server IP, desired ports, and subnets.

## 🎯 Usage

Launch PowerShell as Administrator and run the main entry point:
```powershell
.\src\scripts\main.ps1
```

### Main Flows
- **Server Setup**: Install and configure a VPN server (Optional: Local or Remote).
- **Client Setup**: Install and configure a VPN client (Optional: Local, Remote, or Batch).
- **Protocol Choice**: Choose between OpenVPN (TCP/UDP) or WireGuard (UDP).

## 📁 Documentation

For more detailed information, please refer to:

- [**Feature & Function Reference**](docs/FUNCTIONS.md): A complete list of all module functions.
- [**Developer Guide**](docs/DEVELOPER.md): Information on project structure, how to extend the framework, and testing.

## 🧪 Testing

We use the Pester testing framework. To run the test suite:
```powershell
Invoke-Pester -Path .\tests\
```

## � Security

- **Encryption**: Uses industry-standard encryption (AES-256 for OpenVPN, ChaCha20 for WireGuard).
- **Privilege Principle**: Always check for Admin rights before performing system modifications.
- **Credential Safety**: Remote deployments use `Get-Credential` to ensure password safety.



