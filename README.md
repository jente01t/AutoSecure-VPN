# AutoSecure-VPN

A comprehensive PowerShell automation tool for OpenVPN server and client setup on Windows. AutoSecure-VPN streamlines the entire VPN deployment process, from installation to configuration, certificate management, and connection establishment.

## 🚀 Features

- **Automated OpenVPN Installation**: Downloads and installs the latest stable OpenVPN version
- **Certificate Management**: Automated EasyRSA integration for CA and certificate generation
- **Server Setup**: Complete server configuration with firewall rules and routing
- **Client Setup**: Automated client configuration and VPN connection establishment
- **Remote Deployment**: Deploy VPN infrastructure to remote machines via PowerShell remoting
- **Batch Operations**: Configure multiple clients simultaneously from CSV files
- **Interactive Menus**: User-friendly console interface with clear options
- **Comprehensive Logging**: Detailed logs for troubleshooting and audit trails
- **Flexible Configuration**: Separate stable and variable configuration files

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or higher
- **Administrator Rights**: Required for installation and configuration
- **Internet Connection**: For downloading OpenVPN and EasyRSA installers

### For Remote Deployments
- PowerShell Remoting enabled on target machines
- Administrator credentials for remote systems
- Network connectivity to remote hosts
- TrustedHosts configured (or domain environment)

## 🔧 Installation

1. **Clone or Download the Repository**
   ```powershell
   git clone https://github.com/yourusername/AutoSecure-VPN.git
   cd AutoSecure-VPN
   ```

2. **Configure Settings**
   
   Copy the example configuration files and customize them:
   ```powershell
   Copy-Item src\config\Stable.psd1.example src\config\Stable.psd1
   Copy-Item src\config\Variable.psd1.example src\config\Variable.psd1
   ```

3. **Edit Configuration Files**
   
   Edit `src\config\Variable.psd1` with your specific settings:
   ```powershell
   @{
       # Server configuration
       serverName = 'vpn-server'           # VPN server name
       serverIP = 'your.server.ip.here'    # WAN IP or DDNS address
       lanSubnet = '192.168.1.0'           # LAN subnet behind VPN server
       lanMask = '255.255.255.0'           # LAN subnet mask
       
       # VPN network settings
       port = 443                          # OpenVPN port
       protocol = 'TCP'                    # Protocol (TCP/UDP)
       vpnSubnet = '10.8.0.0'              # VPN subnet
       vpnMask = '255.255.255.0'           # VPN subnet mask
       
       # DNS servers
       dns1 = '8.8.8.8'
       dns2 = '8.8.4.4'
       
       # Client configuration
       clientName = 'client1'              # Default client name
   }
   ```

## 🎯 Usage

### Running the Script

Launch PowerShell as Administrator and run:
```powershell
cd AutoSecure-VPN
.\src\scripts\main.ps1
```

### Main Menu Options

#### 1. Server Setup
- **Local Server Setup**: Install and configure OpenVPN server on the current machine
  - Installs OpenVPN and EasyRSA
  - Generates CA and server certificates
  - Creates server configuration file
  - Configures Windows Firewall rules
  - Enables IP routing
  - Starts OpenVPN service

- **Remote Server Setup**: Deploy OpenVPN server to a remote machine
  - Requires PowerShell remoting access
  - Performs all local setup steps remotely
  - Copies necessary files to remote system

#### 2. Client Setup
- **Local Client Setup**: Configure VPN client on the current machine
  - Installs OpenVPN client
  - Imports client certificate package (.ovpn file)
  - Establishes VPN connection
  - Tests connectivity

- **Remote Client Setup**: Deploy VPN client to a remote machine
  - Automated remote installation
  - Transfers client package
  - Configures and starts VPN connection

- **Batch Remote Setup**: Deploy to multiple clients from CSV
  - Uses CSV file format: `ComputerName,ClientName`
  - Processes multiple clients sequentially
  - Generates detailed reports

### Certificate Management

Generate client certificates using the built-in functions:
```powershell
# Creates a new client certificate package
New-ClientPackage -ClientName "client1"
```

Output files are saved to the `output/` directory with `.ovpn` extension.

## 📁 Project Structure

```
AutoSecure-VPN/
├── src/
│   ├── config/
│   │   ├── Stable.psd1              # Stable configuration (rarely changes)
│   │   ├── Stable.psd1.example      # Template for stable config
│   │   ├── Variable.psd1            # Variable configuration (user-specific)
│   │   └── Variable.psd1.example    # Template for variable config
│   ├── module/
│   │   └── AutoSecureVPN.psm1       # Core PowerShell module with all functions
│   └── scripts/
│       └── main.ps1                 # Main entry point script
├── tests/
│   └── AutoSecureVPN.Tests.ps1      # Pester unit tests
├── logs/                             # Log files directory
│   ├── vpn-setup.log                # Main log file
│   └── transcript.log               # PowerShell transcript
├── output/                           # Generated client configurations
│   └── *.ovpn                       # Client configuration packages
└── README.md                         # This file
```

## 🔍 Configuration Files

### Stable.psd1
Contains configuration that rarely changes:
- OpenVPN installation paths
- EasyRSA settings
- Certificate parameters (key size, expiration)
- Default paths and logging settings

### Variable.psd1
Contains user-specific configuration:
- Server IP and network settings
- VPN subnet and ports
- DNS servers
- Client names
- Protocol preferences

## 🧪 Testing

The project includes comprehensive Pester tests:

```powershell
# Install Pester if needed
Install-Module -Name Pester -Force -SkipPublisherCheck

# Run all tests
Invoke-Pester .\tests\AutoSecureVPN.Tests.ps1

# Run tests with detailed output
Invoke-Pester .\tests\AutoSecureVPN.Tests.ps1 -Output Detailed
```

## 📝 Core Functions

### Server Functions
- `Install-OpenVPN`: Downloads and installs OpenVPN
- `Initialize-EasyRSA`: Sets up EasyRSA for certificate management
- `Initialize-Certificates`: Generates CA and server certificates
- `New-ServerConfig`: Creates server configuration file
- `Set-Firewall`: Configures Windows Firewall rules
- `Start-VPNService`: Starts the OpenVPN service
- `Install-RemoteServer`: Deploys server to remote machine

### Client Functions
- `New-ClientPackage`: Generates client certificate and .ovpn file
- `Import-ClientConfiguration`: Imports client configuration
- `Install-RemoteClient`: Deploys client to remote machine
- `Start-VPNConnection`: Establishes VPN connection
- `Test-VPNConnection`: Verifies VPN connectivity
- `Test-TAPAdapter`: Checks TAP adapter status

### Utility Functions
- `Show-Menu`: Interactive console menus
- `Write-Log`: Logging functionality
- `Test-IsAdmin`: Administrator privilege check
- `Get-ServerConfiguration`: Interactive server configuration wizard

## 🔐 Security Considerations

- **Administrator Rights**: Required for system modifications
- **Certificate Protection**: Store certificates securely
- **Private Keys**: Never share or expose private keys
- **Firewall Rules**: Automatically configured for security
- **Remote Access**: Use secure credentials for remote deployments
- **TrustedHosts**: Configure carefully, avoid using '*' in production

## 🐛 Troubleshooting

### Common Issues

**OpenVPN Service Won't Start**
- Check logs in `C:\Program Files\OpenVPN\log\`
- Verify firewall rules allow traffic on configured port
- Ensure certificates are valid and not expired

**Remote Deployment Fails**
- Verify PowerShell Remoting is enabled: `Enable-PSRemoting -Force`
- Check TrustedHosts configuration: `Get-Item WSMan:\localhost\Client\TrustedHosts`
- Confirm network connectivity and credentials

**VPN Connection Fails**
- Verify TAP adapter is installed and enabled
- Check client configuration (.ovpn) has correct server IP
- Review logs: `logs\vpn-setup.log`
- Test server connectivity: `Test-NetConnection -ComputerName <server-ip> -Port <vpn-port>`

## 📊 Logging

All operations are logged to multiple locations:
- **Main Log**: `logs/vpn-setup.log` - Structured logging with timestamps
- **Transcript**: `logs/transcript.log` - Complete PowerShell session output
- **OpenVPN Logs**: `C:\Program Files\OpenVPN\log\` - OpenVPN service logs

Log levels: INFO, WARNING, ERROR, SUCCESS
