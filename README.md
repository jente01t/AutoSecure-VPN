# AutoSecure-VPN

A comprehensive PowerShell automation framework for **OpenVPN** and **WireGuard** VPN deployment on Windows. AutoSecure-VPN streamlines the entire VPN setup process, from installation to configuration, certificate management, and connection establishment—both locally and remotely.

---

## Table of Contents

1. [Project Purpose](#-project-purpose)
2. [Key Features](#-key-features)
3. [Requirements](#-requirements)
4. [Installation](#-installation)
5. [Configuration](#-configuration)
6. [Usage](#-usage)
7. [Project Architecture](#-project-architecture)
8. [Testing](#-testing)
9. [Sources & References](#-sources--references)
10. [License](#-license)

---

## 🎯 Project Purpose

**AutoSecure-VPN** is designed to automate the deployment and management of VPN infrastructure on Windows systems. The project addresses the following challenges:

- **Time-consuming manual setup**: Manually installing and configuring VPN servers and clients is error-prone and repetitive.
- **Multi-protocol support**: Organizations may need both OpenVPN (proven, widely supported) and WireGuard (modern, high-performance).
- **Remote deployment**: IT administrators need to deploy VPN infrastructure across multiple machines without physical access.
- **Batch operations**: Configuring dozens of clients individually is impractical; CSV-based batch deployment solves this.

### What Does It Do?

1. **Installs VPN Software**: Automatically downloads and installs the latest stable versions of OpenVPN or WireGuard.
2. **Generates Certificates & Keys**: Creates PKI infrastructure (CA, server/client certificates) for OpenVPN using EasyRSA, or generates WireGuard key pairs.
3. **Configures Servers & Clients**: Generates properly configured `.ovpn` or `.conf` files with all necessary settings.
4. **Manages Windows Services**: Starts, stops, and configures VPN services and firewall rules.
5. **Supports Remote Deployment**: Uses PowerShell Remoting to deploy to remote Windows machines.
6. **Batch Client Setup**: Reads client information from CSV files to deploy multiple clients in parallel.
7. **Generates QR Codes**: Creates QR codes for easy WireGuard mobile client configuration.

---

## 🚀 Key Features

| Feature | OpenVPN | WireGuard |
|---------|---------|-----------|
| Automated Installation | ✅ | ✅ |
| Certificate/Key Generation | ✅ (EasyRSA) | ✅ (wg.exe) |
| Server Configuration | ✅ | ✅ |
| Client Configuration | ✅ | ✅ |
| Remote Deployment | ✅ | ✅ |
| Batch Client Deployment | ✅ | ✅ |
| QR Code Generation | ❌ | ✅ |
| Service Management | ✅ | ✅ |
| Firewall Configuration | ✅ | ✅ |

### Additional Features

- **Interactive Console Menus**: User-friendly navigation through setup wizards.
- **Comprehensive Logging**: Detailed audit trails for troubleshooting in the `logs/` directory.
- **Modular Architecture**: Easy to extend with new protocols or features.
- **Configuration Files**: Separate stable defaults and user-variable settings.

---

## 📋 Requirements

### System Requirements

| Requirement | Minimum 
|-------------|---------
| Operating System | Windows 10 / Server 2016 
| PowerShell | 7.0 
| Privileges | Administrator
| Internet | Required 

### Software Dependencies

- **PowerShell 7.0+**: The module uses features specific to PowerShell 7 (e.g., `ForEach-Object -Parallel`).
- **Pester 5.x** (optional): Required only for running unit tests.

### Remote Deployment Requirements

For deploying to remote machines, ensure the following on target systems:

```powershell
# Enable PowerShell Remoting on target machine
Enable-PSRemoting -Force

# Set execution policy (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Verify WinRM service is running
Get-Service WinRM | Select-Object Status, StartType
```

Additionally:
- Network connectivity between management and target machines.
- Target machine inside private network or public with domain.
- Firewall rules allowing WinRM (TCP 5985/5986).
- Administrator credentials for remote systems.

WARNING: script uses Internet Connection Sharing (ICS), VPN wont have outisde connection when network adapter already in use. Dubble check if adapter is not already in use.

---

## 🔧 Installation

### Option 1: Install from PowerShell Gallery 

```powershell
# Install the module from PowerShell Gallery
Install-Module -Name AutoSecure-VPN 
```

### Option 2: Clone from Repository 

```powershell
# Clone the repository
git clone https://github.com/jente01t/AutoSecure-VPN.git

# Navigate to the project directory
cd AutoSecure-VPN
```



### Option 3: Manual Installation

1. Download the latest release ZIP from GitHub.
2. Extract to your PowerShell modules folder:
   ```powershell
   # User modules folder
   $env:USERPROFILE\Documents\PowerShell\Modules\AutoSecure-VPN\
   ```
3. Import the module:
   ```powershell
   Import-Module AutoSecure-VPN
   ```

### Verify Installation

```powershell
# Check if module is available
Get-Module -ListAvailable AutoSecure-VPN

# Import and verify
Import-Module AutoSecure-VPN
Get-Command -Module AutoSecure-VPN
```

---

## ⚙️ Configuration

The project uses **PowerShell Data Files (`.psd1`)** for configuration, split into two files:

### Configuration Files Overview

| File | Purpose | Should You Edit? |
|------|---------|------------------|
| `Stable.psd1` | System defaults, paths, installer URLs | Rarely |
| `Variable.psd1` | User-specific settings (IPs, ports, subnets) | **Yes** |

### Initial Setup

1. **Copy the example configuration files**:
   ```powershell
   cd src\module
   Copy-Item Stable.psd1.example Stable.psd1
   Copy-Item Variable.psd1.example Variable.psd1
   ```

2. **Edit `Variable.psd1`** with your environment-specific settings:
   ```powershell
   notepad Variable.psd1
   ```

### Variable.psd1 - Key Settings Explained

```powershell
@{
    # === Network Settings ===
    port          = 443              # VPN listening port
    protocol      = 'TCP'            # 'TCP' or 'UDP'
    vpnSubnet     = '10.8.0.0'       # VPN tunnel subnet
    vpnMask       = '255.255.255.0'  # VPN subnet mask
    dns1          = '8.8.8.8'        # Primary DNS for VPN clients
    dns2          = '8.8.4.4'        # Secondary DNS for VPN clients

    # === Server Configuration ===
    serverName    = 'vpn-server'     # Hostname/identifier for the server
    serverIP      = '192.168.1.10'   # LAN IP of the VPN server
    serverWanIP   = 'vpn.example.com' # Public IP or DDNS hostname
    lanSubnet     = '192.168.1.0'    # Network behind the VPN server
    lanMask       = '255.255.255.0'  # LAN subnet mask

    # === Client Configuration ===
    clientName    = 'client1'        # Default client name
    noPass        = $true            # Generate certificates without password

    # === WireGuard Specific ===
    wireGuardPort       = 51820      # WireGuard UDP port
    wireGuardBaseSubnet = '10.13.13' # WireGuard subnet (first 3 octets)
    wireGuardDefaultDns = '8.8.8.8'  # DNS for WireGuard clients

    # === Batch Deployment ===
    clientCSVPath = 'output\clients.csv'  # Path to CSV for batch deployment
}
```

### CSV Format for Batch Deployment

Create a CSV file with client information for batch deployment:

```csv
Name,IP,Username,Password
Client1,192.168.0.101,admin,SecurePass123
Client2,192.168.0.102,admin,SecurePass456
Client3,192.168.0.103,admin,SecurePass789
```

See [examples/clients.csv](examples/clients.csv) for a template.

---

## 🎯 Usage

### Starting the Application

```powershell
# Method 1: Import module and run
Import-Module AutoSecure-VPN
Start-VPNSetup

# Method 2: Direct execution (from repository)
.\src\module\AutoSecure-VPN.psm1
Start-VPNSetup
```

> ⚠️ **Important**: Always run PowerShell as Administrator for VPN setup operations.

### Main Menu Flow

```
┌─────────────────────────────────────────┐
│         AutoSecure-VPN Setup            │
├─────────────────────────────────────────┤
│  [1] Server Setup                       │
│  [2] Client Setup                       │
│  [Q] Quit                               │
└─────────────────────────────────────────┘
```

### Server Setup Workflow

1. Select **Server Setup** from the main menu.
2. Choose deployment target:
   - **Local**: Install on the current machine.
   - **Remote**: Deploy to a remote Windows machine via PowerShell Remoting.
3. Select VPN protocol:
   - **OpenVPN**: Traditional, widely compatible (TCP/UDP).
   - **WireGuard**: Modern, high-performance (UDP only).
4. The wizard will:
   - Install the VPN software.
   - Generate certificates/keys.
   - Create server configuration.
   - Configure Windows Firewall.
   - Start the VPN service.

### Client Setup Workflow

1. Select **Client Setup** from the main menu.
2. Choose deployment mode:
   - **Local**: Configure the current machine as a VPN client.
   - **Remote**: Deploy client configuration to a remote machine.
   - **Batch**: Deploy to multiple machines using a CSV file.
3. Select VPN protocol (must match server).
4. The wizard will:
   - Install client software.
   - Import or generate client configuration.
   - Establish VPN connection.
   - Verify connectivity.

### Example: Complete Server + Client Setup

```powershell
# Step 1: Configure your settings
cd AutoSecure-VPN
notepad src\module\Variable.psd1

# Step 2: Start the setup wizard
Import-Module .\src\module\AutoSecure-VPN.psd1
Start-VPNSetup

# Step 3: Follow the interactive menus
# - Select "Server Setup" → "Local" → "WireGuard"
# - After server setup, select "Client Setup" → "Local" → "WireGuard"
```

### Command-Line Functions

For advanced users, you can call functions directly:

```powershell
# Import the module
Import-Module AutoSecure-VPN

# Server mode selection
Select-ServerMode

# Client mode selection  
Select-ClientMode
```

---

## 🏗️ Project Architecture

This section provides technical details for developers who need to maintain or extend the project.

### Directory Structure

```
AutoSecure-VPN/
├── examples/                       # Example files
│   ├── client.ovpn                 # Sample OpenVPN 
│   └── clients.csv                 # Sample CSV for batch deployment
├── logs/                           # Runtime log files
├── output/                         # Generated configurations
│   ├── *.zip                       # OpenVPN client configs
│   ├── *.conf                      # WireGuard configs
│   └── *.png                       # QR codes for WireGuard
├── src/
│   ├── config/                     # Configuration files
│   │   ├── Stable.psd1             # System defaults
│   │   ├── Stable.psd1.example     # Template for Stable.psd1
│   │   ├── Variable.psd1           # User settings
│   │   └── Variable.psd1.example   # Template for Variable.psd1
│   └── module/                     # PowerShell module
│       ├── AutoSecure-VPN.psd1     # Module manifest
│       └── AutoSecure-VPN.psm1     # Module implementation
├── tests/                          # Pester test files
│   ├── AutoSecure-VPN.Tests.ps1    # Main test suite
│   └── Manual/
│       └── Integration.Tests.ps1   # Manual integration tests
├── publish.ps1                     # Script to publish to PSGallery
└── README.md                       # This file
```

### Module Architecture

The module (`AutoSecure-VPN.psm1`) follows a **single-file module pattern** with logical regions:

```
┌──────────────────────────────────────────────────────────────┐
│                    AutoSecure-VPN.psm1                       │
├──────────────────────────────────────────────────────────────┤
│  #region Module Header                                       │
│    - Module metadata and requirements                        │
│    - Base path initialization                                │
│                                                              │
│  #region Core / Menu System                                  │
│    - Start-VPNSetup     (Main entry point)                   │
│    - Select-ServerMode  (Server setup wizard)                │
│    - Select-ClientMode  (Client setup wizard)                │
│    - Select-VPNProtocol (Protocol selection)                 │
│    - Show-Menu          (UI rendering)                       │
│                                                              │
│  #region OpenVPN Setup Orchestration                         │
│    - Invoke-OpenVPNClientSetup                               │
│    - Invoke-RemoteOpenVPNClientSetup                         │
│    - Invoke-OpenVPNServerSetup                               │
│    - Invoke-RemoteOpenVPNServerSetup                         │
│    - Invoke-BatchRemoteClientSetup                           │
│                                                              │
│  #region WireGuard Setup Orchestration                       │
│    - Invoke-WireGuardClientSetup                             │
│    - Invoke-WireGuardServerSetup                             │
│    - Invoke-RemoteWireGuardServerSetup                       │
│    - Invoke-RemoteWireGuardClientSetup                       │
│                                                              │
│  #region Module Initialization & Configuration Loading       │
│    - Loading of Stable.psd1 and Variable.psd1                │
│                                                              │
│  #region Helper Functions & Utilities                        │
│    - Write-Log          (Logging)                            │
│    - Test-IsAdmin       (Privilege check)                    │
│    - Set-Firewall       (Firewall management)                │
│    - Enable-VPNNAT      (NAT configuration)                  │
│    - Enable-IPForwarding (IP forwarding)                     │
│    - Invoke-Rollback    (Rollback on failure)                │
│                                                              │
│  #region OpenVPN Implementation Details                      │
│    - Install-OpenVPN                                         │
│    - Initialize-EasyRSA                                      │
│    - Initialize-Certificates                                 │
│    - New-ServerConfig                                        │
│    - New-ClientPackage                                       │
│    - Install-RemoteServer                                    │
│    - Install-RemoteClient                                    │
│    - Invoke-BatchRemoteClientInstall                         │
│                                                              │
│  #region WireGuard Implementation Details                    │
│    - Install-WireGuard                                       │
│    - Initialize-WireGuardKeys                                │
│    - New-WireGuardServerConfig                               │
│    - New-WireGuardClientConfig                               │
│    - New-WireGuardQRCode                                     │
│    - Install-RemoteWireGuardServer                           │
│    - Install-RemoteWireGuardClient                           │
│    - Invoke-BatchRemoteWireGuardClientInstall                │
└──────────────────────────────────────────────────────────────┘
```

### Function Reference

This section lists all functions in the module, grouped by region, with brief descriptions.

#### Core / Menu System
- **`Start-VPNSetup`**: Main entry point that displays the initial menu for server or client setup.
- **`Select-ServerMode`**: Displays menu for server setup options (local or remote).
- **`Select-ClientMode`**: Displays menu for client setup options (local, remote, or batch).
- **`Select-VPNProtocol`**: Prompts user to choose between OpenVPN and WireGuard.
- **`Show-Menu`**: Displays interactive menus, success messages, or error messages.
- **`Wait-Input`**: Pauses execution and waits for user input to continue.

#### OpenVPN Setup Orchestration
- **`Invoke-OpenVPNClientSetup`**: Orchestrates local OpenVPN client installation and configuration.
- **`Invoke-RemoteOpenVPNClientSetup`**: Orchestrates remote OpenVPN client installation via PowerShell Remoting.
- **`Invoke-OpenVPNServerSetup`**: Orchestrates local OpenVPN server installation and configuration.
- **`Invoke-RemoteOpenVPNServerSetup`**: Orchestrates remote OpenVPN server installation via PowerShell Remoting.
- **`Invoke-BatchRemoteClientSetup`**: Performs batch remote OpenVPN client setup for multiple machines.

#### WireGuard Setup Orchestration
- **`Invoke-WireGuardClientSetup`**: Orchestrates local WireGuard client installation and configuration.
- **`Invoke-WireGuardServerSetup`**: Orchestrates local WireGuard server installation and configuration.
- **`Invoke-RemoteWireGuardServerSetup`**: Orchestrates remote WireGuard server installation via PowerShell Remoting.
- **`Invoke-RemoteWireGuardClientSetup`**: Orchestrates remote WireGuard client installation via PowerShell Remoting.

#### Helper Functions & Utilities
- **`Set-ModuleSettings`**: Initializes module settings from configuration files.
- **`Test-IsAdmin`**: Checks if the current PowerShell session has Administrator privileges.
- **`Write-Log`**: Handles logging to console and log file.
- **`Set-Firewall`**: Configures Windows Firewall rules for VPN ports.
- **`Enable-VPNNAT`**: Enables NAT for VPN subnet using Internet Connection Sharing.
- **`Enable-IPForwarding`**: Enables IP forwarding on the system.
- **`Invoke-Rollback`**: Attempts to rollback changes in case of setup failure.

#### OpenVPN Implementation Details
- **`Install-RemoteServer`**: Installs and configures OpenVPN server on a remote machine.
- **`Install-OpenVPN`**: Downloads and installs OpenVPN MSI package.
- **`Get-ServerConfiguration`**: Retrieves server configuration details.
- **`Initialize-EasyRSA`**: Downloads and sets up EasyRSA for certificate management.
- **`Initialize-Certificates`**: Generates CA, server certificates, and DH parameters.
- **`New-ServerConfig`**: Creates the OpenVPN server configuration file.
- **`Start-VPNService`**: Starts the OpenVPN Windows service.
- **`New-ClientPackage`**: Generates client certificates and packages them into a ZIP file.
- **`Import-ClientConfiguration`**: Imports and extracts client configuration package.
- **`Test-TAPAdapter`**: Checks for the presence of the OpenVPN TAP adapter.
- **`Start-VPNConnection`**: Initiates VPN connection using OpenVPN GUI.
- **`Test-VPNConnection`**: Verifies connectivity through the VPN tunnel.
- **`Install-RemoteClient`**: Installs OpenVPN client on a remote machine.
- **`Invoke-BatchRemoteClientInstall`**: Deploys OpenVPN clients to multiple remote machines in parallel.

#### WireGuard Implementation Details
- **`Install-WireGuard`**: Downloads and installs WireGuard for Windows.
- **`Initialize-WireGuardKeys`**: Generates public/private key pairs using wg.exe.
- **`New-WireGuardServerConfig`**: Creates the WireGuard server configuration file.
- **`New-WireGuardClientConfig`**: Creates WireGuard client configuration files.
- **`Start-WireGuardService`**: Installs and starts the WireGuard tunnel service.
- **`Stop-WireGuardService`**: Stops and removes WireGuard tunnel services.
- **`New-WireGuardQRCode`**: Generates QR code for mobile WireGuard client configuration.
- **`Install-RemoteWireGuardServer`**: Deploys WireGuard server to a remote machine.
- **`Install-RemoteWireGuardClient`**: Deploys WireGuard client to a remote machine.
- **`Invoke-BatchRemoteWireGuardClientInstall`**: Batch deploys WireGuard clients to multiple machines.

### Key Design Decisions

1. **Single PSM1 File**: All functions are in one file for easier distribution and installation via PowerShell Gallery.

2. **Script-Scoped Variables**: Configuration is stored in `$Script:Settings` to share state across functions without global pollution.

3. **Separation of Concerns**:
   - **Core functions**: Reusable utilities (logging, UI, firewall).
   - **Protocol functions**: OpenVPN and WireGuard specific implementations.
   - **Orchestration functions**: User-facing wizards that tie everything together.

4. **Configuration Layering**: `Stable.psd1` provides defaults; `Variable.psd1` overrides them. This allows updates without losing user settings.

5. **Remote Execution**: Uses `Invoke-Command` with script blocks for remote deployment, copying necessary files via PowerShell Remoting.

### Extending the Module

#### Adding a New VPN Protocol

1. Create functions following the naming convention: `Install-NewProtocol`, `New-NewProtocolServerConfig`, etc.
2. Add them to the appropriate region in `AutoSecure-VPN.psm1`.
3. Update `Select-ServerMode` and `Select-ClientMode` to include the new protocol option.
4. Export new public functions in `AutoSecure-VPN.psd1`.

#### Adding a New Feature

1. Determine if it's a core utility or protocol-specific.
2. Add the function to the appropriate region.
3. Use `$Script:Settings` for any configurable values.
4. Add corresponding settings to the `.psd1.example` files.
5. Write Pester tests in the `tests/` directory.

---

## 🧪 Testing

The project uses **Pester 5.x** for unit and integration testing.

### Running Tests

```powershell
# Run all tests
Invoke-Pester -Path .\tests\

# Run with detailed output
Invoke-Pester -Path .\tests\ -Output Detailed

# Run specific test file
Invoke-Pester -Path .\tests\AutoSecure-VPN.Tests.ps1

# Run with code coverage
Invoke-Pester -Path .\tests\ -CodeCoverage .\src\module\AutoSecure-VPN.psm1
```

### Test Structure

```
tests/
├── AutoSecure-VPN.Tests.ps1     # Automated unit tests
└── Manual/
    └── Integration.Tests.ps1    # Manual integration tests (require VPN infrastructure)
```

## 📚 Sources & References

### Official Documentation

- [OpenVPN Documentation](https://openvpn.net/community-resources/) - Official OpenVPN community resources and guides.
- [WireGuard Documentation](https://www.wireguard.com/quickstart/) - Official WireGuard quick start and protocol documentation.
- [EasyRSA Documentation](https://easy-rsa.readthedocs.io/) - Certificate authority management for OpenVPN.
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/) - Microsoft's official PowerShell documentation.
- [Pester Documentation](https://pester.dev/docs/quick-start) - Testing framework documentation.
- [PowerShell Gallery Publishing](https://docs.microsoft.com/en-us/powershell/scripting/gallery/how-to/publishing-packages/publishing-a-package) - Guide for publishing modules.

### Course Materials

- PowerShell course materials espcially: Parameters en validatie, Modules, Remoting, Ouput, Logging and hyperthreading.
- PluralSight: "Extending Windows PowerShell " courses.
- 

### AI-Assisted Development

The following AI tools were used during development:

- **GitHub Copilot**: Code completion, function comments, inline comments and suggestions for PowerShell functions.
- **Chats from Copilot**: can be found in the file AI-Prompts.txt.
- **ChatGPT** Chats: 
  - https://chatgpt.com/share/69542015-0b20-800b-9a95-6b9c259d29b5 
  - https://chatgpt.com/share/69542067-6aa0-800b-96d8-74f799eacdb5 
  - https://chatgpt.com/share/6954235d-b5ac-800b-8636-4d9ce09bd104

### Code References

- Reference for silent installation parameters: https://github.com/OpenVPN/openvpn
- Reference for `wg.exe` key generation: https://git.zx2c4.com/wireguard-windows/
- Inspiration for QR code generation approach: https://github.com/codebude/QRCoder


- Aircraft. (2020, 9 november). How can I enable packet forwarding on Windows? Server Fault. https://serverfault.com/questions/929081/how-can-i-enable-packet-forwarding-on-windows 


- AivanF. (2020, 12 maart). Cannot setup WireGuard VPN. Server Fault. https://serverfault.com/questions/1006595/cannot-setup-wireguard-vpn 

- Bodnar, J. (z.d.). PowerShell Get-NetRoute. https://zetcode.com/powershell/get-netroute/ 

- Brehm, A. J. (2016, 9 september). Internet Connection Sharing stopped working after Windows 10 Anniversary Update. Super User. https://superuser.com/questions/1110866/internet-connection-sharing-stopped-working-after-windows-10-anniversary-update 

- Cartier, M. (2011, 12 maart). Validating IPv4 addresses with regexp. Stack Overflow. https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp 

- Chuchuva, P. (2021, 12 januari). How to enable execution of PowerShell scripts? Super User. https://superuser.com/questions/106360/how-to-enable-execution-of-powershell-scripts 

- CodeAndKeep.Com. (z.d.). Check if you are running as Administrator. https://codeandkeep.com/Check-If-Running-As-Admin/ 

- Commands, P. (2024, 6 juli). Convert to secure String PowerShell: A quick guide. Powershell Commands. https://powershellcommands.com/convert-to-secure-string-powershell 

- Dotnet-Bot. (z.d.-a). Environment.GetFolderPath Method (System). Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.environment.getfolderpath?view=net-9.0 

- Dotnet-Bot. (z.d.-b). Path.GetFileNameWithoutExtension Method (System.IO). Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.io.path.getfilenamewithoutextension?view=net-9.0 

- Dotnet-Bot. (z.d.-c). Path.GetTempFileName Method (System.IO). Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.io.path.gettempfilename?view=net-9.0 

- Dotnet-Bot. (z.d.-d). ZipFile.ExtractToDirectory Method (System.IO.Compression). Microsoft Learn. https://learn.microsoft.com/en-us/dotnet/api/system.io.compression.zipfile.extracttodirectory?view=net-9.0 

- Dsf3g. (2015, 27 december). Spruce Up Your Scripts With Menus and Color: Part III. Davespowershellblog. https://davespowershellblog.wordpress.com/2015/12/27/spruce-up-your-scripts-with-menus-and-color-part-iii/

- Error with .ovpnf file on router: cipher set to ‘AES-256-CBC’ but missing in --data-ciphers (AES-256-GCM:AES-128-GCM) - OpenVPN Support Forum. (z.d.). https://forums.openvpn.net/viewtopic.php?t=33536

- Exception messages. (2018, 26 maart). PowerShell Forums. https://forums.powershell.org/t/exception-messages/10391 
 
- (Get-CimInstance Win32_ComputerSystem).UserName doesn’t return a value. Why???? (z.d.). reddit.com. https://www.reddit.com/r/PowerShell/comments/pjy53m/getciminstance_win32_computersystemusername/ 
 
- Get-Date - PowerShell Command | PDQ. (z.d.). https://www.pdq.com/powershell/get-date/ 
 
- How to schedule tasks using PowerShell | PDQ. (z.d.). https://www.pdq.com/blog/scheduled-tasks-in-powershell/ 
 
- Howell, A. (z.d.). Learn to automate with PowerShell and Task Scheduler. SearchWindows Server. https://www.techtarget.com/searchwindowsserver/tutorial/Learn-how-to-create-a-scheduled-task-with-PowerShell 

- Internet Connection Sharing (ICS) stops working after reboot in Windows 10 | Windows OS Hub. (2024, 16 maart). Windows OS Hub. https://woshub.com/internet-connection-sharing-not-working-windows-reboot/ 

- Invoke-Command to run a Powershell script on a remote computer. (2021, 16 april). PowerShell Forums. https://forums.powershell.org/t/invoke-command-to-run-a-powershell-script-on-a-remote-computer/16268 

- Invoke-WebRequest - PowerShell Command | PDQ. (z.d.). https://www.pdq.com/powershell/invoke-webrequest/

- Kumar, S. (2022, 4 februari). Manage Network Adapter Settings via PowerShell. TechTutsOnline. https://www.techtutsonline.com/manage-network-adapter-settings-via-powershell/ 

- Micah. (z.d.). What does $script: do in PowerShell? Stack Overflow. https://stackoverflow.com/questions/4330346/what-does-script-do-in-powershell 

- Mkdahan. (2021, 12 december). Build a script to check-uncheck sharing boxes at Ethernet adapter. Stack Overflow. https://stackoverflow.com/questions/70321804/build-a-script-to-check-uncheck-sharing-boxes-at-ethernet-adapter 

- New-PSSessionOption - PowerShell - SS64.com. (z.d.). https://ss64.com/ps/new-pssessionoption.html 

- OpenVPN. (z.d.-a). easy-rsa/README.quickstart.md at master · OpenVPN/easy-rsa. GitHub. https://github.com/OpenVPN/easy-rsa/blob/master/README.quickstart.md 

- OpenVPN. (z.d.-b). openvpn/sample/sample-config-files/client.conf at master · OpenVPN/openvpn. GitHub. https://github.com/OpenVPN/openvpn/blob/master/sample/sample-config-files/client.conf 

- OpenVPN. (z.d.-c). openvpn/sample/sample-config-files/server.conf at master · OpenVPN/openvpn. GitHub. https://github.com/OpenVPN/openvpn/blob/master/sample/sample-config-files/server.conf 

- OpenVPN Configuration with Easy-RSA - Nitrokey Documentation. (z.d.). https://docs.nitrokey.com/nitrokeys/features/openpgp-card/openvpn/easyrsa 

- PowerShell Gallery | ExportedFunctions/Out-BarcodeImage.ps1 1.0.0.40. (z.d.). https://www.powershellgallery.com/packages/QrCodes/1.0.0.40/Content/ExportedFunctions%5COut-BarcodeImage.ps1 

- Reset ICS on Tap Adapter - OpenVPN Support Forum. (z.d.). https://forums.openvpn.net/viewtopic.php?f=15&t=32607 

- Robinharwood. (z.d.-a). Get-NetFireWallRule (NetSecurity). Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps 

- Robinharwood. (z.d.-b). Get-NetRoute (NetTCPIP). Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute?view=windowsserver2025-ps 

- Robinharwood. (z.d.-c). New-NetFirewallRule (NetSecurity). Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps 

- Sdwheeler. (z.d.-a). ConvertTo-Json (Microsoft.PowerShell.Utility) - PowerShell. Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-7.5 

- Sdwheeler. (z.d.-b). Import-PowerShellDataFile (Microsoft.PowerShell.Utility) - PowerShell. Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/import-powershelldatafile?view=powershell-7.5 

- Sdwheeler. (z.d.-c). Invoke-RestMethod (Microsoft.PowerShell.Utility) - PowerShell. Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod?view=powershell-7.5 

- Sdwheeler. (z.d.-d). Write-Progress (Microsoft.PowerShell.Utility) - PowerShell. Microsoft Learn. https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/write-progress?view=powershell-7.5 

- Seveves. (2013, 12 juli). How does Windows know which network adapter is a wireless device? Super User. https://superuser.com/questions/618908/how-does-windows-know-which-network-adapter-is-a-wireless-device 

- Shanbhag, P. (2017, 19 december). Powershell script to get number of Physical CPU’s. Stack Overflow. https://stackoverflow.com/questions/47880162/powershell-script-to-get-number-of-physical-cpus 

- Sv, L. (2021, 6 mei). Configure Windows Firewall Rules with PowerShell. Bobcares. https://bobcares.com/blog/configure-windows-firewall-rules-with-powershell/ 

- Test Network Connectivity with PowerShell Test-Connection (With Examples). (z.d.). petri.com. https://petri.com/powershell-test-connection-examples/ 

- User, C. (2025, 25 juli). How to add more than one machine to the trusted hosts list using winrm. Stack Overflow. https://stackoverflow.com/questions/21548566/how-to-add-more-than-one-machine-to-the-trusted-hosts-list-using-winrm 

- Vimes. (2014, 3 november). How can I create a registry value and path leading to it in one line using PowerShell? Stack Overflow. https://stackoverflow.com/questions/26719206/how-can-i-create-a-registry-value-and-path-leading-to-it-in-one-line-using-power 

- When creating a new session on PowerShell, how do I enter it? (z.d.). reddit.com. https://www.reddit.com/r/PowerShell/comments/rbjoha/when_creating_a_new_session_on_powershell_how_do/ 

- Where is the trusted host list stored. (z.d.). reddit.com. https://www.reddit.com/r/PowerShell/comments/908coz/where_is_the_trusted_host_list_stored/ 

- Zhou, D. (z.d.). Why doesn’t Get-NetFirewallRule show all information of the firewall rule? (like netsh). Stack Overflow. https://stackoverflow.com/questions/42110526/why-doesnt-get-netfirewallrule-show-all-information-of-the-firewall-rule-like



---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

