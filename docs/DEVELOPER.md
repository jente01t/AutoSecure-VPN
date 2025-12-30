# Developer Guide

Welcome to the AutoSecureVPN developer guide. This document explains the internal structure of the project and how to contribute or extend its functionality.

## Project Structure

```text
AutoSecure-VPN/
├── docs/                      # Documentation and guides
│   ├── DEVELOPER.md           # Developer guidance (this file)
│   └── FUNCTIONS.md           # Function reference
├── logs/                      # Log files and transcripts
├── output/                    # Generated VPN client configurations (.ovpn, .conf, .png)
├── src/
│   ├── config/                # PSD1 configuration files
│   │   ├── Stable.psd1        # Global defaults and installer URLs
│   │   └── Variable.psd1      # User-specific overrides (IPs, Ports)
│   ├── module/                # Core logic broken into components
│   │   ├── AutoSecureVPN.psd1 # Module manifest
│   │   ├── AutoSecureVPN.psm1 # Module loader (dot-sources components)
│   │   ├── Core.ps1           # Utilities and logging
│   │   ├── OpenVPN.ps1        # OpenVPN implementation
│   │   └── WireGuard.ps1      # WireGuard implementation
│   └── scripts/               # Orchestration and UI entry points
│       ├── CoreSetup.ps1      # Main menu and protocol logic
│       ├── OpenVPNSetup.ps1   # OpenVPN wizard orchestration
│       ├── WireGuardSetup.ps1 # WireGuard wizard orchestration
│       └── main.ps1           # Main script entry point
└── tests/                     # Pester unit tests
    ├── Core.Tests.ps1         # Tests for Core utilities
    ├── OpenVPN.Tests.ps1      # Tests for OpenVPN logic
    └── WireGuard.Tests.ps1    # Tests for WireGuard logic
```

## Project Architecture

The project follows a modular design to separate concerns and improve maintainability.

### Module Layer (`src/module/`)

- **`AutoSecureVPN.psm1`**: The main entry point for the module. It handles dot-sourcing the component files and initializing global session variables like `$Script:Settings` and `$Script:BasePath`.
- **`Core.ps1`**: Shared logic, UI helpers, and logging.
- **`OpenVPN.ps1`**: Implementation of OpenVPN-specific logic.
- **`WireGuard.ps1`**: Implementation of WireGuard-specific logic.
- **`AutoSecureVPN.psd1`**: The module manifest, which defines versioning, requirements, and exported functions.

### Scripts Layer (`src/scripts/`)

- **`main.ps1`**: The user's entry point. It imports the module and launches the main menu.
- **`CoreSetup.ps1`**, **`OpenVPNSetup.ps1`**, **`WireGuardSetup.ps1`**: Contain the orchestration logic (the "glue" code) that ties the UI to the module functions.

### Configuration Layer (`src/config/`)

- **`Stable.psd1`**: Hardcoded defaults and paths (Installer URLs, version check endpoints).
- **`Variable.psd1`**: User-specific overrides (Server IPs, ports, subnets).

## How to Extend

### Adding a New VPN Protocol
1.  Create a new component file in `src/module/` (e.g., `NewProtocol.ps1`).
2.  Export the new functions in `AutoSecureVPN.psd1`.
3.  Create an orchestration script in `src/scripts/` (e.g., `NewProtocolSetup.ps1`).
4.  Update `CoreSetup.ps1` to include the new protocol in the `Select-VPNProtocol` function.

### Adding a Feature
- Utility functions should go into `Core.ps1`.
- Protocol-specific logic should go into their respective files.
- Always use `$Script:Settings` for any configurable value.

## Testing

We use [Pester](https://pester.dev/) for unit testing.

### Running Tests
To run all tests:
```powershell
Invoke-Pester -Path .\tests\
```

### Writing Tests
- Create a new file in `tests/` named `ComponentName.Tests.ps1`.
- Mock external dependencies (like `Invoke-WebRequest` or `Start-Process`) to ensure tests are fast and reliable.
- Use the module context to access script-scoped variables.

## Best Practices
- **Logging**: Always use `Write-Log` for important status updates.
- **Error Handling**: Wrap complex operations in `try-catch` blocks and use `throw` to propagate critical errors to the orchestration layer.
- **Indentation**: Use 4 spaces for indentation.
- **Naming**: Use standard PowerShell `Verb-Noun` naming conventions.
