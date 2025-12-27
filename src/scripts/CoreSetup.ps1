# Orchestration logic for Core setup
# Copy the full function definitions from main.ps1 to here.

function Start-VPNSetup {
    <#
    .SYNOPSIS
        Displays the main menu for VPN setup selection.

    .DESCRIPTION
        This function shows a menu with options for server or client setup selection.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    Write-Log "=== AutoSecure-VPN Automatic Setup Started ===" -Level "INFO"
    
    $choice = Show-Menu -Mode Menu -Title "AutoSecure-VPN Automatic Setup v1.0" -Options @("Server Setup", "Client Setup", "Exit") -HeaderColor Cyan -OptionColor Green -FooterColor Cyan -Prompt "Enter your choice (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Server Setup selected" -Level "INFO"
            Select-ServerMode
        }
        2 {
            Write-Host "`n[*] Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Client Setup selected" -Level "INFO"
            Select-ClientMode
        }
        3 {
            Write-Host "`n[*] Exiting setup..." -ForegroundColor Yellow
            Write-Log "Setup closed by user" -Level "INFO"
            exit 0
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Start-VPNSetup
        }
    }
}
function Select-ServerMode {
    <#
    .SYNOPSIS
        Displays submenu for server setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local or remote server setup.

    .EXAMPLE
        Select-ServerMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Server Setup Options" -Options @("Local (Install and configure VPN server on this machine)", "Remote (Install and configure VPN server remotely)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Server Setup selected" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardServerSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Server Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Server Setup selected" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardServerSetup
            }
        }
        3 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ServerMode
        }
    }
}
function Select-ClientMode {
    <#
    .SYNOPSIS
        Displays submenu for client setup choice (local or remote).

    .DESCRIPTION
        This function shows a submenu for choosing between local or remote client setup.

    .EXAMPLE
        Select-ClientMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Client Setup Options" -Options @("Local (Install and connect VPN client on this machine)", "Remote (Install and connect VPN client remotely)", "Batch Remote (Install VPN client on multiple machines)", "Back to main menu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Enter your choice (1-4)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Local Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Local Client Setup selected" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardClientSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Remote Client Setup selected" -Level "INFO"
             
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardClientSetup
            }
        }
        3 {
            Write-Host "`n[*] Batch Remote Client Setup selected..." -ForegroundColor Cyan
            Write-Log "Batch Remote Client Setup selected" -Level "INFO"
            Invoke-BatchRemoteClientSetup
        }
        4 {
            Write-Host "`n[*] Back to main menu..." -ForegroundColor Yellow
            Write-Log "Back to main menu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Invalid choice. Please try again." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}
function Select-VPNProtocol {
    <#
    .SYNOPSIS
        Asks the user to choose a VPN protocol.
    #>
    $choice = Show-Menu -Mode Menu -Title "Choose VPN Protocol" -Options @("OpenVPN", "WireGuard") -HeaderColor Magenta -OptionColor White -Prompt "Select protocol (1-2)"
    
    switch ($choice) {
        1 { return "OpenVPN" }
        2 { return "WireGuard" }
    }
}

