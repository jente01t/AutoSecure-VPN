# Orchestration logic for Core setup
# Copy the full function definitions from main.ps1 to here.

function Start-VPNSetup {
    <#
    .SYNOPSIS
        Toont het hoofdmenu voor VPN setup keuze.

    .DESCRIPTION
        Deze functie toont een menu met opties voor server of client setup keuze.

    .EXAMPLE
        Start-VPNSetup
    #>
    
    Write-Log "=== OpenVPN Automatische Setup Gestart ===" -Level "INFO"
    
    $choice = Show-Menu -Mode Menu -Title "OpenVPN Automatische Setup v1.0" -Options @("Server Setup", "Client Setup", "Afsluiten") -HeaderColor Cyan -OptionColor Green -FooterColor Cyan -Prompt "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Server Setup geselecteerd" -Level "INFO"
            Select-ServerMode
        }
        2 {
            Write-Host "`n[*] Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Client Setup geselecteerd" -Level "INFO"
            Select-ClientMode
        }
        3 {
            Write-Host "`n[*] Setup wordt afgesloten..." -ForegroundColor Yellow
            Write-Log "Setup afgesloten door gebruiker" -Level "INFO"
            exit 0
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Start-VPNSetup
        }
    }
}
function Select-ServerMode {
    <#
    .SYNOPSIS
        Toont submenu voor server setup keuze (lokaal of remote).

    .DESCRIPTION
        Deze functie toont een submenu voor het kiezen tussen lokale of remote server setup.

    .EXAMPLE
        Select-ServerMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Server Setup Opties" -Options @("Lokaal (VPN-server installeren en configureren op deze machine)", "Remote (VPN-server installeren en configureren op afstand)", "Terug naar hoofdmenu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Voer uw keuze in (1-3)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Lokale Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Lokale Server Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardServerSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Server Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Remote Server Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNServerSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardServerSetup
            }
        }
        3 {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
            Write-Log "Terug naar hoofdmenu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ServerMode
        }
    }
}
function Select-ClientMode {
    <#
    .SYNOPSIS
        Toont submenu voor client setup keuze (lokaal of remote).

    .DESCRIPTION
        Deze functie toont een submenu voor het kiezen tussen lokale of remote client setup.

    .EXAMPLE
        Select-ClientMode
    #>
    
    $choice = Show-Menu -Mode Menu -Title "Client Setup Opties" -Options @("Lokaal (VPN-client installeren en verbinden op deze machine)", "Remote (VPN-client installeren en verbinden op afstand)", "Batch Remote (VPN-client installeren op meerdere machines)", "Terug naar hoofdmenu") -HeaderColor Yellow -OptionColor Green -FooterColor Red -Prompt "Voer uw keuze in (1-4)"
    
    switch ($choice) {
        1 {
            Write-Host "`n[*] Lokale Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Lokale Client Setup geselecteerd" -Level "INFO"
            
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-OpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-WireGuardClientSetup
            }
        }
        2 {
            Write-Host "`n[*] Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Remote Client Setup geselecteerd" -Level "INFO"
             
            $protocol = Select-VPNProtocol
            if ($protocol -eq "OpenVPN") {
                Invoke-RemoteOpenVPNClientSetup
            }
            elseif ($protocol -eq "WireGuard") {
                Invoke-RemoteWireGuardClientSetup
            }
        }
        3 {
            Write-Host "`n[*] Batch Remote Client Setup geselecteerd..." -ForegroundColor Cyan
            Write-Log "Batch Remote Client Setup geselecteerd" -Level "INFO"
            Invoke-BatchRemoteClientSetup
        }
        4 {
            Write-Host "`n[*] Terug naar hoofdmenu..." -ForegroundColor Yellow
            Write-Log "Terug naar hoofdmenu" -Level "INFO"
            Start-VPNSetup
        }
        default {
            Write-Host "`n[!] Ongeldige keuze. Probeer opnieuw." -ForegroundColor Red
            Start-Sleep -Seconds 2
            Select-ClientMode
        }
    }
}
function Select-VPNProtocol {
    <#
    .SYNOPSIS
        Vraagt de gebruiker om een VPN protocol te kiezen.
    #>
    $choice = Show-Menu -Mode Menu -Title "Kies VPN Protocol" -Options @("OpenVPN", "WireGuard (Experimental)") -HeaderColor Magenta -OptionColor White -Prompt "Kies protocol (1-2)"
    
    switch ($choice) {
        1 { return "OpenVPN" }
        2 { return "WireGuard" }
    }
}

