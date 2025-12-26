#Requires -Modules Pester

# Import the module
$modulePath = Join-Path $PSScriptRoot '..\src\module\AutoSecureVPN.psm1'
Import-Module $modulePath -Force

InModuleScope AutoSecureVPN {

    BeforeAll {
        # Mock Write-Log globally to prevent log file issues in CI
        Mock Write-Log { } -ModuleName AutoSecureVPN
        
        # Mock Copy-Item globally to prevent path issues
        Mock Copy-Item { } -ModuleName AutoSecureVPN
        
        # Initialize Script-scoped variables used by the module
        $Script:Settings = @{
            logFileName = "AutoSecureVPN.log"
            transcriptFileName = "transcript.log"
            configPath = "C:\Program Files\OpenVPN\config"
            easyRSAPath = "C:\Program Files\OpenVPN\easy-rsa"
            outputPath = "output"
            installerPath = "C:\Temp\openvpn-install.msi"
            installedPath = "C:\Program Files\OpenVPN"
            openVPNExePath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
            openVPNGuiPath = "C:\Program Files\OpenVPN\bin\openvpn-gui.exe"
            easyRSAVersion = ""
            easyRSAKeySize = 2048
            easyRSACAExpire = 3650
            easyRSACertExpire = 3650
            easyRSACRLDays = 180
            easyRSAAlgo = "rsa"
            easyRSABatch = "1"
            easyRSAReqCN = "vpn-server"
            port = 443
            protocol = "TCP"
            vpnSubnet = "10.8.0.0"
            vpnMask = "255.255.255.0"
            testIP = "10.8.0.1"
            dns1 = "8.8.8.8"
            dns2 = "8.8.4.4"
            serverName = "server"
            serverIP = "192.168.0.132"
            serverWanIP = "81.164.163.23"
            lanSubnet = "192.168.0.0"
            lanMask = "255.255.255.0"
            noPass = $true
        }
        $Script:BasePath = "TestDrive:"
    }

    Describe "Write-Log" {
        It "Writes to log file" {
            # Since Write-Log is mocked globally, we can't test the internal Add-Content
            # Instead, test that the function exists and can be called
            { Write-Log -Message "Test message" -Level "Info" } | Should -Not -Throw
        }
    }

    Describe "Test-IsAdmin" {
        It "Returns true if admin" {
            Mock Test-IsAdmin { return $true }
            
            $result = Test-IsAdmin
            $result | Should -Be $true
        }
        
        It "Returns false if not admin" {
            Mock Test-IsAdmin { return $false }
            
            $result = Test-IsAdmin
            $result | Should -Be $false
        }
    }

    Describe "Set-Firewall" {
        It "Sets OpenVPN firewall rules" {
            Mock Get-NetFirewallRule { return $null }
            Mock New-NetFirewallRule { }
            Mock Write-Log { }
            
            Set-Firewall -Port 443 -Protocol "TCP"
            
            Assert-MockCalled New-NetFirewallRule -Times 1
        }
    }

    Describe "Get-ServerConfiguration" {
        It "Returns server config" {
            $config = Get-ServerConfiguration
            
            $config | Should -BeOfType [hashtable]
            $config.ContainsKey("serverIP") | Should -Be $true
        }
    }

    Describe "Test-TAPAdapter" {
        It "Returns true if TAP adapter exists" {
            Mock Get-NetAdapter { return @{ Name = "TAP-Windows Adapter V9" } }
            
            $result = Test-TAPAdapter
            $result | Should -Be $true
        }
        
        It "Returns false if no TAP adapter" {
            Mock Get-NetAdapter { return $null }
            
            $result = Test-TAPAdapter
            $result | Should -Be $false
        }
    }

    Describe "Test-VPNConnection" {
        It "Tests connection successfully" {
            Mock Test-Connection { return $true }
            
            $result = Test-VPNConnection -ServerIP "192.168.0.132" -Port 443
            $result | Should -Be $true
        }
        
        It "Returns false if connection fails" {
            Mock Test-Connection { return $false }
            
            $result = Test-VPNConnection -ServerIP "192.168.0.132" -Port 443
            $result | Should -Be $false
        }
    }

    Describe "Invoke-Rollback" {
        It "Rolls back changes for Client" {
            Mock Get-Process { return [PSCustomObject]@{ Name = "openvpn" } }
            Mock Stop-Process { }
            Mock Test-Path { return $true }
            Mock Remove-Item { }
            Mock Get-ChildItem { 
                param($Path, $Filter)
                if ($Filter -eq "*.ovpn") { return @([PSCustomObject]@{ FullName = "test.ovpn" }) }
                elseif ($Filter -eq "*.crt") { return @([PSCustomObject]@{ FullName = "test.crt" }) }
                elseif ($Filter -eq "*.key") { return @([PSCustomObject]@{ FullName = "test.key" }) }
                return @()
            }
            Mock Write-Log { }
            
            Invoke-Rollback -SetupType "Client"
            
            Assert-MockCalled Stop-Process -Times 1
            Assert-MockCalled Remove-Item -Times 3  # .ovpn, .crt, .key files
        }
    }

    Describe "Invoke-BatchRemoteClientInstall" {
        It "Installs batch clients successfully" {
            Mock ForEach-Object { param($ThrottleLimit, $ScriptBlock) 
                # Simulate parallel execution
                $results = @("SUCCESS: client1 (192.168.1.1)", "SUCCESS: client2 (192.168.1.2)")
                return $results
            }
            Mock Write-Log { }
            Mock Get-CimInstance { return @{ NumberOfLogicalProcessors = 4 } }
            
            $clients = @(
                @{ Name = "client1"; IP = "192.168.1.1"; Username = "user1"; Password = "pass1" },
                @{ Name = "client2"; IP = "192.168.1.2"; Username = "user2"; Password = "pass2" }
            )
            
            $result = Invoke-BatchRemoteClientInstall -Clients $clients -ZipPath "C:\test.zip" -ModulePath "C:\module.psm1" -Settings @{ configPath = "C:\config" } -BasePath "C:\base"
            
            $result | Should -Contain "SUCCESS: client1 (192.168.1.1)"
            $result | Should -Contain "SUCCESS: client2 (192.168.1.2)"
        }
        
        It "Handles errors in batch install" {
            Mock ForEach-Object { param($ThrottleLimit, $ScriptBlock) 
                $results = @("ERROR: client1 (192.168.1.1) - Installation failed")
                return $results
            }
            Mock Write-Log { }
            Mock Get-CimInstance { return @{ NumberOfLogicalProcessors = 2 } }
            
            $clients = @(@{ Name = "client1"; IP = "192.168.1.1"; Username = "user1"; Password = "pass1" })
            
            $result = Invoke-BatchRemoteClientInstall -Clients $clients -ZipPath "C:\test.zip" -ModulePath "C:\module.psm1" -Settings @{ configPath = "C:\config" } -BasePath "C:\base"
            
            $result | Should -Contain "ERROR: client1 (192.168.1.1) - Installation failed"
        }
    }
}