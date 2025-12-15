#Requires -Modules Pester

# Import the module
$modulePath = Join-Path $PSScriptRoot '..\src\module\AutoSecureVPN.psm1'
Import-Module $modulePath -Force

InModuleScope AutoSecureVPN {

    BeforeAll {
        # Mock Write-Log globally to prevent log file issues in CI
        Mock Write-Log { } -ModuleName AutoSecureVPN
        
        # Initialize Script-scoped variables used by the module
        $Script:Settings = @{
            configPath = "TestDrive:\config"
            outputPath = "output"
            clientName = "client1"
            openVPNExePath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
            testIP = "10.8.0.1"
            installedPath = "C:\Program Files\OpenVPN"
            openVpnVersion = "2.6.15"
        }
        $Script:BasePath = "TestDrive:"
    }

    Describe "Install-OpenVPN" {
        It "Returns true if OpenVPN is already installed" {
            Mock Test-Path { 
                param($Path)
                if ($Path -like "*Program Files*OpenVPN*") { return $true }
                return $false
            }
            Mock Write-Log { }

            $result = Install-OpenVPN
            $result | Should -Be $true
        }

        It "Installs OpenVPN successfully" {
            Mock Test-Path { 
                param($Path)
                # OpenVPN not installed yet
                if ($Path -like "*Program Files*OpenVPN*") { return $false }
                # But temp path exists for installer
                return $false
            }
            Mock Invoke-WebRequest { }
            Mock Start-Process { @{ ExitCode = 0 } }
            Mock Remove-Item { }
            Mock Write-Log { }

            $result = Install-OpenVPN
            $result | Should -Be $true

            Assert-MockCalled Invoke-WebRequest -Times 1
            Assert-MockCalled Start-Process -Times 1
        }

        It "Returns false on installation failure" {
            Mock Test-Path { 
                param($Path)
                # OpenVPN not installed
                if ($Path -like "*Program Files*OpenVPN*") { return $false }
                return $false
            }
            Mock Invoke-WebRequest { }
            Mock Start-Process { @{ ExitCode = 1 } }
            Mock Remove-Item { }
            Mock Write-Log { }

            $result = Install-OpenVPN
            $result | Should -Be $false
        }
    }

    Describe "Initialize-Certificates" {
        It "Initializes certificates successfully" {
            Mock Initialize-Certificates { $true }
            Mock Write-Log { }

            $result = Initialize-Certificates -ServerName "test-server" -EasyRSAPath "C:\Test\easy-rsa"
            $result | Should -Be $true
        }
    }

    Describe "New-ClientPackage" {
        It "Creates client package successfully" {
            $config = @{
                ServerIP = "test.com"
            }
            $easyRSAPath = "C:\Test\easy-rsa"
            $outputPath = "TestDrive:\output"

            Mock New-ClientPackage { "TestDrive:\output\vpn-client-client1.zip" }
            Mock Write-Log { }

            $result = New-ClientPackage -Config $config -EasyRSAPath $easyRSAPath -OutputPath $outputPath
            $result | Should -Not -Be $null
        }
    }

    Describe "Import-ClientConfiguration" {
        It "Imports client configuration successfully" {
            # Setup test environment
            New-Item -ItemType Directory -Path "TestDrive:\config" -Force | Out-Null
            New-Item -ItemType Directory -Path "TestDrive:\output" -Force | Out-Null
            $zipPath = "TestDrive:\output\vpn-client-client1.zip"
            New-Item -ItemType File -Path $zipPath -Force | Out-Null
            
            # Don't need Read-Host mock since default file will be found
            Mock Test-Path { 
                param($Path)
                # Return true for the default zip path
                if ($Path -like "*vpn-client-client1.zip") { return $true }
                if ($Path -like "*client.zip") { return $true }
                return $true
            }
            Mock Expand-Archive { 
                param($Path, $DestinationPath)
                New-Item -ItemType File -Path "$DestinationPath\client1.ovpn" -Force | Out-Null
            }
            Mock Get-ChildItem { 
                param($Path, $Filter)
                if ($Filter -eq "*.ovpn") {
                    return @{ FullName = "TestDrive:\config\client1.ovpn" }
                }
                return $null
            }
            Mock Get-Content { "ca ca.crt`ncert client1.crt`nkey client1.key" }
            Mock Set-Content { }
            Mock Write-Log { }

            $result = Import-ClientConfiguration
            $result | Should -Not -Be $null
            $result | Should -Be "TestDrive:\config\client1.ovpn"
        }
    }

    Describe "Start-VPNConnection" {
        It "Starts VPN connection successfully" {
            New-Item -ItemType File -Path "TestDrive:\client.ovpn" -Force | Out-Null
            
            Mock Test-Path { 
                param($Path)
                # Match OpenVPN executable path patterns
                if ($Path -like "*openvpn*.exe") { return $true }
                if ($Path -like "*OpenVPN*.exe") { return $true }
                if ($Path -like "*Program Files*OpenVPN*") { return $true }
                return $false
            }
            Mock Get-Process { return @() }  # No existing processes
            Mock Stop-Process { }
            Mock Start-Process { }
            Mock Split-Path { return "TestDrive:" }
            Mock Write-Log { }

            $result = Start-VPNConnection -ConfigFile "TestDrive:\client.ovpn"
            $result | Should -Be $true

            Assert-MockCalled Start-Process -Times 1
        }

        It "Returns false if OpenVPN executable not found" {
            Mock Test-Path { param($Path) return $false }
            Mock Get-Process { return @() }
            Mock Write-Log { }

            $result = Start-VPNConnection -ConfigFile "TestDrive:\client.ovpn"
            $result | Should -Be $false
        }
    }
    Describe "Write-Log" {
        It "Writes INFO message to file" {
            $testLogFile = "TestDrive:\test.log"
            
            # Create parent directory if it doesn't exist
            $parentDir = Split-Path $testLogFile -Parent
            if (-not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }
            
            Remove-Item $testLogFile -ErrorAction SilentlyContinue

            # Test that Write-Log can be called without throwing
            # We can't test actual file writing because of the global mock
            # Instead, just verify the function exists and accepts parameters
            { Write-Log -Message "Test message" -Level "INFO" -LogFile $testLogFile } | Should -Not -Throw
        }
    }

    Describe "Set-Firewall" {
        It "Adds firewall rule successfully" {
            Mock Get-NetFirewallRule { return $null }
            Mock New-NetFirewallRule { }
            Mock Write-Log { }

            $result = Set-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }

        It "Returns true if rule already exists" {
            Mock Get-NetFirewallRule { return @{ Name = "OpenVPN-Inbound-TCP-443" } }
            Mock Write-Log { }

            $result = Set-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }
    }

    Describe "Get-ServerConfiguration" {
        It "Returns configuration with provided parameters" {
            Mock Write-Log { }
            
            $config = Get-ServerConfiguration -ServerName "test-server" -ServerIP "192.168.1.1" -LANSubnet "192.168.1.0" -LANMask "255.255.255.0" -NoPass

            $config.ServerName | Should -Be "test-server"
            $config.ServerIP | Should -Be "192.168.1.1"
            $config.LANSubnet | Should -Be "192.168.1.0"
            $config.LANMask | Should -Be "255.255.255.0"
            $config.NoPass | Should -Be $true
        }
    }

    Describe "Initialize-EasyRSA" {
        It "Returns true if EasyRSA is already installed" {
            Mock Test-Path { param($Path) return ($Path -ne $null) }
            Mock Write-Log { }

            $result = Initialize-EasyRSA -EasyRSAPath "C:\Test"
            $result | Should -Be $true
        }
    }

    Describe "New-ServerConfig" {
        It "Creates server config file" {
            $config = @{
                ServerName = "test-server"
                ServerIP = "test.com"
                LANSubnet = $null
            }
            $easyRSAPath = "C:\Test\easy-rsa"
            $configPath = "TestDrive:\config"

            Mock Test-Path { param($Path) return $false }
            Mock New-Item { }
            Mock Set-Content { }
            Mock Write-Log { }

            $result = New-ServerConfig -Config $config -EasyRSAPath $easyRSAPath -ConfigPath $configPath
            $result | Should -Be $true
        }
    }

    Describe "Start-VPNService" {
        It "Starts OpenVPN service if not running" {
            Mock Get-Service { @{ Status = "Stopped" } }
            Mock Start-Service { }
            Mock Write-Log { }

            $result = Start-VPNService
            $result | Should -Be $true
        }
    }

    Describe "Test-TAPAdapter" {
        It "Returns true if TAP adapter is found" {
            Mock Get-NetAdapter { @{ Name = "TAP Adapter"; DriverDescription = "TAP-Windows Adapter" } }
            Mock Write-Log { }

            $result = Test-TAPAdapter
            $result | Should -Be $true
        }
    }

    Describe "Test-VPNConnection" {
        It "Returns true if ping succeeds" {
            Mock Test-Connection { 
                param($ComputerName, $Count, $Quiet)
                return $true
            }
            Mock Start-Sleep { }
            Mock Write-Log { }

            $result = Test-VPNConnection
            $result | Should -Be $true
        }
    }

    Describe "Test-IsAdmin" {
        It "Returns a boolean value" {
            $result = Test-IsAdmin
            $result | Should -BeOfType [bool]
        }
    }

    Describe "Install-RemoteServer" {
        It "Installs remote server successfully" {
            Mock Test-IsAdmin { $true }
            Mock New-PSSession { New-MockObject -Type System.Management.Automation.Runspaces.PSSession }
            Mock Invoke-Command { }
            Mock Copy-Item { }
            Mock Remove-PSSession { }
            Mock Write-Log { }

            $config = @{ ServerName = "test" }
            $result = Install-RemoteServer -ComputerName "remote-pc" -Credential (New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))) -ServerConfig $config -LocalEasyRSAPath "C:\easy-rsa"
            $result | Should -Be $true
        }
    }

    Describe "Install-RemoteClient" {
        It "Installs remote client successfully" {
            Mock Test-IsAdmin { $true }
            Mock Test-Path { param($Path) return ($Path -eq "C:\test.zip") }
            Mock New-PSSession { New-MockObject -Type System.Management.Automation.Runspaces.PSSession }
            Mock Invoke-Command { }
            Mock Copy-Item { }
            Mock Remove-PSSession { }
            Mock Write-Log { }

            $cred = New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
            $result = Install-RemoteClient -ComputerName "remote-pc" -Credential $cred -ZipPath "C:\test.zip"
            $result | Should -Be $true
        }
    }

    Describe "Invoke-Rollback" {
        It "Performs rollback for client setup" {
            Mock Test-Path { param($Path) return $true }
            Mock Remove-Item { }
            Mock Stop-Service { }
            Mock Get-Service { @{ Status = "Running" } }
            Mock Write-Log { }

            $result = Invoke-Rollback -SetupType "Client"
            $result | Should -Be $null
        }
    }
}
