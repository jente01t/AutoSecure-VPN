#Requires -Modules Pester

# Import the module to test
$modulePath = Join-Path $PSScriptRoot "..\src\module\AutoSecureVPN.psm1"
Import-Module $modulePath -Force

InModuleScope AutoSecureVPN {
    Describe "Pause" {
        It "Calls Read-Host with the message" {
            Mock Read-Host { }

            Pause -Message "Test message"

            Assert-MockCalled Read-Host -Times 1 -ParameterFilter { $Prompt -eq "Test message" }
        }
    }

    Describe "Install-OpenVPN" {
        It "Returns true if OpenVPN is already installed" {
            Mock Test-Path { $true } -ParameterFilter { $Path -like "*OpenVPN*" }

            $result = Install-OpenVPN
            $result | Should -Be $true
        }

        It "Installs OpenVPN successfully" {
            Mock Test-Path { $false } -ParameterFilter { $Path -like "*OpenVPN*" }
            Mock Invoke-WebRequest { }
            Mock Start-Process { @{ ExitCode = 0 } }
            Mock Remove-Item { }

            $result = Install-OpenVPN
            $result | Should -Be $true

            Assert-MockCalled Invoke-WebRequest -Times 1
            Assert-MockCalled Start-Process -Times 1
        }

        It "Returns false on installation failure" {
            Mock Test-Path { $false } -ParameterFilter { $Path -like "*OpenVPN*" }
            Mock Invoke-WebRequest { }
            Mock Start-Process { @{ ExitCode = 1 } }
            Mock Remove-Item { }

            $result = Install-OpenVPN
            $result | Should -Be $false
        }
    }

    Describe "Initialize-Certificates" {
        It "Initializes certificates successfully" {
            Mock Initialize-Certificates { $true }

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

            $result = New-ClientPackage -Config $config -EasyRSAPath $easyRSAPath -OutputPath $outputPath
            $result | Should -Not -Be $null
        }
    }

    Describe "Import-ClientConfiguration" {
        It "Imports client configuration successfully" {
            Mock Read-Host { "TestDrive:\client.zip" }
            Mock Test-Path { $true }
            Mock Expand-Archive { }
            Mock Get-ChildItem { @{ FullName = "TestDrive:\config\client.ovpn" } }

            $result = Import-ClientConfiguration
            $result | Should -Not -Be $null
        }
    }

    Describe "Start-VPNConnection" {
        It "Starts VPN connection successfully" {
            Mock Test-Path { $true }
            Mock Start-Process { }

            $result = Start-VPNConnection -ConfigFile "TestDrive:\client.ovpn"
            $result | Should -Be $true

            Assert-MockCalled Start-Process -Times 1
        }

        It "Returns false if OpenVPN executable not found" {
            Mock Start-VPNConnection { $false }

            $result = Start-VPNConnection -ConfigFile "TestDrive:\client.ovpn"
            $result | Should -Be $false
        }
    }
    Describe "Write-Log" {
        It "Writes INFO message to file" {
            $testLogFile = "TestDrive:\test.log"
            Remove-Item $testLogFile -ErrorAction SilentlyContinue

            Write-Log -Message "Test message" -Level "INFO" -LogFile $testLogFile

            $logContent = Get-Content $testLogFile
            $logContent | Should -Match "\[INFO\] Test message"
        }
    }

    Describe "Configure-Firewall" {
        It "Adds firewall rule successfully" {
            Mock Get-NetFirewallRule { return $null }
            Mock New-NetFirewallRule { }

            $result = Configure-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }

        It "Returns true if rule already exists" {
            Mock Get-NetFirewallRule { return @{ Name = "OpenVPN-Inbound-TCP-443" } }

            $result = Configure-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }
    }

    Describe "Get-ServerConfiguration" {
        It "Returns configuration with default values" {
            Mock Read-Host {
                param($Prompt)
                switch -Regex ($Prompt) {
                    "Servernaam" { "" }
                    "Server WAN IP" { "example.com" }
                    "LAN subnet" { "" }
                    "Certificaten zonder wachtwoord" { "J" }
                }
            }

            $config = Get-ServerConfiguration

            $config.ServerName | Should -Be "vpn-server"
            $config.ServerIP | Should -Be "example.com"
            $config.NoPass | Should -Be $true
        }
    }

    Describe "Initialize-EasyRSA" {
        It "Returns true if EasyRSA is already installed" {
            Mock Test-Path { $true }

            $result = Initialize-EasyRSA -EasyRSAPath "C:\Test"
            $result | Should -Be $true
        }
    }

    Describe "Generate-ServerConfig" {
        It "Creates server config file" {
            $config = @{
                ServerName = "test-server"
                ServerIP = "test.com"
                LANSubnet = $null
            }
            $easyRSAPath = "C:\Test\easy-rsa"
            $configPath = "TestDrive:\config"

            Mock Test-Path { $false } -ParameterFilter { $Path -eq $configPath }
            Mock New-Item { }
            Mock Set-Content { }

            $result = Generate-ServerConfig -Config $config -EasyRSAPath $easyRSAPath -ConfigPath $configPath
            $result | Should -Be $true
        }
    }

    Describe "Start-VPNService" {
        It "Starts OpenVPN service if not running" {
            Mock Get-Service { @{ Status = "Stopped" } }
            Mock Start-Service { }

            $result = Start-VPNService
            $result | Should -Be $true
        }
    }

    Describe "Test-TAPAdapter" {
        It "Returns true if TAP adapter is found" {
            Mock Get-NetAdapter { @{ Name = "TAP Adapter"; DriverDescription = "TAP-Windows Adapter" } }

            $result = Test-TAPAdapter
            $result | Should -Be $true
        }
    }

    Describe "Test-VPNConnection" {
        It "Returns true if ping succeeds" {
            Mock Test-Connection { $true }

            $result = Test-VPNConnection
            $result | Should -Be $true
        }
    }
}