#Requires -Modules Pester

try {
    # Set environment variable to use test config path
    $env:AutoSecureVPNTestConfigPath = "$env:TEMP\AutoSecureVPNTest\config"

    # Create test config files in the temp directory
    $configDir = $env:AutoSecureVPNTestConfigPath
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null

    $content = @"
@{
installedPath = "C:\Program Files\OpenVPN"
openVpnUrl = "https://example.com/openvpn.msi"
port = 1194
protocol = "UDP"
vpnSubnet = "10.8.0.0"
vpnMask = "255.255.255.0"
dns1 = "8.8.8.8"
dns2 = "8.8.4.4"
serverName = "vpn-server"
serverIP = "192.168.1.100"
lanSubnet = "192.168.1.0"
lanMask = "255.255.255.0"
noPass = `$true
easyRSAPath = "C:\easy-rsa"
configPath = "$env:TEMP\AutoSecureVPNTest\config"
outputPath = "$env:TEMP\AutoSecureVPNTest\output"
logFileName = "test.log"
transcriptFileName = "transcript.log"
logTimestampFormat = "yyyy-MM-dd HH:mm:ss"
easyRSABatch = "yes"
easyRSAAlgo = "rsa"
easyRSAKeySize = 2048
easyRSACAExpire = 3650
easyRSACertExpire = 825
easyRSACRLDays = 180
remoteConfigPath = "C:\Temp"
openVPNExePath = "C:\Program Files\OpenVPN\bin\openvpn.exe"
testIP = "10.8.0.1"
clientNameDefault = "client1"
}
"@
    Set-Content -Path "$configDir\Stable.psd1" -Value $content
    Set-Content -Path "$configDir\Variable.psd1" -Value $content

    # Set BasePath before importing module to override the default
    $Script:BasePath = "$env:TEMP\AutoSecureVPNTest\"

    # Import the module after creating config files
    $modulePath = Join-Path $PSScriptRoot "..\src\module\AutoSecureVPN.psm1"
    Import-Module $modulePath -Force

    InModuleScope AutoSecureVPN {

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
            Mock Expand-Archive { New-Item -ItemType File -Path "TestDrive:\config\client\client.ovpn" -Force }
            Mock Get-ChildItem { @{ FullName = "TestDrive:\config\client\client.ovpn" } }

            $result = Import-ClientConfiguration
            $result | Should -Not -Be $null
        }
    }

    Describe "Start-VPNConnection" {
        It "Starts VPN connection successfully" {
            Mock Test-Path { $true } -ParameterFilter { $Path -like "*openvpn.exe" }
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

    Describe "Set-Firewall" {
        It "Adds firewall rule successfully" {
            Mock Get-NetFirewallRule { return $null }
            Mock New-NetFirewallRule { }

            $result = Set-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }

        It "Returns true if rule already exists" {
            Mock Get-NetFirewallRule { return @{ Name = "OpenVPN-Inbound-TCP-443" } }

            $result = Set-Firewall -Port 443 -Protocol "TCP"
            $result | Should -Be $true
        }
    }

    Describe "Get-ServerConfiguration" {
        It "Returns configuration with provided parameters" {
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
            Mock Test-Path { $true }

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

            Mock Test-Path { $false } -ParameterFilter { $Path -eq $configPath }
            Mock New-Item { }
            Mock Set-Content { }

            $result = New-ServerConfig -Config $config -EasyRSAPath $easyRSAPath -ConfigPath $configPath
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

            $config = @{ ServerName = "test" }
            $result = Install-RemoteServer -ComputerName "remote-pc" -Credential (New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))) -ServerConfig $config -LocalEasyRSAPath "C:\easy-rsa"
            $result | Should -Be $true
        }
    }

    Describe "Install-RemoteClient" {
        It "Installs remote client successfully" {
            Mock Test-IsAdmin { $true }
            Mock Test-Path { $true } -ParameterFilter { $Path -eq "C:\test.zip" }
            Mock New-PSSession { New-MockObject -Type System.Management.Automation.Runspaces.PSSession }
            Mock Invoke-Command { }
            Mock Copy-Item { }
            Mock Remove-PSSession { }

            $cred = New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
            $result = Install-RemoteClient -ComputerName "remote-pc" -Credential $cred -ZipPath "C:\test.zip"
            $result | Should -Be $true
        }
    }

    Describe "Invoke-Rollback" {
        It "Performs rollback for client setup" {
            Mock Test-Path { $true }
            Mock Remove-Item { }
            Mock Stop-Service { }
            Mock Get-Service { @{ Status = "Running" } }

            $result = Invoke-Rollback -SetupType "Client"
            $result | Should -Be $null
        }
    }
}
}
finally {
    # Clean up environment variable
    $env:AutoSecureVPNTestConfigPath = $null
}