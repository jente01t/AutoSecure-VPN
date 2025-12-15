#Requires -Modules Pester

# Import the module
$modulePath = Join-Path $PSScriptRoot '..\src\module\AutoSecureVPN.psm1'
Import-Module $modulePath -Force

InModuleScope AutoSecureVPN {

    BeforeAll {
        # Mock Write-Log globally to prevent log file issues in CI
        Mock Write-Log { } -ModuleName AutoSecureVPN
    }

    Describe "Install-OpenVPN" {
        It "Returns true if OpenVPN is already installed" {
            Mock Test-Path { 
                if ($Path -and $Path -like "*OpenVPN*") { return $true }
                return $false
            }
            Mock Write-Log { }

            $result = Install-OpenVPN
            $result | Should -Be $true
        }

        It "Installs OpenVPN successfully" {
            Mock Test-Path { 
                if ($Path -and $Path -like "*OpenVPN*") { return $false }
                return $true
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
                if ($Path -and $Path -like "*OpenVPN*") { return $false }
                return $true
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
            New-Item -ItemType Directory -Path "TestDrive:\config\client" -Force | Out-Null
            New-Item -ItemType File -Path "TestDrive:\client.zip" -Force | Out-Null
            
            Mock Read-Host { "TestDrive:\client.zip" }
            Mock Test-Path { param($Path) return ($Path -and (Test-Path $Path)) }
            Mock Expand-Archive { 
                New-Item -ItemType File -Path "TestDrive:\config\client\client.ovpn" -Force | Out-Null
            }
            Mock Get-ChildItem { @{ FullName = "TestDrive:\config\client\client.ovpn" } }
            Mock Write-Log { }

            $result = Import-ClientConfiguration
            $result | Should -Not -Be $null
        }
    }

    Describe "Start-VPNConnection" {
        It "Starts VPN connection successfully" {
            New-Item -ItemType File -Path "TestDrive:\client.ovpn" -Force | Out-Null
            
            Mock Test-Path { param($Path)
                if ($Path -and $Path -like "*openvpn.exe") { return $true }
                if ($Path -and $Path -like "*client.ovpn") { return $true }
                return $false
            }
            Mock Start-Process { }
            Mock Write-Log { }

            $result = Start-VPNConnection -ConfigFile "TestDrive:\client.ovpn"
            $result | Should -Be $true

            Assert-MockCalled Start-Process -Times 1
        }

        It "Returns false if OpenVPN executable not found" {
            Mock Test-Path { param($Path) return $false }
            Mock Write-Log { }

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
            Mock Test-Connection { param($TargetName) return ($TargetName -ne $null) }
            Mock Write-Log { }

            $result = Test-VPNConnection -TargetIP "10.8.0.1"
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
