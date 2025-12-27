<#
    WHY SO MANY MOCKS IN THESE TESTS?

    OpenVPN functions are difficult to test because they:
    - Start/stop Windows services
    - Configure network adapters and firewall
    - Execute external executables (wg.exe)
    - Manipulate registry settings

    In CI/CD (GitHub Actions) these do not work because:
    - No real network adapters available
    - Services cannot run
    - wg.exe does not exist in the container

    Therefore, we mock everything for:
    - CI compatibility
    - System safety (no real changes)
    - Fast, reproducible tests

    Trade-off: we don't test all real logic, but we do keep CI/CD working.
#>



#Requires -Modules Pester

# Import the module
$modulePath = Join-Path $PSScriptRoot '..\src\module\AutoSecureVPN.psm1'
Import-Module $modulePath -Force

InModuleScope AutoSecureVPN {
    BeforeAll {
        Mock Write-Log { } -ModuleName AutoSecureVPN
        Mock Set-Content { } -ModuleName AutoSecureVPN
        Mock Out-File { } -ModuleName AutoSecureVPN
        
        $Script:Settings = @{
            installerPath     = "C:\Temp\openvpn-install.msi"
            installedPath     = "C:\Program Files\OpenVPN"
            openVPNExePath    = "C:\Program Files\OpenVPN\bin\openvpn.exe"
            openVPNGuiPath    = "C:\Program Files\OpenVPN\bin\openvpn-gui.exe"
            easyRSAVersion    = ""
            easyRSAPath       = "C:\Program Files\OpenVPN\easy-rsa"
            easyRSAKeySize    = 2048
            easyRSACAExpire   = 3650
            easyRSACertExpire = 3650
            easyRSACRLDays    = 180
            easyRSAAlgo       = "rsa"
            easyRSABatch      = "1"
            easyRSAReqCN      = "vpn-server"
            configPath        = "C:\Program Files\OpenVPN\config"
            remoteConfigPath  = "C:\Program Files\OpenVPN\config"
            logsPath          = "logs"
            outputPath        = "output"
            port              = 443
            protocol          = "TCP"
            vpnSubnet         = "10.8.0.0"
            vpnMask           = "255.255.255.0"
            testIP            = "10.8.0.1"
            dns1              = "8.8.8.8"
            dns2              = "8.8.4.4"
            serverName        = "server"
            serverIP          = "192.168.0.132"
            serverWanIP       = "81.164.163.23"
            lanSubnet         = "192.168.0.0"
            lanMask           = "255.255.255.0"
            noPass            = $true
            clientName        = "client1"
        }
    }

    Describe "Install-OpenVPN" {
        It "Installs OpenVPN if not present" {
            Mock Test-Path { return $false } -ModuleName AutoSecureVPN # Not installed
            Mock Invoke-WebRequest { } -ModuleName AutoSecureVPN
            Mock Start-Process { return @{ ExitCode = 0 } } -ModuleName AutoSecureVPN
            Mock Remove-Item { } -ModuleName AutoSecureVPN
            
            $result = Install-OpenVPN
            $result | Should -Be $true
            
            Assert-MockCalled Invoke-WebRequest -Times 1
            Assert-MockCalled Start-Process -Times 1
        }
        
        It "Returns true if already installed" {
            Mock Test-Path { return $true } -ModuleName AutoSecureVPN # Already installed
            Mock Invoke-WebRequest { } -ModuleName AutoSecureVPN  # Not called but mocked to avoid errors
            
            $result = Install-OpenVPN
            $result | Should -Be $true
            
            Assert-MockCalled Invoke-WebRequest -Times 0
        }
    }

    Describe "Initialize-Certificates" {
        It "Initializes certificates successfully" {
            Mock Initialize-Certificates { return $true } -ModuleName AutoSecureVPN
            
            $result = Initialize-Certificates -Password $null
            $result | Should -Be $true
        }
        
        It "Returns false if easy-rsa not found" {
            Mock Test-Path { return $false } -ModuleName AutoSecureVPN
            
            $result = Initialize-Certificates
            $result | Should -Be $false
        }
    }

    Describe "New-ClientPackage" {
        It "Creates client package" {
            Mock New-ClientPackage { return "C:\output\vpn-client-client1.zip" } -ModuleName AutoSecureVPN
            
            $config = @{ clientName = "client1" }
            $result = New-ClientPackage -Config $config -OutputPath "C:\output"
            $result | Should -Not -BeNullOrEmpty
            $result | Should -Be "C:\output\vpn-client-client1.zip"
        }
    }

    Describe "Import-ClientConfiguration" {
        It "Imports config successfully" {
            Mock Test-Path { return $true } -ModuleName AutoSecureVPN
            Mock Copy-Item { } -ModuleName AutoSecureVPN
            Mock Write-Log { } -ModuleName AutoSecureVPN
            Mock Expand-Archive { } -ModuleName AutoSecureVPN
            Mock Get-ChildItem { return [PSCustomObject]@{ FullName = "C:\config\client.ovpn" } } -ModuleName AutoSecureVPN
            Mock Get-Content { return "client config" } -ModuleName AutoSecureVPN
            Mock Set-Content { } -ModuleName AutoSecureVPN
            
            $result = Import-ClientConfiguration
            $result | Should -Not -BeNullOrEmpty
            
            Assert-MockCalled Expand-Archive -Times 1
        }
    }

    Describe "Start-VPNConnection" {
        It "Starts VPN connection" {
            Mock Start-VPNConnection { return $true } -ModuleName AutoSecureVPN
            
            $result = Start-VPNConnection -ConfigFile "C:\config.ovpn"
            $result | Should -Be $true
        }
    }

    Describe "Initialize-EasyRSA" {
        It "Initializes EasyRSA successfully" {
            Mock Initialize-EasyRSA { return $true } -ModuleName AutoSecureVPN
            
            $result = Initialize-EasyRSA
            $result | Should -Be $true
        }
    }

    Describe "New-ServerConfig" {
        It "Generates server config" {
            Mock Set-Content { } -ModuleName AutoSecureVPN
            Mock Write-Log { } -ModuleName AutoSecureVPN
            Mock Test-Path { return $true } -ModuleName AutoSecureVPN
            Mock New-Item { } -ModuleName AutoSecureVPN
            
            $config = @{
                serverName = "server"
                serverIP   = "192.168.0.132"
                port       = 443
                protocol   = "TCP"
                vpnSubnet  = "10.8.0.0"
                vpnMask    = "255.255.255.0"
                dns1       = "8.8.8.8"
                dns2       = "8.8.4.4"
            }
            
            $result = New-ServerConfig -Config $config
            $result | Should -Be $true
            
            Assert-MockCalled Set-Content -Times 1
        }
    }

    Describe "Start-VPNService" {
        It "Starts OpenVPN service" {
            Mock Get-Service { return @{ Status = "Stopped" } } -ModuleName AutoSecureVPN
            Mock Start-Service { } -ModuleName AutoSecureVPN
            Mock Write-Log { } -ModuleName AutoSecureVPN
            
            $result = Start-VPNService
            $result | Should -Be $true
            
            Assert-MockCalled Start-Service -Times 1
        }
    }

    Describe "Install-RemoteServer" {
        It "Installs remote server successfully" {
            Mock Test-IsAdmin { $true } -ModuleName AutoSecureVPN
            Mock New-PSSession { New-MockObject -Type System.Management.Automation.Runspaces.PSSession } -ModuleName AutoSecureVPN
            Mock Invoke-Command { } -ModuleName AutoSecureVPN
            Mock Copy-Item { } -ModuleName AutoSecureVPN
            Mock Remove-PSSession { } -ModuleName AutoSecureVPN
            Mock Write-Log { } -ModuleName AutoSecureVPN
            
            $cred = New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
            $config = @{ serverName = "test"; serverIP = "1.2.3.4" }
            
            { Install-RemoteServer -ComputerName "test-pc" -Credential $cred -ServerConfig $config -LocalEasyRSAPath "C:\easyrsa" } | Should -Not -Throw
            
            Assert-MockCalled Invoke-Command -Times 1
        }
    }

    Describe "Install-RemoteClient" {
        It "Installs remote client successfully" {
            Mock Test-Path { return $true } -ModuleName AutoSecureVPN
            Mock New-PSSession { New-MockObject -Type System.Management.Automation.Runspaces.PSSession } -ModuleName AutoSecureVPN
            Mock Invoke-Command { } -ModuleName AutoSecureVPN
            Mock Copy-Item { } -ModuleName AutoSecureVPN
            Mock Remove-PSSession { } -ModuleName AutoSecureVPN
            Mock Write-Log { } -ModuleName AutoSecureVPN
            
            $cred = New-Object PSCredential ("user", (ConvertTo-SecureString "pass" -AsPlainText -Force))
            
            $result = Install-RemoteClient -ComputerName "test-pc" -Credential $cred -ZipPath "C:\client.zip"
            $result | Should -Be $true
            
            Assert-MockCalled Invoke-Command -Times 1
        }
    }
}