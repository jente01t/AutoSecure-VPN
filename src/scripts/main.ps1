


$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$modulePath = Join-Path $scriptDir '..\module\AutoSecureVPN.psm1'
if (-not (Test-Path $modulePath)) {
	Write-Host "Module niet gevonden: $modulePath" -ForegroundColor Red
	exit 1
}
Import-Module $modulePath -Force



while ($true) {
	$choice = Show-Menu -Title 'AutoSecureVPN Hoofdmenu' -Options @('Install','Configure','Exit')
	switch ($choice) {
		1 {
			$installChoice = Show-Menu -Title 'Installatie' -Options @('Server','Client','Back')
			switch ($installChoice) {
				1 {
					$serverChoice = Show-Menu -Title 'Server Installatie' -Options @('Install OpenVPN lokaal','Install OpenVPN remote','Back')
					switch ($serverChoice) {
						1 { $installationChoise = Show-Menu -Title 'Installatie Type' -Options @('Installatie via MSI','Installatie met eigen installatiebestand','Back')
							switch ($installationChoise) {
								1 { Add-ServerOpenVPNMSILocal; Pause }
								2 { Write-Host 'Installatie met eigen installatiebestand niet geïmplementeerd.' -ForegroundColor Yellow; Pause }
								default { }
							}
						}
						2 { Write-Host 'Start installatie OpenVPN remote...' -ForegroundColor Green; Pause }
						default { }
					}
				}
				2 { Write-Host 'Client install not implemented yet.' -ForegroundColor Yellow; Pause }
				default { }
			}
		}
		2 {
			Write-Host 'Configuratieopties niet geïmplementeerd.' -ForegroundColor Yellow
			Pause
		}
		3 { 
			Write-Host 'Aflsuitnen...' -ForegroundColor Cyan
			exit 0
		}
	}
}






