
param (
	[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
	[ValidateScript({Test-Path $_})]
	[String] $Path
)

function Initialize-SecretScan {
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
		[String] $Path
	)
	begin {
		$resolvedPath = Resolve-Path -Path $Path;
		$mainFileUrl = "https://raw.githubusercontent.com/SavoLabs/posh-secrets-scan/master/Secrets-Scan.ps1";
		$configFileUrl = "https://raw.githubusercontent.com/SavoLabs/posh-secrets-scan/master/.secrets-scan.json";
		$mainFileOutput = Join-Path -Path $resolvedPath -ChildPath "Secrets-Scan.ps1";
		$configFileOutput = Join-Path -Path $resolvedPath -ChildPath ".secrets-scan.json";
	}
	process {
		try {
			Invoke-WebRequest -Uri $configFileUrl -OutFile $configFileOutput;
			Invoke-WebRequest -Uri $mainFileUrl -OutFile $mainFileOutput;
		} catch (exception) {
			$_ | Write-Warning;
		}
	}
}

if( ($Execute -eq $null) -or ($Execute -eq $true) ) {
	Initialize-SecretScan -Path $Path;
}
