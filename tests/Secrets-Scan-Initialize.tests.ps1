if($PSCommandPath -eq $null) {
	$CommandRootPath = (Split-Path -Parent $MyInvocation.MyCommand.Path);
} else {
	$CommandRootPath = (Split-Path -Parent $PSCommandPath);
}

# This stops the initial invoking of Invoke-Setup;
$Execute = $false;

."$(Join-Path -Path $CommandRootPath -ChildPath "../Secrets-Scan-Initialize.ps1")" -Path .;

Describe "Initialize-SecretScan" {
	Context "When destination path does not exist" {
		It "Must throw exception" {
			{ Initialize-SecretScan -Path "$TestDrive\scripts" } | Should Throw;
		}
	}
}
