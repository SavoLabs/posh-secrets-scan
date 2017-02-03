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
			{ Initialize-SecretScan -Path "$TestDrive\posh" } | Should Throw;
		}
	}

	Context "When destination path does exist" {
		It "Must download the files to the destination" {
			$ssFileName = "$TestDrive\scripts\Secrets-Scan.ps1";
			$ssFile = "dummy content";
			$jsonFileName = "$TestDrive\scripts\.secrets-scan.json";
			$jsonFile = "{ `"patterns`" : [ `"dummy-regex`" ]}";
			Mock Invoke-WebRequest {
				Set-Content -Path "$ssFileName" -Value $ssFile;
				} -ParameterFilter { $OutFile -and $OutFile -eq $ssFileName };
			Mock Invoke-WebRequest {
				Set-Content -Path "$jsonFileName" -Value $jsonFile;
			} -ParameterFilter { $OutFile -and $OutFile -eq $jsonFileName };
			# Setup was not working for some reason
			New-Item -Path "$TestDrive\scripts" -ItemType Directory -Force  | Out-Null;
			$destPath = "$TestDrive\scripts";
			{ Initialize-SecretScan -Path "$TestDrive\scripts" } | Should Not Throw;
			$ssFileName | Should Exist;
			$jsonFileName | Should Exist;
			$resultJson = Get-Content -Path $jsonFileName | ConvertFrom-Json;
			$resultSS = Get-Content -Path $ssFileName;
			$resultJson.patterns | Should Not Be $null;
			$resultJson.patterns.Count | Should Be 1;
			$resultSS | Should Be $ssFile;
			Assert-MockCalled -CommandName Invoke-WebRequest -Exactly -Times 2;
			Assert-MockCalled -CommandName Invoke-WebRequest -Exactly -Times 1 -ParameterFilter { $OutFile -contains $ssFileName };
			Assert-MockCalled -CommandName Invoke-WebRequest -Exactly -Times 1 -ParameterFilter { $OutFile -contains $jsonFileName };
			Remove-Item -Path "$TestDrive\scripts" -Force -Recurse | Out-Null;
		}
	}

	Context "When Invoke-WebRequest throws exception" {
		It "Must catch the exception and log it" {
			$warnings = ""
			Mock Invoke-WebRequest { throw "Invalid Request"; };
			Mock Write-Warning { return $Message; };
			Mock Test-Path { return $true; };
			Mock Resolve-Path { return "$TestDrive\fake-path"; };
			$result = Initialize-SecretScan -Path ".\fake-path";
			Assert-MockCalled Invoke-WebRequest -Exactly -Times 1;
			Assert-MockCalled Test-Path -Exactly -Times 1;
			Assert-MockCalled Write-Warning -Exactly -Times 1;
			$result | Should BeExactly "Invalid Request";
		}
	}
}
