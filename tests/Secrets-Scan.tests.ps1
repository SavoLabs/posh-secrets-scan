if($PSCommandPath -eq $null) {
	$CommandRootPath = (Split-Path -Parent $MyInvocation.MyCommand.Path);
} else {
	$CommandRootPath = (Split-Path -Parent $PSCommandPath);
}

# This stops the initial invoking of Invoke-Setup;
$Execute = $false;

."$(Join-Path -Path $CommandRootPath -ChildPath "../Secrets-Scan.ps1")" -Path .;

$configPrimary = "{
	`"patterns`": [
		`"(?s)(\`"|')?(AWS|aws|Aws)?_?(SECRET|secret|Secret)?_?(ACCESS|access|Access)?_?(KEY|key|Key)(\`"|')?\\s*(:|=>|=)\\s*(\`"|')?[A-Za-z0-9/\\+=]{40}(\`"|')?`",
		`"(?s)(\`"|')?(AWS|aws|Aws)?_?(ACCOUNT|account|Account)_?(ID|id|Id)?(\`"|')?\\s*(:|=>|=)\\s*(\`"|')?[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}(\`"|')?`",
		`"(?s)^-----BEGIN\\sRSA\\sPRIVATE\\sKEY-----`",
		`"(?s)^-----BEGIN\\sPUBLIC\\sKEY-----`"
	],
	`"allowed`": [
		`"AKIAIOSFODNN7EXAMPLE`",
		`"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`"
	]
}";
$configSecondary = "{
	`"patterns`": [
	],
	`"allowed`": [
		`"(?s)-----BEGIN\\sPUBLIC\\sKEY-----$`"
	]
}";
Describe "Load-Rules" {

	Context "When .secrets-scan.json file exists" {
		Setup -File "secrets-scan.json" -Content $configPrimary;
		It "Must return the contents of the file" {
			$expected = $configPrimary | ConvertFrom-Json;
			$results = Load-Rules -Path "$TestDrive\secrets-scan.json";
			$results | Should Not Be $null;
			$results.patterns | Should Not Be $null;
			$results.patterns.Count | Should Be $expected.patterns.Count;
			$results.allowed | Should Not Be $null;
			$results.allowed.Count | Should Be $expected.allowed.Count;
		}
	}
	Context "When .secrets-scan.json file does not exist" {
		It "Must throw exception" {
			{ Load-Rules -Path "$TestDrive\secrets-scan.json" } | Should Throw;
		}
	}
}

Describe "Scan-Path" {
	Context "When Path does not exist" {
		It "Must throw exception" {
			{ Scan-Path -Path "$TestDrive\fake-path" } | Should Throw;
		}
	}
}

Describe "Merge-JSON" {
	Context "When 2 objects merge" {
		It "Must return the combined object" {
			$primary = $configPrimary | ConvertFrom-Json;
			$secondary = $configSecondary | ConvertFrom-Json;
			$expectedPrimary = $configPrimary | ConvertFrom-Json;
			$expectedSecondary = $configSecondary | ConvertFrom-Json;
			$results = Merge-JSON -Base $primary -Ext $secondary;
			$results | Should Not Be $null;
			$results.patterns | Should Not Be $null;
			$results.patterns.Count | Should Be ($expectedPrimary.patterns.Count + $expectedSecondary.patterns.Count);
			$results.allowed | Should Not Be $null;
			$results.allowed.Count | Should Be ($expectedPrimary.allowed.Count + $expectedSecondary.allowed.Count);
		}
	}
}
