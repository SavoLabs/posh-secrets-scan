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
		`"(?si)(\`"|')?(aws)?_?(secret)?_?(access)?_?(key)(\`"|')?\\s*(:|=>|=)\\s*(\`"|')?[a-z0-9/\\+=]{40}(\`"|')?`",
		`"(?si)(\`"|')?(aws)?_?(account)_?(id)?(\`"|')?\\s*(:|=>|=)\\s*(\`"|')?[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}(\`"|')?`",
		`"(?si)-{5}begin\\s[rd]sa\\sprivate\\skey-{5}`",
		`"\\[?(?:\`"|'|:)?(password)(?:\`"|'|:)?\\]?\\s*(:|=>|=)\\s*(?:\`"|')?([\\w|\\s|\\d|\\-*\/~``!@\\#\\$%\\^&\\(\\)_\\<\\>]+)(?:\`"|'|)?`"
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

$configTertiary = "{
	`"patterns`": [
	],
	`"allowed`": [
		`"PnsrlQ4QaWqISJ5zcNkma1ClqHBshI0Y65mYwnNT`",
		`"RtwpOEp4IeQqHawn7hsBIC13Cap2qCt1AmQqIOMY`",
		`"aws_account_id:129398745743`"
	]
}";

$configQuaternary = "{
	`"patterns`": [
	],
	`"allowed`": [
		`"\\\\repo\\\\my-secrets\\.txt`"
	]
}"

$privateKey = "-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgFO/h8+74h1G6tMEvuv+Rg0SqAx//gZx2H2CJsnfy9Bdr0e0qvZD
kE3jJOwIaVy5jxzzuVQyNgZd5t+0jPGh374SjoZopBdd+IYwYdcfeauPds1IyJYa
jog9CqRnTW/rMnpvgGYQxNys+2tzDvHnL2uPgicVWjZHWzpAS6L3jKvLAgMBAAEC
gYA85Vo1vSJvs29wvVSueRgqzVQQssjdms6WhJr705V6D4UymLZvlzVIzU+9qWgj
mnHr1XT/Oft6qbEFHV4XHWN5Fbdm2VdyFUCZBZWxmrSx24BqfvPajagehzL9UDif
JsLcwF/0HLKR1Bu37g0/USCOpUINLjjmISyiculUoqui0QJBAKVMI5iXfF3Pgpb5
rIwpEn9/MIW08o24ls6X5wWpYw/v0OrrfJvqhtHgkrE/HsmN3V4Rze+i7D/cXnWD
gsyo4+8CQQCBs+e+4OmJTh9s7uQfyCJGPrpHjL0Jrb+VGO1N7PwRFp0qkE+TZQy/
0TeTOtFlCYGG3I+C1bQxBHaxRAH6AKnlAkEAh8Zq1sRX25a/5dNf8CEsmJ2Y9bsU
IWUmOrx7fyMLw+Nw8AZObKPP6kVVOVJnr5df5g0p41UoSaxxyoUjw4hW8QJBAIAx
Vg28slV5F2pNOr+GyQlwmiB5o6VbSw2ME49/eStSlIgrFdtydoVnvWwRKECagqDO
gjEoEu6XoNBXjTSRT1kCQEmt0GiKee3WfUJIrKhuFaCe9ihta4rfhjPeBioJyzqa
dBgY6tF4GMfg9bTPgRmg9KSoAHxG7niXwmnJunbrvHI=
-----END RSA PRIVATE KEY-----";
$publicKey = "-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBVSJi+7w5nALWcwMQn3OW1
sxFyX6sKHJmBT6uWgsqdq7OtWSh8Yo/+42eVgkJ9NXa2ayY8/pOF26BtK2A2yNuG
rnHZ1nB3/IiJAzOx2p0sMd6Q0T5yk0rPSx6PvsmWJnK12l2HWbERKw1IVvPtm8pN
PhsiDsweZpcmpvSqiPpdk/AqhCkt88WA+1/0YY9mlY92H63MRX3w+FPwgkC/dPzX
a9yTFie4sqLQ88YA2s81VPhPgaG7pallrM8hPVNhNgkMmOKPA6wffkjW+tD5q97V
1/njNSfrSW++S972KjNl9ZkiXe2yAJ9WD6vOhIGvFbIl7jnkziIfbKhRegDK9QzL
AgMBAAE=
-----END PUBLIC KEY-----";
$secretsFile = "aws_account_id:129398745743
AWS_SECRET_KEY=PnsrlQ4QaWqISJ5zcNkma1ClqHBshI0Y65mYwnNT
AWS_ACCESS_KEY=RtwpOEp4IeQqHawn7hsBIC13Cap2qCt1AmQqIOMY
AWS_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
key=s35RpQlY7K1Pjg8mby2ltHVabtBU9tsyB9QGw1do
password=Passsw0rd
os['windows']['password'] => 'Passw0rd'
os[:windows][:password] => 'Passw0rd'
os[windows:][password:] => 'Passw0rd'
";

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
	Context "When Path exists and has hidden folder" {
		It "Must scan the hidden folders" {
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			Setup -Directory "repo";
			Setup -Directory "repo/.fake";
			Setup -File "repo/.fake/COMMIT_EDITMSG" -Content "new key: AWS_SECRET_KEY=PnsrlQ4QaWqISJ5zcNkma1ClqHBshI0Y65mYwnNT";
			$hiddenDir = Get-Item -Path "$TestDrive/repo/.fake" -Force;
			$hiddenDir | foreach {$_.Attributes = "hidden"};
			{ Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet } | Should Not Throw;
			$result = Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet;
			$result | Should Not Be $null;
			$result.violations | Should Not Be $null;
			$result.warnings | Should Be $null;
			$result.violations.Count | Should Be 1;
			$hiddenDir | select Attributes | Should Match "Hidden";
			$hiddenDir | select Attributes | Should Match "Directory";
		}
	}
	Context "When a file has multiple violations that are excluded" {
		It "Must report all of them as warnings" {
			Setup -Directory "repo";
			Setup -File "repo\my-secrets.txt" -Content $secretsFile;
			Setup -File "repo\.secrets-scan.json" -Content $configTertiary;
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			{ Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet } | Should Not Throw;
			$result = Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet;
			$result | Should Not Be $null;
			$result.rules.allowed.Count | Should Be 5;
			$result.violations | Should Not Be $null;
			$result.warnings | Should Not Be $null;
			$result.warnings.Count | Should Be 5;
			$result.violations.Count | Should Be 5;

		}
	}
	Context "When an entire file is in the allowed" {
		It "Must ignore everything in that file" {
			Setup -Directory "repo";
			Setup -File "repo\my-secrets.txt" -Content $secretsFile;
			Setup -File "repo\.secrets-scan.json" -Content $configQuaternary;
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			{ Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet } | Should Not Throw;
			$result = Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet;
			$result | Should Not Be $null;
			$result.rules.allowed.Count | Should Be 3;
			$result.violations | Should Be $null;
			$result.violations.Count | Should Be 0;
			$result.warnings | Should Not Be $null;
			$result.warnings.Count | Should Be 9;
		}
	}
	Context "When Path exists and has overrides file and violations exist" {
		It "Must processess the files in 'Path' and report violations" {
			Setup -Directory "repo";
			Setup -File "repo\my-secrets.txt" -Content $secretsFile;
			Setup -File "repo\my-key.pem" -Content $privateKey;
			Setup -File "repo\my-key.pub" -Content $publicKey;
			Setup -File "repo\.secrets-scan.json" -Content $configSecondary;
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			{ Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet } | Should Not Throw;
			$result = Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet;
			$result | Should Not Be $null;
			$result.violations | Should Not Be $null;
			$result.warnings | Should Not Be $null;
			$result.warnings.Count | Should Be 1;
			$result.violations.Count | Should Be 9;
		}
	}
	Context "When Path exists and violations exist" {
		It "Must processess the files in 'Path' and report violations" {
			Setup -Directory "repo";
			Setup -File "repo\my-secrets.txt" -Content $secretsFile;
			Setup -File "repo\my-key.pem" -Content $privateKey;
			Setup -File "repo\my-key.pub" -Content $publicKey;
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			{ Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet } | Should Not Throw;
			$result = Scan-Path -Path "$TestDrive\repo" -ConfigFile "$TestDrive\.secrets-scan.json" -Quiet;
			$result | Should Not Be $null;
			$result.violations | Should Not Be $null;
			$result.warnings | Should Not Be $null;
			$result.warnings.Count | Should Be 1;
			$result.violations.Count | Should Be 9;
		}
	}

	Context "When using the short names for the arguments" {
		It "Must not throw an exception" {
			Setup -Directory "repo";
			Setup -File ".secrets-scan.json" -Content $configPrimary;
			Setup -File "repo\my-secrets.txt" -Content $secretsFile;
			{ Scan-Path -P "$TestDrive\repo" -C "$TestDrive\.secrets-scan.json" -Q } | Should Not Throw;
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
			$results.patterns.Count | Should Not Be 0;
			$results.patterns.Count | Should Be ($expectedPrimary.patterns.Count + $expectedSecondary.patterns.Count);
			$results.allowed | Should Not Be $null;
			$results.allowed.Count | Should Not Be 0;
			$results.allowed.Count | Should Be ($expectedPrimary.allowed.Count + $expectedSecondary.allowed.Count);
		}
	}
}
