if($PSCommandPath -eq $null) {
	$CommandRootPath = (Split-Path -Parent $MyInvocation.MyCommand.Path);
} else {
	$CommandRootPath = (Split-Path -Parent $PSCommandPath);
}

if(-not (Get-Module -ListAvailable -Name "pester")) {
	choco install pester -y | Write-Host;
}

Import-Module "pester" -Verbose -Force;
$cdir = $PWD;


$testsDir = (Join-Path -Path "$CommandRootPath" -ChildPath "..\tests" -Resolve);
$scriptDir = (Join-Path -Path "$CommandRootPath" -ChildPath "..\" -Resolve);

$outDir = (Join-Path -Path "$CommandRootPath" -ChildPath "..\bin\");

if ( !(Test-Path -Path $outDir) ) {
	New-Item -ItemType "directory" -Path $outDir | Out-Null;
}

Set-Location -Path $testsDir | Out-Null;

$psModuleFiles = "$scriptDir\*.ps*1";

$tests = (Get-ChildItem -Path "$testsDir\*.Tests.ps1" | % { $_.FullName });
$coverageFiles = (Get-ChildItem -Path "$testsDir\*.ps*1") | where { $_.Name -inotmatch "\.tests\.ps1$" -and $_.Name -inotmatch "\.psd1$" } | % { $_.FullName };
$resultsOutput = (Join-Path -Path $outDir -ChildPath "secrets-scan.results.xml");

Invoke-Pester -Script $tests -OutputFormat NUnitXml -OutputFile $resultsOutput -CodeCoverage $coverageFiles -Strict;

Set-Location -Path $cdir | Out-Null;
