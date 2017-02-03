param (
	[Parameter(Mandatory=$true,ValueFromPipeline=$true, ParameterSetName="Scan")]
	[ValidateScript({Test-Path $_})]
  [String] $Path,
	[Parameter(Mandatory=$false,ValueFromPipeline=$true, ParameterSetName="Scan")]
	[ValidateScript({Test-Path $_})]
	[String] $ConfigFile = "./.secrets-scan.json",
	[Alias("Q")]
	[Parameter(Mandatory=$false,ValueFromPipeline=$true, ParameterSetName="Scan")]
	[Switch] $Quiet
)

function Load-Rules {
  param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
    [String] $Path
  )
  process {
    return Get-Content -Raw -Path (Resolve-Path -Path $Path)  | ConvertFrom-Json;
  }
}

function Scan-Path {
  param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
    [String] $Path,
		[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
		[String] $ConfigFile = "./.secrets-scan.json",
		[Parameter(Mandatory=$false,ValueFromPipeline=$true)]
		[Switch] $Quiet
  )
	begin {
		$resolvedPath = (Resolve-Path -Path $Path);
		$rules = Load-Rules -Path $ConfigFile;
		$lrf = (Join-Path -Path $resolvedPath -ChildPath ".secrets-scan.json");
		if( Test-Path -Path $lrf ) {
			$localRules = Load-Rules -Path $lrf;
			$rules = Merge-JSON -Base $rules -Ext $localRules;
		}
		# TODO: refactor this to not recurse here. It is slow.
		$children = @(Get-ChildItem -Path $resolvedPath -Recurse -Force | where { $_.GetType().Name -eq "FileInfo" });
		[System.Collections.ArrayList] $violations = @();
		[System.Collections.ArrayList] $warnings = @();
		$stopWatch = [Diagnostics.Stopwatch]::StartNew();
		$filesScannedCount = 0;
		$commitScannedCount = 0;
		$cwd = Get-Location;
		Set-Location -Path $resolvedPath;
	}
  process {

		$exitResult = 0;
		try {
			for($i = 0; $i -lt $children.Count; ++$i) {
	    # $children | foreach {
	      $item = $children[$i];
	      if ( -not $item.PSIsContainer ) {
					$filesScannedCount++;
					$content = (Get-Content -Path $item.FullName);
					(Get-Violations -Rules $rules -Data @{ Content = $content; Name = $item.FullName; }) | foreach {
						if($violations.IndexOf($_) -lt 0) {
							$violations.Add($_) | Out-Null;
						}
					};
					$logContent = (Get-GitLogForFile -Path $item.FullName) | foreach {
						"logContent: $logContent" | write-warning;
						$xContent = $_;
						$commitScannedCount++;
						(Get-Violations -Rules $rules -Data @{ Content = $xContent.Content; Name = $xContent.Name; }) | foreach {
							if($violations.IndexOf($_) -lt 0) {
								$violations.Add($_) | Out-Null;
							}
						};
					};
	      } else {
					# Ignore Folders
	      }
	    };

			$postProcess = Invoke-PostProcessViolations -Rules $rules -Violations $violations -Warnings $warnings;

			$outViolations = Write-Violations -Violations $violations -Warnings $warnings -Quiet:$Quiet.IsPresent;
	  } catch {
			$_ | Write-Error;
			exit 999;
		} finally {

			$stopWatch.Stop();
			$time = $stopWatch.Elapsed;
			$filesText = "files";
			if($filesScannedCount -eq 1) {
				$filesText = "file";
			}
			$commitsText = "commits";
			if($commitScannedCount -eq 1) {
				$commitsText = "commit";
			}

			if(!$Quiet.IsPresent) {
				"`n[Scanned $filesScannedCount $filesText and $commitScannedCount $commitsText in $time]`n" | Write-Host;
			}

			Set-Location -Path $cwd;
		}

		return @{
			rules = $rules;
			violations = $violations;
			warnings = $warnings;
		};

		exit $violations.Count;
	}
}

function Write-Violations {
	param (
		[System.Collections.ArrayList] $Violations,
		[System.Collections.ArrayList] $Warnings,
		[Switch] $Quiet
	)
	process {
		if($Warnings.Count -gt 0 -and !$Quiet.IsPresent) {
			if($Warnings.Count -eq 1) {
				$vtext = "Violation";
				$wtext = "was";
			} else {
				$wtext = "were";
				$vtext = "Violations";
			}
			"`n[Warning]: Found $($Warnings.Count) $vtext that $wtext overridden by exception rules.`n" | Write-Host -foregroundcolor yellow;
			$Warnings | foreach { "`t[-] $_" | Write-Host -foregroundcolor yellow; };
		}
		if($Violations.Count -gt 0) {
			if(!$Quiet.IsPresent) {
				if($Violations.Count -eq 1) {
					$vtext = "Violation";
				} else {
					$vtext = "Violations";
				}
				"`n[Error]: Found $($Violations.Count) $vtext.`n" | Write-Host -foregroundcolor red;
				$Violations | foreach { "`t[x] $_" | Write-Host -foregroundcolor red; };
				"`nPossible mitigations:`n
	- Mark false positives as allowed by adding exceptions to '.secrets-scan.json'
	- Revoke the Secret that was identified. The secret is no longer secure as it now exists in the commit history, even if removed from code.`n`n" | Write-Host;
			}
		}

		return @{
			violations = $Violations;
			warnings = $Warnings;
		};
	}
}

function Invoke-PostProcessViolations {
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[PSCustomObject]$Rules,
		[System.Collections.ArrayList] $Violations,
		[System.Collections.ArrayList] $Warnings
	)
	process {
		[System.Collections.ArrayList] $removeIndex = @();
		for($a = 0; $a -lt $Rules.allowed.Count; $a++) {
			$allowed = $Rules.allowed[$a];
			for($x = $Violations.Count; $x -ge 0; $x--) {
				$v = $Violations[$x];
				$v | Select-String -Pattern $allowed -AllMatches | foreach { $_.Matches } | foreach {
					$match = $_;
					$m = $match.Groups[0].Value;
					$vidx = $Violations.IndexOf($v);
					if($vidx -ge 0) {
						$riidx = $removeIndex.IndexOf($vidx);
						if(-not $removeIndex.Contains($vidx)) {
							$removeIndex.Add($vidx);
						}
					}
					if($Warnings -notcontains $v) {
						$Warnings.Add($v) | Out-Null;
					}
				}
			}
		}
		$removeIndex.sort() | Out-Null;
		$removeIndex.reverse() | Out-Null;
		$removeIndex | foreach {
			$Violations.RemoveAt($_) | Out-Null;
	 	}
		return @{
			violations = $Violations;
			warnings = $Warnings;
		}
	}
}

function Get-GitLogForFile {
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
		[String] $Path
	)

	process {
		$output = Execute-GitLogCommand -Path $Path;
		$output | write-warning;
		[System.Collections.ArrayList]$dataList = @();
		if($output -ne $null) {
			$currentSHA = "";
			$SHAregex = "(\b[0-9a-f]{5,40}\b)$";
			$commitSHA1Regex = "(?mi)commit\s$SHAregex";
			[regex]::split($output, $commitSHA1Regex) | foreach {
				if($_ -match $SHAregex) {
					$currentSHA = $_;
				} else {
					if($currentSHA -ne "") {
						$dataList.Add(@{
							Name = "$($Path): [Commit]$currentSHA";
							Content = $_;
						}) | Out-Null;
					}
				}
			}
		} else {
			"no output found" | write-warning;
			return @();
		}
		return $dataList;
	}
}

function Execute-GitLogCommand {
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
		[String] $Path,
		[Int] $CommitCount = 3
	)
	begin {
		$git = "git.exe";
	}
	process {
		if ((Get-Command -Name $git -ErrorAction SilentlyContinue)) {
			return (Invoke-Expression "$git log -$CommitCount -p $Path *>&1") -join "`n";
		} else {
			return $null;
		}
	}
}

function Get-Violations {
	param(
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[PSCustomObject] $Data,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[PSCustomObject] $Rules
	)
	begin {
		[System.Collections.ArrayList] $ruleViolations = New-Object System.Collections.ArrayList;
	}
	process {
		for($y = 0; $y -lt $Rules.patterns.Count; ++$y) {
		# $rules.patterns | foreach {
			$pattern = $Rules.patterns[$y];
			$Data.Content | Select-String -Pattern $pattern -AllMatches | foreach { $_.Matches; } | foreach {
				$match = $_;
				$m = $match.Groups[0].Value;
				$result = "$($Data.Name): $($match)";
				if ( $ruleViolations.IndexOf($result) -ge 0 ) {
					continue;
				}
				$ruleViolations.Add($result) | Out-Null;
			};
		};
		return [Array]$ruleViolations;
	}
}

function Merge-JSON {
	param (
		[Parameter(Mandatory=$true)]
		[PSObject] $Base,
		[Parameter(Mandatory=$true)]
		[PSObject] $Ext
	)
	process {
		$propNames = $($ext | Get-Member -MemberType *Property).Name
		foreach ($propName in $propNames) {
			if ($base.PSObject.Properties.Match($propName).Count) {
				if ($base.$propName.GetType().Name -eq "PSCustomObject") {
					$base.$propName = Merge-JSON -Base $base.$propName -Ext $ext.$propName;
				} elseif ( $base.$propName.GetType().Name -eq "Object[]") {
					$ext.$propName | foreach {
						if ( $base.$propName -notcontains $_ ) {
							$base.$propName += $_;
						}
					}
				} else {
					$base.$propName = $ext.$propName;
				}
			} else {
				$base | Add-Member -MemberType NoteProperty -Name $propName -Value $ext.$propName;
			}
		}
		return $base;
	}
}

if( ($Execute -eq $null) -or ($Execute -eq $true) ) {
	$results = Scan-Path -Path $Path -ConfigFile $ConfigFile -Quiet:$Quiet;
	exit $results.violations.Count;
}
