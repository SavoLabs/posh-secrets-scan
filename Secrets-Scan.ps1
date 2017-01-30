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
		$children = @(Get-ChildItem -Path $resolvedPath -Recurse -Force | where { $_.GetType().Name -eq "FileInfo" });
		[System.Collections.ArrayList] $violations = @();
		[System.Collections.ArrayList] $warnings = @();
		$stopWatch = [Diagnostics.Stopwatch]::StartNew();
		$filesScannedCount = 0;
	}
  process {
		$exitResult = 0;
		try {
			for($i = 0; $i -lt $children.Count; ++$i) {
	    # $children | foreach {
	      $item = $children[$i];
	      if ( -not $item.PSIsContainer ) {
					$filesScannedCount++;
					$content = Get-Content -Path $item.FullName;
					for($y = 0; $y -lt $rules.patterns.Count; ++$y) {
	        # $rules.patterns | foreach {
						$pattern = $rules.patterns[$y];
	          $content | Select-String -Pattern $pattern -AllMatches | foreach { $_.Matches; } | foreach {
							$match = $_
							$m = $match.Groups[0].Value;
	            $result = "$($item.FullName): $($match)";
							if ( $violations.IndexOf($result) -ge 0 ) {
								continue;
							}
							$violations.Add($result) | Out-Null;
	          };
	        };
	      } else {
					# Ignore Folders
	      }
	    };
			for($x = 0; $x -lt $violations.Count; ++$x) {
				$v = $violations[$x];
				$rules.allowed | foreach {
					$allowed = $_;
					if($v -match $allowed) {
						$vidx = $violations.IndexOf($v);
						if($vidx -ge 0) {
							$violations.Remove($v) | Out-Null;
						}
						if($warnings -notcontains $v) {
							$warnings.Add($v) | Out-Null;
						}
					}
				}
			}
			if($warnings.Count -gt 0 -and !$Quiet.IsPresent) {
				if($warnings.Count -eq 1) {
					$vtext = "Violation";
					$wtext = "was";
				} else {
					$wtext = "were";
					$vtext = "Violations";
				}
				"`n[Warning]: Found $($warnings.Count) $vtext that $wtext overridden by exception rules.`n" | Write-Host -foregroundcolor yellow;
				$warnings | foreach { "`t[-] $_" | Write-Host -foregroundcolor yellow; };
			}
			if($violations.Count -gt 0) {
				if(!$Quiet.IsPresent) {
					if($violations.Count -eq 1) {
						$vtext = "Violation";
					} else {
						$vtext = "Violations";
					}
					"`n[Error]: Found $($violations.Count) $vtext.`n" | Write-Host -foregroundcolor red;
					$violations | foreach { "`t[x] $_" | Write-Host -foregroundcolor red; };
					"`nPossible mitigations:`n
- Mark false positives as allowed by adding exceptions to '.secrets-scan.json'
- Revoke the Secret that was identified. The secret is no longer secure as it now exists in the commit history, even if removed from code.`n`n" | Write-Host;
				}
			}
	  } catch {
			$_ | Write-Error;
			exit 999;
		}

		$stopWatch.Stop();
		$time = $stopWatch.Elapsed;
		if($filesScannedCount -eq 1) {
			$filesText = "file";
		} else {
			$filesText = "files";
		}
		"`n[Scanned $filesScannedCount $filesText in $time]`n" | Write-Host;

		return @{
			violations = $violations;
			warnings = $warnings
		};

		exit $violations.Count;
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
