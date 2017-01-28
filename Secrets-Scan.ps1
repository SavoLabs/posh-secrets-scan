param (
	[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
	[ValidateScript({Test-Path $_})]
  [String] $Path
)
function Load-Rules {
  param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
    [String] $Path
  )
  process {
    return Get-Content -Raw -Path $Path | ConvertFrom-Json;
  }
}
function Scan-Path {
  param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[ValidateScript({Test-Path $_})]
    [String] $Path
  )
	begin {
		if($PSCommandPath -eq $null) {
			$CommandRootPath = (Split-Path -Parent $MyInvocation.MyCommand.Path);
		} else {
			$CommandRootPath = (Split-Path -Parent $PSCommandPath);
		}
		$resolvedPath = (Resolve-Path -Path $Path);
		$rules = Load-Rules -Path (Join-Path -Path $CommandRootPath -ChildPath ".secrets-scan.json");
		$lrf = (Join-Path -Path $resolvedPath -ChildPath ".secrets-scan.json");
		if( Test-Path -Path $lrf ) {
			$localRules = Load-Rules -Path $lrf;
			$rules = Merge-JSON -Base $rules -Ext $localRules;
		}

		$children = @(Get-ChildItem -Path $resolvedPath -Recurse | where { $_.GetType().Name -eq "FileInfo" });
		[System.Collections.ArrayList] $violations = @();
		[System.Collections.ArrayList] $warnings = @();
	}
  process {
		try {
			for($i = 0; $i -lt $children.Count; ++$i) {
	    # $children | foreach {
	      $item = $children[$i];
	      if ( -not $item.PSIsContainer ) {
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
			if($warnings.Count -gt 0) {
				"`n[Warning]: Found $($warnings.Count) Violations that were overridden by exception rules.`n" | Write-Host;
				$warnings | foreach { "`t[-] $_" | Write-Host; };
			}
			if($violations.Count -gt 0) {
				"`n[Error]: Found $($violations.Count) Violations.`n" | Write-Host;
				$violations | foreach { "`t[x] $_" | Write-Host; };
				"`nPossible mitigations:`n
	- Mark false positives as allowed by adding exceptions to '.secrets-scan.json'
	- Revoke the Secret that was identified. The secret is no longer secure as it now exists in the commit history, even if removed from code.`n`n" | Write-Host -ForegroundColor DarkYellow;
				exit $violations.Count;
			}
	  } catch {
			$_ | Write-Error;
			exit 999;
		}
	}
}

function Merge-JSON {
	param (
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[PSObject] $Base,
		[Parameter(Mandatory=$true,ValueFromPipeline=$true)]
		[PSObject] $Ext
	)
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

Scan-Path -Path $Path;
