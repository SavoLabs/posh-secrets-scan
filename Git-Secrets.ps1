param (
  [String] $Path
)
function Load-Rules {
  param (
    [String] $Path
  )
  process {
    return Get-Content -Raw -Path $Path | ConvertFrom-Json;
  }
}
function Scan-Path {
  param (
    [String] $Path
  )
	begin {
		$rules = Load-Rules -Path "./rules.json";
	}
  process {
		$children = @(Get-ChildItem -Path (Resolve-Path -Path $Path) -Recurse);
		[System.Collections.ArrayList] $violations = @();
    $children | foreach {
      $item = $_;
			$item | Write-Host;
      if ( -not $item.PSIsContainer ) {
				$content = Get-Content -Path $item.FullName;
        $rules.patterns | foreach {
					$pattern = $_;
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
				#return Recursive-Scan -Path $item.FullName;
      }
    };

		$violations | foreach {
			$v = $_
			$rules.allowed | foreach {
				$allowed = $_;
				if($v -match $allowed) {
					$vidx = $violations.IndexOf($v);
					if($vidx -ge 0) {
						$violations.Remove($v) | Out-Null;
					}
				}
			}
		}
		$violations | Write-Host;
		if($violations.Count -gt 0) {
			"`n[Error]: Found $($violations.Count) Violations.`n" | Write-Host -ForegroundColor DarkYellow;
			"Possible mitigations:`n`t- Mark false positives as allowed adding exceptions to 'rules.json'`n`n" | Write-Host -ForegroundColor DarkYellow;
			exit $violations.Count;
		}
  }
}

Scan-Path -Path $Path;
