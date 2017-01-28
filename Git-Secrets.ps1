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
  process {
    Recursive-Scan -Path $Path;
  }
}

function Recursive-Scan {
  param (
    [String] $Path
  )
  begin {
    $rules = Load-Rules -Path "./rules.json";
  }
  process {
    $children = Get-ChildItem -Path $Path;
		[System.Collections.ArrayList] $violations = @();
    $children | foreach {
      $item = $_;
      if ( $item.PSIsContainer ) {
        return Recursive-Scan -Path $item.FullName;
      } else {
        $content = Get-Content -Path $item.FullName;
        $rules.patterns | foreach {
					$pattern = $_;
          $content | Select-String -Pattern $pattern | foreach { $_.Matches; } | foreach {
						$match = $_
						$m = $match.Groups[0].Value;
            $result = "$($item.FullName): $($match)";
						if ( $violations.IndexOf($result) -ge 0 ) {
							continue;
						}
						$violations.Add($result) | Out-Null;
          };
        };
      }
    }

		$violations | Select -Unique | foreach {
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
		$violations | Select -Unique;
  }
}

Scan-Path -Path $Path;
