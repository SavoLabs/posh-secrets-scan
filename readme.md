# Secrets Scan

This is a `powershell` script that will scan a directory for `secret violations`. These can be RSA keys, AWS Access Keys, or any other type of secrets that may be present in code.

This will not prevent someone from checking them in to a `git` repository. The purpose is for CI, like jenkins, to execute the scan before the build process, and fail the build if there are secrets found.

If you would like to prevent the commit from even happening, you should look at [`git-secrets` from _awslabs_](https://github.com/awslabs/git-secrets). This is a git hook bash script to run on your local development environment. They have a very detailed `readme` to explain how to configure it.

### Mitigations

- Mark false positives as allowed by adding exceptions to `.secrets-scan.json`
- Revoke the Secret that was identified. The secret is no longer secure as it now exists in the commit history, even if removed from code.

### Install

The way we run this scan is on a Jenkins Windows Build Agent. On the build agent, we
have a specific directory to scripts. We have an environment variable `ENV:SCRIPTS_PATH`
defined that contains that path.

Here is a sample build configuration for a job to scan a repository:

- The first block makes sure the build agent has the latest version of the script installed.
 - It does this by downloading a script that exists in this repository and executes it.
 - The downloaded script will download the necessary files to the specified `-Path` argument, which is set to the `ENV:SCRIPTS_PATH` in the example below.
- The second block executes the scan and returns based on the result of the scan.

Windows Powershell:
```
$scriptsPath = "$ENV:SCRIPTS_PATH";
$initScript = (New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/SavoLabs/posh-secrets-scan/master/Secret-Scan-Initialize.ps1");
& $([scriptblock]::Create($initScript)) -Path $scriptsPath;
```
Windows Powershell:
```
(& powershell.exe -File "$ENV:SCRIPTS_PATH\secrets-scan.ps1" -Path "$ENV:WORKSPACE" -ConfigFile "$ENV:SCRIPTS_PATH\.secrets-scan.json");
exit $LASTEXITCODE;
```


### Usage

`PS> ./Secrets-Scan.ps1 -Path "C:\code\my-project\"`

Rules are defined in `.secrets-scan.json` in the root directory of the `Secrets-Scan.ps1`. Additionally, a scanned directory can contain its own `.secrets-scan.json` that will be merged with the _root_ configuration. See the [_Rules_](#rules) section below for more information.

Example of passing all parameters:

`PS> ./Secrets-Scan.ps1 -Path "C:\code\my-project\" -ConfigFile ".\.secrets-scan.json" -Quiet`

### Parameters

| Name | Description | Required | Type | Default |
| :--- | :--- | :---: | :--- | :--- |
| Path | The path to scan | ☑ | `String` | `NULL` |
| ConfigFile | The path to the `Rules` file | ☐ | `String` | `./.secrets-scan.json` |
| Quiet | If provided, no output will be logged | ☐ | `Switch` | `false` |

### Violations

The `exit code` of the script will be `0` for success, or it will be the count of the number of `Violations` found. The script will output the full path of the files that have violations, and the matching violation. `Warnings` will not change the `exit code`.

```
[Warning]: Found 1 Violation that was overridden by exception rules.
    [-] C:\code\my-project\super-secret-key.txt: AWS_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[Error]: Found 5 Violations.
    [x] C:\code\my-project\super-secret-key.txt: AWS_SECRET_KEY=PnsrlQ4QaWqISJ5zcNkma1ClqHBshI0Y65mYwnNT
    [x] C:\code\my-project\super-secret-key.txt: AWS_ACCESS_KEY=RtwpOEp4IeQqHawn7hsBIC13Cap2qCt1AmQqIOMY
    [x] C:\code\my-project\Subfolder\more-secrets.txt: aws_account_id:129398745743
    [x] C:\code\my-project\Subfolder\my-key.pem: -----BEGIN RSA PRIVATE KEY-----
    [x] C:\code\my-project\Subfolder\my-key.pub: -----BEGIN PUBLIC KEY-----


Possible mitigations:
    - Mark false positives as allowed by adding exceptions to '.secrets-scan.json'
    - Revoke the Secret that was identified. The secret is no longer secure as it
        now exists in the commit history, even if removed from code.
```

### Rules

Rules are defined in `.secrets-scan.json`. In there, you define the matching `patterns`, and the `allowed` exceptions. Both `patterns` and `allowed` sections are arrays of `regex` patterns.

#### Pattern

This matches on the text in the file.

#### Allowed

This matches on the file name and the violation match.

`/path/to/file.ext: VIOLATION_MATCH`

Ideally, only _basic_ exceptions should be defined in the main `.secrets-scan.json`, other exceptions would be defined in a file, also called `.secrets-scan.json`, within the root directory of the repository to be scanned. The script will load, and merge, the 2 configurations together.

```
{
    "patterns": [
        "(?s)(\"|')?(AWS|aws|Aws)?_?(SECRET|secret|Secret)?_?(ACCESS|access|Access)?_?(KEY|key|Key)(\"|')?\\s*(:|=>|=)\\s*(\"|')?[A-Za-z0-9/\\+=]{40}(\"|')?",
        "(?s)(\"|')?(AWS|aws|Aws)?_?(ACCOUNT|account|Account)_?(ID|id|Id)?(\"|')?\\s*(:|=>|=)\\s*(\"|')?[0-9]{4}\\-?[0-9]{4}\\-?[0-9]{4}(\"|')?",
        "(?s)^-----BEGIN\\sRSA\\sPRIVATE\\sKEY-----",
        "(?s)^-----BEGIN\\sPUBLIC\\sKEY-----"
    ],
    "allowed": [
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    ]
}
```
